#!/usr/bin/env python3
"""
CVA6 Pipeline Viewer — Phase 3 pipeline tracer.

Extends Phase 2 to track the full instruction lifecycle, not just the fetch
handshake. Each instance is followed through:

    fetch → decode → issue (allocates trans_id) → execute → writeback → commit

with stage cycles populated, flushes detected and recorded, and the warmup
boundary identified via the first commit at `--user-entry-pc`. The output
JSON matches the schema in cva6_viewer_phase0_spec.md §5 with these fields
now populated in addition to Phase 2's set:

    id_cycle, is_cycle, ex_cycle, wb_cycle, co_cycle,
    trans_id, flushed, flush_reason, is_warmup,
    instr_word (now masked to 16 bits when is_compressed)

Per-port handling:
  - wt_valid_i is a packed 5-bit bus in this config (one VCD signal); each
    bit is a writeback port. trans_id_i is 5 separate 3-bit signals indexed
    by port. To match a writeback to an in-flight instance: at each rising
    edge, for each port where wt_valid bit is 1, look up trans_id_i[port]
    and find the instance with that trans_id.
  - commit_ack_o is a packed 2-bit bus. The corresponding scoreboard
    commit_pointer_q[0] / [1] tell us the trans_id being released on each
    port.

Per-cycle processing order at each rising clock edge:
  1. Flush detection (cascade: flush_ex flushes EX + ID + IF)
  2. Commit (releases scoreboard slots BEFORE issue can reuse them)
  3. Writeback (updates wb_cycle on still-in-flight instances)
  4. Issue (decoded → issued, captures trans_id)
  5. Decode (fetched → decoded)
  6. Fetch (new instance enters fetched)

This order ensures that within a single cycle, commits release slots
before issue claims new ones, mirroring the actual hardware FIFO discipline.

Usage:
    python3 phase3_pipeline_tracer.py <path-to.vcd>
    python3 phase3_pipeline_tracer.py fdiv.vcd \\
        --user-entry-pc 0x80003000 \\
        --output fdiv.phase3.json
"""

import argparse
import json
import re
import sys
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ============================================================================
# I$ controller FSM enum (Phase 4b)
# ============================================================================
# Mirrors cva6_icache.sv:122. Used by ICacheTimeline.on_cycle to classify
# each delivery as a hit (state_q == READ at fe2) or miss (state_q == MISS).
# VCD encodes the 3-bit state as a binary string, e.g. "011" for MISS.

FSM_FLUSH       = "000"
FSM_IDLE        = "001"
FSM_READ        = "010"
FSM_MISS        = "011"
FSM_KILL_ATRANS = "100"
FSM_KILL_MISS   = "101"


# ============================================================================
# LSU FSM enums (Phase 6a)
# ============================================================================
# load_unit.sv:83  — 4-bit FSM, 9 states
# store_unit.sv:119 — 2-bit FSM, 4 states
#
# SystemVerilog enum without explicit values auto-assigns sequential
# integers from 0. VCD encodes each as a binary string of the declared
# width (4 chars for load_unit, 2 for store_unit). Names lifted
# verbatim from the SV source.

LOAD_FSM_NAMES = {
    0: "IDLE",
    1: "WAIT_GNT",
    2: "SEND_TAG",
    3: "WAIT_PAGE_OFFSET",
    4: "ABORT_TRANSACTION",
    5: "ABORT_TRANSACTION_NI",
    6: "WAIT_TRANSLATION",
    7: "WAIT_FLUSH",
    8: "WAIT_WB_EMPTY",
}

STORE_FSM_NAMES = {
    0: "IDLE",
    1: "VALID_STORE",
    2: "WAIT_TRANSLATION",
    3: "WAIT_STORE_READY",
}


# ============================================================================
# Control-flow type enum (Phase 7a — branch predictor)
# ============================================================================
# Per ariane_pkg.sv:170-176. The cf_t type is used both as the prediction
# carried with each instruction (branchpredict_sbe_t.cf) and as the
# resolution emitted by the branch_unit (bp_resolve_t.cf_type).
#
#   NoCF   = 0  : no control-flow prediction made. For a non-branch
#                 instruction this is the steady state. For an actual
#                 branch that was predicted not-taken, this is also the
#                 value (no jump was predicted).
#   Branch = 1  : conditional branch predicted taken by the BHT.
#   Jump   = 2  : unconditional direct jump (target is known at decode).
#   JumpR  = 3  : indirect jump (target predicted by the BTB).
#   Return = 4  : return predicted by the RAS.
#
# A `cf` value at issue thus also identifies the predictor source:
#   Branch -> BHT
#   JumpR  -> BTB
#   Return -> RAS
#   Jump   -> none needed (decoder-resolved)
#   NoCF   -> none (or non-branch instruction)

CF_T_NAMES = {
    0: "NoCF",
    1: "Branch",
    2: "Jump",
    3: "JumpR",
    4: "Return",
}

def cf_name(s):
    """Decode a cf_t binary string. Returns 'NoCF' on None/unknown."""
    if s is None:
        return None
    v = binary_to_int(s)
    if v is None:
        return None
    return CF_T_NAMES.get(v, f"UNK_{v}")


# ============================================================================
# HPDcache requestor source-ID assignment (Phase 6b)
# ============================================================================
# Per cva6_hpdcache_wrapper.sv (NumPorts=4 in
# cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv) the SID layout is:
#
#   - sid 0   : PTW load adapter         (page table walker, MMU)
#   - sid 1   : LSU load_unit adapter    (data loads — what we care about)
#   - sid 2   : Accelerator load adapter (acc_cache[0])
#   - sid 3   : STORE adapter            (NumPorts-1)
#   - sid 4   : CMO adapter              (NumPorts)
#   - sid 5   : hwpf_stride prefetcher   (NumPorts+1)
#
# Mapping derived by tracing cva6.sv:1321..1327 (dcache_req_to_cache[0..3]
# assignments) → load_store_unit.sv:315/586/545 (port 0=PTW, 1=load_unit,
# 2=store_unit). The HPDcache wrapper feeds dcache_req_ports_i[0..2] to
# load adapter slots r=0..2 with hpdcache_req_sid_i = r.
#
# IMPORTANT ARCHITECTURAL FINDING (Phase 6b 0.1 empirical validation):
# Across both fdiv (4279 cyc) and compress (5177 cyc) the ONLY SID
# observed firing mshr_alloc_i is sid=3 (STORE), with exactly 20 events
# each — all with tid=0 and pf=0. The LSU load_unit (sid=1) never
# primary-allocates an MSHR in either workload.
#
# Why: hpdcache_ctrl_pe.sv:498-590 routes load misses through a
# cascade of "go to replay table" conditions before falling through
# to `st2_mshr_alloc_o = 1'b1`. The dominant condition for loads is
# `st1_mshr_hit_i` (the line is already pending an MSHR entry,
# typically from a preceding store) — the load coalesces instead of
# allocating. In load/store-interleaved workloads this means stores
# get to the cache first and allocate, loads piggyback. Pure
# read-only workloads OR post-flush cold loads should exercise the
# load primary-allocation path; we just don't have such tests yet.
#
# Implication for attribution:
# `dc_primary_miss` is set only when an alloc fires with sid ==
# LOAD_UNIT_SID (= 1) AND mTID == record.trans_id. The full
# LOAD_ADAPTER_SIDS set is kept for documentation but NOT used for
# the boolean — PTW (sid=0) allocations have their own semantics
# (they're page-walk misses, not data-load misses) and would be
# misattributed if a LOAD record's window happened to bracket them.

HPDCACHE_NUM_PORTS  = 4
LOAD_ADAPTER_SIDS   = frozenset(range(HPDCACHE_NUM_PORTS - 1))   # {0, 1, 2}
PTW_LOAD_SID        = 0
LOAD_UNIT_SID       = 1   # ← the only SID that flips dc_primary_miss on a LOAD record
ACCEL_LOAD_SID      = 2
STORE_ADAPTER_SID   = HPDCACHE_NUM_PORTS - 1                     # 3
CMO_ADAPTER_SID     = HPDCACHE_NUM_PORTS                          # 4
HWPF_ADAPTER_SID    = HPDCACHE_NUM_PORTS + 1                      # 5

# REFILL_FSM enum from hpdcache_miss_handler.sv. Verilator widens this
# to 32 bits because the typedef has no explicit width — see line 397
# (refill_tid_q assignment). State 0 is the idle state; any non-zero
# value means a refill is in progress.
REFILL_FSM_IDLE = 0


# ============================================================================
# Whitelist (Phase 2 set + commit_pointer_q for trans_id-based commit matching)
# ============================================================================

WHITELIST = [
    # Clock
    "clk_i",

    # I$ request / response
    "i_frontend.icache_dreq_o.req",
    "i_frontend.icache_dreq_o.vaddr",
    "i_frontend.icache_dreq_o.kill_s1",
    "i_frontend.icache_dreq_o.kill_s2",
    "i_frontend.icache_dreq_i.valid",
    "i_frontend.icache_dreq_i.vaddr",

    # Fetch handshake
    "id_stage_i.fetch_entry_valid_i",
    "id_stage_i.fetch_entry_ready_o",
    "id_stage_i.rvfi_is_compressed_o",

    # Per-instruction payload from frontend
    "fetch_entry_if_id[0].address",
    "fetch_entry_if_id[0].instruction",

    # Decode handshake
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",

    # Issue handshake
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",

    # Decoded-instruction fields sampled at decode handshake (Phase 4a).
    # decoded_instr_i is declared `[NrIssuePorts-1:0]`; with NrIssuePorts=1
    # only [0] exists.
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].fu",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rs1",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rs2",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rd",
    # Phase 7a: branch prediction also flows in via decoded_instr_i.bp.
    # Reading from `mem_q[tid].sbe.bp` at issue time was buggy — at
    # post-edge of the issue rising edge, issue_pointer_q has already
    # advanced and mem_q[tid] points at the PREVIOUS occupant's data
    # (we'd attribute stale bp values to the newly issued record).
    # The decoded_instr_i.bp combinational signal carries the correct
    # data right BEFORE the rising edge, so pre-edge snapshotting
    # (same approach as fu/rs1/rs2/rd) is the clean source.
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.cf",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.predict_address",

    # Phase 8a: forwarding capture. Probed at the issue cycle to learn
    # whether each source operand was taken from the regfile or from
    # the forwarding network, and from which producer slot.
    #
    # forward_rsX : 1 bit when the source had a RAW hazard AND the
    #               operand was available from the forwarding network
    #               (the producer's result is either in mem_q[tid].sbe
    #               or arriving on the writeback bus this cycle).
    # idx_hzd_rsX : TRANS_ID_BITS-wide scoreboard slot index the source
    #               is forwarding FROM. Only meaningful when
    #               forward_rsX = 1.
    #
    # All six are declared `[NrIssuePorts-1:0]` in issue_read_operands.
    # With NrIssuePorts=1, the signal is a 1-bit (for forward_rsX) or
    # TRANS_ID_BITS-bit (for idx_hzd_rsX, after the [0] selector) value.
    "issue_stage_i.i_issue_read_operands.forward_rs1",
    "issue_stage_i.i_issue_read_operands.forward_rs2",
    "issue_stage_i.i_issue_read_operands.forward_rs3",
    "issue_stage_i.i_issue_read_operands.idx_hzd_rs1[0]",
    "issue_stage_i.i_issue_read_operands.idx_hzd_rs2[0]",
    "issue_stage_i.i_issue_read_operands.idx_hzd_rs3[0]",

    # Writeback (packed 5-bit wt_valid_i bus + 5 indexed trans_id_i)
    "issue_stage_i.i_scoreboard.wt_valid_i",
    "issue_stage_i.i_scoreboard.trans_id_i[0]",
    "issue_stage_i.i_scoreboard.trans_id_i[1]",
    "issue_stage_i.i_scoreboard.trans_id_i[2]",
    "issue_stage_i.i_scoreboard.trans_id_i[3]",
    "issue_stage_i.i_scoreboard.trans_id_i[4]",

    # Phase 4a v0.2: scoreboard's REGISTERED mem_q ring buffer. Reading
    # fu/rs1/rs2/rd from mem_q[trans_id].sbe at writeback time gives the
    # authoritative decoded fields with no timing ambiguity: mem_q is written
    # at decode-handshake's edge and stays constant until the slot is reused.
    # The decoded_instr_i[0].* path above is kept as a fallback for flushed
    # records that never reach writeback. (NR_SB_ENTRIES = 8.)
    "issue_stage_i.i_scoreboard.mem_q[0].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[1].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[2].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[3].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[4].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[5].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[6].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[7].sbe.fu",
    "issue_stage_i.i_scoreboard.mem_q[0].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[1].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[2].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[3].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[4].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[5].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[6].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[7].sbe.rs1",
    "issue_stage_i.i_scoreboard.mem_q[0].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[1].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[2].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[3].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[4].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[5].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[6].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[7].sbe.rs2",
    "issue_stage_i.i_scoreboard.mem_q[0].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[1].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[2].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[3].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[4].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[5].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[6].sbe.rd",
    "issue_stage_i.i_scoreboard.mem_q[7].sbe.rd",

    # Phase 7a v0.2: NOTE that branch prediction is captured from
    # decoded_instr_i[0].bp via pre-edge snapshot (see entries above
    # in the decoded_instr_i block), NOT from mem_q[N].sbe.bp.
    # An earlier v0.1 attempt to read mem_q[tid].sbe.bp at issue
    # time produced stale values because issue_pointer_q advances
    # on the issue rising edge — at post-edge, `tid` points at the
    # NEXT slot, not the just-allocated one, so mem_q[tid] holds
    # the previous occupant's bp. Phase 4a sidesteps this for
    # fu/rs1/rs2/rd by pre-edge snapshotting decoded_instr_i; we
    # apply the same technique for bp.cf and bp.predict_address.

    # Phase 7a: branch resolution from the EX-stage's branch_unit.
    # bp_resolve_t struct (cva6.sv:134) carries pc, target_address,
    # is_taken, is_mispredict, cf_type when valid=1 for one cycle at
    # the branch's ex_cycle. Captured at the scoreboard's input
    # (scoreboard.sv:73-265 use `resolved_branch_i`). We bind by PC
    # match against in-flight CTRL_FLOW records, disambiguating by
    # oldest is_cycle when multiple records share a PC (loop bodies).
    "issue_stage_i.i_scoreboard.resolved_branch_i.valid",
    "issue_stage_i.i_scoreboard.resolved_branch_i.pc",
    "issue_stage_i.i_scoreboard.resolved_branch_i.target_address",
    "issue_stage_i.i_scoreboard.resolved_branch_i.is_taken",
    "issue_stage_i.i_scoreboard.resolved_branch_i.is_mispredict",
    "issue_stage_i.i_scoreboard.resolved_branch_i.cf_type",

    # Commit (packed 2-bit commit_ack_o + 2 indexed commit_pointer_q)
    "commit_stage_i.commit_ack_o",
    "issue_stage_i.i_scoreboard.commit_pointer_q[0]",
    "issue_stage_i.i_scoreboard.commit_pointer_q[1]",

    # Flush
    "flush_ctrl_if",
    "flush_ctrl_id",
    "flush_ctrl_ex",
    "flush_ctrl_bp",
    # Phase 4a v0.3: flush_unissued_instr_i gates the scoreboard's actual
    # mem_n write at the decode handshake (scoreboard.sv line 171). When it
    # is high, DV && DA both still fire but HW does NOT allocate a slot —
    # so we must NOT fire on_decode either, or the fetched queue drifts
    # ahead of HW and every subsequent mem_q read is read from the wrong
    # slot.
    "issue_stage_i.i_scoreboard.flush_unissued_instr_i",

    # Phase 4b: I$ controller FSM state register. Used to distinguish
    # hits (state_q == READ at fe2) from genuine line misses
    # (state_q == MISS at fe2). The frontend-side dreq signals above
    # (i_frontend.icache_dreq_{i,o}) carry the request/response
    # handshake; this one carries the cache's internal state machine.
    # The 6-state enum is defined in cva6_icache.sv:122
    # (FLUSH/IDLE/READ/MISS/KILL_ATRANS/KILL_MISS).
    "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.state_q",

    # Phase 6a: LSU pipeline FSM state registers. Sampled per rising
    # edge in parallel with the existing dispatch steps; transitions
    # are attributed to the currently-pending record (set by the
    # scoreboard issue handshake when fu is LOAD or STORE).
    # load_unit.sv:83  — 9 states across 4 bits
    # store_unit.sv:119 — 4 states across 2 bits
    "ex_stage_i.lsu_i.i_load_unit.state_q",
    "ex_stage_i.lsu_i.i_store_unit.state_q",
    # Phase 6a v0.4: lsu_ctrl is the combinational wire feeding both
    # FSMs (load_store_unit.sv:174). Its trans_id at the cycle
    # BEFORE an FSM IDLE→non-IDLE transition is the admitted record.
    "ex_stage_i.lsu_i.lsu_ctrl.trans_id",
    # Phase 6a v0.5: pop_ld / pop_st are asserted by load_unit and
    # store_unit respectively whenever they consume a request from
    # lsu_bypass. pop_ld=1 while load FSM is in SEND_TAG is an
    # admit-while-busy event (load_unit.sv:343) — a NEW load is
    # being admitted while the previous one's tag is being sent.
    # pop_st=1 while store FSM is in VALID_STORE is the analog
    # (store_unit.sv:191).
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i",
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i",

    # Phase 6b: HPDcache miss/refill event signals. Hierarchy includes
    # the `gen_cache_hpd.` generate block — there are 3 cache subsystem
    # variants in cva6.sv (lines 1366/1426/1490) under different
    # gen_cache_* generate blocks for different DCacheType values;
    # this build uses HPDcache. All signals live under:
    #   gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.
    #     hpdcache_miss_handler_i.*
    #
    # The mshr_alloc_* group is sampled when mshr_alloc_i pulses high
    # (primary miss → fresh MSHR entry). mshr_alloc_sid_i identifies
    # the requestor (see SID assignment constants above) and is the
    # only way to distinguish a load-adapter miss from a
    # store/prefetch-initiated miss — without this filter, allocations
    # would be wrongly attributed to whichever LSU FSM is currently in
    # admit/non-IDLE state.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_tid_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_sid_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_is_prefetch_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_nline_i",
    # mshr_check_i / mshr_check_hit_o capture the secondary-miss
    # path: when a request finds its nline already in an MSHR entry
    # (mshr_check_hit_o=1 on the same cycle mshr_check_i pulses),
    # the request coalesces. This is the dominant path for fdiv-style
    # workloads where loads follow stores to the same line.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_check_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_check_nline_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_check_hit_o",
    # refill_fsm_q (any non-zero value = active refill) lets us flag
    # loads that overlap a refill cycle even when not directly
    # involved in alloc/coalesce — e.g., id=142 in fdiv was a hit
    # delayed by a refill consuming the cache port.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_fsm_q",
    # refill_core_rsp_valid_o pulses when refill data is delivered
    # back to the requesting core port. refill_core_rsp_o.tid carries
    # the requesting tid (see hpdcache_miss_handler.sv:382,397).
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_core_rsp_valid_o",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_core_rsp_o.tid",

    # Phase 7b: dirty victim WRITEBACK path. This config is WRITE-BACK
    # (wtEn=0, wbEn=1): the write buffer is configured out (gen_no_wbuf),
    # so stores retire to the cache (dirty) and a line reaches memory only
    # on eviction, via the flush/wback unit (gen_flush.flush_i). We trace
    # that lifecycle at the i_hpdcache level:
    #   ALLOC  flush_alloc && flush_alloc_ready (nline = flush_alloc_nline)
    #          miss handler hands a dirty victim to the flush unit
    #   SEND   mem_req_write_flush_valid && _ready (id/addr in the struct)
    #          writeback request issued to memory
    #   ACK    mem_resp_write_flush_valid && _ready (id; flush_ack_nline)
    #          memory acknowledges
    # send<->ack pair EXACTLY by flush slot id (mem_req_id==mem_resp_w_id;
    # the flush channel carries the raw slot id, the high-bit source tag is
    # applied only at the write arbiter so no masking is needed here).
    # alloc<->ack join by nline. AXI write latency = ack - send (validated
    # at 6 cyc median on daxpy, matching the read-refill dc_refill_overlap).
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_alloc",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_alloc_ready",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_alloc_nline",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_req_write_flush_valid",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_req_write_flush_ready",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_req_write_flush.mem_req_id",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_req_write_flush.mem_req_addr",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_resp_write_flush_valid",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_resp_write_flush_ready",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.mem_resp_write_flush.mem_resp_w_id",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_ack_nline",

    # Phase 7b linkage: tie each writeback to the eviction that caused it.
    # The controller (st2) drives the dirty-victim flush_alloc together with
    # the miss allocation (same cycle, validated delta=0). The join key is
    # (set, victim_way): the incoming line X (mshr_alloc_nline_i) and the
    # evicted victim Y (flush_alloc_nline) share the cache set, and the
    # victim way matches (one-hot on both sides). 256 sets / 8 ways ->
    # set = nline & 0xff. Reuses mshr_alloc_i / mshr_alloc_nline_i from the
    # Phase 6b group; adds the wback flag, the one-hot victim way, and the
    # flush-side one-hot way.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_wback_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_alloc_victim_way_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_alloc_way",
]

REQUIRED_SIGNALS = {
    "clk_i",
    "id_stage_i.fetch_entry_valid_i",
    "id_stage_i.fetch_entry_ready_o",
    "fetch_entry_if_id[0].address",
    "fetch_entry_if_id[0].instruction",
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].fu",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rs1",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rs2",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].rd",
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",
    "issue_stage_i.i_scoreboard.wt_valid_i",
    "issue_stage_i.i_scoreboard.trans_id_i[0]",
    "commit_stage_i.commit_ack_o",
}

PHASE3_POPULATES = {
    "id", "pc", "instr_word", "is_compressed", "is_warmup", "fetch_port",
    "fe_cycle", "id_cycle", "is_cycle", "ex_cycle", "wb_cycle", "co_cycle",
    "trans_id", "flushed", "flush_reason",
}

PHASE4A_POPULATES = PHASE3_POPULATES | {"fu", "fu_category", "rs1", "rs2", "rd"}


# ============================================================================
# Functional-unit metadata (from ariane_pkg.sv fu_t enum + spec §5.7 rollup)
# ============================================================================

FU_NAME = {
    0:  "NONE",
    1:  "LOAD",
    2:  "STORE",
    3:  "ALU",
    4:  "CTRL_FLOW",
    5:  "MULT",
    6:  "CSR",
    7:  "FPU",
    8:  "FPU_VEC",
    9:  "CVXIF",
    10: "ACCEL",
    11: "AES",
}

# Per spec §5.7. MemFP (FP load/store) requires looking at the op or
# is_rd_fpr/is_rs2_fpr flag, not just fu — deferred to a later increment.
# Both LOAD and STORE roll up to Mem regardless of int/FP target here.
FU_CATEGORY = {
    "ALU":       "Int",
    "CTRL_FLOW": "Int",
    "MULT":      "Int",
    "CSR":       "Int",
    "AES":       "Int",     # AES extensions execute on the FLU/AES unit
    "LOAD":      "Mem",
    "STORE":     "Mem",
    "FPU":       "FP",
    "FPU_VEC":   "FP",
    "CVXIF":     "CVXIF",
    "ACCEL":     "ACCEL",
    "NONE":      "None",
}


# ============================================================================
# Instruction record
# ============================================================================

@dataclass
class InstructionRecord:
    id: int = 0
    pc: str = None
    instr_word: str = None
    disasm: str = None
    is_compressed: bool = False
    is_warmup: bool = False
    fu: str = None
    fu_category: str = None
    rd: int = None
    rs1: int = None
    rs2: int = None
    trans_id: int = None
    fetch_port: int = 0
    # Phase 4b: I$ pipeline stage cycles. if1_cycle is the cycle the I$
    # accepted the request; if2_cycle is the cycle the I$ delivered data
    # via dreq_o.valid=1. For hits: if2 = if1 + 1. For cacheable misses:
    # if2 = if1 + ~5. For NC bypass: if2 = if1 + 4. RVC pairs in the same
    # 4-byte word share identical if1/if2.
    if1_cycle: int = None
    if2_cycle: int = None
    # Phase 4b: True if the I$ went to memory for this PC's line
    # (state_q == MISS at if2). False for cache hits (including "stuck
    # hits" that were just queued behind a prior miss).
    ic_miss: bool = None
    fe_cycle: int = None
    id_cycle: int = None
    is_cycle: int = None
    ex_cycle: int = None
    wb_cycle: int = None
    co_cycle: int = None
    flushed: bool = False
    flush_reason: str = None
    # Phase 6a: LSU FSM state history. For LOAD records, captures the
    # transitions of load_unit.state_q while the FSM was processing
    # this record's trans_id. For STORE records, same for
    # store_unit.state_q. Each entry is {cycle: int, state: str}.
    # "Minimal" scope (Phase 6a v0.1): transitions only, IDLE→non-IDLE
    # opens the trace, non-IDLE→IDLE closes it (the closing IDLE is
    # NOT appended; lsu_complete_cycle records it instead).
    lsu_state_history: list = None
    # Phase 6a: cycle the LSU FSM first transitioned out of IDLE for
    # this record (the actual admission cycle). Usually is_cycle + 1
    # but can be later under stalls or with TLB miss inserts.
    lsu_admit_cycle: int = None
    # Phase 6a: cycle the LSU FSM returned to IDLE after this record
    # (admission phase complete). For loads, the actual data response
    # arrives later via ldbuf — this only marks the FSM's release.
    lsu_complete_cycle: int = None

    # Phase 6b: D$ event correlation. Populated for LOAD and STORE
    # records by attribute_dc_events_to_records() after the VCD scan
    # finishes, based on cache events that fired during
    # [lsu_admit_cycle, lsu_complete_cycle].
    #
    #   dc_primary_miss   : an mshr_alloc fired with sid == LOAD_UNIT_SID
    #                       (= 1, the LSU load_unit's HPDcache adapter)
    #                       AND mTID == this record's trans_id, during
    #                       [admit, complete]. Empirically rare under
    #                       load/store-interleaved workloads where stores
    #                       allocate first and loads coalesce (see
    #                       architectural note above LOAD_UNIT_SID).
    #   dc_coalesced      : an mshr_check_hit fired during this record's
    #                       lifetime — at least one request coalesced on
    #                       an existing MSHR entry. Approximate (no per-
    #                       check sid available), but a strong signal for
    #                       loads that piggybacked on a store's miss.
    #   dc_refill_overlap : refill_fsm_q was non-IDLE for at least one
    #                       cycle during the record's lifetime. Catches
    #                       loads delayed by a concurrent refill consuming
    #                       the cache port even when not coalescing.
    #   dc_events         : raw chronological event list. Each entry is
    #                       a dict with at minimum 'cycle' and 'type'
    #                       (alloc | check_hit | check_miss | refill_rsp)
    #                       plus type-specific fields:
    #                         alloc      : sid, tid, pf, nline
    #                         check_*    : nline
    #                         refill_rsp : tid
    dc_primary_miss: bool = False
    dc_coalesced: bool = False
    dc_refill_overlap: bool = False
    dc_events: list = None

    # Phase 7a: branch prediction & resolution. Populated for records
    # with fu == CTRL_FLOW (and indirectly relevant for any branch the
    # frontend predicted, even if the decoder ultimately classifies the
    # instruction as something else — though that's rare).
    #
    # PREDICTION (captured at issue handshake from
    # mem_q[trans_id].sbe.bp, written there at decode time by the
    # frontend's predictor stack):
    #   bp_predicted_cf      : "NoCF" / "Branch" / "Jump" / "JumpR" /
    #                          "Return". Also identifies the predictor
    #                          source — Branch=BHT, JumpR=BTB,
    #                          Return=RAS, Jump=direct (no predictor),
    #                          NoCF=no prediction (or non-branch).
    #   bp_predicted_target  : VLEN-bit target address as int, or None
    #                          for NoCF.
    #
    # RESOLUTION (captured per-cycle from
    # i_scoreboard.resolved_branch_i, which pulses valid=1 for one
    # cycle at the branch's ex_cycle):
    #   bp_resolved_cf       : resolved control-flow type (per
    #                          branch_unit.sv:64-107, may differ from
    #                          predicted_cf if BTB/RAS missed).
    #   bp_resolved_target   : actual computed target VLEN bits.
    #   bp_resolved_taken    : actual branch outcome (False for
    #                          not-taken / sequential).
    #   bp_mispredict        : direct is_mispredict from resolution —
    #                          covers direction mispredicts (Branch
    #                          predicted T but actually NT, or vice
    #                          versa) and target mispredicts (BTB/RAS
    #                          predicted wrong address).
    #   bp_resolution_cycle  : the cycle resolved_branch_i.valid=1
    #                          fired for this record. Should equal
    #                          ex_cycle for cleanly-pipelined branches.
    bp_predicted_cf: str = None
    bp_predicted_target: int = None
    bp_resolved_cf: str = None
    bp_resolved_target: int = None
    bp_resolved_taken: bool = None
    bp_mispredict: bool = None
    bp_resolution_cycle: int = None

    # Phase 8a: operand forwarding capture, sampled at the issue cycle.
    #
    # For each source operand (rs1, rs2, rs3), the issue_read_operands stage
    # decides whether to take the value from the regfile (no in-flight
    # producer) or from the forwarding network (some scoreboard slot still
    # holds the result). The signals are combinational and live for one
    # cycle at the issue rising edge, so we snapshot them pre-edge.
    #
    #   fwd_rsX_used     : True iff the issue stage took the operand from
    #                      the forwarding network instead of the regfile.
    #                      Derived from i_issue_read_operands.forward_rsX.
    #                      False when the source has no RAW hazard (or
    #                      when there's a hazard but a stall fired). Stalls
    #                      manifest as the issue handshake itself not
    #                      firing, so within our capture (which only runs
    #                      on a successful handshake) "used=False" simply
    #                      means "regfile read".
    #
    #   fwd_rsX_from_tid : The scoreboard slot index that the operand came
    #                      from. Read from idx_hzd_rsX[0]. Only meaningful
    #                      when fwd_rsX_used is True; None otherwise.
    #
    #   fwd_rsX_via      : "sb" or "wb".
    #                      "sb" : the value came from mem_q[from_tid].sbe.
    #                             result, i.e. the producer had ALREADY
    #                             written back in a previous cycle and the
    #                             scoreboard is holding it.
    #                      "wb" : the value was bypassed on the same cycle
    #                             from one of the writeback ports
    #                             (wt_valid_i[w]==1 with trans_id_i[w] ==
    #                             from_tid). This is the "tightest" case,
    #                             ALU-to-ALU bypass within back-to-back
    #                             dependent ops.
    #                      Only meaningful when fwd_rsX_used is True;
    #                      None otherwise.
    #
    # rs3 is captured for FMA-class FPU ops (3-source instructions); for
    # all other ops fwd_rs3_used is False and fwd_rs3_* are None.
    fwd_rs1_used: bool = False
    fwd_rs1_from_tid: int = None
    fwd_rs1_via: str = None
    fwd_rs2_used: bool = False
    fwd_rs2_from_tid: int = None
    fwd_rs2_via: str = None
    fwd_rs3_used: bool = False
    fwd_rs3_from_tid: int = None
    fwd_rs3_via: str = None


# ============================================================================
# I$ event timeline (Phase 4b)
# ============================================================================

@dataclass
class ICacheEvent:
    fe1_cycle: int
    fe2_cycle: int
    vaddr_word: int   # 4-byte aligned
    ic_miss: bool


class ICacheTimeline:
    """Walks the VCD's I$ signal stream in lockstep with the main tracer
    and emits one ICacheEvent per successful (non-killed) data delivery.

    fe1 attribution rule (v0.3):

      A NEW I$ ACCESS starts at the cycle when EITHER:
        (a) vaddr_o transitions to a different value (consecutive
            fetches to distinct addresses), or
        (b) state_q transitions to READ from a non-READ state
            (a fresh access after an IDLE/KILL_*/FLUSH dwell — most
            commonly a branch-misprediction recovery re-fetch).

      fe1_cycle = (cycle the new access started) - 1
      fe2_cycle = cycle dreq_o.valid==1 and kill_s2==0
      ic_miss   = (state_q == MISS at fe2)

    The two-path detection is necessary: without (b), a re-fetch where
    the frontend reissues the SAME address after a transient idle
    would inherit the ORIGINAL transition cycle for fe1, inflating lat
    from 1 to (idle_dwell + 1). With both paths, every hit lands at
    lat=1 and every cacheable miss at lat=5 in the fdiv trace.

    Worked examples (verified during Phase 4b validation):

      Clean hit (consecutive line words):
        Cycle 311: vaddr_o transitions to 0x80000004 (path a).
        vld=1 same cycle. if1=310, if2=311, lat=1.

      Cacheable cold miss (id=1959, PC 0x80003000):
        Cycle 3840: vaddr_o transitions. path (a). access_start=3840.
        Cycles 3841-3843: state=MISS dwell.
        Cycle 3844: vld=1, state=MISS. if1=3839, if2=3844, lat=5,
        ic_miss=True.

      Branch-mispredict re-fetch (id=243, PC 0x80004134):
        Cycle 818: original delivery. Event A: if1=817, if2=818.
        Cycle 819-821: state=IDLE (kill_s1 voided pipeline).
        Cycle 822: state=READ (was IDLE), path (b) fires.
        access_start=822. vld=1 same cycle. Event B: if1=821, if2=822.

      NC bypass (id=0, PC 0x10000):
        Cycle 270: vaddr_o transitions to 0x10000 (path a).
        Cycle 273: state=MISS, vld=1. if1=269, if2=273, lat=4.
    """

    NON_READ_STATES = frozenset({
        FSM_FLUSH, FSM_IDLE, FSM_MISS, FSM_KILL_ATRANS, FSM_KILL_MISS, None,
    })

    def __init__(self):
        self.events = []
        self.last_vaddr_o_str = None
        self.last_state_q = None
        self.last_access_start_cycle = None

    def on_cycle(self, cycle, state_q_str, vld, vaddr_o_str, k2):
        """Process one rising clock edge."""

        # --- Detect new access (either path) ---
        vaddr_o_changed = (vaddr_o_str != self.last_vaddr_o_str)
        state_to_read = (state_q_str == FSM_READ
                         and self.last_state_q in self.NON_READ_STATES)

        if vaddr_o_changed or state_to_read:
            self.last_access_start_cycle = cycle

        self.last_vaddr_o_str = vaddr_o_str
        self.last_state_q = state_q_str

        # --- Emit event on delivery ---
        if vld == "1" and k2 != "1" and vaddr_o_str is not None:
            try:
                vaddr_o = int(vaddr_o_str, 2)
            except ValueError:
                return
            if self.last_access_start_cycle is not None:
                fe1 = self.last_access_start_cycle - 1
            else:
                fe1 = cycle - 1
            fe1 = max(0, fe1)
            ic_miss = (state_q_str == FSM_MISS)
            self.events.append(ICacheEvent(
                fe1_cycle=fe1,
                fe2_cycle=cycle,
                vaddr_word=vaddr_o & ~0x3,
                ic_miss=ic_miss,
            ))


def match_records_to_events(records, events):
    """Bind if1_cycle / if2_cycle / ic_miss onto each record.

    For each record with PC P and fetch-handshake cycle fe_cycle,
    finds the I$ event for word (P & ~3) whose fe2_cycle is the
    maximum value still <= fe_cycle. RVC pair sharing falls out
    naturally: both halves of a pair have close fe_cycles and select
    the same event. Different loop iterations have well-separated
    fe_cycles and bind to their own iteration's event.

    Records with no matching event (truly killed accesses, fui drops)
    keep if1/if2/ic_miss as None. Returns (n_matched, n_unmatched)."""

    by_word = defaultdict(list)
    for ev in events:
        by_word[ev.vaddr_word].append(ev)
    for word in by_word:
        by_word[word].sort(key=lambda e: e.fe2_cycle)

    n_matched = 0
    n_unmatched = 0

    for rec in records:
        if rec.pc is None or rec.fe_cycle is None:
            n_unmatched += 1
            continue
        try:
            pc_int = int(rec.pc, 16)
        except (TypeError, ValueError):
            n_unmatched += 1
            continue
        word = pc_int & ~0x3
        candidates = by_word.get(word, [])
        best = None
        for ev in candidates:
            if ev.fe2_cycle > rec.fe_cycle:
                break
            best = ev
        if best is not None:
            rec.if1_cycle = best.fe1_cycle
            rec.if2_cycle = best.fe2_cycle
            rec.ic_miss = best.ic_miss
            n_matched += 1
        else:
            n_unmatched += 1

    return n_matched, n_unmatched


# ============================================================================
# Pipeline tracker
# ============================================================================

class PipelineTracker:
    """Maintains queues of in-flight instances and applies handshake/flush
    events. Order discipline: each queue is strict FIFO (in-order pipeline)."""

    def __init__(self, user_entry_pc=None, n_wb_ports=5, n_commit_ports=2):
        self.user_entry_pc = user_entry_pc
        self.n_wb_ports = n_wb_ports
        self.n_commit_ports = n_commit_ports

        self.warmup_end_cycle = None

        self.fetched = deque()        # has fe_cycle; awaiting decode
        self.decoded = deque()        # has id_cycle; awaiting issue
        self.issued = {}              # trans_id → record; awaiting wb/commit
        self.completed = []           # terminal list

        self.next_id = 0
        self.n_committed = 0
        self.n_flushed_if = 0
        self.n_flushed_id = 0
        self.n_flushed_ex = 0
        self.n_unmatched_writebacks = 0
        self.n_unmatched_commits = 0

        # Phase 8a diagnostics. The three per-source counters fire ONLY
        # when a real forward is happening AND the producer slot is on
        # the wb bus this cycle. If all three end up 0 across the trace,
        # via=wb is genuinely impossible at this signal boundary and the
        # via field can be collapsed; if any of them is nonzero but the
        # final via=wb stat is 0, the via writer in on_decode_issue has
        # a bug.
        self._diag_n_issue_cycles = 0
        self._diag_n_issue_with_any_wb = 0
        self._diag_n_real_match_rs1 = 0
        self._diag_n_real_match_rs2 = 0
        self._diag_n_real_match_rs3 = 0

        # Phase 4b: I$ event timeline. Populated per-cycle by the walker
        # in parallel with the existing dispatch steps. After the walk
        # completes, match_records_to_events binds if1/if2/ic_miss onto
        # each record by 4-byte-aligned PC.
        self.icache_timeline = ICacheTimeline()

        # Phase 6a v0.4: LSU FSM correlation via lsu_ctrl.trans_id.
        # See on_lsu_fsm_sample for details.
        #
        # v0.5 adds detection of admit-while-busy events that v0.4
        # missed: pop_ld=1 in SEND_TAG and pop_st=1 in VALID_STORE
        # state mean a NEW load/store is being admitted while the
        # FSM continues processing the previous one. In these cases
        # state_q doesn't transition (SEND_TAG→SEND_TAG /
        # VALID_STORE→VALID_STORE), so the v0.4 rule misses them.
        # `pending_admit_*_tid_str` defers the admission by one
        # cycle to align with the FSM's logical handoff.
        self.active_lsu_load = None
        self.active_lsu_store = None
        self.prev_load_state_str = None
        self.prev_store_state_str = None
        self.prev_lsu_ctrl_trans_id_str = None
        self.pending_admit_load_tid_str = None
        self.pending_admit_store_tid_str = None

        # Phase 6b: D$ event log. Populated during the per-cycle scan
        # by on_dcache_sample (alloc/check/refill_rsp pulses) and
        # refill-FSM-active-cycle tracking. After the scan completes,
        # attribute_dc_events_to_records walks self.completed and
        # binds events to records via the [admit, complete] cycle
        # window (+ tid match for tid-bearing events).
        #
        # Events arrive in cycle order during the scan since the
        # caller invokes on_dcache_sample once per rising edge in
        # ascending cycle order. We rely on this invariant in the
        # attribution pass instead of re-sorting.
        self._dc_events = []
        self._rfsm_active_cycles = set()

        # Phase 7b: dirty victim writeback events (flush/wback unit).
        # Each handshake is logged in cycle order during the scan; pairing
        # and the AXI-write-latency aggregate are computed in
        # finalize_writebacks() after the walk. send<->ack pair by flush
        # slot id; alloc<->ack join by nline.
        self._wb_allocs = []   # (cycle, nline_hex, way_onehot)
        self._wb_sends = []    # (cycle, slot_id_int, addr_hex)
        self._wb_acks = []     # (cycle, slot_id_int, nline_hex)
        # Phase 7b linkage: dirty-victim evictions from the miss handler.
        # (cycle, incoming_nline_hex, victim_way_onehot). Joined to writebacks
        # by (set, way) in finalize_writebacks.
        self._wb_evicts = []
        self.writeback_events = []
        self.writeback_stats = {}

    # -- per-stage event handlers ------------------------------------------

    def on_fetch(self, cycle, pc, instr_word, is_compressed):
        # Mask the 32-bit instruction word to 16 bits when compressed.
        # The frontend's instruction field carries the I$ line's lower 32
        # bits, which for an RVC instr pair contains BOTH instructions —
        # we want only the one at this PC, which lives in the low 16.
        if is_compressed and instr_word is not None:
            try:
                instr_word = f"0x{int(instr_word, 16) & 0xFFFF:04x}"
            except ValueError:
                pass
        rec = InstructionRecord(
            id=self.next_id,
            pc=pc,
            instr_word=instr_word,
            is_compressed=is_compressed,
            fe_cycle=cycle,
        )
        self.fetched.append(rec)
        self.next_id += 1

    def on_fetch_dropped(self, cycle, pc, instr_word, is_compressed):
        """Phase 4a v0.5: FE handshake fired at the same cycle that
        flush_unissued_instr_i is high. Per id_stage.sv:444, id_stage
        forces issue_n[0].valid=0 when flush_i (= controller's
        flush_unissued_instr_o) is high — overriding the valid=1 that
        line 433 set from the FE handshake. Net result: HW's frontend
        pops its instr_queue (fetch_entry_ready_o was 1) but id_stage
        immediately discards the entry. The instruction is silently
        dropped.

        If we pushed this record to `fetched` (as v0.4 did), HW's
        id_stage queue advances by 1 less than our `fetched`, leaving a
        phantom record at the head. Every subsequent pop would then be
        +1 ahead of HW's actual decode — exactly the offset we
        observed in v0.4. Instead, record the dropped fetch as a
        flushed entry (for diagnostic visibility into the discarded
        speculative path) but do NOT add it to `fetched`."""
        if is_compressed and instr_word is not None:
            try:
                instr_word = f"0x{int(instr_word, 16) & 0xFFFF:04x}"
            except ValueError:
                pass
        rec = InstructionRecord(
            id=self.next_id,
            pc=pc,
            instr_word=instr_word,
            is_compressed=is_compressed,
            fe_cycle=cycle,
            flushed=True,
            flush_reason="fetch_dropped_fui",
        )
        self.completed.append(rec)
        self.next_id += 1
        self.n_flushed_if += 1

    def on_decode(self, cycle, fu_val=None, rs1=None, rs2=None, rd=None):
        if not self.fetched:
            return
        rec = self.fetched.popleft()
        rec.id_cycle = cycle
        # Phase 4a: decoded fields sampled at the same handshake.
        if fu_val is not None:
            rec.fu = FU_NAME.get(fu_val, f"UNK_{fu_val}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Other")
        rec.rs1 = rs1
        rec.rs2 = rs2
        rec.rd = rd
        self.decoded.append(rec)

    def on_decode_issue(self, cycle, trans_id,
                        fu_val=None, rs1=None, rs2=None, rd=None,
                        bp_cf_val=None, bp_predict_target=None,
                        fwd_rs1_used=False, fwd_rs2_used=False, fwd_rs3_used=False,
                        ihz_rs1=None, ihz_rs2=None, ihz_rs3=None,
                        wb_view=None):
        """Phase 4a v0.4: combined decode+issue handler. In non-superscalar
        CVA6 the scoreboard's issue_instr_o is a combinational passthrough
        of decoded_instr_i (scoreboard.sv:151), so DV/DA and IV/IA fire as
        a SINGLE handshake. Tracking them as two events causes the issued
        trans_id to be read from IPTR at the wrong cycle whenever the
        pipeline stalls between fetches, putting MY_TID +N ahead of the
        actual HW slot. This handler pops fetched and assigns trans_id in
        one step, using the IPTR value at the cycle the handshake fires -
        which equals the HW slot being allocated.

        ex_cycle is still cycle+1 (CVA6 ALU/FPU pipeline depth invariant).

        Phase 7a additions: bp_cf_val and bp_predict_target are read from
        mem_q[trans_id].sbe.bp.cf and .predict_address - the prediction
        carried with this instruction from the frontend. They're captured
        here because they're stable from the slot's decode write until
        slot reuse, so any time during the slot's lifetime works; we
        choose issue (the moment the record acquires trans_id) for
        clean attribution.

        Phase 8a additions: forwarding capture. fwd_rsX_used is the
        boolean from i_issue_read_operands.forward_rsX at this rising
        edge (pre-edge snapshotted, like fu/rs1/rs2/rd, because the
        signal advances to the next instruction at post-edge).
        ihz_rsX is the producer scoreboard slot from idx_hzd_rsX[0].
        wb_view is the same-cycle writeback bus as a list of
        (port, trans_id) tuples filtered to ports with wt_valid_i=1;
        if the producer slot appears there, we tag via='wb' (bypassed
        on the same cycle), otherwise via='sb' (read from the
        scoreboard's stored result for that slot).
        """
        if not self.fetched:
            return
        # Phase 8a diagnostics. The match counters below ONLY fire when a
        # real forward is happening (fwd_rsX_used=True). The earlier coarse
        # diagnostic counted stale idx_hzd_rsX values that had nothing to
        # do with actual forwards, which overstated the match rate.
        # If these three per-source numbers end up 0, no real forward in
        # the trace coincides with the producer's wb on the scoreboard
        # bus, which means via=wb=0 is the true answer for this CVA6
        # build. If nonzero, the via writer below has a bug.
        self._diag_n_issue_cycles += 1
        wb_tids_set = {tid for _port, tid in (wb_view or [])}
        if wb_view:
            self._diag_n_issue_with_any_wb += 1
            if fwd_rs1_used and ihz_rs1 in wb_tids_set:
                self._diag_n_real_match_rs1 += 1
            if fwd_rs2_used and ihz_rs2 in wb_tids_set:
                self._diag_n_real_match_rs2 += 1
            if fwd_rs3_used and ihz_rs3 in wb_tids_set:
                self._diag_n_real_match_rs3 += 1
        rec = self.fetched.popleft()
        rec.id_cycle = cycle
        rec.is_cycle = cycle
        rec.ex_cycle = cycle + 1
        rec.trans_id = trans_id
        if fu_val is not None:
            rec.fu = FU_NAME.get(fu_val, f"UNK_{fu_val}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Other")
        rec.rs1 = rs1
        rec.rs2 = rs2
        rec.rd = rd
        # Phase 7a: branch prediction snapshot. bp_cf_val is the cf_t
        # enum int from mem_q[trans_id].sbe.bp.cf; bp_predict_target
        # is the VLEN-bit predict_address as int (or None).
        if bp_cf_val is not None:
            rec.bp_predicted_cf = CF_T_NAMES.get(
                bp_cf_val, f"UNK_{bp_cf_val}")
            # Only attach a target when a prediction was made;
            # leave None for NoCF to avoid the misleading 0 target.
            if rec.bp_predicted_cf != "NoCF":
                rec.bp_predicted_target = bp_predict_target
        # Phase 8a: forwarding capture. For each source where forwarding
        # fired, look up the producer trans_id in the same-cycle wb_view
        # to classify the path as "wb" (bypassed from the writeback bus
        # this cycle) or "sb" (read from the scoreboard's stored result).
        wb_tids = {tid for _port, tid in (wb_view or [])}
        if fwd_rs1_used:
            rec.fwd_rs1_used = True
            rec.fwd_rs1_from_tid = ihz_rs1
            rec.fwd_rs1_via = "wb" if ihz_rs1 in wb_tids else "sb"
        if fwd_rs2_used:
            rec.fwd_rs2_used = True
            rec.fwd_rs2_from_tid = ihz_rs2
            rec.fwd_rs2_via = "wb" if ihz_rs2 in wb_tids else "sb"
        if fwd_rs3_used:
            rec.fwd_rs3_used = True
            rec.fwd_rs3_from_tid = ihz_rs3
            rec.fwd_rs3_via = "wb" if ihz_rs3 in wb_tids else "sb"
        self.issued[trans_id] = rec
        # Phase 6a v0.4: no LSU pending-assignment needed here.
        # Correlation happens via lsu_ctrl.trans_id at FSM-transition
        # time in on_lsu_fsm_sample, looking up self.issued[prev_tid].

    def on_branch_resolved(self, cycle, pc_str, target_str,
                           is_taken_str, is_mispredict_str, cf_type_str):
        """Phase 7a: handle a branch resolution pulse.

        bp_resolve_t.valid is high for exactly one cycle when the
        branch_unit resolves a branch (branch_unit.sv:84). The pc field
        identifies the resolved branch. We bind to an in-flight record
        by matching pc against rec.pc among CTRL_FLOW records in
        self.issued — picking the OLDEST (lowest is_cycle) on a tie,
        because loops can have multiple instances of the same PC in
        flight and the branch_unit resolves them in issue order.

        Fields written onto the record:
          - bp_resolved_cf, bp_resolved_target, bp_resolved_taken
          - bp_mispredict (direct from resolved_branch_i.is_mispredict)
          - bp_resolution_cycle = `cycle`

        If no matching record is found (resolution for a record that
        was already flushed, or a stray pulse), the resolution is
        silently dropped. We don't track these as warnings because
        flushes can legitimately strand resolutions in the pipeline.
        """
        if pc_str is None:
            return
        pc_int = binary_to_int(pc_str)
        if pc_int is None:
            return
        pc_hex = f"0x{pc_int:x}"

        # Find candidate records: in-flight CTRL_FLOW with matching pc.
        candidates = []
        for tid, rec in self.issued.items():
            if rec.fu != "CTRL_FLOW":
                continue
            if rec.pc is None:
                continue
            # rec.pc is the hex string written by on_fetch — normalize
            # both sides for comparison (some pc values lose leading
            # zeros after binary_to_hex; compare as ints).
            try:
                rec_pc_int = int(rec.pc, 16)
            except (TypeError, ValueError):
                continue
            if rec_pc_int == pc_int:
                candidates.append((rec.is_cycle or 0, tid, rec))

        if not candidates:
            return

        # Oldest-first if multiple share the PC (loop iteration).
        candidates.sort(key=lambda x: (x[0], x[1]))
        _, _, rec = candidates[0]

        # Refuse to overwrite a prior resolution on the same record —
        # would only happen if the same record were resolved twice,
        # which CVA6's in-order issue precludes.
        if rec.bp_resolution_cycle is not None:
            return

        rec.bp_resolution_cycle = cycle
        rec.bp_resolved_cf      = cf_name(cf_type_str)
        rec.bp_resolved_target  = binary_to_int(target_str) if target_str else None
        rec.bp_resolved_taken   = (is_taken_str == "1")
        rec.bp_mispredict       = (is_mispredict_str == "1")

    def on_lsu_fsm_sample(self, cycle, load_state_str, store_state_str,
                          lsu_ctrl_trans_id_str=None,
                          pop_ld_str=None, pop_st_str=None):
        """Phase 6a v0.6: lsu_ctrl + pop + extended-transition FSM
        correlation.

        Combines three admission-detection rules:

        A. State transition IDLE → non-IDLE: standard admission, the
           FSM just left idle to process a new record. trans_id =
           previous cycle's lsu_ctrl.trans_id.

        B. pop_ld_o=1 while load FSM is in SEND_TAG (load_unit.sv:343)
           or pop_st_o=1 while store FSM is in VALID_STORE
           (store_unit.sv:191): admit-while-busy with NO state
           transition (SEND_TAG→SEND_TAG / VALID_STORE→VALID_STORE
           — only the load identity changes). Deferred by one
           cycle via `pending_admit_*_tid_str`.

        B'. State transition SEND_TAG → non-IDLE (any non-IDLE) for
            load FSM, or VALID_STORE → non-IDLE for store FSM. Per
            load_unit.sv:332-353 and store_unit.sv:179-206, the
            only way to exit SEND_TAG / VALID_STORE while staying
            non-IDLE is by accepting a new request (accept_req=1).
            The OLD record was finishing its tag/post at the prev
            cycle; the NEW record takes over the FSM at this cycle.
            trans_id = prev cycle's lsu_ctrl.trans_id.

        Rule B' is the v0.6 addition. v0.5 missed the STG→WGT,
        STG→WPO, STG→ABT, VST→WTL, VST→WSR cases because they
        admit a new load without asserting pop_ld_o/pop_st_o
        (the pop only fires on grant or store-buffer-ready, which
        for these admissions hasn't happened yet). That mistake
        caused id=140 in compress (which went IDL→WGT→STG→WPO→
        WGT→STG, with the WPO entering on a STG→WPO admission)
        to inherit the wrong record and the prior load to absorb
        the wrong entries.

        Mutual exclusion: Rule B (pop) only fires when state stays
        SEND_TAG/VALID_STORE (no transition); Rule B' (transition)
        only fires when state changes out of SEND_TAG/VALID_STORE.
        Both cannot fire on the same cycle for the same FSM."""

        # ---- LOAD FSM ----
        if load_state_str is not None:
            try:
                new_int = int(load_state_str, 2)
            except (ValueError, TypeError):
                new_int = None
            new_name = LOAD_FSM_NAMES.get(new_int, f"?{load_state_str}")

            if self.prev_load_state_str is None:
                # First sample — just prime the cache.
                self.prev_load_state_str = load_state_str
            else:
                handled_admit_this_cycle = False

                # Rule B: pending admit from prev-cycle's
                # pop_ld_o=1 / SEND_TAG combination.
                if self.pending_admit_load_tid_str is not None:
                    tid = binary_to_int(self.pending_admit_load_tid_str)
                    rec = self.issued.get(tid) if tid is not None else None
                    # Close out the old active record (handoff).
                    if self.active_lsu_load is not None:
                        self.active_lsu_load.lsu_complete_cycle = cycle
                    if rec is not None:
                        self.active_lsu_load = rec
                        rec.lsu_admit_cycle = cycle
                        if rec.lsu_state_history is None:
                            rec.lsu_state_history = []
                        rec.lsu_state_history.append({
                            "cycle": cycle, "state": new_name})
                    else:
                        self.active_lsu_load = None
                    self.pending_admit_load_tid_str = None
                    handled_admit_this_cycle = True

                # Rule A: state transition admission / completion /
                # mid-flight, only if rule B didn't already handle
                # an admission this cycle.
                if (not handled_admit_this_cycle
                        and load_state_str != self.prev_load_state_str):
                    try:
                        old_int = int(self.prev_load_state_str, 2)
                    except (ValueError, TypeError):
                        old_int = None
                    old_name = LOAD_FSM_NAMES.get(old_int, "?")

                    if old_name == "IDLE" and new_name != "IDLE":
                        # Rule A: standard admission.
                        tid = None
                        if self.prev_lsu_ctrl_trans_id_str is not None:
                            tid = binary_to_int(
                                self.prev_lsu_ctrl_trans_id_str)
                        rec = self.issued.get(tid) if tid is not None else None
                        if rec is not None:
                            self.active_lsu_load = rec
                            rec.lsu_admit_cycle = cycle
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})
                    elif old_name == "SEND_TAG" and new_name != "IDLE":
                        # Rule B' (v0.6): admit-while-busy via state
                        # transition out of SEND_TAG into any non-IDLE
                        # state. Per load_unit.sv:320-354, the only
                        # transitions from SEND_TAG are: IDLE (no new
                        # request, handled by completion branch
                        # below); SEND_TAG (handled by pop-based Rule
                        # B); WAIT_GNT (new request, no grant); WAIT_
                        # PAGE_OFFSET (new request, page-offset
                        # match); ABORT_TRANSACTION{,_NI} (new
                        # request, TLB / non-idempotence). All except
                        # IDLE are NEW admissions — the OLD load's
                        # tag was sent at the previous cycle and the
                        # FSM now serves the new request.
                        if self.active_lsu_load is not None:
                            self.active_lsu_load.lsu_complete_cycle = cycle
                        tid = None
                        if self.prev_lsu_ctrl_trans_id_str is not None:
                            tid = binary_to_int(
                                self.prev_lsu_ctrl_trans_id_str)
                        rec = self.issued.get(tid) if tid is not None else None
                        if rec is not None:
                            self.active_lsu_load = rec
                            rec.lsu_admit_cycle = cycle
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})
                        else:
                            self.active_lsu_load = None
                    elif new_name == "IDLE":
                        if self.active_lsu_load is not None:
                            self.active_lsu_load.lsu_complete_cycle = cycle
                            self.active_lsu_load = None
                    else:
                        if self.active_lsu_load is not None:
                            rec = self.active_lsu_load
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})

                self.prev_load_state_str = load_state_str

                # Rule B detect: schedule pending admit for next cycle.
                if (pop_ld_str == "1" and new_name == "SEND_TAG"
                        and lsu_ctrl_trans_id_str is not None):
                    self.pending_admit_load_tid_str = lsu_ctrl_trans_id_str

        # ---- STORE FSM (mirror) ----
        if store_state_str is not None:
            try:
                new_int = int(store_state_str, 2)
            except (ValueError, TypeError):
                new_int = None
            new_name = STORE_FSM_NAMES.get(new_int, f"?{store_state_str}")

            if self.prev_store_state_str is None:
                self.prev_store_state_str = store_state_str
            else:
                handled_admit_this_cycle = False

                if self.pending_admit_store_tid_str is not None:
                    tid = binary_to_int(self.pending_admit_store_tid_str)
                    rec = self.issued.get(tid) if tid is not None else None
                    if self.active_lsu_store is not None:
                        self.active_lsu_store.lsu_complete_cycle = cycle
                    if rec is not None:
                        self.active_lsu_store = rec
                        rec.lsu_admit_cycle = cycle
                        if rec.lsu_state_history is None:
                            rec.lsu_state_history = []
                        rec.lsu_state_history.append({
                            "cycle": cycle, "state": new_name})
                    else:
                        self.active_lsu_store = None
                    self.pending_admit_store_tid_str = None
                    handled_admit_this_cycle = True

                if (not handled_admit_this_cycle
                        and store_state_str != self.prev_store_state_str):
                    try:
                        old_int = int(self.prev_store_state_str, 2)
                    except (ValueError, TypeError):
                        old_int = None
                    old_name = STORE_FSM_NAMES.get(old_int, "?")

                    if old_name == "IDLE" and new_name != "IDLE":
                        # Rule A: standard admission.
                        tid = None
                        if self.prev_lsu_ctrl_trans_id_str is not None:
                            tid = binary_to_int(
                                self.prev_lsu_ctrl_trans_id_str)
                        rec = self.issued.get(tid) if tid is not None else None
                        if rec is not None:
                            self.active_lsu_store = rec
                            rec.lsu_admit_cycle = cycle
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})
                    elif old_name == "VALID_STORE" and new_name != "IDLE":
                        # Rule B' (v0.6): admit-while-busy via state
                        # transition out of VALID_STORE. Per
                        # store_unit.sv:179-206, VALID_STORE exits
                        # to: IDLE (no new request, handled by
                        # completion); VALID_STORE (handled by Rule
                        # B pop-based); WAIT_TRANSLATION (new
                        # request + TLB miss); WAIT_STORE_READY
                        # (new request + store buffer full). The
                        # latter two are NEW admissions.
                        if self.active_lsu_store is not None:
                            self.active_lsu_store.lsu_complete_cycle = cycle
                        tid = None
                        if self.prev_lsu_ctrl_trans_id_str is not None:
                            tid = binary_to_int(
                                self.prev_lsu_ctrl_trans_id_str)
                        rec = self.issued.get(tid) if tid is not None else None
                        if rec is not None:
                            self.active_lsu_store = rec
                            rec.lsu_admit_cycle = cycle
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})
                        else:
                            self.active_lsu_store = None
                    elif new_name == "IDLE":
                        if self.active_lsu_store is not None:
                            self.active_lsu_store.lsu_complete_cycle = cycle
                            self.active_lsu_store = None
                    else:
                        if self.active_lsu_store is not None:
                            rec = self.active_lsu_store
                            if rec.lsu_state_history is None:
                                rec.lsu_state_history = []
                            rec.lsu_state_history.append({
                                "cycle": cycle, "state": new_name})

                self.prev_store_state_str = store_state_str

                if (pop_st_str == "1" and new_name == "VALID_STORE"
                        and lsu_ctrl_trans_id_str is not None):
                    self.pending_admit_store_tid_str = lsu_ctrl_trans_id_str

        # ---- Cache lsu_ctrl.trans_id for next cycle's transitions ----
        if lsu_ctrl_trans_id_str is not None:
            self.prev_lsu_ctrl_trans_id_str = lsu_ctrl_trans_id_str

    def on_dcache_sample(self, cycle,
                         mallo, mtid, msid, mpf, mnline_alloc,
                         mchk, mchk_nline, mchkhit,
                         rfsm, rrsp, rtid):
        """Phase 6b: capture per-cycle HPDcache miss-handler events.

        Each non-zero pulse appends a typed event to `self._dc_events`.
        The refill FSM is sampled independently (any non-IDLE cycle is
        recorded in `self._rfsm_active_cycles` for later overlap
        checks). Tid-bearing events store the resolved integer tid;
        attribution to a specific record happens later in
        attribute_dc_events_to_records by matching cycle and
        (where applicable) tid against each record's
        [lsu_admit_cycle, lsu_complete_cycle] window.

        Argument strings come from the VCD `state` dict raw — we
        decode them here to keep the per-cycle dispatch in
        stream_and_extract slim. None signals (missing in this VCD)
        are tolerated: their events are simply not generated.
        """
        # MSHR allocation pulse. The sid distinguishes load-adapter
        # vs store/CMO/HWPF allocations — only sid in LOAD_ADAPTER_SIDS
        # is eligible to become a `dc_primary_miss` later. We store
        # the sid raw so the viewer/postprocess can re-classify.
        if mallo == "1":
            self._dc_events.append({
                "cycle": cycle,
                "type":  "alloc",
                "sid":   binary_to_int(msid)         if msid         else None,
                "tid":   binary_to_int(mtid)         if mtid         else None,
                "pf":    binary_to_int(mpf)          if mpf          else None,
                "nline": binary_to_int(mnline_alloc) if mnline_alloc else None,
            })

        # MSHR-check pulse: classified as 'check_hit' or 'check_miss'
        # based on mshr_check_hit_o (combinational, sampled same edge).
        # check_hit is the coalescing signal — a request found its
        # nline already pending. No sid input on the check path, so
        # attribution is purely by cycle window.
        if mchk == "1":
            hit = (mchkhit == "1")
            self._dc_events.append({
                "cycle": cycle,
                "type":  "check_hit" if hit else "check_miss",
                "nline": binary_to_int(mchk_nline) if mchk_nline else None,
            })

        # Refill response: when refill data finally reaches the core
        # port for a primary miss. Tid identifies which requestor
        # gets the data (see hpdcache_miss_handler.sv:382,397).
        if rrsp == "1":
            self._dc_events.append({
                "cycle": cycle,
                "type":  "refill_rsp",
                "tid":   binary_to_int(rtid) if rtid else None,
            })

        # Refill-FSM activity tracking: any non-zero state means a
        # refill is actively writing the data RAM (REFILL_WRITE),
        # updating the directory (REFILL_WRITE_DIR), or invalidating
        # (REFILL_INVAL). The data RAM port is consumed during these
        # cycles, which can stall unrelated loads — hence the
        # `dc_refill_overlap` boolean even for hits.
        if rfsm is not None:
            rfsm_val = binary_to_int(rfsm)
            if rfsm_val is not None and rfsm_val != REFILL_FSM_IDLE:
                self._rfsm_active_cycles.add(cycle)

    def attribute_dc_events_to_records(self):
        """Phase 6b: bind D$ events back to LOAD/STORE records.

        Runs once after the VCD scan completes and `self.completed`
        is final. For each Mem record whose LSU FSM trace bracketed
        a [admit, complete] window:

        - Walks the global event log (cycle-sorted by construction)
          and copies events falling in the window into the record's
          `dc_events` list.
        - Sets `dc_primary_miss=True` if any alloc event in the
          window has sid in LOAD_ADAPTER_SIDS AND tid matching the
          record's trans_id. This is the *only* case where we
          attribute a primary miss to a specific record — store and
          prefetch allocations are recorded as context but never
          flip this bit on a load record.
        - Sets `dc_coalesced=True` if any check_hit event fell in
          the window. This is approximate (no per-check sid) but
          serves as a strong heuristic — see id=139 in fdiv for the
          canonical case.
        - Sets `dc_refill_overlap=True` if any cycle in
          [admit, complete] is in self._rfsm_active_cycles.

        Records without a complete LSU trace (e.g. flushed before
        admission) get `dc_events=[]` and all booleans False.
        Non-Mem records are left untouched.
        """
        # Index events by cycle for the window scan. Events are
        # already in cycle order (on_dcache_sample is called once
        # per rising edge in ascending cycle order); we exploit that
        # to short-circuit when the cursor passes the window.
        evlog = self._dc_events
        n_events = len(evlog)

        n_loads = n_stores = 0
        n_prim = n_coal = n_overlap = 0

        for rec in self.completed:
            if rec.fu_category != "Mem":
                continue
            if rec.fu == "LOAD":
                n_loads += 1
            elif rec.fu == "STORE":
                n_stores += 1

            admit    = rec.lsu_admit_cycle
            complete = rec.lsu_complete_cycle
            if admit is None or complete is None:
                rec.dc_events = []
                continue

            # Linear scan with binary-search would be faster, but
            # 1k–5k records × 100s of events each is fast enough.
            events_in_window = []
            primary_miss = False
            coalesced    = False

            for ev in evlog:
                c = ev["cycle"]
                if c < admit:
                    continue
                if c > complete:
                    break
                events_in_window.append(ev)
                etype = ev["type"]
                if etype == "alloc":
                    sid = ev.get("sid")
                    tid = ev.get("tid")
                    # Only the LSU load_unit (sid=1) can give us a
                    # "primary LOAD miss". PTW (sid=0) allocations
                    # are page-walk misses, not data-load misses;
                    # accel (sid=2) is an accelerator port. Both
                    # would be misattributed if we used the broader
                    # LOAD_ADAPTER_SIDS set here, even though
                    # empirically (fdiv, compress) neither fires.
                    # See the architectural note above on
                    # LOAD_UNIT_SID for why sid=1 itself is also
                    # rare in load/store-interleaved workloads.
                    if (sid == LOAD_UNIT_SID
                            and tid == rec.trans_id):
                        primary_miss = True
                elif etype == "check_hit":
                    coalesced = True

            # Refill overlap: any cycle in [admit, complete] in the
            # rFSM-active set. set lookup is O(1) per cycle.
            refill_overlap = any(
                c in self._rfsm_active_cycles
                for c in range(admit, complete + 1)
            )

            rec.dc_events = events_in_window

            # Classification booleans are LOAD-only. The check_hit
            # event has no source-ID input on the miss handler, so
            # we can't strictly attribute it to a specific
            # requestor; we exploit the fact that the LSU's
            # load_unit FSM is single-threaded — at most one load
            # is in WGT at a time, so a check_hit during a LOAD's
            # window is overwhelmingly that load's check.
            #
            # STOREs are different: their FSM window is short
            # (~1–3 cycles), they don't typically emit check_i
            # (stores allocate, not coalesce), and any check_hit
            # in their window is almost certainly from a different
            # requestor (a concurrent load or prefetcher). Flipping
            # dc_coalesced=True on the store would be a false
            # positive. Same logic for dc_refill_overlap: the
            # refill is not because of this store. We keep
            # dc_events populated on STOREs as context, but leave
            # all three booleans False.
            if rec.fu == "LOAD":
                rec.dc_primary_miss   = primary_miss
                rec.dc_coalesced      = coalesced
                rec.dc_refill_overlap = refill_overlap

                if primary_miss:   n_prim    += 1
                if coalesced:      n_coal    += 1
                if refill_overlap: n_overlap += 1

        return {
            "total_dc_events":       n_events,
            "rfsm_active_cycles":    len(self._rfsm_active_cycles),
            "n_loads":               n_loads,
            "n_stores":              n_stores,
            "n_primary_miss_loads":  n_prim,
            "n_coalesced_loads":     n_coal,
            "n_refill_overlap_loads":n_overlap,
        }

    # -- Phase 7b: dirty victim writeback (flush/wback unit) ---------------

    def on_wback_sample(self, cycle,
                        alloc_v, alloc_r, alloc_nline, alloc_way,
                        send_v, send_r, send_id, send_addr,
                        ack_v, ack_r, ack_id, ack_nline):
        """Log writeback handshakes. Called once per rising edge (cycle
        order). alloc = victim handed to flush unit; send = mem write
        request issued; ack = memory response. Pairing is deferred to
        finalize_writebacks(). alloc_way is the one-hot victim way (used for
        the eviction join)."""
        if alloc_v == "1" and alloc_r == "1":
            self._wb_allocs.append((cycle, binary_to_hex(alloc_nline),
                                    binary_to_int(alloc_way)))
        if send_v == "1" and send_r == "1":
            self._wb_sends.append((cycle, binary_to_int(send_id),
                                   binary_to_hex(send_addr)))
        if ack_v == "1" and ack_r == "1":
            self._wb_acks.append((cycle, binary_to_int(ack_id),
                                  binary_to_hex(ack_nline)))

    def on_evict_sample(self, cycle, alloc_v, wback, mshr_nline, victim_way):
        """Log a dirty-victim eviction whenever the miss handler allocates a
        miss whose selected victim way is dirty (mshr_alloc_i && wback). The
        incoming line is mshr_nline (X); the victim Y (same set, same way) is
        written back. Joined to a writeback in finalize_writebacks by
        (set, way). No ready-gate: the (set,way)+window join is robust to the
        held-high duplicate cycles (validated 1312/1312 on daxpy)."""
        if alloc_v == "1" and wback == "1":
            self._wb_evicts.append((cycle, binary_to_hex(mshr_nline),
                                    binary_to_int(victim_way)))

    def finalize_writebacks(self):
        """Pair send<->ack by flush slot id (FIFO per id) to get AXI write
        latency, join alloc<->ack by nline (FIFO per nline) to get total
        residency, and build the writeback event list + latency aggregate.
        Mirrors the validated p7b_wback_diag pairing exactly."""
        from statistics import median

        send_q = defaultdict(deque)
        for c, sid, addr in self._wb_sends:
            send_q[sid].append((c, addr))

        events = []
        latencies = []
        unmatched_acks = 0
        for ac, sid, nline in self._wb_acks:     # acks already in cycle order
            if send_q[sid]:
                sc, addr = send_q[sid].popleft()
                lat = ac - sc
                latencies.append(lat)
                events.append({
                    "send_cycle":          sc,
                    "ack_cycle":           ac,
                    "alloc_cycle":         None,   # filled by the nline join
                    "flush_slot":          sid,
                    "nline":               nline,
                    "addr":                addr,
                    "axi_write_latency":   lat,
                    "residency":           None,
                    "way":                 None,   # victim way (one-hot->idx)
                    "evict_incoming_nline":None,   # line X that displaced Y
                    "evict_cycle":         None,
                    "linked":              False,
                })
            else:
                unmatched_acks += 1
        sends_never_acked = sum(len(q) for q in send_q.values())

        # alloc -> ack join by nline (FIFO per nline, ack-time order); also
        # carries the one-hot victim way captured at flush_alloc.
        alloc_q = defaultdict(deque)
        for c, nline, way in self._wb_allocs:
            alloc_q[nline].append((c, way))
        for ev in events:
            q = alloc_q.get(ev["nline"])
            if q:
                ac_cycle, way_oh = q.popleft()
                ev["alloc_cycle"] = ac_cycle
                ev["residency"] = ev["ack_cycle"] - ac_cycle
                ev["way"] = _onehot_to_idx(way_oh)

        events.sort(key=lambda e: e["send_cycle"])

        # --- eviction linkage: join each writeback to the dirty eviction
        # that caused it, by (set, victim_way) nearest within a small window
        # (validated: same-cycle, delta=0; window absorbs handshake skew).
        SET_MASK = (1 << 8) - 1          # 256 sets -> setWidth 8
        WINDOW = 4
        n_linked = 0
        ev_by_key = defaultdict(list)    # (set, way_oh) -> [(cycle, X_hex), ...]
        for ec, x_nline, vway_oh in self._wb_evicts:
            x_int = int(x_nline, 16) if x_nline else None
            s = None if x_int is None else (x_int & SET_MASK)
            ev_by_key[(s, vway_oh)].append((ec, x_nline))
        for v in ev_by_key.values():
            v.sort()
        used = defaultdict(set)
        for ev in events:
            y_int = int(ev["nline"], 16) if ev["nline"] else None
            s = None if y_int is None else (y_int & SET_MASK)
            anchor = ev["alloc_cycle"] if ev["alloc_cycle"] is not None else ev["send_cycle"]
            way_oh = None
            # recover the one-hot from the stored index (single bit)
            if ev["way"] is not None:
                way_oh = 1 << ev["way"]
            cands = ev_by_key.get((s, way_oh), [])
            best = None
            for idx, (ec, x_hex) in enumerate(cands):
                if idx in used[(s, way_oh)]:
                    continue
                if abs(ec - anchor) <= WINDOW:
                    if best is None or abs(ec - anchor) < abs(best[1] - anchor):
                        best = (idx, ec, x_hex)
            if best is not None:
                used[(s, way_oh)].add(best[0])
                ev["evict_cycle"] = best[1]
                ev["evict_incoming_nline"] = best[2]
                ev["linked"] = True
                n_linked += 1

        agg = {}
        if latencies:
            ls = sorted(latencies)
            hist = defaultdict(int)
            for L in latencies:
                hist[L] += 1
            agg = {
                "n":         len(ls),
                "min":       ls[0],
                "median":    int(median(ls)),
                "max":       ls[-1],
                "histogram": {str(k): v for k, v in sorted(hist.items())},
            }

        self.writeback_events = events
        self.writeback_stats = {
            "n_allocs":            len(self._wb_allocs),
            "n_sends":             len(self._wb_sends),
            "n_acks":              len(self._wb_acks),
            "matched_pairs":       len(latencies),
            "acks_no_prior_send":  unmatched_acks,
            "sends_never_acked":   sends_never_acked,
            "n_evictions":         len(self._wb_evicts),
            "n_linked":            n_linked,
            "n_unlinked":          len(events) - n_linked,
            "axi_write_latency":   agg,
        }
        return self.writeback_stats

    def on_issue(self, cycle, trans_id):
        if self.decoded:
            rec = self.decoded.popleft()
            rec.is_cycle = cycle
            rec.ex_cycle = cycle + 1     # CVA6 invariant
            rec.trans_id = trans_id
            # If the slot is somehow already occupied (shouldn't happen if
            # we processed commit first), the old occupant is unrecoverable.
            self.issued[trans_id] = rec

    def on_writeback(self, cycle, port, trans_id,
                     mq_fu=None, mq_rs1=None, mq_rs2=None, mq_rd=None):
        rec = self.issued.get(trans_id)
        if rec is None:
            self.n_unmatched_writebacks += 1
            return
        if rec.wb_cycle is None:
            rec.wb_cycle = cycle
        # Phase 4a v0.2: overwrite decoded fields with the AUTHORITATIVE values
        # from the scoreboard's registered mem_q ring buffer. These are stable
        # from decode+1 cycle to commit, so reading at writeback has no
        # timing ambiguity. (When mem_q paths aren't available in the VCD,
        # caller passes mq_* = None and the decode-time pre-edge values stay.)
        if mq_fu is not None:
            rec.fu = FU_NAME.get(mq_fu, f"UNK_{mq_fu}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Unknown")
        if mq_rs1 is not None:
            rec.rs1 = mq_rs1
        if mq_rs2 is not None:
            rec.rs2 = mq_rs2
        if mq_rd is not None:
            rec.rd = mq_rd

    def on_commit(self, cycle, port, trans_id,
                  mq_fu=None, mq_rs1=None, mq_rs2=None, mq_rd=None):
        rec = self.issued.pop(trans_id, None)
        if rec is None:
            self.n_unmatched_commits += 1
            return
        rec.co_cycle = cycle
        # Phase 4a v0.2: apply mem_q decoded fields if rec.fu wasn't set at
        # writeback (e.g., NONE-fu instructions auto-validate without going
        # through a writeback port — see scoreboard.sv line 189).
        if mq_fu is not None and rec.fu is None:
            rec.fu = FU_NAME.get(mq_fu, f"UNK_{mq_fu}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Unknown")
        if mq_rs1 is not None and rec.rs1 is None:
            rec.rs1 = mq_rs1
        if mq_rs2 is not None and rec.rs2 is None:
            rec.rs2 = mq_rs2
        if mq_rd is not None and rec.rd is None:
            rec.rd = mq_rd
        self.completed.append(rec)
        self.n_committed += 1
        # Detect warmup boundary on first commit at user_entry_pc.
        # The boundary is the FETCH cycle of that first committed instance —
        # not its commit cycle — so that main's entry instruction and the
        # ones immediately after it count as user code (their fe_cycle is
        # <= boundary instructions' fe_cycle), not as warmup.
        if (self.warmup_end_cycle is None
                and self.user_entry_pc is not None
                and rec.pc is not None
                and rec.fe_cycle is not None
                and int(rec.pc, 16) == int(self.user_entry_pc, 16)):
            self.warmup_end_cycle = rec.fe_cycle

    # -- flush handlers ----------------------------------------------------

    def _flush_fetched(self, reason):
        while self.fetched:
            rec = self.fetched.popleft()
            rec.flushed = True
            rec.flush_reason = reason
            self.completed.append(rec)
            self.n_flushed_if += 1

    def _flush_decoded(self, reason):
        while self.decoded:
            rec = self.decoded.popleft()
            rec.flushed = True
            rec.flush_reason = reason
            self.completed.append(rec)
            self.n_flushed_id += 1

    def _flush_issued(self, reason):
        for tid in list(self.issued.keys()):
            rec = self.issued.pop(tid)
            rec.flushed = True
            rec.flush_reason = reason
            self.completed.append(rec)
            self.n_flushed_ex += 1

    def on_flush_if(self, cycle):
        self._flush_fetched("flush_if")

    def on_flush_id(self, cycle):
        # ID flush also affects fetched (cascade up).
        self._flush_fetched("flush_id_cascade_if")
        self._flush_decoded("flush_id")

    def on_flush_ex(self, cycle):
        # EX flush cascades back through ID and IF.
        self._flush_fetched("flush_ex_cascade_if")
        self._flush_decoded("flush_ex_cascade_id")
        self._flush_issued("flush_ex_branch_mispredict")

    # -- finalization ------------------------------------------------------

    def finalize(self):
        # Anything still in-flight at EOF is incomplete — mark as flushed.
        if self.fetched or self.decoded or self.issued:
            self._flush_fetched("eof")
            self._flush_decoded("eof")
            self._flush_issued("eof")
        # Restore id-sorted order; flushes can interleave.
        self.completed.sort(key=lambda r: r.id)
        # Apply warmup classification.
        if self.warmup_end_cycle is not None:
            for rec in self.completed:
                if rec.fe_cycle is not None:
                    rec.is_warmup = rec.fe_cycle < self.warmup_end_cycle


# ============================================================================
# VCD header parsing
# ============================================================================

_BIT_RANGE_RE = re.compile(r"\[\d+:\d+\]$")
_ARRAY_INDEX_RE = re.compile(r"\[(\d+)\]")


def strip_bit_range(path):
    while True:
        new = _BIT_RANGE_RE.sub("", path)
        if new == path:
            return path
        path = new


def parse_var_block(f):
    scope_stack = []
    path_to_id = {}
    id_to_path = {}
    timescale = "unknown"
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith("$enddefinitions"):
            return path_to_id, id_to_path, timescale
        if line.startswith("$scope"):
            tokens = line.split()
            if len(tokens) >= 3:
                scope_stack.append(tokens[2])
        elif line.startswith("$upscope"):
            if scope_stack:
                scope_stack.pop()
        elif line.startswith("$timescale"):
            rest = line[len("$timescale"):].split("$end")[0].strip()
            if rest:
                timescale = rest
        elif line.startswith("$var"):
            tokens = line.split()
            if len(tokens) < 6:
                continue
            vcd_id = tokens[3]
            sig_name = tokens[4]
            if len(tokens) >= 7 and tokens[5] != "$end":
                sig_name += tokens[5]
            full_path = ".".join(scope_stack + [sig_name])
            path_to_id[full_path] = vcd_id
            id_to_path[vcd_id] = full_path
    return path_to_id, id_to_path, timescale


def match_whitelist(whitelist, path_to_id, scope_prefix):
    by_stripped = defaultdict(list)
    for full_path, vcd_id in path_to_id.items():
        by_stripped[strip_bit_range(full_path)].append((full_path, vcd_id))
    matches = []
    for entry in whitelist:
        target = f"{scope_prefix}.{entry}" if scope_prefix else entry
        hits = by_stripped.get(target, [])
        matches.append({
            "whitelist_path": entry,
            "full_paths": [h[0] for h in hits],
            "vcd_ids": [h[1] for h in hits],
        })
    return matches


def build_port_map(full_paths, vcd_ids):
    """For array-indexed multi-element signals, map port (first single-index
    in the path) to its VCD ID."""
    result = {}
    for path, vid in zip(full_paths, vcd_ids):
        indices = _ARRAY_INDEX_RE.findall(path)
        if indices:
            port = int(indices[0])
            result[port] = vid
    return result


# ============================================================================
# Value helpers
# ============================================================================

def get_bit(binary_str, bit_idx):
    """Return bit at position bit_idx counted from the LSB. 0 for missing/x/z."""
    if not binary_str:
        return 0
    s = binary_str.strip()
    if not s:
        return 0
    if "x" in s.lower() or "z" in s.lower():
        return 0
    if len(s) <= bit_idx:
        return 0
    return 1 if s[-(bit_idx + 1)] == "1" else 0


def binary_to_int(s):
    if not s:
        return None
    s = s.strip()
    if any(c in s.lower() for c in "xz"):
        return None
    try:
        return int(s, 2)
    except ValueError:
        return None


def binary_to_hex(s):
    n = binary_to_int(s)
    return None if n is None else f"0x{n:x}"


def _onehot_to_idx(v):
    """One-hot integer -> bit index (way number). None or non-one-hot -> None."""
    if v is None or v <= 0:
        return None
    if v & (v - 1):          # more than one bit set: not clean one-hot
        return None
    return v.bit_length() - 1


# ============================================================================
# Streaming
# ============================================================================

def stream_and_extract(f, matches, args, n_wb_ports, n_commit_ports):
    # Build lookup maps from matches.
    single_id = {}    # whitelist_path → vcd_id (for entries with one match)
    port_maps = {}    # whitelist_path → {port: vcd_id} (for multi-element)
    for m in matches:
        if not m["vcd_ids"]:
            continue
        if len(m["vcd_ids"]) == 1:
            single_id[m["whitelist_path"]] = m["vcd_ids"][0]
        else:
            port_maps[m["whitelist_path"]] = build_port_map(
                m["full_paths"], m["vcd_ids"])

    # Collect all tracked VCD IDs for the body filter.
    tracked = set()
    for vid in single_id.values():
        tracked.add(vid)
    for pm in port_maps.values():
        tracked.update(pm.values())

    state = {}
    tracker = PipelineTracker(
        user_entry_pc=args.user_entry_pc,
        n_wb_ports=n_wb_ports,
        n_commit_ports=n_commit_ports,
    )

    # Quick aliases for the hot path.
    CLK = single_id.get("clk_i")
    FE_V = single_id.get("id_stage_i.fetch_entry_valid_i")
    FE_R = single_id.get("id_stage_i.fetch_entry_ready_o")
    PC_ID = single_id.get("fetch_entry_if_id[0].address")
    IN_ID = single_id.get("fetch_entry_if_id[0].instruction")
    RVC = single_id.get("id_stage_i.rvfi_is_compressed_o")

    DV = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_valid_i")
    DA = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_ack_o")
    # Phase 4a: decoded_instr_i fields sampled at decode handshake.
    DFU = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_i[0].fu")
    DRS1 = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_i[0].rs1")
    DRS2 = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_i[0].rs2")
    DRD = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_i[0].rd")
    # Phase 7a: decoded_instr_i.bp.{cf,predict_address} at decode
    # handshake. Captured via pre-edge snapshot (pre_dbp_cf,
    # pre_dbp_tgt) to avoid the same advance-on-rising-edge issue
    # that affects fu/rs1/rs2/rd.
    DBP_CF  = single_id.get(
        "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.cf")
    DBP_TGT = single_id.get(
        "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.predict_address")

    # Phase 8a: forwarding signals from issue_read_operands. Snapshot
    # pre-edge at the issue rising edge (same pattern as decoded_instr_i.*
    # because forward_rsX/idx_hzd_rsX are also combinational outputs that
    # advance to the next instruction's view on the rising edge).
    FWD_RS1 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs1")
    FWD_RS2 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs2")
    FWD_RS3 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs3")
    IHZ_RS1 = single_id.get("issue_stage_i.i_issue_read_operands.idx_hzd_rs1[0]")
    IHZ_RS2 = single_id.get("issue_stage_i.i_issue_read_operands.idx_hzd_rs2[0]")
    IHZ_RS3 = single_id.get("issue_stage_i.i_issue_read_operands.idx_hzd_rs3[0]")
    FWD_AVAILABLE = all(s is not None for s in (
        FWD_RS1, FWD_RS2, FWD_RS3, IHZ_RS1, IHZ_RS2, IHZ_RS3))
    if FWD_AVAILABLE:
        print("Phase 8a: issue_read_operands forwarding signals resolved",
              file=sys.stderr)
    else:
        missing = [name for name, sig in [
            ("forward_rs1",   FWD_RS1), ("forward_rs2", FWD_RS2),
            ("forward_rs3",   FWD_RS3), ("idx_hzd_rs1[0]", IHZ_RS1),
            ("idx_hzd_rs2[0]", IHZ_RS2), ("idx_hzd_rs3[0]", IHZ_RS3),
        ] if sig is None]
        print("WARNING: Phase 8a - forwarding signals not resolved; "
              "fwd_rsX_* fields will be left null on all records. "
              "Missing: " + ", ".join(missing), file=sys.stderr)
    IV = single_id.get("issue_stage_i.i_scoreboard.issue_instr_valid_o")
    IA = single_id.get("issue_stage_i.i_scoreboard.issue_ack_i")
    IPTR = single_id.get("issue_stage_i.i_scoreboard.issue_pointer_q")

    WTV = single_id.get("issue_stage_i.i_scoreboard.wt_valid_i")
    # trans_id_i per port: explicit per-port whitelist entries.
    TID_MAP = {}
    for port in range(n_wb_ports):
        vid = single_id.get(f"issue_stage_i.i_scoreboard.trans_id_i[{port}]")
        if vid is not None:
            TID_MAP[port] = vid

    # Phase 4a v0.2: per-slot maps for scoreboard's registered mem_q.
    # MEMQ_FU[N] = vcd_id of mem_q[N].sbe.fu (None if slot not exposed).
    NR_SB = 8
    MEMQ_FU = [None] * NR_SB
    MEMQ_RS1 = [None] * NR_SB
    MEMQ_RS2 = [None] * NR_SB
    MEMQ_RD = [None] * NR_SB
    memq_resolved = 0
    for n in range(NR_SB):
        f_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.fu")
        r1_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs1")
        r2_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs2")
        rd_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rd")
        MEMQ_FU[n] = f_vid
        MEMQ_RS1[n] = r1_vid
        MEMQ_RS2[n] = r2_vid
        MEMQ_RD[n] = rd_vid
        if all(v is not None for v in (f_vid, r1_vid, r2_vid, rd_vid)):
            memq_resolved += 1
    MEMQ_AVAILABLE = (memq_resolved == NR_SB)

    # Phase 7a: decoded_instr_i[0].bp.{cf,predict_address} availability.
    BP_DECODE_AVAILABLE = (DBP_CF is not None and DBP_TGT is not None)
    if BP_DECODE_AVAILABLE:
        print("Phase 7a: decoded_instr_i[0].bp.{cf,predict_address} resolved — "
              "using pre-edge snapshot for prediction capture",
              file=sys.stderr)
    else:
        missing = [name for name, sig in [
            ("decoded_instr_i[0].bp.cf", DBP_CF),
            ("decoded_instr_i[0].bp.predict_address", DBP_TGT),
        ] if sig is None]
        print("WARNING: Phase 7a — decoded_instr_i.bp.* not resolved; "
              "bp_predicted_* fields will be left None on all records. "
              "Missing: " + ", ".join(missing), file=sys.stderr)

    if MEMQ_AVAILABLE:
        print(f"mem_q ring buffer: all {NR_SB} slots resolved — using authoritative reads",
              file=sys.stderr)
    elif memq_resolved > 0:
        print(f"mem_q ring buffer: only {memq_resolved}/{NR_SB} slots resolved — "
              "falling back to decode-time pre-edge capture",
              file=sys.stderr)
        MEMQ_AVAILABLE = False
    else:
        print("mem_q ring buffer: NOT exposed in VCD — falling back to decode-time pre-edge capture",
              file=sys.stderr)

    CA = single_id.get("commit_stage_i.commit_ack_o")
    CPTR0 = single_id.get("issue_stage_i.i_scoreboard.commit_pointer_q[0]")
    CPTR1 = single_id.get("issue_stage_i.i_scoreboard.commit_pointer_q[1]")
    CPTR_PORTS = [CPTR0, CPTR1]

    FIF = single_id.get("flush_ctrl_if")
    FID = single_id.get("flush_ctrl_id")
    FEX = single_id.get("flush_ctrl_ex")
    # Phase 4a v0.3: gate on_decode by !flush_unissued_instr_i.
    FUI = single_id.get("issue_stage_i.i_scoreboard.flush_unissued_instr_i")
    if FUI is None:
        print("WARNING: flush_unissued_instr_i not resolved — phantom-decode "
              "gating will be DISABLED and the +N slot drift may return.",
              file=sys.stderr)

    # Phase 4b: I$ signal lookups for ICacheTimeline.on_cycle. STATE_Q
    # is the I$ controller's FSM (cva6_icache.sv:122). The dreq_o
    # signals are sourced from the FRONTEND-side mirror
    # (i_frontend.icache_dreq_i, already in the whitelist), which is
    # electrically the same as the I$'s dreq_o output but reachable
    # without adding a separate I$-scoped lookup.
    STATE_Q = single_id.get(
        "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.state_q")
    IC_VLD   = single_id.get("i_frontend.icache_dreq_i.valid")
    IC_VADDR = single_id.get("i_frontend.icache_dreq_i.vaddr")
    IC_K2    = single_id.get("i_frontend.icache_dreq_o.kill_s2")
    icache_resolved = all(s is not None
                          for s in (STATE_Q, IC_VLD, IC_VADDR, IC_K2))
    if not icache_resolved:
        print("WARNING: Phase 4b I$ signals not all resolved — "
              "if1_cycle/if2_cycle/ic_miss will be left as None on every "
              "record. Missing: " +
              ", ".join(name for name, s in [
                  ("state_q", STATE_Q),
                  ("dreq_o.valid", IC_VLD),
                  ("dreq_o.vaddr", IC_VADDR),
                  ("dreq_i.kill_s2", IC_K2),
              ] if s is None),
              file=sys.stderr)
    else:
        print("Phase 4b I$ tracking enabled (state_q + frontend dreq mirror)",
              file=sys.stderr)

    # Phase 6a: LSU FSM state register lookups.
    LOAD_STATE  = single_id.get("ex_stage_i.lsu_i.i_load_unit.state_q")
    STORE_STATE = single_id.get("ex_stage_i.lsu_i.i_store_unit.state_q")
    # Phase 6a v0.4: lsu_ctrl.trans_id for FSM admission correlation.
    LSU_CTRL_TID = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.trans_id")
    # Phase 6a v0.5: pop_ld / pop_st for admit-while-busy detection.
    POP_LD = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i")
    POP_ST = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i")
    lsu_resolved = (LOAD_STATE is not None and STORE_STATE is not None)

    # Phase 6b: HPDcache miss-handler signal IDs. The `gen_cache_hpd.`
    # generate-block prefix is mandatory — cva6.sv instantiates three
    # cache subsystem variants under different generate branches and
    # this build's signals live under gen_cache_hpd only. (Other
    # branches: gen_cache_std for std_cache, gen_cache_wt for the
    # write-through nbdcache.)
    _DC_BASE = ("gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
                "hpdcache_miss_handler_i.")
    DC_MALLO  = single_id.get(_DC_BASE + "mshr_alloc_i")
    DC_MTID   = single_id.get(_DC_BASE + "mshr_alloc_tid_i")
    DC_MSID   = single_id.get(_DC_BASE + "mshr_alloc_sid_i")
    DC_MPF    = single_id.get(_DC_BASE + "mshr_alloc_is_prefetch_i")
    DC_MNLINE = single_id.get(_DC_BASE + "mshr_alloc_nline_i")
    DC_MCHK   = single_id.get(_DC_BASE + "mshr_check_i")
    DC_MCHKN  = single_id.get(_DC_BASE + "mshr_check_nline_i")
    DC_MCHKH  = single_id.get(_DC_BASE + "mshr_check_hit_o")
    DC_RFSM   = single_id.get(_DC_BASE + "refill_fsm_q")
    DC_RRSP   = single_id.get(_DC_BASE + "refill_core_rsp_valid_o")
    DC_RTID   = single_id.get(_DC_BASE + "refill_core_rsp_o.tid")
    dcache_resolved = all(s is not None for s in [
        DC_MALLO, DC_MTID, DC_MSID, DC_MPF, DC_MNLINE,
        DC_MCHK, DC_MCHKN, DC_MCHKH, DC_RFSM, DC_RRSP, DC_RTID,
    ])

    # Phase 7b: dirty victim writeback (flush/wback unit) signals, all at
    # the i_hpdcache level. send/ack are the live flush channel; the wbuf
    # channel is dead in this WB config (gen_no_wbuf).
    _WB_BASE = "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    WB_ALLOC_V  = single_id.get(_WB_BASE + "flush_alloc")
    WB_ALLOC_R  = single_id.get(_WB_BASE + "flush_alloc_ready")
    WB_ALLOC_NL = single_id.get(_WB_BASE + "flush_alloc_nline")
    WB_SEND_V   = single_id.get(_WB_BASE + "mem_req_write_flush_valid")
    WB_SEND_R   = single_id.get(_WB_BASE + "mem_req_write_flush_ready")
    WB_SEND_ID  = single_id.get(_WB_BASE + "mem_req_write_flush.mem_req_id")
    WB_SEND_AD  = single_id.get(_WB_BASE + "mem_req_write_flush.mem_req_addr")
    WB_ACK_V    = single_id.get(_WB_BASE + "mem_resp_write_flush_valid")
    WB_ACK_R    = single_id.get(_WB_BASE + "mem_resp_write_flush_ready")
    WB_ACK_ID   = single_id.get(_WB_BASE + "mem_resp_write_flush.mem_resp_w_id")
    WB_ACK_NL   = single_id.get(_WB_BASE + "flush_ack_nline")
    wback_resolved = all(s is not None for s in [
        WB_ALLOC_V, WB_ALLOC_R, WB_ALLOC_NL,
        WB_SEND_V, WB_SEND_R, WB_SEND_ID, WB_SEND_AD,
        WB_ACK_V, WB_ACK_R, WB_ACK_ID, WB_ACK_NL,
    ])
    # Phase 7b linkage: flush-side victim way + miss-handler eviction signals
    # (mshr_alloc_i / mshr_alloc_nline_i reused from the Phase 6b group as
    # DC_MALLO / DC_MNLINE).
    WB_FWAY   = single_id.get(_WB_BASE + "flush_alloc_way")
    EV_WBACK  = single_id.get(_DC_BASE + "mshr_alloc_wback_i")
    EV_VWAY   = single_id.get(_DC_BASE + "mshr_alloc_victim_way_i")
    link_resolved = all(s is not None for s in [
        WB_FWAY, EV_WBACK, EV_VWAY, DC_MALLO, DC_MNLINE,
    ])

    # Phase 7a: branch resolution signals. bp_resolve_t struct fields
    # under issue_stage_i.i_scoreboard.resolved_branch_i.*. The valid
    # field pulses high for one cycle when branch_unit emits a
    # resolution; the rest carry the resolution payload.
    _RB = "issue_stage_i.i_scoreboard.resolved_branch_i."
    RB_VLD   = single_id.get(_RB + "valid")
    RB_PC    = single_id.get(_RB + "pc")
    RB_TGT   = single_id.get(_RB + "target_address")
    RB_TKN   = single_id.get(_RB + "is_taken")
    RB_MISP  = single_id.get(_RB + "is_mispredict")
    RB_CFT   = single_id.get(_RB + "cf_type")
    bp_resolved = all(s is not None for s in
                      [RB_VLD, RB_PC, RB_TGT, RB_TKN, RB_MISP, RB_CFT])
    if not bp_resolved:
        missing = [name for name, sig in [
            ("resolved_branch_i.valid", RB_VLD),
            ("resolved_branch_i.pc", RB_PC),
            ("resolved_branch_i.target_address", RB_TGT),
            ("resolved_branch_i.is_taken", RB_TKN),
            ("resolved_branch_i.is_mispredict", RB_MISP),
            ("resolved_branch_i.cf_type", RB_CFT),
        ] if sig is None]
        print("WARNING: Phase 7a branch-resolve signals not all "
              "resolved — bp_resolved_* fields will be left None "
              "on all records. Missing: " + ", ".join(missing),
              file=sys.stderr)
    else:
        print("Phase 7a branch resolution tracking enabled "
              "(resolved_branch_i: valid + pc + target + taken + "
              "mispredict + cf_type)", file=sys.stderr)

    if not lsu_resolved:
        missing = []
        if LOAD_STATE is None:  missing.append("i_load_unit.state_q")
        if STORE_STATE is None: missing.append("i_store_unit.state_q")
        print("WARNING: Phase 6a LSU signals not all resolved — "
              "lsu_state_history will be left as None on every record. "
              "Missing: " + ", ".join(missing), file=sys.stderr)
    else:
        extras = []
        if not LSU_CTRL_TID: extras.append("lsu_ctrl.trans_id")
        if not POP_LD: extras.append("pop_ld")
        if not POP_ST: extras.append("pop_st")
        extras_msg = ("" if not extras
                      else f" — degraded (missing: {', '.join(extras)})")
        print("Phase 6a LSU FSM tracking enabled "
              f"(load_unit.state_q + store_unit.state_q + "
              f"lsu_ctrl.trans_id + pop_ld + pop_st){extras_msg}",
              file=sys.stderr)

    # Phase 6b: announce dcache event tracking status.
    if not dcache_resolved:
        missing = [name for name, sig in [
            ("mshr_alloc_i", DC_MALLO),
            ("mshr_alloc_tid_i", DC_MTID),
            ("mshr_alloc_sid_i", DC_MSID),
            ("mshr_alloc_is_prefetch_i", DC_MPF),
            ("mshr_alloc_nline_i", DC_MNLINE),
            ("mshr_check_i", DC_MCHK),
            ("mshr_check_nline_i", DC_MCHKN),
            ("mshr_check_hit_o", DC_MCHKH),
            ("refill_fsm_q", DC_RFSM),
            ("refill_core_rsp_valid_o", DC_RRSP),
            ("refill_core_rsp_o.tid", DC_RTID),
        ] if sig is None]
        print(f"WARNING: Phase 6b dcache signals not all resolved — "
              f"dc_* fields will be left at defaults. "
              f"Missing: {', '.join(missing)}", file=sys.stderr)
    else:
        print("Phase 6b D$ event tracking enabled "
              "(mshr_alloc + mshr_check + refill_fsm + refill_rsp)",
              file=sys.stderr)

    # Phase 7b: announce writeback (flush/wback) tracking status.
    if not wback_resolved:
        missing = [name for name, sig in [
            ("flush_alloc", WB_ALLOC_V),
            ("flush_alloc_ready", WB_ALLOC_R),
            ("flush_alloc_nline", WB_ALLOC_NL),
            ("mem_req_write_flush_valid", WB_SEND_V),
            ("mem_req_write_flush_ready", WB_SEND_R),
            ("mem_req_write_flush.mem_req_id", WB_SEND_ID),
            ("mem_req_write_flush.mem_req_addr", WB_SEND_AD),
            ("mem_resp_write_flush_valid", WB_ACK_V),
            ("mem_resp_write_flush_ready", WB_ACK_R),
            ("mem_resp_write_flush.mem_resp_w_id", WB_ACK_ID),
            ("flush_ack_nline", WB_ACK_NL),
        ] if sig is None]
        print("WARNING: Phase 7b writeback signals not all resolved — "
              "writebacks[] will be empty. Missing: " + ", ".join(missing),
              file=sys.stderr)
    else:
        print("Phase 7b dirty-victim writeback tracking enabled "
              "(flush alloc + mem_req_write_flush + mem_resp_write_flush)",
              file=sys.stderr)
        if link_resolved:
            print("Phase 7b writeback<->eviction linkage enabled "
                  "(mshr_alloc_wback + victim_way + flush_alloc_way, "
                  "join by (set,way))", file=sys.stderr)
        else:
            print("WARNING: Phase 7b linkage signals not all resolved — "
                  "writebacks will have linked=false. (need "
                  "mshr_alloc_wback_i, mshr_alloc_victim_way_i, "
                  "flush_alloc_way)", file=sys.stderr)

    cycle = -1
    first_ts_seen = False
    clk_at_ts_start = "0"
    prev_flush_if = "0"
    prev_flush_id = "0"
    prev_flush_ex = "0"

    # Pre-edge snapshot of decoded_instr_i fields. These are sourced from
    # id_stage's registered `issue_q`, which advances AT the rising edge of
    # every decode handshake. Verilator dumps the post-edge value, so a
    # naive `state[DFU]` read at the rising-edge timestamp yields the
    # *next* instruction's fields. We snapshot at each `#` marker before
    # applying that timestamp's value changes — when a rising edge is
    # then detected at the following `#`, the snapshot holds the pre-edge
    # (correct) values.
    pre_dfu = None
    pre_drs1 = None
    pre_drs2 = None
    pre_drd = None
    # Phase 7a: pre-edge snapshots of decoded_instr_i[0].bp.{cf,
    # predict_address}. Reading these straight from `state` at the
    # rising-edge timestamp would land us on the next instruction's
    # values (id_stage's issue_q advances at the same edge that
    # latches the handshake), so we mirror the Phase 4a pre-edge
    # snapshot pattern used for fu/rs1/rs2/rd.
    pre_dbp_cf = None
    pre_dbp_tgt = None
    # Phase 8a: pre-edge snapshot of forwarding signals.
    pre_fwd_rs1 = None
    pre_fwd_rs2 = None
    pre_fwd_rs3 = None
    pre_ihz_rs1 = None
    pre_ihz_rs2 = None
    pre_ihz_rs3 = None
    # Phase 8a: pre-edge snapshot of the writeback bus (wt_valid_i and
    # the per-port trans_id_i). Needed for via=sb/wb classification.
    # The wb pulse from a 1-cycle ALU is HIGH during cycle P.wb_cycle and
    # 0 by cycle P.wb_cycle+1. A consumer Q forwarding via the wb-path
    # is at-head during P.wb_cycle and its handshake fires at the rising
    # edge of P.wb_cycle+1, giving Q.is_cycle = P.wb_cycle+1. Inside
    # at_rising_edge for that cycle, state.get(WTV) returns wt_valid_i
    # DURING Q.is_cycle (post-edge), by which point the pulse is already
    # gone. The pre-edge snapshot taken at the start of this # gives
    # wt_valid_i at end-of-previous-TS = during Q's at-head cycle, which
    # IS the cycle where the wb override actually fired.
    pre_wtv = None
    pre_tids = {}     # port -> pre-edge trans_id_i[port] (raw VCD string)

    n_lines = 0
    n_changes = 0
    last_ts = 0
    last_report = 0
    start = time.time()

    def at_rising_edge():
        nonlocal cycle, prev_flush_if, prev_flush_id, prev_flush_ex
        cycle += 1

        # Phase 6a v0.4: no drain step. Correlation is via
        # lsu_ctrl.trans_id at FSM-transition time (see
        # on_lsu_fsm_sample), not via a deferred pending slot.
        # v0.2's drain was needed to read the authoritative mem_q.fu
        # value; v0.3 added a FIFO queue to handle back-to-back
        # issues. Both are obviated by sampling lsu_ctrl directly,
        # which is what the FSM itself sees.

        # 1. Flush detection on rising edges of flush_ctrl_*.
        flush_if_now = state.get(FIF, "0") if FIF else "0"
        flush_id_now = state.get(FID, "0") if FID else "0"
        flush_ex_now = state.get(FEX, "0") if FEX else "0"
        # EX cascade covers ID + IF, so check it first.
        if flush_ex_now == "1" and prev_flush_ex == "0":
            tracker.on_flush_ex(cycle)
        elif flush_id_now == "1" and prev_flush_id == "0":
            tracker.on_flush_id(cycle)
        elif flush_if_now == "1" and prev_flush_if == "0":
            tracker.on_flush_if(cycle)
        prev_flush_if, prev_flush_id, prev_flush_ex = (
            flush_if_now, flush_id_now, flush_ex_now)

        # 2. Commit (release scoreboard slots before issue can claim them).
        if CA is not None:
            ca_bus = state.get(CA, "0")
            for port in range(n_commit_ports):
                if get_bit(ca_bus, port) == 1:
                    ptr_id = CPTR_PORTS[port] if port < len(CPTR_PORTS) else None
                    if ptr_id is not None:
                        tid = binary_to_int(state.get(ptr_id))
                        if tid is not None:
                            mq_fu = mq_rs1 = mq_rs2 = mq_rd = None
                            if MEMQ_AVAILABLE and 0 <= tid < NR_SB:
                                mq_fu = binary_to_int(state.get(MEMQ_FU[tid]))
                                mq_rs1 = binary_to_int(state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(state.get(MEMQ_RS2[tid]))
                                mq_rd = binary_to_int(state.get(MEMQ_RD[tid]))
                            tracker.on_commit(cycle, port, tid,
                                              mq_fu, mq_rs1, mq_rs2, mq_rd)

        # 3. Writeback.
        if WTV is not None:
            wt_bus = state.get(WTV, "0")
            for port in range(n_wb_ports):
                if get_bit(wt_bus, port) == 1:
                    tid_vid = TID_MAP.get(port)
                    if tid_vid is not None:
                        tid = binary_to_int(state.get(tid_vid))
                        if tid is not None:
                            mq_fu = mq_rs1 = mq_rs2 = mq_rd = None
                            if MEMQ_AVAILABLE and 0 <= tid < NR_SB:
                                mq_fu = binary_to_int(state.get(MEMQ_FU[tid]))
                                mq_rs1 = binary_to_int(state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(state.get(MEMQ_RS2[tid]))
                                mq_rd = binary_to_int(state.get(MEMQ_RD[tid]))
                            tracker.on_writeback(cycle, port, tid,
                                                 mq_fu, mq_rs1, mq_rs2, mq_rd)

        # 4+5. Combined decode+issue handshake. Phase 4a v0.4: in
        # non-superscalar CVA6, scoreboard's issue_instr_o is a
        # combinational passthrough of decoded_instr_i (scoreboard.sv:151)
        # — DV/DA and IV/IA both fire in the same cycle for the same
        # instruction. Treating them as separate events caused MY_TID to
        # be read from IPTR multiple cycles late whenever the pipeline
        # stalled, putting trans_id assignments +N ahead of the HW slot
        # and making every mem_q lookup land on the wrong slot.
        if DV and DA and state.get(DV) == "1" and state.get(DA) == "1":
            flush_unissued = (FUI is not None and state.get(FUI) == "1")
            if not flush_unissued:
                tid = binary_to_int(state.get(IPTR))
                if tid is not None:
                    fu_val = binary_to_int(pre_dfu)
                    rs1 = binary_to_int(pre_drs1)
                    rs2 = binary_to_int(pre_drs2)
                    rd = binary_to_int(pre_drd)
                    # Phase 7a: bp.cf and bp.predict_address come
                    # from the SAME pre-edge snapshot pattern as
                    # fu/rs1/rs2/rd above. Reading mem_q[tid].sbe.bp
                    # at this rising edge gives stale values (the
                    # previous slot occupant's bp) because
                    # issue_pointer_q advances on this same edge —
                    # decoded_instr_i.bp at pre-edge is the only
                    # source for the new instruction's bp.
                    bp_cf_val = (binary_to_int(pre_dbp_cf)
                                 if BP_DECODE_AVAILABLE else None)
                    bp_target = (binary_to_int(pre_dbp_tgt)
                                 if BP_DECODE_AVAILABLE else None)
                    # Phase 8a: forwarding snapshot. forward_rsX is a
                    # single-bit value at NrIssuePorts=1, so we treat the
                    # raw VCD string as a bool. idx_hzd_rsX[0] is
                    # TRANS_ID_BITS-wide. wb_view is the same-cycle
                    # writeback bus, used to tag via=wb when the producer
                    # slot is also being written back this cycle.
                    if FWD_AVAILABLE:
                        fwd_rs1_bit = (pre_fwd_rs1 == "1")
                        fwd_rs2_bit = (pre_fwd_rs2 == "1")
                        fwd_rs3_bit = (pre_fwd_rs3 == "1")
                        ihz_rs1_v = binary_to_int(pre_ihz_rs1)
                        ihz_rs2_v = binary_to_int(pre_ihz_rs2)
                        ihz_rs3_v = binary_to_int(pre_ihz_rs3)
                    else:
                        fwd_rs1_bit = fwd_rs2_bit = fwd_rs3_bit = False
                        ihz_rs1_v = ihz_rs2_v = ihz_rs3_v = None
                    # Build wb_view from the PRE-EDGE snapshot of the
                    # writeback bus. This captures wt_valid_i/trans_id_i
                    # at end-of-previous-TS, which is during Q's at-head
                    # cycle — the cycle when the wb override actually
                    # fired and made Q issuable. Using live state here
                    # would read wt_valid_i during Q.is_cycle (post-edge),
                    # by which point P's wb pulse has ended.
                    wb_view = []
                    if WTV is not None and pre_wtv is not None:
                        wt_bits = pre_wtv
                        for port, raw_tid in pre_tids.items():
                            # wt_valid_i is dumped MSB-first; bit `port`
                            # is at index (len - 1 - port).
                            idx = len(wt_bits) - 1 - port
                            if 0 <= idx < len(wt_bits) and wt_bits[idx] == "1":
                                wb_tid = binary_to_int(raw_tid)
                                if wb_tid is not None:
                                    wb_view.append((port, wb_tid))
                    tracker.on_decode_issue(cycle, tid,
                                            fu_val, rs1, rs2, rd,
                                            bp_cf_val, bp_target,
                                            fwd_rs1_bit, fwd_rs2_bit, fwd_rs3_bit,
                                            ihz_rs1_v, ihz_rs2_v, ihz_rs3_v,
                                            wb_view)

        # 6. Fetch.
        #
        # Phase 4a v0.5: gate on flush_unissued_instr_i (fui). When fui=1
        # at the same cycle as an FE handshake, id_stage.sv:444 forces
        # issue_n[0].valid=0, overriding the valid=1 line 433 sets from
        # the FE handshake. HW's frontend still pops its instr_queue
        # (fetch_entry_ready_o was 1) but id_stage immediately discards
        # the entry — the instruction is silently dropped.
        #
        # v0.4 unconditionally pushed any FE handshake to `fetched`. At
        # cycles where fui=1 (e.g., the bnez-misprediction flush event),
        # this created a phantom record in `fetched` that HW's id_stage
        # never had. Every subsequent pop in `on_decode_issue` was then
        # +1 ahead of HW's true decode, producing a stable +1 trans_id
        # offset for every record afterward.
        #
        # In v0.5 we route these dropped fetches to `on_fetch_dropped`,
        # which records them as flushed (so the speculative path is
        # still visible) without adding them to the `fetched` queue —
        # keeping our queue exactly aligned with HW's id_stage.
        if FE_V and FE_R and state.get(FE_V) == "1" and state.get(FE_R) == "1":
            pc = binary_to_hex(state.get(PC_ID))
            instr = binary_to_hex(state.get(IN_ID))
            rvc = (state.get(RVC) == "1") if RVC else False
            flush_active = (FUI is not None and state.get(FUI) == "1")
            if flush_active:
                tracker.on_fetch_dropped(cycle, pc, instr, rvc)
            else:
                tracker.on_fetch(cycle, pc, instr, rvc)

        # 7. Phase 4b: feed the I$ event timeline. Independent of the
        # instruction-record handlers above — this just observes the
        # I$ controller's FSM and dreq handshake. After the walk
        # completes, match_records_to_events binds the resulting
        # events back onto each record by 4-byte-aligned PC.
        if icache_resolved:
            tracker.icache_timeline.on_cycle(
                cycle,
                state.get(STATE_Q),
                state.get(IC_VLD),
                state.get(IC_VADDR),
                state.get(IC_K2),
            )

        # 8. Phase 6a: sample LSU FSMs. v0.5 detects admissions via
        # both IDL→non-IDL state transitions (via prev lsu_ctrl.trans_id)
        # and pop_ld/pop_st pulses in SEND_TAG/VALID_STORE state
        # (admit-while-busy events).
        if lsu_resolved:
            tracker.on_lsu_fsm_sample(
                cycle,
                state.get(LOAD_STATE),
                state.get(STORE_STATE),
                state.get(LSU_CTRL_TID) if LSU_CTRL_TID else None,
                state.get(POP_LD) if POP_LD else None,
                state.get(POP_ST) if POP_ST else None,
            )

        # 9. Phase 6b: sample HPDcache miss-handler signals. Captures
        # alloc/check/refill_rsp pulses and rFSM-active cycles into a
        # global log keyed by cycle; attribution to records happens
        # after the scan in attribute_dc_events_to_records.
        if dcache_resolved:
            tracker.on_dcache_sample(
                cycle,
                state.get(DC_MALLO),
                state.get(DC_MTID),
                state.get(DC_MSID),
                state.get(DC_MPF),
                state.get(DC_MNLINE),
                state.get(DC_MCHK),
                state.get(DC_MCHKN),
                state.get(DC_MCHKH),
                state.get(DC_RFSM),
                state.get(DC_RRSP),
                state.get(DC_RTID),
            )

        # 9b. Phase 7b: sample the flush/wback unit handshakes. Logged in
        # cycle order; pairing + AXI-write-latency aggregate computed in
        # finalize_writebacks() after the walk.
        if wback_resolved:
            tracker.on_wback_sample(
                cycle,
                state.get(WB_ALLOC_V),
                state.get(WB_ALLOC_R),
                state.get(WB_ALLOC_NL),
                state.get(WB_FWAY) if WB_FWAY else None,
                state.get(WB_SEND_V),
                state.get(WB_SEND_R),
                state.get(WB_SEND_ID),
                state.get(WB_SEND_AD),
                state.get(WB_ACK_V),
                state.get(WB_ACK_R),
                state.get(WB_ACK_ID),
                state.get(WB_ACK_NL),
            )

        # 9c. Phase 7b linkage: log dirty-victim evictions (mshr_alloc with
        # wback=1). Joined to writebacks by (set, way) in finalize.
        if link_resolved:
            tracker.on_evict_sample(
                cycle,
                state.get(DC_MALLO),
                state.get(EV_WBACK),
                state.get(DC_MNLINE),
                state.get(EV_VWAY),
            )

        # 10. Phase 7a: branch resolution pulse. The branch_unit's
        # resolved_branch_o.valid goes high for one cycle at the
        # branch's ex_cycle (or shortly after if there's contention).
        # We bind it to an in-flight CTRL_FLOW record by PC match in
        # on_branch_resolved, picking the oldest in-flight on a tie.
        if bp_resolved and state.get(RB_VLD) == "1":
            tracker.on_branch_resolved(
                cycle,
                state.get(RB_PC),
                state.get(RB_TGT),
                state.get(RB_TKN),
                state.get(RB_MISP),
                state.get(RB_CFT),
            )

    for line in f:
        n_lines += 1
        line = line.rstrip()
        if not line:
            continue
        c0 = line[0]

        if c0 == "#":
            if first_ts_seen:
                curr_clk = state.get(CLK, "0")
                if clk_at_ts_start == "0" and curr_clk == "1":
                    at_rising_edge()
            else:
                first_ts_seen = True
            try:
                last_ts = int(line[1:])
            except ValueError:
                pass
            clk_at_ts_start = state.get(CLK) or "0"
            # Snapshot decoded fields BEFORE this timestamp's changes are
            # applied. If the next `#` reveals a rising edge happened here,
            # at_rising_edge() will read these (pre-edge) values for the
            # decode handshake's decoded data.
            if DFU:
                pre_dfu = state.get(DFU)
            if DRS1:
                pre_drs1 = state.get(DRS1)
            if DRS2:
                pre_drs2 = state.get(DRS2)
            if DRD:
                pre_drd = state.get(DRD)
            # Phase 7a: pre-edge snapshot of decoded_instr_i[0].bp.
            if DBP_CF:
                pre_dbp_cf = state.get(DBP_CF)
            if DBP_TGT:
                pre_dbp_tgt = state.get(DBP_TGT)
            # Phase 8a: pre-edge snapshot of forwarding signals from
            # issue_read_operands. Same advance-on-rising-edge concern
            # as decoded_instr_i.* — at post-edge these reflect the
            # NEXT issue candidate's hazard view, not the one that
            # just issued.
            if FWD_RS1:
                pre_fwd_rs1 = state.get(FWD_RS1)
            if FWD_RS2:
                pre_fwd_rs2 = state.get(FWD_RS2)
            if FWD_RS3:
                pre_fwd_rs3 = state.get(FWD_RS3)
            if IHZ_RS1:
                pre_ihz_rs1 = state.get(IHZ_RS1)
            if IHZ_RS2:
                pre_ihz_rs2 = state.get(IHZ_RS2)
            if IHZ_RS3:
                pre_ihz_rs3 = state.get(IHZ_RS3)
            # Phase 8a: pre-edge snapshot of the writeback bus. Required
            # because the wb pulse from a 1-cycle FU is HIGH during cycle
            # P.wb_cycle and back to 0 by P.wb_cycle+1. A consumer that
            # uses the wb-path forward has its handshake fire at the
            # rising edge of P.wb_cycle+1 (Q.is_cycle = P.wb_cycle+1).
            # state.get(WTV) inside at_rising_edge for Q.is_cycle returns
            # wt_valid_i during cycle Q.is_cycle (POST-edge), at which
            # point P's pulse is already gone. The pre-edge snapshot
            # here captures end-of-previous-TS = during Q's at-head cycle,
            # which is when the wb override actually fired.
            if WTV:
                pre_wtv = state.get(WTV)
            if TID_MAP:
                pre_tids = {port: state.get(vid)
                            for port, vid in TID_MAP.items()}

            if n_lines - last_report >= 10_000_000:
                elapsed = time.time() - start
                print(
                    f"  ... {n_lines:>15,} lines | "
                    f"{n_changes:>15,} changes | "
                    f"cycle {cycle:>10,} | "
                    f"fetched={tracker.next_id:>8,} "
                    f"committed={tracker.n_committed:>8,} | "
                    f"{elapsed:6.1f}s",
                    file=sys.stderr,
                )
                last_report = n_lines
            continue

        if c0 in "01xXzZ":
            value = c0
            vcd_id = line[1:]
        elif c0 in "bBrR":
            sp = line.find(" ")
            if sp <= 0:
                continue
            value = line[1:sp]
            vcd_id = line[sp + 1:]
        else:
            continue
        n_changes += 1

        if vcd_id in tracked:
            state[vcd_id] = value

    # EOF: flush whatever the final timestamp contained.
    if first_ts_seen:
        curr_clk = state.get(CLK, "0")
        if clk_at_ts_start == "0" and curr_clk == "1":
            at_rising_edge()

    tracker.finalize()

    # Phase 4b: bind I$ timeline events onto records by 4-byte-aligned
    # PC. Each record gets if1_cycle / if2_cycle / ic_miss populated
    # (or left as None if no matching event exists — typically because
    # the access was truly killed before delivery).
    n_ic_events = len(tracker.icache_timeline.events)
    n_ic_hits = sum(1 for ev in tracker.icache_timeline.events
                    if not ev.ic_miss)
    n_ic_misses = n_ic_events - n_ic_hits
    n_matched, n_unmatched = match_records_to_events(
        tracker.completed, tracker.icache_timeline.events)
    print(f"Phase 4b: {n_ic_events} I$ events "
          f"({n_ic_hits} hits, {n_ic_misses} misses); "
          f"{n_matched} records matched, {n_unmatched} unmatched",
          file=sys.stderr)

    # Phase 6a: count how many LOAD/STORE records got an FSM trace.
    # A trace is "present" when lsu_state_history has at least one
    # entry. Records where pending was set but no transition ever
    # fired (FSM didn't move while the record was pending — extremely
    # rare; only if a flush happened immediately) end up untraced.
    n_load_traced = 0; n_load_untraced = 0
    n_store_traced = 0; n_store_untraced = 0
    for rec in tracker.completed:
        if rec.fu == "LOAD":
            if rec.lsu_state_history:
                n_load_traced += 1
            else:
                n_load_untraced += 1
        elif rec.fu == "STORE":
            if rec.lsu_state_history:
                n_store_traced += 1
            else:
                n_store_untraced += 1
    print(f"Phase 6a: LSU FSM traces — "
          f"loads {n_load_traced} traced / {n_load_untraced} untraced; "
          f"stores {n_store_traced} traced / {n_store_untraced} untraced",
          file=sys.stderr)

    # Phase 6b: attribute D$ events to records.
    if dcache_resolved:
        dc_stats = tracker.attribute_dc_events_to_records()
        print(
            f"Phase 6b: D$ events — {dc_stats['total_dc_events']} total "
            f"alloc/check/refill_rsp pulses; "
            f"{dc_stats['rfsm_active_cycles']} refill-active cycles. "
            f"Per-record summary: "
            f"{dc_stats['n_primary_miss_loads']} primary-miss / "
            f"{dc_stats['n_coalesced_loads']} coalesced / "
            f"{dc_stats['n_refill_overlap_loads']} refill-overlap "
            f"(of {dc_stats['n_loads']} LOAD + "
            f"{dc_stats['n_stores']} STORE)",
            file=sys.stderr)
    else:
        dc_stats = {}

    # Phase 7a: branch prediction stats. Walk the completed records
    # and count predictions, resolutions, mispredicts, and per-cf
    # breakdowns. A branch is any record with fu=CTRL_FLOW; predicted
    # means bp_predicted_cf is non-None and not 'NoCF'; resolved
    # means bp_resolution_cycle is non-None.
    n_cf = 0
    n_pred = 0
    n_resolved = 0
    n_misp = 0
    n_pred_by_cf = {"Branch": 0, "Jump": 0, "JumpR": 0, "Return": 0}
    n_misp_by_cf = {"Branch": 0, "Jump": 0, "JumpR": 0, "Return": 0, "NoCF": 0}
    n_misp_flushed_before_resolve = 0
    for r in tracker.completed:
        if r.fu != "CTRL_FLOW":
            continue
        n_cf += 1
        if r.bp_predicted_cf and r.bp_predicted_cf != "NoCF":
            n_pred += 1
            n_pred_by_cf[r.bp_predicted_cf] = (
                n_pred_by_cf.get(r.bp_predicted_cf, 0) + 1)
        if r.bp_resolution_cycle is not None:
            n_resolved += 1
            if r.bp_mispredict:
                n_misp += 1
                key = r.bp_resolved_cf or "NoCF"
                n_misp_by_cf[key] = n_misp_by_cf.get(key, 0) + 1
        elif r.flush_reason == "flush_ex_branch_mispredict":
            # The branch itself was flushed before our scan saw the
            # resolution pulse. Rare but possible if the resolution
            # cycle coincides with the flush handshake.
            n_misp_flushed_before_resolve += 1
    bp_hit_rate = (
        100.0 * (n_resolved - n_misp) / n_resolved if n_resolved else 0.0)
    print(
        f"Phase 7a: branches — {n_cf} CTRL_FLOW records; "
        f"{n_pred} got a non-NoCF prediction "
        f"({n_pred_by_cf}); "
        f"{n_resolved} reached resolution; "
        f"{n_misp} mispredicts ({n_misp_by_cf}); "
        f"hit rate {bp_hit_rate:.1f}%"
        + (f"; {n_misp_flushed_before_resolve} flushed before resolve"
           if n_misp_flushed_before_resolve else ""),
        file=sys.stderr)
    bp_stats = {
        "n_ctrl_flow_records":  n_cf,
        "n_predictions":        n_pred,
        "n_resolutions":        n_resolved,
        "n_mispredicts":        n_misp,
        "n_predictions_by_cf":  n_pred_by_cf,
        "n_mispredicts_by_cf":  n_misp_by_cf,
        "hit_rate_pct":         round(bp_hit_rate, 2),
        "n_flushed_before_resolve": n_misp_flushed_before_resolve,
    }

    # Phase 7b: pair writeback send<->ack, build event list + latency agg.
    if wback_resolved:
        wb_stats = tracker.finalize_writebacks()
        awl = wb_stats.get("axi_write_latency", {})
        print(
            f"Phase 7b: writebacks — {wb_stats['n_allocs']} alloc / "
            f"{wb_stats['n_sends']} send / {wb_stats['n_acks']} ack; "
            f"{wb_stats['matched_pairs']} paired "
            f"({wb_stats['acks_no_prior_send']} acks w/o send, "
            f"{wb_stats['sends_never_acked']} sends unacked). "
            f"AXI write latency: "
            f"min={awl.get('min')} median={awl.get('median')} "
            f"max={awl.get('max')} cyc",
            file=sys.stderr)
        print(
            f"Phase 7b: writeback<->eviction linkage — "
            f"{wb_stats.get('n_evictions', 0)} eviction samples; "
            f"{wb_stats.get('n_linked', 0)} writebacks linked / "
            f"{wb_stats.get('n_unlinked', 0)} unlinked",
            file=sys.stderr)
    else:
        wb_stats = {}

    # Phase 8a: forwarding summary across committed records.
    n_fwd_any = 0
    n_fwd_rs1 = n_fwd_rs2 = n_fwd_rs3 = 0
    n_via_sb = n_via_wb = 0
    for r in tracker.completed:
        if r.flushed:
            continue
        used = False
        for via in (r.fwd_rs1_via, r.fwd_rs2_via, r.fwd_rs3_via):
            if via == "sb": n_via_sb += 1; used = True
            elif via == "wb": n_via_wb += 1; used = True
        if r.fwd_rs1_used: n_fwd_rs1 += 1
        if r.fwd_rs2_used: n_fwd_rs2 += 1
        if r.fwd_rs3_used: n_fwd_rs3 += 1
        if used: n_fwd_any += 1
    n_committed_seen = sum(1 for r in tracker.completed if not r.flushed)
    fwd_stats = {
        "n_committed_seen":   n_committed_seen,
        "n_with_any_forward": n_fwd_any,
        "n_rs1_forwarded":    n_fwd_rs1,
        "n_rs2_forwarded":    n_fwd_rs2,
        "n_rs3_forwarded":    n_fwd_rs3,
        "n_via_sb":           n_via_sb,
        "n_via_wb":           n_via_wb,
        # Diagnostics from the VCD stream: how many real forwards (gated
        # on fwd_rsX_used=True) had the producer slot on the wb bus at
        # the same cycle, per source. These are the ground truth for
        # whether via=wb should ever fire.
        "n_issue_cycles":             tracker._diag_n_issue_cycles,
        "n_issue_cycles_with_any_wb": tracker._diag_n_issue_with_any_wb,
        "n_real_match_rs1":           tracker._diag_n_real_match_rs1,
        "n_real_match_rs2":           tracker._diag_n_real_match_rs2,
        "n_real_match_rs3":           tracker._diag_n_real_match_rs3,
    }
    if n_committed_seen:
        pct = 100.0 * n_fwd_any / n_committed_seen
        print(
            f"Phase 8a: forwarding - {n_fwd_any}/{n_committed_seen} "
            f"committed records ({pct:.1f}%) used at least one forwarded "
            f"operand; rs1={n_fwd_rs1} rs2={n_fwd_rs2} rs3={n_fwd_rs3}; "
            f"via sb/wb = {n_via_sb}/{n_via_wb}",
            file=sys.stderr)
        # Diagnostic: count real forwards (fwd_rsX_used=True) where the
        # producer slot was also on the wb bus this same cycle. These
        # are the cases where via=wb SHOULD fire.
        n_real_match_total = (
            tracker._diag_n_real_match_rs1
            + tracker._diag_n_real_match_rs2
            + tracker._diag_n_real_match_rs3)
        print(
            f"Phase 8a diag: {tracker._diag_n_issue_cycles} issue cycles, "
            f"{tracker._diag_n_issue_with_any_wb} had any wt_valid_i bit set. "
            f"Real forward AND producer on wb bus: "
            f"rs1={tracker._diag_n_real_match_rs1} "
            f"rs2={tracker._diag_n_real_match_rs2} "
            f"rs3={tracker._diag_n_real_match_rs3} "
            f"(total={n_real_match_total}).",
            file=sys.stderr)

    stats = {
        "n_lines": n_lines,
        "n_changes": n_changes,
        "last_ts": last_ts,
        "n_cycles": cycle + 1,
        "icache_event_count": n_ic_events,
        "icache_event_hits": n_ic_hits,
        "icache_event_misses": n_ic_misses,
        "icache_records_matched": n_matched,
        "icache_records_unmatched": n_unmatched,
        "lsu_load_records_traced": n_load_traced,
        "lsu_load_records_untraced": n_load_untraced,
        "lsu_store_records_traced": n_store_traced,
        "lsu_store_records_untraced": n_store_untraced,
        "phase6b": dc_stats,
        "phase7a": bp_stats,
        "phase7b": wb_stats,
        "phase8a": fwd_stats,
    }
    return tracker, stats


# ============================================================================
# Disassembly listing (Phase 5)
# ============================================================================
#
# Phase 5 binds a human-readable disasm string onto each InstructionRecord
# by parsing an objdump -dS output file (typically produced by the user's
# RISC-V toolchain as part of the test build). This avoids any toolchain
# dependency in the tracer's environment — the listing is pre-built and
# passed in via --disasm-list.
#
# The listing format we parse (from riscv64-unknown-elf-objdump -dS):
#
#     /path/to/source.S:18                          ← source-interleave
#     _start:                                       ← function label
#     0000000080003000 <main>:                      ← address-tagged label
#         80003000:<tab>715d                 <tab>addi<tab>sp,sp,-80
#         80003002:<tab>4285                 <tab>li<tab>x5,0
#         ...
#
# The regex below intentionally requires LEADING WHITESPACE on the PC
# line so the all-hex 64-bit address labels (which start at column 0)
# never match. Source lines, labels, section headers, and assembler
# directives all start with characters outside `[0-9a-f]`, so they
# never match either.

_DISASM_LINE_RE = re.compile(
    r'^\s+([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s+(.+)$'
)


def parse_disasm_list(path):
    """Parse an objdump-style disassembly listing into a PC→string map.

    Returns dict mapping integer PC to a compact "mnemonic operands"
    string with all internal whitespace runs collapsed to single
    spaces. Lines that don't look like instructions are silently
    ignored — the parser is permissive by design.

    Raises FileNotFoundError if the path doesn't exist."""
    disasm = {}
    with open(path) as f:
        for line in f:
            m = _DISASM_LINE_RE.match(line.rstrip('\n'))
            if not m:
                continue
            pc = int(m.group(1), 16)
            # m.group(3) is everything after the raw bytes: mnemonic +
            # operands + any objdump-resolved symbolic comment. Collapse
            # tabs/spaces into a single space and strip.
            text = re.sub(r'\s+', ' ', m.group(3)).strip()
            disasm[pc] = text
    return disasm


def apply_disasm(records, disasm_map):
    """Annotate each record's `disasm` field by PC lookup.

    Returns (n_annotated, n_no_pc, n_unmapped) for the summary:
      n_annotated → records where disasm_map had a matching PC
      n_no_pc     → records with rec.pc unset or unparseable
      n_unmapped  → records whose PC fell outside the listing (e.g.
                    bootrom code at 0x10000 that isn't part of the
                    user-program ELF)."""
    n_annotated = 0
    n_no_pc = 0
    n_unmapped = 0
    for rec in records:
        if rec.pc is None:
            n_no_pc += 1
            continue
        try:
            pc_int = int(rec.pc, 16)
        except (TypeError, ValueError):
            n_no_pc += 1
            continue
        text = disasm_map.get(pc_int)
        if text is None:
            n_unmapped += 1
        else:
            rec.disasm = text
            n_annotated += 1
    return n_annotated, n_no_pc, n_unmapped


# ============================================================================
# Output
# ============================================================================

CV64A6_HPDC_WB_DEFAULTS = {
    "SuperscalarEn": False,
    "RVC": True,
    "CvxifEn": True,
    "NrIssuePorts": 1,
    "NrCommitPorts": 2,
    "NrWbPorts": 5,
    "NrScoreboardEntries": 8,
    "TRANS_ID_BITS": 3,
    "FETCH_WIDTH": 32,
    "INSTR_PER_FETCH": 2,
}


def write_output_json(output_path, args, stats, tracker):
    metadata = {
        "config_name": "cv64a6_imafdc_sv39_hpdcache_wb",
        "elf_path": None,
        "disasm_list_path": stats.get("disasm_list_path"),
        "vcd_path": str(args.vcd_path),
        "user_entry_pc": args.user_entry_pc,
        "user_end_pc": args.user_end_pc,
        "warmup_end_cycle": tracker.warmup_end_cycle,
        "tohost_cycle": None,
        "vcd_scope_prefix": args.scope_prefix,
        "invariants_verified": [],
        "stats": {
            "n_committed": tracker.n_committed,
            "n_flushed_if": tracker.n_flushed_if,
            "n_flushed_id": tracker.n_flushed_id,
            "n_flushed_ex": tracker.n_flushed_ex,
            "n_unmatched_writebacks": tracker.n_unmatched_writebacks,
            "n_unmatched_commits": tracker.n_unmatched_commits,
            # Phase 4b stats: I$ event counts and record-match results.
            "icache_event_count": stats.get("icache_event_count", 0),
            "icache_event_hits": stats.get("icache_event_hits", 0),
            "icache_event_misses": stats.get("icache_event_misses", 0),
            "icache_records_matched": stats.get(
                "icache_records_matched", 0),
            "icache_records_unmatched": stats.get(
                "icache_records_unmatched", 0),
            # Phase 5 stats: disassembly coverage.
            "disasm_annotated": stats.get("disasm_annotated", 0),
            "disasm_unmapped": stats.get("disasm_unmapped", 0),
            "disasm_no_pc": stats.get("disasm_no_pc", 0),
            # Phase 6a stats: LSU FSM tracking coverage.
            "lsu_load_records_traced": stats.get(
                "lsu_load_records_traced", 0),
            "lsu_store_records_traced": stats.get(
                "lsu_store_records_traced", 0),
            "lsu_load_records_untraced": stats.get(
                "lsu_load_records_untraced", 0),
            "lsu_store_records_untraced": stats.get(
                "lsu_store_records_untraced", 0),
            # Phase 6b stats: D$ event attribution coverage.
            "phase6b": stats.get("phase6b", {}),
            # Phase 7a stats: branch prediction tracking coverage.
            "phase7a": stats.get("phase7a", {}),
            # Phase 7b stats: dirty victim writeback + AXI write latency.
            "phase7b": stats.get("phase7b", {}),
            # Phase 8a stats: forwarding aggregates.
            "phase8a": stats.get("phase8a", {}),
        },
    }
    with output_path.open("w") as f:
        f.write("{\n")
        f.write(f'  "metadata": {json.dumps(metadata, indent=2)},\n')
        f.write(f'  "config_params": {json.dumps(CV64A6_HPDC_WB_DEFAULTS, indent=2)},\n')
        f.write(f'  "buffer_maxima": {json.dumps({})},\n')
        f.write('  "instructions": [\n')
        recs = tracker.completed
        for i, rec in enumerate(recs):
            d = asdict(rec)
            comma = "," if i < len(recs) - 1 else ""
            f.write(f"    {json.dumps(d)}{comma}\n")
        f.write("  ],\n")
        # Phase 7b: dirty victim writeback events (separate track, not
        # per-instruction — a writeback is per-evicted-line, many stores
        # coalesce into one line, decoupled in time from the stores).
        wbs = tracker.writeback_events
        f.write('  "writebacks": [\n')
        for i, wb in enumerate(wbs):
            comma = "," if i < len(wbs) - 1 else ""
            f.write(f"    {json.dumps(wb)}{comma}\n")
        f.write("  ]\n")
        f.write("}\n")


# ============================================================================
# Diagnostics
# ============================================================================

def report_missing(matches, path_to_id):
    missing = [m for m in matches if not m["vcd_ids"]]
    if not missing:
        return []
    print(file=sys.stderr)
    print("Missing whitelist entries:", file=sys.stderr)
    for m in missing:
        last_seg = m["whitelist_path"].rsplit(".", 1)[-1]
        last_seg = last_seg.split("[")[0]   # drop array index suffix for search
        print(f"  - {m['whitelist_path']}", file=sys.stderr)
        cands = [p for p in path_to_id if last_seg in p]
        for c in cands[:5]:
            print(f"      candidate: {c}", file=sys.stderr)
        if len(cands) > 5:
            print(f"      ... and {len(cands) - 5} more", file=sys.stderr)
        if not cands:
            print(f"      (no VCD path contains '{last_seg}')", file=sys.stderr)
    return [m["whitelist_path"] for m in missing]


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="CVA6 pipeline tracer for the CVA6 pipeline viewer.",
    )
    parser.add_argument("vcd_path", help="Path to the .vcd file.")
    parser.add_argument(
        "--scope-prefix",
        default="TOP.ariane_testharness.i_ariane.i_cva6",
        help="Hierarchical prefix to prepend to each whitelist entry.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON. Defaults to <vcd_basename>.phase3.json.",
    )
    parser.add_argument(
        "--user-entry-pc",
        default=None,
        help="Hex PC of `main` (e.g. 0x80003000) for warmup detection.",
    )
    parser.add_argument(
        "--user-end-pc",
        default=None,
        help="Hex PC of the last instruction of user code (e.g. 0x8000314c, "
             "typically the `jal ra, <exit>`). Emitted to metadata.user_end_pc; "
             "the viewer's `Main code` button reads it as the upper bound of "
             "the user-program range.",
    )
    parser.add_argument(
        "--disasm-list",
        default=None,
        help="Path to an objdump -dS listing of the test ELF. When provided, "
             "each record's `disasm` field is populated by PC lookup. "
             "Records whose PC falls outside the listing (e.g. bootrom) "
             "keep disasm=None.",
    )
    args = parser.parse_args()

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD file not found: {vcd_path}")
    args.vcd_path = vcd_path

    out_path = Path(args.output) if args.output else vcd_path.with_suffix(".phase3.json")

    n_wb_ports = CV64A6_HPDC_WB_DEFAULTS["NrWbPorts"]
    n_commit_ports = CV64A6_HPDC_WB_DEFAULTS["NrCommitPorts"]

    file_size = vcd_path.stat().st_size
    print(f"Opening {vcd_path} ({file_size / (1024 ** 3):.3f} GB)...")
    if args.user_entry_pc:
        print(f"User entry PC: {args.user_entry_pc}")
    start = time.time()

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, timescale = parse_var_block(f)
        print(f"Header parsed: {len(path_to_id):,} signals, timescale={timescale}")

        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        missing_paths = report_missing(matches, path_to_id)

        found = {m["whitelist_path"] for m in matches if m["vcd_ids"]}
        missing_required = REQUIRED_SIGNALS - found
        if missing_required:
            print()
            for s in sorted(missing_required):
                print(f"ERROR: required signal '{s}' not found.", file=sys.stderr)
            print("Aborting — Phase 3 cannot proceed.", file=sys.stderr)
            return 2

        tracked = sum(len(m["vcd_ids"]) for m in matches)
        print(f"Tracking {tracked} VCD signal IDs across "
              f"{len(matches) - len(missing_paths)}/{len(matches)} whitelist groups")
        print("Streaming body, tracing pipeline...")
        tracker, stats = stream_and_extract(
            f, matches, args, n_wb_ports, n_commit_ports)

    elapsed = time.time() - start

    # Phase 5: annotate records with disassembly text, if a listing was
    # provided. Done after the walk completes so we annotate exactly the
    # records that will be serialized (committed + flushed).
    if args.disasm_list:
        disasm_path = Path(args.disasm_list)
        if not disasm_path.exists():
            print(f"WARNING: --disasm-list {disasm_path} not found; "
                  "skipping disasm annotation.", file=sys.stderr)
            stats["disasm_annotated"] = 0
            stats["disasm_unmapped"] = 0
            stats["disasm_no_pc"] = 0
            stats["disasm_list_path"] = None
        else:
            disasm_map = parse_disasm_list(disasm_path)
            n_ann, n_no_pc, n_unmapped = apply_disasm(
                tracker.completed, disasm_map)
            print(f"Phase 5: parsed {len(disasm_map):,} disasm entries from "
                  f"{disasm_path.name}; annotated {n_ann:,} records "
                  f"({n_unmapped:,} unmapped, {n_no_pc:,} without PC)",
                  file=sys.stderr)
            stats["disasm_annotated"] = n_ann
            stats["disasm_unmapped"] = n_unmapped
            stats["disasm_no_pc"] = n_no_pc
            stats["disasm_list_path"] = str(disasm_path)
    else:
        stats["disasm_annotated"] = 0
        stats["disasm_unmapped"] = 0
        stats["disasm_no_pc"] = 0
        stats["disasm_list_path"] = None

    write_output_json(out_path, args, stats, tracker)

    mb = file_size / (1024 ** 2)
    speed = mb / elapsed if elapsed > 0 else 0.0

    print()
    print("=" * 78)
    print(" Phase 3 Tracer — Summary")
    print("=" * 78)
    print(f" Input                 : {vcd_path}")
    print(f" Output                : {out_path}")
    print(f" File size             : {file_size:>15,} bytes ({file_size / (1024**3):.3f} GB)")
    print(f" Lines processed       : {stats['n_lines']:>15,}")
    print(f" Value changes seen    : {stats['n_changes']:>15,}")
    print(f" Cycles seen (rising)  : {stats['n_cycles']:>15,}")
    print(f" Final timestamp       : {stats['last_ts']:>15,}")
    print(f" Elapsed               : {elapsed:>14.1f}s ({speed:.1f} MB/s)")
    print()
    n_total = len(tracker.completed)
    n_warmup = sum(1 for r in tracker.completed if r.is_warmup)
    n_compr = sum(1 for r in tracker.completed if r.is_compressed)
    n_flushed = sum(1 for r in tracker.completed if r.flushed)
    print(f" Records total         : {n_total:>15,}")
    print(f"   committed           : {tracker.n_committed:>15,}")
    print(f"   flushed             : {n_flushed:>15,}  "
          f"(IF={tracker.n_flushed_if}, ID={tracker.n_flushed_id}, EX={tracker.n_flushed_ex})")
    print(f"   warmup              : {n_warmup:>15,}")
    print(f"   user code           : {n_total - n_warmup:>15,}")
    print(f"   compressed (RVC)    : {n_compr:>15,}")
    print()
    print(f" warmup_end_cycle      : {tracker.warmup_end_cycle}")
    if tracker.n_unmatched_writebacks:
        print(f" UNMATCHED writebacks  : {tracker.n_unmatched_writebacks}  "
              f"(possible signal/timing issue)")
    if tracker.n_unmatched_commits:
        print(f" UNMATCHED commits     : {tracker.n_unmatched_commits}  "
              f"(possible signal/timing issue)")

    # Phase 5 disasm coverage summary.
    if args.disasm_list:
        print()
        print(f" Disassembly listing   : {args.disasm_list}")
        print(f"   annotated records   : {stats.get('disasm_annotated', 0):>15,}")
        print(f"   unmapped (no entry) : {stats.get('disasm_unmapped', 0):>15,}")
        if stats.get('disasm_no_pc', 0):
            print(f"   without PC          : {stats['disasm_no_pc']:>15,}")

    if n_total:
        first_user = next((r for r in tracker.completed if not r.is_warmup), None)
        if first_user:
            print()
            print(f" First user-code record:")
            print(f"   id={first_user.id}, pc={first_user.pc}, "
                  f"instr={first_user.instr_word}, compressed={first_user.is_compressed}")
            if first_user.disasm:
                print(f"   disasm={first_user.disasm}")
            print(f"   fu={first_user.fu}, fu_category={first_user.fu_category}, "
                  f"rs1=x{first_user.rs1}, rs2=x{first_user.rs2}, rd=x{first_user.rd}")
            print(f"   fe={first_user.fe_cycle}  id={first_user.id_cycle}  "
                  f"is={first_user.is_cycle}  ex={first_user.ex_cycle}  "
                  f"wb={first_user.wb_cycle}  co={first_user.co_cycle}")
            print(f"   trans_id={first_user.trans_id}, flushed={first_user.flushed}")

        # FU / FU-category distribution over committed records.
        from collections import Counter as _Counter
        cat_warm = _Counter()
        cat_user = _Counter()
        fu_user = _Counter()
        for r in tracker.completed:
            if r.flushed or r.fu_category is None:
                continue
            (cat_warm if r.is_warmup else cat_user)[r.fu_category] += 1
            if not r.is_warmup:
                fu_user[r.fu] += 1
        print()
        print(" FU category — committed records")
        print(f"   {'category':<10} {'warmup':>8} {'user':>8}")
        cats = sorted(set(cat_warm) | set(cat_user))
        for c in cats:
            print(f"   {c:<10} {cat_warm.get(c, 0):>8} {cat_user.get(c, 0):>8}")
        if fu_user:
            print()
            print(" FU breakdown — user-code committed records")
            for fu, n in fu_user.most_common():
                print(f"   {fu:<12} {n:>5}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
