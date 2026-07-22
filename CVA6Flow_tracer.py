#!/usr/bin/env python3
"""
CVA6 pipeline tracer. Extracts per-instruction lifecycle data from a
Verilator-generated VCD and emits JSON for the CVA6Flow viewer.

Each in-flight instruction is followed through
fetch → decode → issue (allocates trans_id) → execute → writeback →
commit, with stage cycles populated, flushes recorded, and the warmup
boundary identified via the first commit at `--user-entry-pc`. The JSON
"instructions" array carries per-record cycle/trans_id/flush fields plus
instr_word (masked to 16 bits when is_compressed), and separate top-level
arrays for dirty-victim writeback and dcache miss-handler alloc events.

Per-port signal layout (canonical cv64a6_imafdc_sv39_hpdcache_wb config,
auto-adapts for parameter sweeps via the scoreboard depth probe in
stream_and_extract):
  - wt_valid_i is a packed NR_WB_PORTS-bit bus, while trans_id_i is
    NR_WB_PORTS separate TRANS_ID_BITS-wide signals indexed by port. Match a
    writeback by looking up trans_id_i[port] for each set wt_valid bit.
  - commit_ack_o is a packed NR_COMMIT_PORTS-bit bus, and
    commit_pointer_q[0]/[1] give the trans_id released on each port.

Per-cycle processing order at each rising edge (ordering is
correctness-critical: commits must release scoreboard slots before issue
reuses them, mirroring the hardware FIFO discipline):
  1. Flush detection (cascade: flush_ex flushes EX + ID + IF)
  2. Commit (releases scoreboard slots BEFORE issue can reuse them)
  3. Writeback (updates wb_cycle on still-in-flight instances)
  4. Issue (decoded → issued, captures trans_id)
  5. Decode (fetched → decoded)
  6. Fetch (new instance enters fetched)

Usage:
    python3 cva6_pipeline_tracer.py <path-to.vcd>
    python3 cva6_pipeline_tracer.py daxpy.vcd \\
        --user-entry-pc 0x80003000 \\
        --output daxpy.json
"""

import argparse
import bisect
import json
import re
import sys
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ============================================================================
# Loading / progress output (mirrors the MinorFlow tracer)
# ============================================================================
_SHOW_STAGES = False
_PROG = None


def stagelog(*args, **kwargs):
    """Per-stage resolution diagnostics. Silent unless --stages is given."""
    if _SHOW_STAGES:
        print(*args, **kwargs)


class Progress:
    """In-place stderr progress reporter for the streaming parse. Prints e.g.
    "[parse] 14,250,000 lines \u00b7 312,004 insts \u00b7 18.3s" on a single
    rewritten line, throttled to a few times a second."""

    def __init__(self, label, enabled=True):
        self.label = label
        self.enabled = enabled and sys.stderr.isatty()
        self.force_plain = enabled and not sys.stderr.isatty()
        self.start = time.time()
        self.last_emit = 0.0
        self.lines = 0
        self.insts = 0

    def update(self, lines, insts=0, final=False):
        self.lines = lines
        self.insts = insts
        now = time.time()
        if not final and (now - self.last_emit) < 0.25:
            return
        self.last_emit = now
        elapsed = now - self.start
        msg = (f"[{self.label}] {lines:,} lines \u00b7 {insts:,} insts "
               f"\u00b7 {elapsed:.1f}s")
        if self.enabled:
            sys.stderr.write("\r" + msg + "   ")
            sys.stderr.flush()
        elif self.force_plain and (final or int(elapsed) % 5 == 0):
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    def done(self):
        self.update(self.lines, self.insts, final=True)
        if self.enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()


# ============================================================================
# Config
# ============================================================================
# Values are taken from cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv +
# build_config_pkg.sv. The whitelist below and the per-port lookups in
# stream_and_extract iterate these counts, so changing one constant here
# regenerates every config-dependent signal path. Other parts of the
# tracer (FSM enums, sid table, MMU/PTW assumptions) are CVA6-wide and
# do not vary with this config.

# Frontend
SUPERSCALAR_EN = False
RVC_EN = True
FETCH_WIDTH = 32                        # bits (=64 when SuperscalarEn=1)
FETCH_BYTES = FETCH_WIDTH // 8
FETCH_OFFSET_MASK = FETCH_BYTES - 1           # 0x3 for FW=32, 0x7 for FW=64
INSTR_PER_FETCH = FETCH_WIDTH // (16 if RVC_EN else 32)

# Backend
NR_ISSUE_PORTS = 1
NR_COMMIT_PORTS = 2
NR_WB_PORTS = 5
NR_SB_ENTRIES = 8
TRANS_ID_BITS = 3                         # = $clog2(NR_SB_ENTRIES)

# LSU. Ex_stage has three dcache_req_ports_o slots. This is a CVA6-wide
# architectural constant (port 0 = load adapter, 1 = MMU/PTW, 2 = store
# adapter)
DCACHE_REQ_PORTS = 3


# ============================================================================
# I$ controller FSM enum
# ============================================================================
# Used by ICacheTimeline.on_cycle to classify each delivery as a hit
# (state_q == READ at fe2) or miss (state_q == MISS).VCD encodes the
# 3-bit state as a binary string, e.g. "011" for MISS.

FSM_FLUSH = "000"
FSM_IDLE = "001"
FSM_READ = "010"
FSM_MISS = "011"
FSM_KILL_ATRANS = "100"
FSM_KILL_MISS = "101"


# ============================================================================
# LSU FSM enums
# ============================================================================
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
# Control-flow type enum
# ============================================================================
# The cf_t type is both the prediction carried with each instruction
# (branchpredict_sbe_t.cf) and the resolution emitted by the branch_unit
# (bp_resolve_t.cf_type). The value also identifies the predictor source:
#   NoCF   = 0  : no prediction (non-branch, or branch predicted not-taken)
#   Branch = 1  : conditional branch predicted taken -> BHT
#   Jump   = 2  : direct jump, target known at decode -> none (decoder-resolved)
#   JumpR  = 3  : indirect jump -> BTB
#   Return = 4  : return -> RAS

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
# HPDcache requestor source-ID assignment
# ============================================================================
# Per cva6_hpdcache_wrapper.sv (NumPorts=4 in
# cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv) the SID layout is:
#
#   - sid 0   : PTW load adapter         (page table walker, MMU)
#   - sid 1   : LSU load_unit adapter    (data loads, what we care about)
#   - sid 2   : Accelerator load adapter (acc_cache[0])
#   - sid 3   : STORE adapter            (NumPorts-1)
#   - sid 4   : CMO adapter              (NumPorts)
#   - sid 5   : hwpf_stride prefetcher   (NumPorts+1)
#
# Mapping derived by tracing dcache_req_to_cache[0..3] assignments
# → port 0=PTW, 1=load_unit, 2=store_unit. The HPDcache wrapper feeds
# dcache_req_ports_i[0..2] to load adapter slots r=0..2 with
# hpdcache_req_sid_i = r.

HPDCACHE_NUM_PORTS = 4
LOAD_ADAPTER_SIDS = frozenset(range(HPDCACHE_NUM_PORTS - 1))   # {0, 1, 2}
PTW_LOAD_SID = 0
LOAD_UNIT_SID = 1   # ← the only SID that flips dc_primary_miss on a LOAD record
ACCEL_LOAD_SID = 2
STORE_ADAPTER_SID = HPDCACHE_NUM_PORTS - 1                     # 3
CMO_ADAPTER_SID = HPDCACHE_NUM_PORTS                          # 4
HWPF_ADAPTER_SID = HPDCACHE_NUM_PORTS + 1                      # 5
REFILL_FSM_IDLE = 0


# ============================================================================
# Whitelist
# ============================================================================

WHITELIST = [
    # Clock
    "clk_i",

    # CSR-equivalent D-cache access: perf counter l1_dcache_access asserts
    # every cycle ANY of the DCACHE_REQ_PORTS core ports raises data_req
    # (port 0 = load adapter, 1 = MMU/PTW, 2 = store adapter). Ports appended
    # programmatically below.

    # I$ request / response
    "i_frontend.icache_dreq_o.req",
    "i_frontend.icache_dreq_o.vaddr",
    "i_frontend.icache_dreq_o.kill_s1",
    "i_frontend.icache_dreq_o.kill_s2",
    "i_frontend.icache_dreq_i.valid",
    "i_frontend.icache_dreq_i.vaddr",

    # instr_realign output flag: high while combining a 32-bit instruction
    # whose upper half came from the next fetch. Aggregate cross-validation
    # counter against the PC-determinative wraps_line field.
    "i_frontend.i_instr_realign.serving_unaligned_o",

    # Fetch handshake
    "id_stage_i.fetch_entry_valid_i",
    "id_stage_i.fetch_entry_ready_o",
    "id_stage_i.rvfi_is_compressed_o",

    # Per-instruction frontend payload. fetch_entry_if_id is
    # [NrIssuePorts-1:0]. Ports appended programmatically below.

    # Decode handshake
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",

    # Issue handshake
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",

    # Decoded-instruction fields (fu, rs1, rs2, rd, bp.cf, bp.predict_address),
    # decoded_instr_i[NrIssuePorts-1:0], sampled at decode handshake. Per-port
    # entries appended programmatically below.

    # Forwarding capture, probed at issue: which source operands came from
    # the forwarding network vs the regfile, and from which producer slot.
    #   forward_rsX : 1 when the source had a RAW hazard AND the operand was
    #                 available from forwarding (producer result in
    #                 mem_q[tid].sbe or on the writeback bus this cycle).
    #   idx_hzd_rsX : TRANS_ID_BITS scoreboard slot forwarded FROM (only
    #                 meaningful when forward_rsX=1), appended below.
    "issue_stage_i.i_issue_read_operands.forward_rs1",
    "issue_stage_i.i_issue_read_operands.forward_rs2",
    "issue_stage_i.i_issue_read_operands.forward_rs3",

    # Writeback. Wt_valid_i is a packed NR_WB_PORTS-bit bus. Per-port
    # trans_id_i slices are appended programmatically below.
    "issue_stage_i.i_scoreboard.wt_valid_i",

    # Branch prediction (bp.cf, bp.predict_address): primary path reads
    # mem_q[trans_id].sbe.bp.* at writeback (same data commit uses, no timing
    # ambiguity). The fallback is the pre-edge decoded_instr_i[0].bp.* snapshot
    # for when mem_q isn't in the VCD or for flushed records.

    # Branch resolution from the EX branch_unit. bp_resolve_t carries pc,
    # target_address, is_taken, is_mispredict and cf_type, with valid=1 for one
    # cycle at the branch's ex_cycle. Captured at the scoreboard's input.
    "issue_stage_i.i_scoreboard.resolved_branch_i.valid",
    "issue_stage_i.i_scoreboard.resolved_branch_i.pc",
    "issue_stage_i.i_scoreboard.resolved_branch_i.target_address",
    "issue_stage_i.i_scoreboard.resolved_branch_i.is_taken",
    "issue_stage_i.i_scoreboard.resolved_branch_i.is_mispredict",
    "issue_stage_i.i_scoreboard.resolved_branch_i.cf_type",

    # Commit. commit_ack_o is a packed NR_COMMIT_PORTS-bit bus. The
    # per-port commit_pointer_q slices are appended programmatically below.
    "commit_stage_i.commit_ack_o",

    # Flush
    "flush_ctrl_if",
    "flush_ctrl_id",
    "flush_ctrl_ex",
    "flush_ctrl_bp",
    # flush_unissued_instr_i gates the scoreboard's actual mem_n write
    # at the decode handshake
    "issue_stage_i.i_scoreboard.flush_unissued_instr_i",

    # I$ controller FSM state register. Used to distinguish
    # hits (state_q == READ at fe2) from genuine line misses
    # (state_q == MISS at fe2).
    "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.state_q",

    # RTL-counter match: I$ miss pulse. cva6_icache asserts miss_o for
    # one cycle when mem_data_ack_i accepts a cacheable ifill request.
    "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.miss_o",

    # LSU pipeline FSM state registers. Sampled per rising
    # edge in parallel with the existing dispatch steps. Transitions
    # are attributed to the currently-pending record (set by the
    # scoreboard issue handshake when fu is LOAD or STORE).
    "ex_stage_i.lsu_i.i_load_unit.state_q",
    "ex_stage_i.lsu_i.i_store_unit.state_q",

    # lsu_ctrl is the combinational wire feeding both FSMs.
    # Its trans_id at the cycle BEFORE an FSM IDLE→non-IDLE
    # transition is the admitted record.
    "ex_stage_i.lsu_i.lsu_ctrl.trans_id",

    # pop_ld / pop_st are asserted by load_unit and
    # store_unit respectively whenever they consume a request from
    # lsu_bypass. Pop_ld=1 while load FSM is in SEND_TAG is an
    # admit-while-busy event.
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i",
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i",

    # HPDcache miss/refill event signals. The `gen_cache_hpd.` generate-block
    # prefix is mandatory: cva6.sv has 3 cache subsystem variants under
    # different gen_cache_* blocks for different DCacheType values.
    #
    # mshr_alloc_* is sampled when mshr_alloc_i pulses (primary miss → fresh
    # MSHR entry). mshr_alloc_sid_i is the ONLY way to tell a load-adapter miss
    # from a store/prefetch miss. Without it, allocations would be
    # misattributed to whichever LSU FSM is currently non-IDLE.
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
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.mshr_check_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.mshr_check_nline_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.mshr_check_hit_o",

    # refill_fsm_q (any non-zero value = active refill) lets us flag
    # loads that overlap a refill cycle even when not directly
    # involved in alloc/coalesce.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.refill_fsm_q",

    # refill_core_rsp_valid_o pulses when refill data is delivered
    # back to the requesting core port.
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.refill_core_rsp_valid_o",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.refill_core_rsp_o.tid",

    # dirty victim WRITEBACK path. This config is WRITE-BACK
    # (wtEn=0, wbEn=1): the write buffer is configured out (gen_no_wbuf),
    # so stores retire to the cache (dirty) and a line reaches memory only
    # on eviction, via the flush/wback unit (gen_flush.flush_i). We trace
    # that lifecycle at the i_hpdcache level:
    #   ALLOC  flush_alloc && flush_alloc_ready (nline = flush_alloc_nline)
    #          miss handler hands a dirty victim to the flush unit
    #   SEND   mem_req_write_flush_valid && _ready (id/addr in the struct)
    #          writeback request issued to memory
    #   ACK    mem_resp_write_flush_valid && _ready (id. Flush_ack_nline)
    #          memory acknowledges
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

    # tie each writeback to the eviction that caused it.
    # The controller (st2) drives the dirty-victim flush_alloc together with
    # the miss allocation (same cycle, validated delta=0). The join key is
    # (set, victim_way): the incoming line X (mshr_alloc_nline_i) and the
    # evicted victim Y (flush_alloc_nline) share the cache set, and the
    # victim way matches (one-hot on both sides).
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.mshr_alloc_wback_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    "hpdcache_miss_handler_i.mshr_alloc_victim_way_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.flush_alloc_way",
]

# ------------------------------------------------------------------ #
# Loop-generated per-port / per-entry signal paths.                  #
# ------------------------------------------------------------------ #

# ex_stage dcache request ports (architectural, NOT scoreboard-derived)
for _p in range(DCACHE_REQ_PORTS):
    WHITELIST.append(f"ex_stage_i.dcache_req_ports_o[{_p}].data_req")

# fetch_entry_if_id (per NrIssuePorts)
for _p in range(NR_ISSUE_PORTS):
    WHITELIST += [
        f"fetch_entry_if_id[{_p}].address",
        f"fetch_entry_if_id[{_p}].instruction",
    ]

# decoded_instr_i (per NrIssuePorts × {fu, rs1, rs2, rd, bp.cf, bp.predict_address})
for _p in range(NR_ISSUE_PORTS):
    WHITELIST += [
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].fu",
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].rs1",
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].rs2",
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].rd",
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].bp.cf",
        f"issue_stage_i.i_scoreboard.decoded_instr_i[{_p}].bp.predict_address",
    ]

# idx_hzd_rs{1,2,3} (per NrIssuePorts)
for _p in range(NR_ISSUE_PORTS):
    for _rs in (1, 2, 3):
        WHITELIST.append(
            f"issue_stage_i.i_issue_read_operands.idx_hzd_rs{_rs}[{_p}]")

# trans_id_i (per NrWbPorts)
for _p in range(NR_WB_PORTS):
    WHITELIST.append(f"issue_stage_i.i_scoreboard.trans_id_i[{_p}]")

# mem_q (per NrScoreboardEntries × {fu, rs1, rs2, rd, bp.cf, bp.predict_address})
# bp.cf and bp.predict_address let the writeback fixup read the AUTHORITATIVE
# predictor verdict from the scoreboard's registered slot, avoiding the
# pre-edge decoded_instr_i.bp.cf misattribution for back-to-back issues.
for _i in range(NR_SB_ENTRIES):
    for _f in ("fu", "rs1", "rs2", "rd", "bp.cf", "bp.predict_address"):
        WHITELIST.append(
            f"issue_stage_i.i_scoreboard.mem_q[{_i}].sbe.{_f}")

# commit_pointer_q (per NrCommitPorts)
for _p in range(NR_COMMIT_PORTS):
    WHITELIST.append(f"issue_stage_i.i_scoreboard.commit_pointer_q[{_p}]")

del _p, _rs, _i, _f  # keep module namespace clean

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

PHASE4A_POPULATES = PHASE3_POPULATES | {
    "fu", "fu_category", "rs1", "rs2", "rd"}


# ============================================================================
# Functional-unit metadata (from ariane_pkg.sv fu_t enum)
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
# is_rd_fpr/is_rs2_fpr flag, not just fu. Deferred to a later increment.
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
    # I$ pipeline cycles per contributing fetch. if1/if2 = request-accept and
    # data-delivery cycles. _lo is the first (lower-address) fetch, the only
    # one for aligned instrs. _hi is the second fetch, populated only when
    # wraps_line. Timing: hit if2=if1+1, cacheable miss if2=if1+~5, NC bypass
    # if2=if1+4. RVC pairs in one 4-byte word share if1_lo/if2_lo.
    if1_lo: int = None
    if2_lo: int = None
    if1_hi: int = None
    if2_hi: int = None
    # True iff this instruction straddles a fetch-block boundary (realigner
    # must combine two fetches): (pc & FETCH_OFFSET_MASK) == FETCH_BYTES-2 AND
    # not compressed. Captured on every record (committed AND flushed) because
    # realigner bookkeeping runs regardless of whether the instr commits.
    wraps_line: bool = False
    # True if the I$ went to memory for this PC's line (state_q==MISS at if2).
    # False for hits (including "stuck hits" queued behind a prior miss).
    ic_miss: bool = None
    # Hi-side miss, only meaningful when wraps_line. Same source (state_q==MISS
    # at the hi fetch's fe2). None when there is no hi fetch.
    ic_miss_hi: bool = None
    fe_cycle: int = None
    id_cycle: int = None
    is_cycle: int = None
    ex_cycle: int = None
    wb_cycle: int = None
    co_cycle: int = None
    flushed: bool = False
    flush_reason: str = None
    # LSU FSM state history: transitions of load_unit/store_unit.state_q while
    # the FSM was processing this record's trans_id. Each entry {cycle, state}.
    # Transitions only: IDLE→non-IDLE opens the trace, non-IDLE→IDLE closes it
    # (closing IDLE not appended, since lsu_complete_cycle records it instead).
    lsu_state_history: list = None
    # Cycle the LSU FSM first left IDLE for this record (admission cycle).
    # Usually is_cycle+1 but later under stalls / TLB-miss inserts.
    lsu_admit_cycle: int = None
    # Cycle the FSM returned to IDLE (admission phase done). For loads the data
    # response arrives later via ldbuf. This only marks the FSM's release.
    lsu_complete_cycle: int = None

    # D$ event correlation for LOAD/STORE, populated by
    # attribute_dc_events_to_records() from events in [admit, complete]:
    #   dc_primary_miss   : mshr_alloc with sid==LOAD_UNIT_SID AND matching tid
    #                       (rare: stores usually allocate and loads coalesce)
    #   dc_coalesced      : mshr_check_hit fired in the window (approximate,
    #                       no per-check sid, but a strong signal for loads
    #                       that piggybacked on a store's miss)
    #   dc_refill_overlap : refill_fsm_q non-IDLE in the window (load delayed
    #                       by a concurrent refill consuming the cache port)
    #   dc_events         : raw chronological list, each {cycle, type} where
    #                       type is alloc(sid,tid,pf,nline) | check_*(nline) |
    #                       refill_rsp(tid)
    dc_primary_miss: bool = False
    dc_coalesced: bool = False
    dc_refill_overlap: bool = False
    dc_events: list = None

    # Branch prediction & resolution, for fu==CTRL_FLOW records.
    # PREDICTION (captured at issue from mem_q[trans_id].sbe.bp):
    #   bp_predicted_cf      : NoCF/Branch/Jump/JumpR/Return (also the
    #                          predictor source, see CF_T_NAMES)
    #   bp_predicted_target  : VLEN-bit target as int, None for NoCF
    # RESOLUTION (captured from resolved_branch_i, valid=1 one cycle at ex):
    #   bp_resolved_cf       : resolved cf type (may differ from predicted
    #                          if BTB/RAS missed, branch_unit.sv:64-107)
    #   bp_resolved_target   : actual computed target
    #   bp_resolved_taken    : actual outcome (False = not-taken/sequential)
    #   bp_mispredict        : is_mispredict, covering both direction and
    #                          target mispredicts
    #   bp_resolution_cycle  : cycle valid=1 fired (== ex_cycle when clean)
    bp_predicted_cf: str = None
    bp_predicted_target: int = None
    bp_resolved_cf: str = None
    bp_resolved_target: int = None
    bp_resolved_taken: bool = None
    bp_mispredict: bool = None
    bp_resolution_cycle: int = None

    # Operand forwarding capture, snapshotted pre-edge at issue (signals are
    # combinational, live one cycle at the issue rising edge).
    #   fwd_rsX_used     : issue took the operand from forwarding vs regfile
    #                      (from forward_rsX). Only fires on a successful
    #                      handshake, so used=False means regfile read.
    #   fwd_rsX_from_tid : producer scoreboard slot (idx_hzd_rsX[0]), only
    #                      meaningful when used.
    #   fwd_rsX_via      : "sb" = producer wrote back earlier, scoreboard holds
    #                      it (mem_q[from_tid].sbe.result). "wb" = bypassed
    #                      this same cycle off a writeback port (tightest,
    #                      ALU-to-ALU back-to-back). Only meaningful when used.
    # rs3 is for FMA-class 3-source FPU ops, otherwise fwd_rs3_* stay default.
    fwd_rs1_used: bool = False
    fwd_rs1_from_tid: int = None
    fwd_rs1_via: str = None
    fwd_rs2_used: bool = False
    fwd_rs2_from_tid: int = None
    fwd_rs2_via: str = None
    fwd_rs3_used: bool = False
    fwd_rs3_from_tid: int = None
    fwd_rs3_via: str = None

    # Branch / flush bubble attribution, set by tag_branch_bubbles() post-walk.
    # A non-flushed record R followed by ≥1 flushed then non-flushed R' makes R
    # the CAUSER and R' the RECOVERY.
    # ON THE CAUSER:
    #   bubble_kind            : 'mispred' (bp_mispredict & cf!=NoCF) /
    #                            'unpred' (bp_mispredict & cf==NoCF, BTB miss) /
    #                            'flush_other' (CSR flush, FENCE*/AMO commit,
    #                            exception entry)
    #   bubble_caused_cycles   : count of flushed records between causer and
    #                            recovery (= wrong-path fetch bandwidth wasted)
    #   bubble_recovery_id     : id of the recovery record
    # ON THE RECOVERY:
    #   bubble_from_branch_id  : id of the causer
    #   bubble_cycles          : duplicate of causer's bubble_caused_cycles so
    #                            either end is queryable without a join
    # A record is causer of at most one bubble and recovery of at most one.
    bubble_kind: str = None
    bubble_caused_cycles: int = None
    bubble_recovery_id: int = None
    bubble_from_branch_id: int = None
    bubble_cycles: int = None


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
            (a fresh access after an IDLE/KILL_*/FLUSH dwell. Most
            commonly a branch-misprediction recovery re-fetch).

      fe1_cycle = (cycle the new access started) - 1
      fe2_cycle = cycle dreq_o.valid==1 and kill_s2==0
      ic_miss   = (state_q == MISS at fe2)

    The two-path detection is necessary: without (b), a re-fetch where
    the frontend reissues the SAME address after a transient idle
    would inherit the ORIGINAL transition cycle for fe1, inflating lat
    from 1 to (idle_dwell + 1).
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
                vaddr_word=vaddr_o & ~FETCH_OFFSET_MASK,
                ic_miss=ic_miss,
            ))


def match_records_to_events(records, events):
    """Bind I$ pipeline timing onto each record.

    Every record: bind if1_lo/if2_lo/ic_miss for the FIRST fetch via the I$
    event whose vaddr_word == (pc & ~FETCH_OFFSET_MASK) with maximum
    fe2_cycle <= rec.fe_cycle. RVC pair sharing falls out naturally (both
    halves have close fe_cycles → same event), while loop iterations have
    well-separated fe_cycles → their own event.

    wraps_line records also bind if1_hi/if2_hi for the SECOND fetch at
    ((pc+2) & ~FETCH_OFFSET_MASK) with the same fe2_cycle ordering rule
    (the upper-half word starts at pc+2 == next block's base).

    Records with no matching event (killed accesses, fui drops) keep None.
    Returns (n_matched, n_unmatched, n_wraps_with_hi, n_rebound, n_synth)."""

    by_word = defaultdict(list)
    for ev in events:
        by_word[ev.vaddr_word].append(ev)
    # Parallel sorted fe2_cycle keys per word so lookups can bisect the event
    # window. A hot loop accumulates one event per iteration per word, so a
    # linear scan is quadratic and could hang on a large trace.
    by_word_fe2 = {}
    for word in by_word:
        by_word[word].sort(key=lambda e: e.fe2_cycle)
        by_word_fe2[word] = [e.fe2_cycle for e in by_word[word]]

    def find_best(word, fe_cycle):
        candidates = by_word.get(word, [])
        if not candidates:
            return None
        idx = bisect.bisect_right(by_word_fe2[word], fe_cycle) - 1
        if idx < 0:
            return None
        return candidates[idx]

    n_matched = 0
    n_unmatched = 0
    n_wraps_with_hi = 0

    for rec in records:
        if rec.pc is None or rec.fe_cycle is None:
            n_unmatched += 1
            continue
        try:
            pc_int = int(rec.pc, 16)
        except (TypeError, ValueError):
            n_unmatched += 1
            continue
        # First fetch: word containing the LOWER half of the instr.
        lo_word = pc_int & ~FETCH_OFFSET_MASK
        best_lo = find_best(lo_word, rec.fe_cycle)
        if best_lo is not None:
            rec.if1_lo = best_lo.fe1_cycle
            rec.if2_lo = best_lo.fe2_cycle
            rec.ic_miss = best_lo.ic_miss
            n_matched += 1
        else:
            n_unmatched += 1
            # Flushed-record fallback: wrong-path fetches killed before the
            # icache delivers emit no ICacheEvent, but the record has fe_cycle
            # (FE saw the kill). Synthesize if1/if2 two cycles before fe_cycle
            # so the timeline draws them instead of an orphan fe_out cell.
            if rec.flushed and rec.fe_cycle is not None:
                rec.if2_lo = max(0, rec.fe_cycle - 1)
                rec.if1_lo = max(0, rec.fe_cycle - 2)
                rec.ic_miss = False
        # Second fetch (wraps_line only): upper half lives at pc+2. Extra
        # constraint fe1_cycle >= rec.if1_lo prevents find_best from picking a
        # STALE event from a prior iteration's prefetch (CVA6's frontend is
        # non-blocking on the hi side and can deliver it ahead of the next
        # iteration's lo word, yielding an if1_hi earlier than this if1_lo).
        if rec.wraps_line:
            hi_word = (pc_int + 2) & ~FETCH_OFFSET_MASK
            hi_candidates = by_word.get(hi_word, [])
            best_hi = None
            lo_floor = rec.if1_lo if rec.if1_lo is not None else 0
            hi_fe2 = by_word_fe2.get(hi_word, [])
            hi_top = bisect.bisect_right(hi_fe2, rec.fe_cycle)
            hi_start = bisect.bisect_left(hi_fe2, lo_floor)
            for i in range(hi_top - 1, hi_start - 1, -1):
                ev = hi_candidates[i]
                if ev.fe1_cycle >= lo_floor:
                    best_hi = ev
                    break
            if best_hi is not None:
                rec.if1_hi = best_hi.fe1_cycle
                rec.if2_hi = best_hi.fe2_cycle
                # Authoritative hi-miss from the icache FSM (state_q==MISS at
                # the fe2 cycle), replacing an if2_hi-if1_hi>1 heuristic that
                # over-counted on cache-port-busy stalls.
                rec.ic_miss_hi = best_hi.ic_miss
                n_wraps_with_hi += 1

    # Post-process: enforce fetch monotonicity in commit order. find_best
    # picks the latest event with fe2 <= fe_cycle, but in a loop where the
    # line stays cached (no fresh event) an iteration-N record can bind to
    # iteration N-1's delivery. Two strategies in order:
    #   1. Rebind to a LATER event for the same word with fe1 >= prev_if1.
    #   2. If none exists, SYNTHESIZE fetch cycles (assume cached hit consumed
    #      from IQ just before fe_cycle) so rendering respects program order.
    prev_if1 = -1
    prev_rec_with_if1 = None
    n_rebound = 0
    n_synth = 0
    for rec in records:
        if rec.if1_lo is None:
            continue
        if rec.if1_lo >= prev_if1:
            prev_if1 = rec.if1_lo
            prev_rec_with_if1 = rec
            continue
        # Violation. First try rebind.
        if rec.pc is None or rec.fe_cycle is None:
            prev_if1 = max(prev_if1, rec.if1_lo)
            continue
        try:
            pc_int = int(rec.pc, 16)
        except (TypeError, ValueError):
            prev_if1 = max(prev_if1, rec.if1_lo)
            continue
        lo_word = pc_int & ~FETCH_OFFSET_MASK
        candidates = by_word.get(lo_word, [])
        new_ev = None
        lo_fe2 = by_word_fe2.get(lo_word, [])
        lo_start = bisect.bisect_left(lo_fe2, prev_if1)
        lo_top = bisect.bisect_right(lo_fe2, rec.fe_cycle)
        for i in range(lo_start, lo_top):
            ev = candidates[i]
            if ev.fe1_cycle >= prev_if1:
                new_ev = ev
                break
        if new_ev is not None:
            rec.if1_lo = new_ev.fe1_cycle
            rec.if2_lo = new_ev.fe2_cycle
            rec.ic_miss = new_ev.ic_miss
            n_rebound += 1
            # Re-evaluate hi side too if this is a wraps_line record.
            if rec.wraps_line:
                hi_word = (pc_int + 2) & ~FETCH_OFFSET_MASK
                hi_candidates = by_word.get(hi_word, [])
                new_hi = None
                hi_fe2b = by_word_fe2.get(hi_word, [])
                hi_start2 = bisect.bisect_left(hi_fe2b, new_ev.fe1_cycle)
                hi_top2 = bisect.bisect_right(hi_fe2b, rec.fe_cycle)
                for i in range(hi_start2, hi_top2):
                    ev = hi_candidates[i]
                    if ev.fe1_cycle >= new_ev.fe1_cycle:
                        new_hi = ev
                        break
                if new_hi is not None:
                    rec.if1_hi = new_hi.fe1_cycle
                    rec.if2_hi = new_hi.fe2_cycle
                    rec.ic_miss_hi = new_hi.ic_miss
        else:
            # No later event: the line is still resident and the icache never
            # re-pulsed. Synthesize using sequential FE timing relative to the
            # previous record's if1 (the FE issues one IF1/cycle in steady
            # state, and one fetch word can serve multiple records):
            #   - lo-word == prev's lo-word -> shared lo fetch (RVC pair)
            #   - lo-word == prev's hi-word -> shared with prev's hi fetch
            #   - otherwise -> new fetch one cycle after prev's last fetch
            # fe_cycle is the upper ceiling (pipeline depth must fit before it).
            # Anchoring at fe_cycle-depth (the OLD fallback, used only without
            # prev context) is wrong when a later record stalls in ID/IS: it
            # invents a fictitious FE gap for an instr that actually fetched on
            # schedule and just waited in instr_queue.
            depth = 3 if rec.wraps_line else 2
            seq_if1 = None
            if (prev_rec_with_if1 is not None
                    and prev_rec_with_if1.pc is not None
                    and prev_rec_with_if1.if1_lo is not None):
                try:
                    prev_pc_int = int(prev_rec_with_if1.pc, 16)
                    prev_lo_word = prev_pc_int & ~FETCH_OFFSET_MASK
                    prev_hi_word = (prev_lo_word + FETCH_BYTES
                                    if prev_rec_with_if1.wraps_line
                                    else None)
                    if prev_lo_word == lo_word:
                        seq_if1 = prev_rec_with_if1.if1_lo
                    elif (prev_hi_word == lo_word
                          and prev_rec_with_if1.if1_hi is not None):
                        seq_if1 = prev_rec_with_if1.if1_hi
                    else:
                        last_prev_fetch = (prev_rec_with_if1.if1_hi
                                           if prev_rec_with_if1.wraps_line
                                           and prev_rec_with_if1.if1_hi
                                           is not None
                                           else prev_rec_with_if1.if1_lo)
                        seq_if1 = last_prev_fetch + 1
                except (TypeError, ValueError):
                    seq_if1 = None
            if seq_if1 is None:
                # No usable prev context -> fall back to fe_cycle anchor.
                seq_if1 = max(prev_if1, rec.fe_cycle - depth)
            synth_if1 = max(seq_if1, prev_if1)
            # Ceiling: synth must leave enough room before fe_cycle
            # for the FE pipeline depth.
            if rec.fe_cycle is not None:
                ceiling = rec.fe_cycle - depth
                if synth_if1 > ceiling:
                    synth_if1 = max(prev_if1, ceiling)
            if rec.wraps_line:
                rec.if1_lo = synth_if1
                rec.if2_lo = synth_if1 + 1
                rec.if1_hi = rec.if2_lo  # shares cycle (pipelined)
                rec.if2_hi = rec.if1_hi + 1
                rec.ic_miss = False
                rec.ic_miss_hi = False
            else:
                rec.if1_lo = synth_if1
                rec.if2_lo = synth_if1 + 1
                rec.ic_miss = False
            n_synth += 1
        prev_if1 = rec.if1_lo
        prev_rec_with_if1 = rec

    # RVC-pair sharing: two compressed instrs in the same 32-bit fetch word
    # come from one icache transaction, so they must share if1_lo/if2_lo/
    # ic_miss (and hi-side when wraps_line). The main loop processes records
    # independently and can bind the two halves to different events on a
    # re-fetch. This pass forces the second to inherit the first's binding.
    n_rvc_paired = 0
    for i in range(1, len(records)):
        prev = records[i - 1]
        curr = records[i]
        if prev.pc is None or curr.pc is None:
            continue
        if not (prev.is_compressed and curr.is_compressed):
            continue
        try:
            prev_pc = int(prev.pc, 16)
            curr_pc = int(curr.pc, 16)
        except (TypeError, ValueError):
            continue
        # Same fetch block AND consecutive 2-byte slots. FETCH_BYTES=4 (this
        # config) has max 2 RVCs/fetch, while FETCH_BYTES=8 chains the
        # propagation across up to 4 consecutive compressed records in the
        # block.
        if (prev_pc & ~FETCH_OFFSET_MASK) != (curr_pc & ~FETCH_OFFSET_MASK):
            continue
        if curr_pc != prev_pc + 2:
            continue
        if prev.if1_lo is None:
            continue
        if curr.if1_lo == prev.if1_lo:
            continue  # already aligned (the common case after main loop)
        curr.if1_lo = prev.if1_lo
        curr.if2_lo = prev.if2_lo
        curr.ic_miss = prev.ic_miss
        # Hi side too if both records are wraps_line. (Unusual for a
        # compressed pair to wrap, but defensive.)
        if prev.wraps_line and curr.wraps_line:
            curr.if1_hi = prev.if1_hi
            curr.if2_hi = prev.if2_hi
            curr.ic_miss_hi = prev.ic_miss_hi
        n_rvc_paired += 1

    return n_matched, n_unmatched, n_wraps_with_hi, n_rebound, n_synth


def tag_branch_bubbles(records):
    """Attribute each pipeline bubble to its causer + recovery instruction.

    Walk records in id order and find [non-flushed][≥1 flushed][non-flushed].
    The first non-flushed is the causer, the second the recovery, the flushed
    run in between is wasted wrong-path fetch bandwidth. completed[] is sorted
    by id first: the live stream can interleave commit and flush events that
    finalize the same cycle, so id order is not guaranteed.

    Classification (causer only):
      - mispred     : bp_mispredict=True AND bp_predicted_cf != 'NoCF'
      - unpred      : bp_mispredict=True AND bp_predicted_cf == 'NoCF'
                      (BTB miss / not-predicted-taken branch)
      - flush_other : else, with a flushed run (CSR side-effect, FENCE*/
                      SFENCE/HFENCE/AMO commit, exception entry)
    flush_other is captured ONLY for a non-trivial bubble. Silent CSRs that
    commit cleanly are not tagged.

    Returns (counts, diag). diag cross-validates against Phase 7a:
    bp_mispredict_total, and of those _flushed (can't be causers),
    _no_followers (instant recovery), _end_of_trace (no recovery, truncated).
    """
    counts = {"mispred": 0, "unpred": 0, "flush_other": 0, "pred_taken": 0}
    diag = {
        "bp_mispredict_total":         0,
        "bp_mispredict_flushed":       0,
        "bp_mispredict_no_followers":  0,
        "bp_mispredict_end_of_trace":  0,
    }
    if len(records) < 2:
        return counts, diag

    # Defensive sort by id (flushed records append at flush time, which can
    # fire the same cycle as a commit, so completed[] is only mostly ordered).
    ordered = sorted(records, key=lambda r: r.id if r.id is not None else -1)
    n = len(ordered)

    # First pass diagnostic: count total bp_mispredict=True records
    # and how many are flushed. This is a sanity check against Phase
    # 7a's resolved-branch mispredict count.
    for r in ordered:
        if r.bp_mispredict is True:
            diag["bp_mispredict_total"] += 1
            if r.flushed:
                diag["bp_mispredict_flushed"] += 1

    i = 0
    while i < n:
        # Advance to the next non-flushed record. Records at the very
        # start of the trace that are flushed (warmup-era kills) have
        # no causer. We skip them silently.
        while i < n and ordered[i].flushed:
            i += 1
        if i >= n:
            break
        causer = ordered[i]
        # Look ahead: count consecutive flushed records after the
        # causer, then find the next non-flushed (the recovery).
        j = i + 1
        while j < n and ordered[j].flushed:
            j += 1
        if j == i + 1:
            # The very next record is also non-flushed → no bubble.
            # If this causer was a mispredicting branch, note it as
            # "instant recovery". No wrong-path fetches happened.
            if causer.bp_mispredict is True:
                diag["bp_mispredict_no_followers"] += 1
            i = j
            continue
        if j >= n:
            # Bubble exists but the trace ended before a recovery
            # record materialized. We don't tag this one (no recovery
            # id to point at).
            if causer.bp_mispredict is True:
                diag["bp_mispredict_end_of_trace"] += 1
            break
        recovery = ordered[j]
        bubble_size = j - i - 1  # count of flushed records between

        # Classify by causer branch state (see docstring). NoCF/None = the
        # predictor missed this PC (branch_unit.sv stays silent on JAL, which
        # bypasses resolution, so NoCF regardless of the mispredict bit).
        pcf = causer.bp_predicted_cf
        if causer.fu == "CTRL_FLOW" and (pcf is None or pcf == "NoCF"):
            kind = "unpred"
        elif causer.bp_mispredict is True:
            kind = "mispred"
        else:
            kind = "flush_other"
            # Refinement A (dual-commit CSR partner). A CSR flush takes effect
            # one cycle after commit. An unrelated op dual-committed the same
            # cycle can look like the "last non-flushed before the bubble" when
            # the CSR is the real cause. If the prior record committed the same
            # cycle and is fu='CSR', prefer it as the causer.
            if i > 0:
                prev = ordered[i - 1]
                if (not prev.flushed
                        and prev.co_cycle is not None
                        and causer.co_cycle is not None
                        and prev.co_cycle == causer.co_cycle
                        and prev.fu == "CSR"):
                    causer = prev
            # Refinement B (self-flushed CSR). A CSR triggering flush_csr_i
            # also asserts flush_ex_o, which re-flushes the CSR itself
            # (flushed=True, wb_cycle set, co_cycle=None). It is the real
            # cause, not the innocent non-flushed predecessor. Signature:
            # fu='CSR' AND wb_cycle set AND flushed, inside the flushed run.
            # Take the first such and shrink bubble_size by 1 (the CSR did
            # real work, not wasted bandwidth).
            if causer.fu != "CSR":
                for k in range(i + 1, j):
                    cand = ordered[k]
                    if (cand.fu == "CSR"
                            and cand.wb_cycle is not None
                            and cand.flushed):
                        causer = cand
                        bubble_size = (j - i - 1) - 1
                        break

        causer.bubble_kind = kind
        causer.bubble_caused_cycles = bubble_size
        causer.bubble_recovery_id = recovery.id
        recovery.bubble_from_branch_id = causer.id
        recovery.bubble_cycles = bubble_size
        counts[kind] += 1

        # The recovery may itself be the next bubble's causer, so leave i = j.
        i = j

    # Second pass: taken-branch fetch bubbles with NO flushed run. Three cases
    # survive the flush-based pass, all costing FE1 redirect cycles:
    #   pred_taken: predictor right. A correctly-predicted taken branch still
    #               has a 1-2 cycle FE1 gap (BHT/BTB see the decoded branch at
    #               FE2 and the redirect takes 1-2 cycles). Always no-flush.
    #   mispred:    predictor wrong, but the wrong-path fetch slots were empty
    #               at resolution (CVA6's instant-recovery path) so nothing
    #               was flushed.
    #   unpred:     predictor silent (default not-taken), with the same
    #               instant-recovery story when the EX redirect lands with no
    #               wrong-path fetches to kill.
    # Scan forward to the next non-flushed record with if1_lo. A FE1 more than
    # 1 cycle after the causer's is a bubble. The flush-based pass takes
    # precedence (skip already-tagged causers and already-claimed recoveries).
    for i in range(n):
        causer = ordered[i]
        if causer.flushed:
            continue
        if causer.if1_lo is None:
            continue
        if causer.bubble_kind is not None:
            continue  # already tagged by flush-based pass

        # Guard on fu=='CTRL_FLOW': the RVFI predict bus does not self-clear
        # between instructions, so a load/ALU op just downstream of a taken
        # jump can carry stale bp_resolved_taken/bp_predicted_cf and steal
        # attribution of the next FE gap from the actual branch.
        if causer.fu != "CTRL_FLOW":
            continue

        # bp_resolved_taken is authoritative, and jumps and returns are always
        # taken, so predicted_cf alone suffices if resolved_taken was dropped.
        is_taken = (causer.bp_resolved_taken is True
                    or causer.bp_predicted_cf in ("Jump", "Return"))
        if not is_taken:
            continue

        # Measure delta from the causer's LAST fetch cycle, not its IF1: the FE
        # redirect can only happen once the instruction is fully delivered.
        # Otherwise the causer's own icache stall (which lives in IF1..IF2)
        # gets absorbed into the bubble, e.g. a predicted-taken branch behind a
        # cold-line miss would show an N-cycle bubble for a 0-cycle redirect.
        causer_fetch_end = (causer.if2_hi
                            if (causer.wraps_line
                                and causer.if2_hi is not None)
                            else causer.if2_lo)
        if causer_fetch_end is None:
            continue

        for j in range(i + 1, n):
            nxt = ordered[j]
            if nxt.flushed:
                continue
            if nxt.if1_lo is None:
                continue
            if nxt.bubble_from_branch_id is not None:
                break  # next is already a recovery for another bubble
            delta = nxt.if1_lo - causer_fetch_end
            if delta > 1:
                bubble_size = delta - 1
                # Same scheme as the flush-based pass. NoCF/None -> "unpred"
                # regardless of the mispredict bit (it stays False for
                # JAL-style direct jumps that bypass branch_unit resolution).
                pcf = causer.bp_predicted_cf
                if pcf is None or pcf == "NoCF":
                    kind = "unpred"
                elif causer.bp_mispredict is True:
                    kind = "mispred"
                else:
                    kind = "pred_taken"
                    # Cap at the architectural FE-redirect latency: CVA6's
                    # static decoder fires at FE2, so the target fetch issues
                    # one cycle later. Any excess is IQ backpressure, not the
                    # predictor's fault. Mispred/unpred are deliberately NOT
                    # capped: EX must resolve before the FE can redirect, so
                    # those waits really are caused by the branch.
                    bubble_size = min(bubble_size, 1)
                causer.bubble_kind = kind
                causer.bubble_caused_cycles = bubble_size
                causer.bubble_recovery_id = nxt.id
                nxt.bubble_from_branch_id = causer.id
                nxt.bubble_cycles = bubble_size
                counts[kind] += 1
            break

    return counts, diag


# ============================================================================
# Pipeline tracker
# ============================================================================

class PipelineTracker:
    """Maintains queues of in-flight instances and applies handshake/flush
    events. Order discipline: each queue is strict FIFO (in-order pipeline)."""

    def __init__(self, user_entry_pc=None,
                 n_wb_ports=NR_WB_PORTS, n_commit_ports=NR_COMMIT_PORTS):
        self.user_entry_pc = user_entry_pc
        self.n_wb_ports = n_wb_ports
        self.n_commit_ports = n_commit_ports

        self.warmup_end_cycle = None

        self.fetched = deque()        # has fe_cycle, awaiting decode
        self.decoded = deque()        # has id_cycle, awaiting issue
        self.issued = {}              # trans_id -> record, awaiting wb/commit
        self.completed = []           # terminal list

        self.next_id = 0
        self.n_committed = 0
        self.n_flushed_if = 0
        self.n_flushed_id = 0
        self.n_flushed_ex = 0
        self.n_unmatched_writebacks = 0
        self.n_unmatched_commits = 0

        # Realigner counters. serving_unaligned_o (= registered unaligned_q)
        # goes high while the realigner holds a fetch's upper half. It CHAINS:
        # a fetch that completes one unaligned and begins another keeps it at 1
        # with no 0→1 edge, so NEITHER counter equals the wraps_line count.
        #   - starts (0→1 edges): distinct unaligned RUNS. A run yields 0
        #     records (killed by kill_s2) or N (chained dispatches).
        #   - cycles (cycles high): realigner stall time, inflated by icache
        #     gaps/misses between the contributing fetches. Not an instr count.
        # wraps_line correctness is instead verified by the lo→hi binding
        # success rate in match_records_to_events.
        self.n_realigner_unaligned_starts = 0
        self.n_realigner_unaligned_cycles = 0

        # Forwarding diagnostics. The per-source counters fire ONLY on a real
        # forward whose producer slot is on the wb bus that cycle. All zero =>
        # via=wb is impossible at this signal boundary. Nonzero while the final
        # via=wb stat is 0 => the via writer in on_decode_issue has a bug.
        self._diag_n_issue_cycles = 0
        self._diag_n_issue_with_any_wb = 0
        self._diag_n_real_match_rs1 = 0
        self._diag_n_real_match_rs2 = 0
        self._diag_n_real_match_rs3 = 0

        # I$ event timeline. match_records_to_events binds if1/if2/ic_miss onto
        # each record by 4-byte-aligned PC after the walk.
        self.icache_timeline = ICacheTimeline()

        # LSU FSM correlation via lsu_ctrl.trans_id (see on_lsu_fsm_sample).
        # pop_ld=1 in SEND_TAG / pop_st=1 in VALID_STORE mean a NEW access is
        # admitted while the FSM still processes the previous one, with no
        # state_q transition to detect it. `pending_admit_*_tid_str` defers
        # such an admission by one cycle to align with the FSM's handoff.
        self.active_lsu_load = None
        self.active_lsu_store = None
        self.prev_load_state_str = None
        self.prev_store_state_str = None
        self.prev_lsu_ctrl_trans_id_str = None
        self.pending_admit_load_tid_str = None
        self.pending_admit_store_tid_str = None

        # D$ event log, filled by on_dcache_sample and bound to records later
        # by attribute_dc_events_to_records via the [admit, complete] window.
        # Events are in cycle order because on_dcache_sample runs once per
        # rising edge in ascending order, and the attribution pass relies on
        # this invariant instead of re-sorting.
        self._dc_events = []
        self._rfsm_active_cycles = set()

        # Phase 7b: dirty victim writeback events (flush/wback unit).
        # Each handshake is logged in cycle order during the scan. Pairing
        # and the AXI-write-latency aggregate are computed in
        # finalize_writebacks() after the walk. Send<->ack pair by flush
        # slot id. Alloc<->ack join by nline.
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
        # Mask to 16 bits when compressed: the frontend's instruction field
        # carries the I$ line's lower 32 bits, which for an RVC pair holds BOTH
        # instructions. The one at this PC lives in the low 16.
        if is_compressed and instr_word is not None:
            try:
                instr_word = f"0x{int(instr_word, 16) & 0xFFFF:04x}"
            except ValueError:
                pass
        wraps = self._compute_wraps_line(pc, is_compressed)
        rec = InstructionRecord(
            id=self.next_id,
            pc=pc,
            instr_word=instr_word,
            is_compressed=is_compressed,
            fe_cycle=cycle,
            wraps_line=wraps,
        )
        self.fetched.append(rec)
        self.next_id += 1

    @staticmethod
    def _compute_wraps_line(pc, is_compressed):
        """True iff this instruction straddles a fetch-block boundary.

        The icache delivers FETCH_BYTES bytes/cycle aligned to FETCH_BYTES
        (cva6_icache.sv:158, 428), so a 32-bit instruction at offset
        FETCH_BYTES-2 has its upper 16 bits in the NEXT block and the
        realigner must combine two fetches (instr_realign.sv realign_bp_32
        sets unaligned_d at offset 2 for FW=32, realign_bp_64 at offset 6 for
        FW=64). Equivalent to serving_unaligned_o asserting at the realigner's
        output cycle.

        The predicate must stay FETCH_BYTES-aware: an earlier hard-coded
        (pc & 7) == 6 covered only FW=64 and silently missed exactly half the
        wraps on FW=32 traces (records/run ratio ~0.5 instead of >=1.0).
        """
        if is_compressed or pc is None:
            return False
        try:
            return (int(pc, 16) & FETCH_OFFSET_MASK) == FETCH_BYTES - 2
        except (TypeError, ValueError):
            return False

    def on_fetch_dropped(self, cycle, pc, instr_word, is_compressed):
        """FE handshake fired on a cycle where flush_unissued_instr_i is high.

        Per id_stage.sv:444, id_stage forces issue_n[0].valid=0 when flush_i is
        high, overriding the valid=1 the FE handshake set at line 433: the
        frontend pops its instr_queue but id_stage discards the entry.

        Correctness-critical: this record must NOT go on `fetched`. Doing so
        leaves a phantom at the head that HW's id_stage never had, and every
        later pop runs +1 ahead of HW's real decode. Record it as flushed
        instead, for visibility into the discarded speculative path."""
        if is_compressed and instr_word is not None:
            try:
                instr_word = f"0x{int(instr_word, 16) & 0xFFFF:04x}"
            except ValueError:
                pass
        wraps = self._compute_wraps_line(pc, is_compressed)
        rec = InstructionRecord(
            id=self.next_id,
            pc=pc,
            instr_word=instr_word,
            is_compressed=is_compressed,
            fe_cycle=cycle,
            flushed=True,
            flush_reason="fetch_dropped_fui",
            wraps_line=wraps,
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
        """Combined decode+issue handler.

        In non-superscalar CVA6 the scoreboard's issue_instr_o is a
        combinational passthrough of decoded_instr_i (scoreboard.sv:151), so
        DV/DA and IV/IA fire as a SINGLE handshake. Tracking them as two events
        reads trans_id from IPTR at the wrong cycle whenever the pipeline
        stalls between fetches, landing +N ahead of the actual HW slot. Pop
        fetched and assign trans_id in one step from the IPTR value at the
        handshake cycle, which is the HW slot being allocated.

        ex_cycle is cycle+1 (CVA6 ALU/FPU pipeline depth invariant).

        bp_cf_val / bp_predict_target come from mem_q[trans_id].sbe.bp, stable
        from the slot's decode write until slot reuse. Issue is chosen as the
        capture point because that's when the record acquires trans_id.

        Forwarding: fwd_rsX_used from forward_rsX, ihz_rsX the producer slot
        from idx_hzd_rsX[0]. wb_view is the same-cycle writeback bus as
        (port, trans_id) tuples for ports with wt_valid_i=1, and a producer
        slot present there means via='wb' (same-cycle bypass), else via='sb'.
        """
        if not self.fetched:
            return
        # Diagnostics. These gate on fwd_rsX_used=True. An earlier coarse
        # version counted stale idx_hzd_rsX values unrelated to real forwards
        # and overstated the match rate. All-zero here means via=wb=0 is the
        # true answer for this build, and nonzero means the via writer has a
        # bug.
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
        if bp_cf_val is not None:
            rec.bp_predicted_cf = CF_T_NAMES.get(
                bp_cf_val, f"UNK_{bp_cf_val}")
            # Leave the target None for NoCF: a prediction-less record would
            # otherwise carry a misleading 0 target.
            if rec.bp_predicted_cf != "NoCF":
                rec.bp_predicted_target = bp_predict_target
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
        # No LSU pending-assignment here: correlation happens via
        # lsu_ctrl.trans_id at FSM-transition time in on_lsu_fsm_sample.

    def on_branch_resolved(self, cycle, pc_str, target_str,
                           is_taken_str, is_mispredict_str, cf_type_str):
        """Handle a branch resolution pulse.

        bp_resolve_t.valid is high for exactly one cycle when branch_unit
        resolves a branch (branch_unit.sv:84), and its pc identifies it.
        Bind by pc among in-flight CTRL_FLOW records, picking the OLDEST
        (lowest is_cycle) on a tie: loops can have several instances of the
        same PC in flight and branch_unit resolves them in issue order.

        Unmatched resolutions are silently dropped (flushes can legitimately
        strand a resolution in the pipeline), not counted as warnings.
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
            # Compare as ints: binary_to_hex drops leading zeros, so the hex
            # strings on either side are not directly comparable.
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

        # Refuse to overwrite a prior resolution on the same record,
        # would only happen if the same record were resolved twice,
        # which CVA6's in-order issue precludes.
        if rec.bp_resolution_cycle is not None:
            return

        rec.bp_resolution_cycle = cycle
        rec.bp_resolved_cf = cf_name(cf_type_str)
        rec.bp_resolved_target = binary_to_int(
            target_str) if target_str else None
        rec.bp_resolved_taken = (is_taken_str == "1")
        rec.bp_mispredict = (is_mispredict_str == "1")

        # Derive the predictor's verdict algebraically from the resolution
        # signals. Neither direct-read path is reliable: the pre-edge
        # decoded_instr_i.bp.cf snapshot misattributes the PREVIOUS
        # instruction's bp.cf for back-to-back issues (the typical loop), and
        # mem_q[*].sbe.bp isn't always dumped. But branch_unit.sv:99 gives an
        # invertible relation:
        #     is_mispredict = comp_res XOR (predict.cf == Branch)
        # so predict.cf follows exactly from (resolved_cf, taken, mispredict).
        # This is more authoritative than either capture: it is the same logic
        # the hardware uses to decide whether to flush.
        resolved = rec.bp_resolved_cf
        taken = rec.bp_resolved_taken
        mis = rec.bp_mispredict
        derived = None
        if resolved == "Branch":
            # branch_unit overwrites cf_type to Branch on the resolution path,
            # losing the predictor's actual cf. The XOR math recovers it:
            # predict.cf was Branch (taken-predicted) iff (taken XOR mis) == 1.
            if taken is not None and mis is not None:
                derived = "Branch" if (taken ^ mis) else "NoCF"
        elif resolved == "Jump":
            # frontend.sv:256 unconditionally sets cf=Jump for every JAL, so a
            # direct jump has no NoCF path.
            derived = "Jump"
        elif resolved == "JumpR":
            # JALR only (branch_unit.sv:101-107). A mispredict means either a
            # BTB miss (NoCF) or a wrong-target JumpR prediction. The BTB-miss
            # case dominates since the default prediction is fall-through.
            if mis is True:
                derived = "NoCF"
            elif mis is False:
                derived = "JumpR"
        elif resolved == "Return":
            # RAS-predicted. predict.cf was Return either way: on a mispredict
            # (wrong RAS target or underflow) only the address was wrong.
            derived = "Return"
        # else: keep the pre-edge capture. Rare, and shouldn't happen for the
        # CTRL_FLOW records resolve_branch is gated on, but guarded anyway.
        if derived is not None:
            rec.bp_predicted_cf = derived

    def on_lsu_fsm_sample(self, cycle, load_state_str, store_state_str,
                          lsu_ctrl_trans_id_str=None,
                          pop_ld_str=None, pop_st_str=None):
        """LSU FSM correlation via lsu_ctrl + pop + state transitions.

        Three admission-detection rules. In all of them trans_id is the
        PREVIOUS cycle's lsu_ctrl.trans_id:

        A. IDLE → non-IDLE: standard admission.

        B. pop_ld_o=1 while the load FSM is in SEND_TAG (load_unit.sv:343) or
           pop_st_o=1 while the store FSM is in VALID_STORE
           (store_unit.sv:191): admit-while-busy with NO state transition
           (only the access identity changes). Deferred one cycle via
           `pending_admit_*_tid_str`.

        B'. SEND_TAG → any non-IDLE (load), VALID_STORE → any non-IDLE
            (store). Per load_unit.sv:332-353 and store_unit.sv:179-206 the
            only way to leave those states while staying non-IDLE is
            accepting a new request, so the new record takes over the FSM
            this cycle. Needed because these admissions (STG→WGT/WPO/ABT,
            VST→WTL/WSR) never assert pop_ld_o/pop_st_o: the pop fires only
            on grant or store-buffer-ready, which hasn't happened yet.

        B and B' are mutually exclusive: B requires the state to stay
        SEND_TAG/VALID_STORE, B' requires it to change out of them."""

        # ---- LOAD FSM ----
        if load_state_str is not None:
            try:
                new_int = int(load_state_str, 2)
            except (ValueError, TypeError):
                new_int = None
            new_name = LOAD_FSM_NAMES.get(new_int, f"?{load_state_str}")

            if self.prev_load_state_str is None:
                # First sample. Just prime the cache.
                self.prev_load_state_str = load_state_str
            else:
                handled_admit_this_cycle = False

                # Rule B: pending admit from prev cycle's pop_ld_o + SEND_TAG.
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

                # Rule A / completion / mid-flight, only if rule B didn't
                # already handle an admission this cycle.
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
                        # Rule B': admit-while-busy leaving SEND_TAG for any
                        # non-IDLE state. Per load_unit.sv:320-354 the exits
                        # are IDLE (completion, below), SEND_TAG (Rule B), and
                        # WAIT_GNT / WAIT_PAGE_OFFSET / ABORT_TRANSACTION{,_NI},
                        # which are all NEW admissions.
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
                        # Rule B': admit-while-busy leaving VALID_STORE. Per
                        # store_unit.sv:179-206 the exits are IDLE
                        # (completion), VALID_STORE (Rule B), and
                        # WAIT_TRANSLATION / WAIT_STORE_READY, which are NEW
                        # admissions.
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
        """Capture per-cycle HPDcache miss-handler events.

        Each non-zero pulse appends a typed event to `self._dc_events`, and the
        refill FSM is sampled independently into `self._rfsm_active_cycles`.
        Attribution to records happens later in
        attribute_dc_events_to_records.

        Arguments are raw VCD `state` strings, decoded here to keep the
        per-cycle dispatch slim. None signals (absent from this VCD) are
        tolerated: their events are simply not generated.
        """
        # MSHR allocation pulse. sid distinguishes load-adapter from
        # store/CMO/HWPF allocations. Only sid in LOAD_ADAPTER_SIDS can become
        # a dc_primary_miss. Stored raw so consumers can re-classify.
        if mallo == "1":
            self._dc_events.append({
                "cycle": cycle,
                "type":  "alloc",
                "sid":   binary_to_int(msid) if msid else None,
                "tid":   binary_to_int(mtid) if mtid else None,
                "pf":    binary_to_int(mpf) if mpf else None,
                "nline": binary_to_int(mnline_alloc) if mnline_alloc else None,
            })

        # MSHR-check pulse, split by mshr_check_hit_o (combinational, same
        # edge). check_hit is the coalescing signal: a request found its nline
        # already pending. The check path has NO sid input, so attribution is
        # purely by cycle window.
        if mchk == "1":
            hit = (mchkhit == "1")
            self._dc_events.append({
                "cycle": cycle,
                "type":  "check_hit" if hit else "check_miss",
                "nline": binary_to_int(mchk_nline) if mchk_nline else None,
            })

        # Refill response: refill data reaching the core port for a primary
        # miss. tid identifies the requestor (hpdcache_miss_handler.sv:382,397).
        if rrsp == "1":
            self._dc_events.append({
                "cycle": cycle,
                "type":  "refill_rsp",
                "tid":   binary_to_int(rtid) if rtid else None,
            })

        # Any non-zero refill FSM state means a refill is writing the data RAM,
        # updating the directory, or invalidating. The data RAM port is
        # consumed on those cycles and can stall unrelated loads, which is why
        # dc_refill_overlap is tracked even for hits.
        if rfsm is not None:
            rfsm_val = binary_to_int(rfsm)
            if rfsm_val is not None and rfsm_val != REFILL_FSM_IDLE:
                self._rfsm_active_cycles.add(cycle)

    def attribute_dc_events_to_records(self):
        """Bind D$ events back to LOAD/STORE records.

        Runs once after the scan, when `self.completed` is final. For each Mem
        record with an [admit, complete] window, copies the events falling in
        it into `dc_events` and sets dc_primary_miss / dc_coalesced /
        dc_refill_overlap (see the InstructionRecord field docs for their
        exact meaning). Records without a complete LSU trace (flushed before
        admission) get `dc_events=[]` and all booleans False, while non-Mem
        records are untouched.
        """
        # ev_cycles / rfsm_sorted are sorted key arrays so each record can
        # bisect straight to the first event in its window. Events are already
        # in cycle order (on_dcache_sample runs once per ascending rising
        # edge). The old per-record linear scan was records x events, the slow
        # tail that made a big VCD look like it hung after parsing.
        evlog = self._dc_events
        n_events = len(evlog)
        ev_cycles = [ev["cycle"] for ev in evlog]
        rfsm_sorted = sorted(self._rfsm_active_cycles)

        # evlog positions of sid=3 allocs already claimed by an earlier store.
        # Required because HPDCACHE_STORE_LOOKAHEAD widens store windows, and
        # two stores dispatched within the lookahead would otherwise both see
        # the SAME alloc and double-count it.
        consumed_store_alloc_idx = set()

        n_loads = n_stores = 0
        n_prim = n_coal = n_overlap = 0

        for rec in self.completed:
            if rec.fu_category != "Mem":
                continue
            if rec.fu == "LOAD":
                n_loads += 1
            elif rec.fu == "STORE":
                n_stores += 1

            admit = rec.lsu_admit_cycle
            complete = rec.lsu_complete_cycle
            if admit is None or complete is None:
                rec.dc_events = []
                continue

            events_in_window = []
            primary_miss = False
            coalesced = False

            # Stores complete (FSM → IDLE) as soon as the cache acks, but the
            # MSHR alloc fires several cycles later in the cache's st0→st1→st2
            # pipeline, so extend the store window by that depth. Loads keep
            # their window: load_unit waits for data, so complete is already
            # past the alloc.
            HPDCACHE_STORE_LOOKAHEAD = 5
            if rec.fu == "STORE":
                window_end = complete + HPDCACHE_STORE_LOOKAHEAD
            else:
                window_end = complete

            start_idx = bisect.bisect_left(ev_cycles, admit)
            for ev_idx in range(start_idx, n_events):
                ev = evlog[ev_idx]
                c = ev["cycle"]
                if c > window_end:
                    break
                events_in_window.append(ev)
                etype = ev["type"]
                if etype == "alloc":
                    sid = ev.get("sid")
                    # Both LSU FSMs are serial (at most one load in WAIT_GNT,
                    # stores likewise), so a sid=1 alloc in a LOAD's window
                    # belongs to that load and a sid=3 alloc in a STORE's
                    # window to that store. The cache's `tid` cannot
                    # disambiguate: it is cva6_req_i.data_id, which is
                    # ldbuf_windex for loads (not the scoreboard trans_id) and
                    # hard-wired to '0 for stores.
                    if rec.fu == "LOAD" and sid == LOAD_UNIT_SID:
                        primary_miss = True
                    elif rec.fu == "STORE" and sid == STORE_ADAPTER_SID:
                        # Skip allocs already claimed by an earlier store.
                        if ev_idx in consumed_store_alloc_idx:
                            continue
                        consumed_store_alloc_idx.add(ev_idx)
                        primary_miss = True
                elif etype == "check_hit":
                    coalesced = True

            # Refill overlap: any cycle in [admit, complete] is rFSM-active.
            rf_lo = bisect.bisect_left(rfsm_sorted, admit)
            refill_overlap = (rf_lo < len(rfsm_sorted)
                              and rfsm_sorted[rf_lo] <= complete)

            rec.dc_events = events_in_window

            # check_hit has no source-ID input, so attribution leans on
            # load_unit being single-threaded: a check_hit in a LOAD's window
            # is overwhelmingly that load's. dc_coalesced/dc_refill_overlap
            # stay LOAD-only: stores allocate rather than coalesce (no
            # check_i), and a concurrent refill is not "this store's miss".
            if rec.fu == "LOAD":
                rec.dc_primary_miss = primary_miss
                rec.dc_coalesced = coalesced
                rec.dc_refill_overlap = refill_overlap

                if primary_miss:
                    n_prim += 1
                if coalesced:
                    n_coal += 1
                if refill_overlap:
                    n_overlap += 1
            elif rec.fu == "STORE":
                rec.dc_primary_miss = primary_miss
                if primary_miss:
                    n_prim += 1

        # Perf-counter-equivalent totals. HPDcache exports
        # evt_cache_read_miss_o = ~st2_mshr_alloc_is_prefetch_i
        # (hpdcache_ctrl_pe.sv:368), counting ALL non-prefetch MSHR allocs.
        # n_primary_miss_loads is a strict subset (only sid==1 allocs bound to
        # a LOAD record). Stores, PTW, accel and CMO allocs count here but
        # never set dc_primary_miss. Computed so the viewer can show both views.
        n_miss_total = 0
        n_miss_loads_g = 0   # global, sid==LOAD_UNIT_SID, regardless of tid match
        n_miss_stores = 0   # sid==STORE_ADAPTER_SID
        n_miss_other = 0   # PTW, accel, CMO, unknown
        for ev in evlog:
            if ev.get("type") != "alloc":
                continue
            if ev.get("pf") == 1:
                continue
            n_miss_total += 1
            sid = ev.get("sid")
            if sid == LOAD_UNIT_SID:
                n_miss_loads_g += 1
            elif sid == STORE_ADAPTER_SID:
                n_miss_stores += 1
            else:
                n_miss_other += 1

        return {
            "total_dc_events":       n_events,
            "rfsm_active_cycles":    len(self._rfsm_active_cycles),
            "n_loads":               n_loads,
            "n_stores":              n_stores,
            "n_primary_miss_loads":  n_prim,
            "n_coalesced_loads":     n_coal,
            "n_refill_overlap_loads": n_overlap,
            "n_dcache_miss_events_total":  n_miss_total,
            "n_dcache_miss_events_loads":  n_miss_loads_g,
            "n_dcache_miss_events_stores": n_miss_stores,
            "n_dcache_miss_events_other":  n_miss_other,
        }

    # -- Phase 7b: dirty victim writeback (flush/wback unit) ---------------

    def on_wback_sample(self, cycle,
                        alloc_v, alloc_r, alloc_nline, alloc_way,
                        send_v, send_r, send_id, send_addr,
                        ack_v, ack_r, ack_id, ack_nline):
        """Log writeback handshakes. Called once per rising edge (cycle
        order). Alloc = victim handed to flush unit. Send = mem write
        request issued. Ack = memory response. Pairing is deferred to
        finalize_writebacks(). Alloc_way is the one-hot victim way (used for
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
        incoming line is mshr_nline (X). The victim Y (same set, same way) is
        written back. Joined to a writeback in finalize_writebacks by
        (set, way). No ready-gate: the (set,way)+window join is robust to the
        held-high duplicate cycles."""
        if alloc_v == "1" and wback == "1":
            self._wb_evicts.append((cycle, binary_to_hex(mshr_nline),
                                    binary_to_int(victim_way)))

    def finalize_writebacks(self):
        """Pair send<->ack by flush slot id (FIFO per id) for AXI write
        latency, join alloc<->ack by nline (FIFO per nline) for residency, and
        build the writeback event list + latency aggregate."""
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
                    "evict_incoming_nline": None,   # line X that displaced Y
                    "evict_cycle":         None,
                    "linked":              False,
                })
            else:
                unmatched_acks += 1
        sends_never_acked = sum(len(q) for q in send_q.values())

        # alloc -> ack join by nline (FIFO per nline, ack-time order). Also
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

        # Eviction linkage: join each writeback to the dirty eviction that
        # caused it by (set, victim_way), nearest within a small window
        # (evictions are same-cycle in practice, and the window absorbs skew).
        SET_MASK = (1 << 8) - 1          # 256 sets -> setWidth 8
        WINDOW = 4
        n_linked = 0
        # (set, way_oh) -> [(cycle, X_hex), ...]
        ev_by_key = defaultdict(list)
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
            # If the slot is already occupied (shouldn't happen given commit
            # runs first) the old occupant is unrecoverable.
            self.issued[trans_id] = rec

    def on_writeback(self, cycle, port, trans_id,
                     mq_fu=None, mq_rs1=None, mq_rs2=None, mq_rd=None,
                     mq_bp_cf=None):
        rec = self.issued.get(trans_id)
        if rec is None:
            self.n_unmatched_writebacks += 1
            return
        if rec.wb_cycle is None:
            rec.wb_cycle = cycle
        # Overwrite decoded fields with the AUTHORITATIVE values from the
        # scoreboard's registered mem_q ring buffer: stable from decode+1 to
        # commit, so reading at writeback has no timing ambiguity. When mem_q
        # isn't in the VCD the caller passes None and the pre-edge values stay.
        if mq_fu is not None:
            rec.fu = FU_NAME.get(mq_fu, f"UNK_{mq_fu}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Unknown")
        if mq_rs1 is not None:
            rec.rs1 = mq_rs1
        if mq_rs2 is not None:
            rec.rs2 = mq_rs2
        if mq_rd is not None:
            rec.rd = mq_rd
        # Same authoritative correction for the predictor verdict: the pre-edge
        # decoded_instr_i.bp.cf snapshot is wrong for back-to-back issues (it
        # holds the previous instruction's bp, since issue_q only flips at the
        # rising edge), while mem_q[trans_id].sbe.bp.cf is registered a cycle
        # later and stable through commit.
        if mq_bp_cf is not None:
            rec.bp_predicted_cf = CF_T_NAMES.get(mq_bp_cf, f"UNK_{mq_bp_cf}")

    def on_commit(self, cycle, port, trans_id,
                  mq_fu=None, mq_rs1=None, mq_rs2=None, mq_rd=None,
                  mq_bp_cf=None):
        rec = self.issued.pop(trans_id, None)
        if rec is None:
            self.n_unmatched_commits += 1
            return
        rec.co_cycle = cycle
        # Apply mem_q fields if rec.fu wasn't set at writeback: NONE-fu
        # instructions auto-validate without using a writeback port
        # (scoreboard.sv:189).
        if mq_fu is not None and rec.fu is None:
            rec.fu = FU_NAME.get(mq_fu, f"UNK_{mq_fu}")
            rec.fu_category = FU_CATEGORY.get(rec.fu, "Unknown")
        if mq_rs1 is not None and rec.rs1 is None:
            rec.rs1 = mq_rs1
        if mq_rs2 is not None and rec.rs2 is None:
            rec.rs2 = mq_rs2
        if mq_rd is not None and rec.rd is None:
            rec.rd = mq_rd
        # Same fallback for bp.cf: NONE-fu instructions reach commit without
        # ever passing a wb port, so the writeback fixup misses them.
        if mq_bp_cf is not None and rec.bp_predicted_cf is None:
            rec.bp_predicted_cf = CF_T_NAMES.get(mq_bp_cf, f"UNK_{mq_bp_cf}")
        self.completed.append(rec)
        self.n_committed += 1
        # Warmup boundary = the FETCH cycle of the first instance committed at
        # user_entry_pc, NOT its commit cycle, so that main's entry instruction
        # and its immediate successors classify as user code, not warmup.
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
        # Anything still in-flight at EOF is incomplete. Mark as flushed.
        if self.fetched or self.decoded or self.issued:
            self._flush_fetched("eof")
            self._flush_decoded("eof")
            self._flush_issued("eof")
        # Restore id-sorted order. Flushes can interleave.
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


# Matches the tail "mem_q[<N>].sbe.fu" or "mem_q[<N>].sbe.fu[3:0]" of a VCD
# signal path. Used to probe the actual scoreboard depth in the build before
# the whitelist match runs, so we can refuse to process VCDs from builds
# with NrScoreboardEntries > NR_SB_ENTRIES (the tracer's compile-time max).
_MEMQ_SLOT_PROBE_RE = re.compile(r"mem_q\[(\d+)\]\.sbe\.fu(?:\[[\d:]+\])?$")

# Probes used by the pre-flight guards in main(). Each detects a config
# parameter that the tracer cannot handle by deviating from its compile-time
# default. Larger values mean silent wrong output (signals on the high
# indices are not in the whitelist and never read), so the pre-flight
# aborts with a clear instruction to bump the corresponding NR_* constant.
# Smaller values are fine. The unused slots stay None at runtime.
_DECODED_PORT1_RE = re.compile(
    r"decoded_instr_i\[1\]\.fu(?:\[[\d:]+\])?$")
_COMMIT_PTR_RE = re.compile(
    r"commit_pointer_q\[(\d+)\](?:\[[\d:]+\])?$")
_WB_TRANSID_RE = re.compile(
    r"trans_id_i\[(\d+)\](?:\[[\d:]+\])?$")


def probe_max_scoreboard_slot(path_to_id):
    """Find the largest N such that mem_q[N].sbe.fu exists in the VCD.
    Returns -1 if no mem_q slots are present (e.g., a non-CVA6 dump or
    a scoreboard without struct tracing). The scan walks all VCD signal
    paths, not just the whitelisted ones, so it can see slots beyond
    what the tracer would enumerate at compile time."""
    max_n = -1
    for path in path_to_id:
        m = _MEMQ_SLOT_PROBE_RE.search(path)
        if m:
            n = int(m.group(1))
            if n > max_n:
                max_n = n
    return max_n


def probe_superscalar(path_to_id):
    """Return True iff the build has SuperscalarEn=1 (NrIssuePorts > 1).
    Detected by the presence of decoded_instr_i[1].fu, which only exists
    when the scoreboard's decoded_instr_i array has more than one entry."""
    for path in path_to_id:
        if _DECODED_PORT1_RE.search(path):
            return True
    return False


def probe_max_commit_port(path_to_id):
    """Find the largest N such that commit_pointer_q[N] exists in the VCD.
    Tells us the build's NrCommitPorts. Returns -1 if none found."""
    max_n = -1
    for path in path_to_id:
        m = _COMMIT_PTR_RE.search(path)
        if m:
            n = int(m.group(1))
            if n > max_n:
                max_n = n
    return max_n


def probe_max_wb_port(path_to_id):
    """Find the largest N such that trans_id_i[N] exists in the VCD.
    Tells us the build's NrWbPorts. Returns -1 if none found."""
    max_n = -1
    for path in path_to_id:
        m = _WB_TRANSID_RE.search(path)
        if m:
            n = int(m.group(1))
            if n > max_n:
                max_n = n
    return max_n


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
    # decoded_instr_i.bp.{cf,predict_address}, captured via pre-edge snapshot
    # to dodge the same advance-on-rising-edge issue as fu/rs1/rs2/rd.
    DBP_CF = single_id.get(
        "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.cf")
    DBP_TGT = single_id.get(
        "issue_stage_i.i_scoreboard.decoded_instr_i[0].bp.predict_address")

    # Forwarding signals from issue_read_operands. forward_rsX/idx_hzd_rsX are
    # combinational and advance to the next instruction's view on the rising
    # edge, so they need the same pre-edge snapshot as decoded_instr_i.*.
    FWD_RS1 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs1")
    FWD_RS2 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs2")
    FWD_RS3 = single_id.get("issue_stage_i.i_issue_read_operands.forward_rs3")
    IHZ_RS1 = single_id.get(
        "issue_stage_i.i_issue_read_operands.idx_hzd_rs1[0]")
    IHZ_RS2 = single_id.get(
        "issue_stage_i.i_issue_read_operands.idx_hzd_rs2[0]")
    IHZ_RS3 = single_id.get(
        "issue_stage_i.i_issue_read_operands.idx_hzd_rs3[0]")
    FWD_AVAILABLE = all(s is not None for s in (
        FWD_RS1, FWD_RS2, FWD_RS3, IHZ_RS1, IHZ_RS2, IHZ_RS3))
    if FWD_AVAILABLE:
        stagelog("Phase 8a: issue_read_operands forwarding signals resolved",
                 file=sys.stderr)
    else:
        missing = [name for name, sig in [
            ("forward_rs1",   FWD_RS1), ("forward_rs2", FWD_RS2),
            ("forward_rs3",   FWD_RS3), ("idx_hzd_rs1[0]", IHZ_RS1),
            ("idx_hzd_rs2[0]", IHZ_RS2), ("idx_hzd_rs3[0]", IHZ_RS3),
        ] if sig is None]
        stagelog("WARNING: Phase 8a - forwarding signals not resolved. "
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

    # Per-slot maps for the scoreboard's registered mem_q.
    # MEMQ_FU[N] = vcd_id of mem_q[N].sbe.fu (None if slot not exposed).
    NR_SB = NR_SB_ENTRIES
    MEMQ_FU = [None] * NR_SB
    MEMQ_RS1 = [None] * NR_SB
    MEMQ_RS2 = [None] * NR_SB
    MEMQ_RD = [None] * NR_SB
    # Authoritative bp.cf source. The decoded_instr_i pre-edge snapshot is
    # unreliable for back-to-back issues: when the instruction enters issue_q
    # on the same rising edge as iss_ack, the sample holds the PREVIOUS
    # instruction's bp.cf (NoCF for non-CTRL_FLOW). mem_q[tid].sbe.bp.cf is
    # stable from a cycle after issue through commit, so reading it at
    # writeback gives the true predictor verdict.
    MEMQ_BP_CF = [None] * NR_SB
    memq_resolved = 0
    memq_bp_resolved = 0
    for n in range(NR_SB):
        f_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.fu")
        r1_vid = single_id.get(
            f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs1")
        r2_vid = single_id.get(
            f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs2")
        rd_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rd")
        bp_cf_vid = single_id.get(
            f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.bp.cf")
        MEMQ_FU[n] = f_vid
        MEMQ_RS1[n] = r1_vid
        MEMQ_RS2[n] = r2_vid
        MEMQ_RD[n] = rd_vid
        MEMQ_BP_CF[n] = bp_cf_vid
        if all(v is not None for v in (f_vid, r1_vid, r2_vid, rd_vid)):
            memq_resolved += 1
        if bp_cf_vid is not None:
            memq_bp_resolved += 1

    # Detect the actual scoreboard depth from MEMQ_FU presence: parameter-sweep
    # builds may use a smaller scoreboard than the compile-time NR_SB_ENTRIES.
    # Without adapting, `memq_resolved == NR_SB` fails and we fall through to
    # the pre-edge fallback, which is off-by-one for back-to-back issues and
    # yields wrong FU types throughout. (The pre-flight probe in main() bails
    # out for builds with MORE slots than the tracer default.)
    detected_nr_sb = 0
    for n in range(NR_SB):
        if MEMQ_FU[n] is not None:
            detected_nr_sb = n + 1
        else:
            break
    if 0 < detected_nr_sb < NR_SB:
        stagelog(f"Scoreboard depth: detected {detected_nr_sb} slots in VCD "
                 f"(tracer default NR_SB_ENTRIES={NR_SB}). Adapting NR_SB and "
                 f"per-slot arrays. This usually means the build has "
                 f"NrScoreboardEntries={detected_nr_sb} (TRANS_ID_BITS="
                 f"{(detected_nr_sb - 1).bit_length()}).",
                 file=sys.stderr)
        NR_SB = detected_nr_sb
        MEMQ_FU = MEMQ_FU[:NR_SB]
        MEMQ_RS1 = MEMQ_RS1[:NR_SB]
        MEMQ_RS2 = MEMQ_RS2[:NR_SB]
        MEMQ_RD = MEMQ_RD[:NR_SB]
        MEMQ_BP_CF = MEMQ_BP_CF[:NR_SB]
        memq_resolved = sum(1 for v in MEMQ_FU if v is not None)
        memq_bp_resolved = sum(1 for v in MEMQ_BP_CF if v is not None)

    MEMQ_AVAILABLE = (memq_resolved == NR_SB)
    MEMQ_BP_AVAILABLE = (memq_bp_resolved == NR_SB)
    if MEMQ_BP_AVAILABLE:
        stagelog("Phase 7a: mem_q[*].sbe.bp.cf resolved. Using authoritative "
                 "reads at writeback to correct the pre-edge decoded_instr_i "
                 "bp.cf misattribution for back-to-back issues",
                 file=sys.stderr)
    else:
        stagelog(f"WARNING: Phase 7a. mem_q[*].sbe.bp.cf not resolved "
                 f"({memq_bp_resolved}/{NR_SB} slots found). Falling back to "
                 f"the pre-edge decoded_instr_i.bp.cf snapshot, which is "
                 f"INCORRECT for back-to-back issues (the typical loop case): "
                 f"the pre-edge sample reads the PREVIOUS instruction's bp.cf "
                 f"because issue_q only flips at the rising edge. Most loop "
                 f"branches will appear as predicted_cf=NoCF in the output. "
                 f"To fix: ensure your Verilator dump includes mem_q[N].sbe.bp "
                 f"for all scoreboard slots.",
                 file=sys.stderr)

    # Phase 7a: decoded_instr_i[0].bp.{cf,predict_address} availability.
    BP_DECODE_AVAILABLE = (DBP_CF is not None and DBP_TGT is not None)
    if BP_DECODE_AVAILABLE:
        stagelog("Phase 7a: decoded_instr_i[0].bp.{cf,predict_address} resolved. "
                 "using pre-edge snapshot for prediction capture",
                 file=sys.stderr)
    else:
        missing = [name for name, sig in [
            ("decoded_instr_i[0].bp.cf", DBP_CF),
            ("decoded_instr_i[0].bp.predict_address", DBP_TGT),
        ] if sig is None]
        stagelog("WARNING: Phase 7a. Decoded_instr_i.bp.* not resolved. "
                 "bp_predicted_* fields will be left None on all records. "
                 "Missing: " + ", ".join(missing), file=sys.stderr)

    if MEMQ_AVAILABLE:
        stagelog(f"mem_q ring buffer: all {NR_SB} slots resolved. Using authoritative reads",
                 file=sys.stderr)
    elif memq_resolved > 0:
        stagelog(f"mem_q ring buffer: only {memq_resolved}/{NR_SB} slots resolved. "
                 "falling back to decode-time pre-edge capture",
                 file=sys.stderr)
        MEMQ_AVAILABLE = False
    else:
        stagelog("mem_q ring buffer: NOT exposed in VCD. Falling back to decode-time pre-edge capture",
                 file=sys.stderr)

    CA = single_id.get("commit_stage_i.commit_ack_o")
    CPTR_PORTS = [single_id.get(
        f"issue_stage_i.i_scoreboard.commit_pointer_q[{port}]")
        for port in range(NR_COMMIT_PORTS)]

    FIF = single_id.get("flush_ctrl_if")
    FID = single_id.get("flush_ctrl_id")
    FEX = single_id.get("flush_ctrl_ex")
    # Phase 4a v0.3: gate on_decode by !flush_unissued_instr_i.
    FUI = single_id.get("issue_stage_i.i_scoreboard.flush_unissued_instr_i")
    if FUI is None:
        stagelog("WARNING: flush_unissued_instr_i not resolved. Phantom-decode "
                 "gating will be DISABLED and the +N slot drift may return.",
                 file=sys.stderr)

    # I$ signal lookups for ICacheTimeline.on_cycle. STATE_Q is the I$
    # controller FSM (cva6_icache.sv:122). The dreq_o signals come from the
    # FRONTEND-side mirror (i_frontend.icache_dreq_i), electrically the same
    # as the I$'s dreq_o but reachable without an I$-scoped lookup.
    # CSR-equivalent access sources: the perf counters increment on any cycle
    # icache_dreq_o.req is high (I$) or any ex_stage core port raises data_req
    # (D$). Handles resolved once here, sampled in at_rising_edge.
    IC_REQ = single_id.get("i_frontend.icache_dreq_o.req")
    DC_REQ_PORTS = [single_id.get(
        f"ex_stage_i.dcache_req_ports_o[{p}].data_req")
        for p in range(DCACHE_REQ_PORTS)]
    csr_access_resolved = (IC_REQ is not None
                           and all(s is not None for s in DC_REQ_PORTS))
    if csr_access_resolved:
        port_list = ", ".join(
            f"ex_stage_i.dcache_req_ports_o[{p}].data_req"
            for p in range(DCACHE_REQ_PORTS))
        stagelog("CSR-equivalent access counters enabled "
                 f"(icache_dreq_o.req + {port_list})",
                 file=sys.stderr)
    else:
        missing = []
        if IC_REQ is None:
            missing.append("icache_dreq_o.req")
        for p, s in enumerate(DC_REQ_PORTS):
            if s is None:
                missing.append(f"ex_stage_i.dcache_req_ports_o[{p}].data_req")
        stagelog(f"WARNING: CSR-equivalent access counters not all resolved. "
                 f"viewer will fall back to record-derived access counts. "
                 f"Missing: {', '.join(missing)}",
                 file=sys.stderr)

    # Per-cycle access-event cycle lists, filled by at_rising_edge when the
    # signal is high at the edge (i.e. the elapsed cycle had the request
    # asserted). The viewer windows these for the CSR-equivalent access count.
    ic_access_cycles = []
    dc_access_cycles = []
    # RTL-counter-equivalent I$ miss pulse cycles (miss_o high). len() equals
    # perf_counters.sv event 1, the hardware L1 I$ miss count.
    icache_miss_cycles = []

    STATE_Q = single_id.get(
        "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.state_q")
    IC_VLD = single_id.get("i_frontend.icache_dreq_i.valid")
    IC_VADDR = single_id.get("i_frontend.icache_dreq_i.vaddr")
    IC_K2 = single_id.get("i_frontend.icache_dreq_o.kill_s2")
    IC_MISS_O = single_id.get(
        "gen_cache_hpd.i_cache_subsystem.i_cva6_icache.miss_o")
    icache_resolved = all(s is not None
                          for s in (STATE_Q, IC_VLD, IC_VADDR, IC_K2))
    if not icache_resolved:
        stagelog("WARNING: Phase 4b I$ signals not all resolved. "
                 "if1_lo/if2_lo/if1_hi/if2_hi/ic_miss will be left as None "
                 "on every record. Missing: " +
                 ", ".join(name for name, s in [
                     ("state_q", STATE_Q),
                     ("dreq_o.valid", IC_VLD),
                     ("dreq_o.vaddr", IC_VADDR),
                     ("dreq_i.kill_s2", IC_K2),
                 ] if s is None),
                 file=sys.stderr)
    else:
        stagelog("Phase 4b I$ tracking enabled (state_q + frontend dreq mirror)",
                 file=sys.stderr)

    # instr_realign flag for the per-cycle pulse counter. Optional: if absent,
    # wraps_line is still populated from PC, just without cross-validation.
    SVU = single_id.get("i_frontend.i_instr_realign.serving_unaligned_o")
    if SVU is None:
        stagelog("WARNING: Phase 8b serving_unaligned_o not resolved. "
                 "wraps_line will still be set per record from PC, but the "
                 "realigner-pulse cross-validation count will be 0",
                 file=sys.stderr)
    else:
        stagelog("Phase 8b instr_realign tracking enabled "
                 "(serving_unaligned_o pulse counter for wraps_line "
                 "cross-validation)",
                 file=sys.stderr)

    # LSU FSM state registers, plus lsu_ctrl.trans_id for admission
    # correlation and pop_ld/pop_st for admit-while-busy detection.
    LOAD_STATE = single_id.get("ex_stage_i.lsu_i.i_load_unit.state_q")
    STORE_STATE = single_id.get("ex_stage_i.lsu_i.i_store_unit.state_q")
    LSU_CTRL_TID = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.trans_id")
    POP_LD = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i")
    POP_ST = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i")
    lsu_resolved = (LOAD_STATE is not None and STORE_STATE is not None)

    # HPDcache miss-handler signal IDs. The `gen_cache_hpd.` prefix is
    # mandatory: cva6.sv instantiates three cache subsystem variants under
    # different generate branches (gen_cache_std, gen_cache_wt) and this
    # build's signals live under gen_cache_hpd only.
    _DC_BASE = ("gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
                "hpdcache_miss_handler_i.")
    DC_MALLO = single_id.get(_DC_BASE + "mshr_alloc_i")
    DC_MTID = single_id.get(_DC_BASE + "mshr_alloc_tid_i")
    DC_MSID = single_id.get(_DC_BASE + "mshr_alloc_sid_i")
    DC_MPF = single_id.get(_DC_BASE + "mshr_alloc_is_prefetch_i")
    DC_MNLINE = single_id.get(_DC_BASE + "mshr_alloc_nline_i")
    DC_MCHK = single_id.get(_DC_BASE + "mshr_check_i")
    DC_MCHKN = single_id.get(_DC_BASE + "mshr_check_nline_i")
    DC_MCHKH = single_id.get(_DC_BASE + "mshr_check_hit_o")
    DC_RFSM = single_id.get(_DC_BASE + "refill_fsm_q")
    DC_RRSP = single_id.get(_DC_BASE + "refill_core_rsp_valid_o")
    DC_RTID = single_id.get(_DC_BASE + "refill_core_rsp_o.tid")
    dcache_resolved = all(s is not None for s in [
        DC_MALLO, DC_MTID, DC_MSID, DC_MPF, DC_MNLINE,
        DC_MCHK, DC_MCHKN, DC_MCHKH, DC_RFSM, DC_RRSP, DC_RTID,
    ])

    # Dirty-victim writeback (flush/wback unit) signals at the i_hpdcache
    # level. Send/ack are the live flush channel, and the wbuf channel is dead
    # in this write-back config (gen_no_wbuf).
    _WB_BASE = "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
    WB_ALLOC_V = single_id.get(_WB_BASE + "flush_alloc")
    WB_ALLOC_R = single_id.get(_WB_BASE + "flush_alloc_ready")
    WB_ALLOC_NL = single_id.get(_WB_BASE + "flush_alloc_nline")
    WB_SEND_V = single_id.get(_WB_BASE + "mem_req_write_flush_valid")
    WB_SEND_R = single_id.get(_WB_BASE + "mem_req_write_flush_ready")
    WB_SEND_ID = single_id.get(_WB_BASE + "mem_req_write_flush.mem_req_id")
    WB_SEND_AD = single_id.get(_WB_BASE + "mem_req_write_flush.mem_req_addr")
    WB_ACK_V = single_id.get(_WB_BASE + "mem_resp_write_flush_valid")
    WB_ACK_R = single_id.get(_WB_BASE + "mem_resp_write_flush_ready")
    WB_ACK_ID = single_id.get(_WB_BASE + "mem_resp_write_flush.mem_resp_w_id")
    WB_ACK_NL = single_id.get(_WB_BASE + "flush_ack_nline")
    wback_resolved = all(s is not None for s in [
        WB_ALLOC_V, WB_ALLOC_R, WB_ALLOC_NL,
        WB_SEND_V, WB_SEND_R, WB_SEND_ID, WB_SEND_AD,
        WB_ACK_V, WB_ACK_R, WB_ACK_ID, WB_ACK_NL,
    ])
    # Linkage: flush-side victim way + miss-handler eviction signals
    # (mshr_alloc_i / mshr_alloc_nline_i reused as DC_MALLO / DC_MNLINE).
    WB_FWAY = single_id.get(_WB_BASE + "flush_alloc_way")
    EV_WBACK = single_id.get(_DC_BASE + "mshr_alloc_wback_i")
    EV_VWAY = single_id.get(_DC_BASE + "mshr_alloc_victim_way_i")
    link_resolved = all(s is not None for s in [
        WB_FWAY, EV_WBACK, EV_VWAY, DC_MALLO, DC_MNLINE,
    ])

    # Branch resolution signals (bp_resolve_t). valid pulses for one cycle
    # when branch_unit emits a resolution, and the rest carry the payload.
    _RB = "issue_stage_i.i_scoreboard.resolved_branch_i."
    RB_VLD = single_id.get(_RB + "valid")
    RB_PC = single_id.get(_RB + "pc")
    RB_TGT = single_id.get(_RB + "target_address")
    RB_TKN = single_id.get(_RB + "is_taken")
    RB_MISP = single_id.get(_RB + "is_mispredict")
    RB_CFT = single_id.get(_RB + "cf_type")
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
        stagelog("WARNING: Phase 7a branch-resolve signals not all "
                 "resolved. bp_resolved_* fields will be left None "
                 "on all records. Missing: " + ", ".join(missing),
                 file=sys.stderr)
    else:
        stagelog("Phase 7a branch resolution tracking enabled "
                 "(resolved_branch_i: valid + pc + target + taken + "
                 "mispredict + cf_type)", file=sys.stderr)

    if not lsu_resolved:
        missing = []
        if LOAD_STATE is None:
            missing.append("i_load_unit.state_q")
        if STORE_STATE is None:
            missing.append("i_store_unit.state_q")
        stagelog("WARNING: Phase 6a LSU signals not all resolved. "
                 "lsu_state_history will be left as None on every record. "
                 "Missing: " + ", ".join(missing), file=sys.stderr)
    else:
        extras = []
        if not LSU_CTRL_TID:
            extras.append("lsu_ctrl.trans_id")
        if not POP_LD:
            extras.append("pop_ld")
        if not POP_ST:
            extras.append("pop_st")
        extras_msg = ("" if not extras
                      else f". Degraded (missing: {', '.join(extras)})")
        stagelog("Phase 6a LSU FSM tracking enabled "
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
        stagelog(f"WARNING: Phase 6b dcache signals not all resolved. "
                 f"dc_* fields will be left at defaults. "
                 f"Missing: {', '.join(missing)}", file=sys.stderr)
    else:
        stagelog("Phase 6b D$ event tracking enabled "
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
        stagelog("WARNING: Phase 7b writeback signals not all resolved. "
                 "writebacks[] will be empty. Missing: " + ", ".join(missing),
                 file=sys.stderr)
    else:
        stagelog("Phase 7b dirty-victim writeback tracking enabled "
                 "(flush alloc + mem_req_write_flush + mem_resp_write_flush)",
                 file=sys.stderr)
        if link_resolved:
            stagelog("Phase 7b writeback<->eviction linkage enabled "
                     "(mshr_alloc_wback + victim_way + flush_alloc_way, "
                     "join by (set,way))", file=sys.stderr)
        else:
            stagelog("WARNING: Phase 7b linkage signals not all resolved. "
                     "writebacks will have linked=false. (need "
                     "mshr_alloc_wback_i, mshr_alloc_victim_way_i, "
                     "flush_alloc_way)", file=sys.stderr)

    cycle = -1
    first_ts_seen = False
    clk_at_ts_start = "0"
    prev_flush_if = "0"
    prev_flush_id = "0"
    prev_flush_ex = "0"

    # Pre-edge snapshot of decoded_instr_i fields, sourced from id_stage's
    # registered `issue_q`, which advances AT the rising edge of every decode
    # handshake. Verilator dumps the post-edge value, so a naive state[DFU]
    # read at the rising-edge timestamp yields the *next* instruction's
    # fields. Snapshot at each `#` before applying that timestamp's changes,
    # so when the following `#` reveals a rising edge, the snapshot is correct.
    pre_dfu = None
    pre_drs1 = None
    pre_drs2 = None
    pre_drd = None
    # Same pre-edge treatment for decoded_instr_i[0].bp.*: issue_q advances on
    # the same edge that latches the handshake.
    pre_dbp_cf = None
    pre_dbp_tgt = None
    pre_fwd_rs1 = None
    pre_fwd_rs2 = None
    pre_fwd_rs3 = None
    pre_ihz_rs1 = None
    pre_ihz_rs2 = None
    pre_ihz_rs3 = None
    # Pre-edge snapshot of the writeback bus (wt_valid_i + per-port
    # trans_id_i), needed for via=sb/wb classification. A 1-cycle FU's wb pulse
    # is high during P.wb_cycle and gone by P.wb_cycle+1, but the consumer Q's
    # handshake fires at the rising edge of P.wb_cycle+1. Reading state[WTV]
    # inside at_rising_edge would sample post-edge, after the pulse ended. The
    # pre-edge snapshot captures Q's at-head cycle, when the override fired.
    pre_wtv = None
    pre_tids = {}     # port -> pre-edge trans_id_i[port] (raw VCD string)

    n_lines = 0
    n_changes = 0
    last_ts = 0
    last_report = 0
    start = time.time()
    # Previous-cycle serving_unaligned_o, for detecting 0→1 transitions.
    last_svu = None
    # Clock period detection: the gap between the first two rising-edge
    # timestamps is one period, letting downstream tools convert cycles to
    # real time with no external knowledge of the sim clock frequency.
    first_re_ts = None
    clock_period_ts = None

    def at_rising_edge():
        nonlocal cycle, prev_flush_if, prev_flush_id, prev_flush_ex, last_svu
        cycle += 1

        # CSR-equivalent access sampling. perf_counters.sv increments every
        # cycle the request is HIGH (I$: icache_dreq_o.req, D$: any of
        # dcache_req_ports_i[0..2].data_req). Sample the PRE-EDGE value: that
        # is the value during the elapsed cycle, what the synchronous counter
        # sees.
        if csr_access_resolved:
            if state.get(IC_REQ, "0") == "1":
                ic_access_cycles.append(cycle)
            if any(state.get(s, "0") == "1" for s in DC_REQ_PORTS):
                dc_access_cycles.append(cycle)

        # RTL-counter-equivalent I$ miss (pre-edge miss_o). The icache FSM
        # asserts it for one cycle per accepted cacheable ifill
        # (cva6_icache.sv:301-303), so this records one cycle per
        # hardware-counted miss, INCLUDING wrong-path fills squashed before
        # delivery that never produce an icache_event.
        if IC_MISS_O is not None and state.get(IC_MISS_O, "0") == "1":
            icache_miss_cycles.append(cycle)

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
                    ptr_id = CPTR_PORTS[port] if port < len(
                        CPTR_PORTS) else None
                    if ptr_id is not None:
                        tid = binary_to_int(state.get(ptr_id))
                        if tid is not None:
                            mq_fu = mq_rs1 = mq_rs2 = mq_rd = None
                            mq_bp_cf = None
                            if MEMQ_AVAILABLE and 0 <= tid < NR_SB:
                                mq_fu = binary_to_int(state.get(MEMQ_FU[tid]))
                                mq_rs1 = binary_to_int(
                                    state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(
                                    state.get(MEMQ_RS2[tid]))
                                mq_rd = binary_to_int(state.get(MEMQ_RD[tid]))
                            if MEMQ_BP_AVAILABLE and 0 <= tid < NR_SB:
                                mq_bp_cf = binary_to_int(
                                    state.get(MEMQ_BP_CF[tid]))
                            tracker.on_commit(cycle, port, tid,
                                              mq_fu, mq_rs1, mq_rs2, mq_rd,
                                              mq_bp_cf)

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
                            mq_bp_cf = None
                            if MEMQ_AVAILABLE and 0 <= tid < NR_SB:
                                mq_fu = binary_to_int(state.get(MEMQ_FU[tid]))
                                mq_rs1 = binary_to_int(
                                    state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(
                                    state.get(MEMQ_RS2[tid]))
                                mq_rd = binary_to_int(state.get(MEMQ_RD[tid]))
                            if MEMQ_BP_AVAILABLE and 0 <= tid < NR_SB:
                                mq_bp_cf = binary_to_int(
                                    state.get(MEMQ_BP_CF[tid]))
                            tracker.on_writeback(cycle, port, tid,
                                                 mq_fu, mq_rs1, mq_rs2, mq_rd,
                                                 mq_bp_cf)

        # 4+5. Combined decode+issue handshake: in non-superscalar CVA6,
        # issue_instr_o is a combinational passthrough of decoded_instr_i
        # (scoreboard.sv:151), so DV/DA and IV/IA fire the same cycle for the
        # same instruction. Treating them separately reads IPTR cycles late
        # under stalls, putting trans_id +N ahead of the HW slot and landing
        # every mem_q lookup on the wrong slot.
        if DV and DA and state.get(DV) == "1" and state.get(DA) == "1":
            flush_unissued = (FUI is not None and state.get(FUI) == "1")
            if not flush_unissued:
                tid = binary_to_int(state.get(IPTR))
                if tid is not None:
                    fu_val = binary_to_int(pre_dfu)
                    rs1 = binary_to_int(pre_drs1)
                    rs2 = binary_to_int(pre_drs2)
                    rd = binary_to_int(pre_drd)
                    # bp.* uses the same pre-edge snapshot as fu/rs1/rs2/rd:
                    # mem_q[tid].sbe.bp read at this edge is the PREVIOUS slot
                    # occupant's (issue_pointer_q advances on this same edge),
                    # so pre-edge decoded_instr_i.bp is the only live source.
                    bp_cf_val = (binary_to_int(pre_dbp_cf)
                                 if BP_DECODE_AVAILABLE else None)
                    bp_target = (binary_to_int(pre_dbp_tgt)
                                 if BP_DECODE_AVAILABLE else None)
                    # Forwarding uses LIVE (post-edge) state, unlike the fields
                    # above: forward_rsX is combinational off the CURRENT
                    # issue_q[0], which at post-edge of K holds the K-issued
                    # instruction and thus ITS hazard. The pre-edge value is
                    # the K-1 instruction's check and would misattribute.
                    if FWD_AVAILABLE:
                        live_fwd_rs1 = state.get(FWD_RS1) if FWD_RS1 else None
                        live_fwd_rs2 = state.get(FWD_RS2) if FWD_RS2 else None
                        live_fwd_rs3 = state.get(FWD_RS3) if FWD_RS3 else None
                        fwd_rs1_bit = (live_fwd_rs1 == "1")
                        fwd_rs2_bit = (live_fwd_rs2 == "1")
                        fwd_rs3_bit = (live_fwd_rs3 == "1")
                        ihz_rs1_v = binary_to_int(
                            state.get(IHZ_RS1)) if IHZ_RS1 else None
                        ihz_rs2_v = binary_to_int(
                            state.get(IHZ_RS2)) if IHZ_RS2 else None
                        ihz_rs3_v = binary_to_int(
                            state.get(IHZ_RS3)) if IHZ_RS3 else None
                    else:
                        fwd_rs1_bit = fwd_rs2_bit = fwd_rs3_bit = False
                        ihz_rs1_v = ihz_rs2_v = ihz_rs3_v = None
                    # wb_view uses the PRE-EDGE writeback bus: that is Q's
                    # at-head cycle, when the wb override actually fired and
                    # made Q issuable. Live state would read wt_valid_i during
                    # Q.is_cycle, after P's wb pulse has ended.
                    wb_view = []
                    if WTV is not None and pre_wtv is not None:
                        wt_bits = pre_wtv
                        for port, raw_tid in pre_tids.items():
                            # wt_valid_i is dumped MSB-first. Bit `port`
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

        # 6. Fetch, gated on flush_unissued_instr_i (fui). With fui=1 on an FE
        # handshake cycle, id_stage.sv:444 forces issue_n[0].valid=0, so the
        # frontend pops its instr_queue but id_stage discards the entry.
        # Pushing such a fetch to `fetched` would leave a phantom record HW's
        # id_stage never had, making every later pop +1 ahead of the true
        # decode (a stable +1 trans_id offset for all subsequent records).
        # Route them to on_fetch_dropped instead: recorded as flushed for
        # visibility, but kept out of `fetched`.
        if FE_V and FE_R and state.get(FE_V) == "1" and state.get(FE_R) == "1":
            pc = binary_to_hex(state.get(PC_ID))
            instr = binary_to_hex(state.get(IN_ID))
            rvc = (state.get(RVC) == "1") if RVC else False
            flush_active = (FUI is not None and state.get(FUI) == "1")
            if flush_active:
                tracker.on_fetch_dropped(cycle, pc, instr, rvc)
            else:
                tracker.on_fetch(cycle, pc, instr, rvc)

        # 7. Feed the I$ event timeline (independent of the record handlers, as
        # it just observes the I$ FSM and dreq handshake).
        if icache_resolved:
            tracker.icache_timeline.on_cycle(
                cycle,
                state.get(STATE_Q),
                state.get(IC_VLD),
                state.get(IC_VADDR),
                state.get(IC_K2),
            )

        # 7b. Realigner sampling: starts (0→1) counts unaligned RUNS, cycles
        # counts stall cycles. See PipelineTracker.__init__ for why neither
        # equals the wraps_line record count.
        if SVU is not None:
            curr_svu = state.get(SVU)
            if curr_svu == "1":
                tracker.n_realigner_unaligned_cycles += 1
                if last_svu != "1":
                    tracker.n_realigner_unaligned_starts += 1
            last_svu = curr_svu

        # 8. Sample the LSU FSMs (see on_lsu_fsm_sample for the rules).
        if lsu_resolved:
            tracker.on_lsu_fsm_sample(
                cycle,
                state.get(LOAD_STATE),
                state.get(STORE_STATE),
                state.get(LSU_CTRL_TID) if LSU_CTRL_TID else None,
                state.get(POP_LD) if POP_LD else None,
                state.get(POP_ST) if POP_ST else None,
            )

        # 9. Sample HPDcache miss-handler signals into the global cycle-keyed
        # log. Attribution happens after the scan.
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

        # 9b. Sample the flush/wback unit handshakes. They are paired in
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

        # 9c. Log dirty-victim evictions (mshr_alloc with wback=1). These are
        # joined to writebacks by (set, way) in finalize.
        if link_resolved:
            tracker.on_evict_sample(
                cycle,
                state.get(DC_MALLO),
                state.get(EV_WBACK),
                state.get(DC_MNLINE),
                state.get(EV_VWAY),
            )

        # 10. Branch resolution pulse: valid goes high for one cycle at the
        # branch's ex_cycle (or shortly after under contention).
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
        if _PROG is not None and (n_lines & 0x3FFF) == 0:
            _PROG.update(n_lines, len(tracker.completed))
        line = line.rstrip()
        if not line:
            continue
        c0 = line[0]

        if c0 == "#":
            if first_ts_seen:
                curr_clk = state.get(CLK, "0")
                if clk_at_ts_start == "0" and curr_clk == "1":
                    # last_ts is the timestamp BEFORE this rising edge took
                    # effect, i.e. the exact rising-edge time.
                    if first_re_ts is None:
                        first_re_ts = last_ts
                    elif clock_period_ts is None:
                        clock_period_ts = last_ts - first_re_ts
                    at_rising_edge()
            else:
                first_ts_seen = True
            try:
                last_ts = int(line[1:])
            except ValueError:
                pass
            clk_at_ts_start = state.get(CLK) or "0"
            # Snapshot decoded fields BEFORE this timestamp's changes apply, so
            # at_rising_edge() sees pre-edge values if the next `#` reveals a
            # rising edge here.
            if DFU:
                pre_dfu = state.get(DFU)
            if DRS1:
                pre_drs1 = state.get(DRS1)
            if DRS2:
                pre_drs2 = state.get(DRS2)
            if DRD:
                pre_drd = state.get(DRD)
            if DBP_CF:
                pre_dbp_cf = state.get(DBP_CF)
            if DBP_TGT:
                pre_dbp_tgt = state.get(DBP_TGT)
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
            # Pre-edge writeback bus snapshot (see pre_wtv above for why).
            if WTV:
                pre_wtv = state.get(WTV)
            if TID_MAP:
                pre_tids = {port: state.get(vid)
                            for port, vid in TID_MAP.items()}

            if n_lines - last_report >= 10_000_000:
                elapsed = time.time() - start
                stagelog(
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

    # Bind I$ timeline events onto records by 4-byte-aligned PC.
    n_ic_events = len(tracker.icache_timeline.events)
    n_ic_hits = sum(1 for ev in tracker.icache_timeline.events
                    if not ev.ic_miss)
    n_ic_misses = n_ic_events - n_ic_hits
    n_matched, n_unmatched, n_wraps_with_hi, n_rebound, n_synth = match_records_to_events(
        tracker.completed, tracker.icache_timeline.events)
    extra = []
    if n_rebound:
        extra.append(f"{n_rebound} rebound")
    if n_synth:
        extra.append(f"{n_synth} synthesized (cached, no fresh event)")
    extra_str = (", " + ", ".join(extra)) if extra else ""
    stagelog(f"Phase 4b: {n_ic_events} I$ events "
             f"({n_ic_hits} hits, {n_ic_misses} misses). "
             f"{n_matched} records matched, {n_unmatched} unmatched"
             + extra_str,
             file=sys.stderr)
    # wraps_line summary: cross-validate the PC-determinative count against
    # the realigner pulse counter (agree up to flushed-mid-realignment cases).
    n_wraps = sum(1 for r in tracker.completed if r.wraps_line)
    n_wraps_committed = sum(1 for r in tracker.completed
                            if r.wraps_line and not r.flushed)
    if tracker.n_realigner_unaligned_starts:
        records_per_run = (
            f"records/run = "
            f"{n_wraps / tracker.n_realigner_unaligned_starts:.2f}")
    else:
        records_per_run = "records/run = N/A"
    stagelog(f"Phase 8b: wraps_line records = {n_wraps} total "
             f"({n_wraps_committed} committed, "
             f"{n_wraps - n_wraps_committed} flushed). "
             f"{n_wraps_with_hi} bound second fetch (if1_hi/if2_hi). "
             f"Realigner: {tracker.n_realigner_unaligned_starts} runs "
             f"(0→1 transitions), {tracker.n_realigner_unaligned_cycles} "
             f"stall cycles. {records_per_run}.",
             file=sys.stderr)

    # Attribute bubbles to their causer + recovery instructions.
    bubble_counts, bubble_diag = tag_branch_bubbles(tracker.completed)
    n_bub_total = sum(bubble_counts.values())
    n_bub_flushed_total = sum(r.bubble_caused_cycles or 0
                              for r in tracker.completed
                              if r.bubble_caused_cycles)
    stagelog(f"Phase 8c: branch bubbles. "
             f"mispred={bubble_counts['mispred']}, "
             f"unpred={bubble_counts['unpred']}, "
             f"flush_other={bubble_counts['flush_other']}, "
             f"pred_taken={bubble_counts['pred_taken']} "
             f"({n_bub_total} causers, {n_bub_flushed_total} total "
             f"wrong-path records flushed).",
             file=sys.stderr)
    # Accounting tripwire:
    #   total = flushed + classified + no_followers + end_of_trace + unaccounted
    # "unaccounted" must be 0. A nonzero value means some bp_mispredict=True
    # record fell through every category.
    classified = bubble_counts["mispred"] + bubble_counts["unpred"]
    unaccounted = (bubble_diag["bp_mispredict_total"]
                   - bubble_diag["bp_mispredict_flushed"]
                   - classified
                   - bubble_diag["bp_mispredict_no_followers"]
                   - bubble_diag["bp_mispredict_end_of_trace"])
    stagelog(f"Phase 8c diag: {bubble_diag['bp_mispredict_total']} records "
             f"have bp_mispredict=True "
             f"({bubble_diag['bp_mispredict_flushed']} flushed, "
             f"{classified} tagged as causers, "
             f"{bubble_diag['bp_mispredict_no_followers']} had no "
             f"flushed followers, "
             f"{bubble_diag['bp_mispredict_end_of_trace']} were end-of-trace, "
             f"{unaccounted} unaccounted).",
             file=sys.stderr)

    # Count LOAD/STORE records with an FSM trace (lsu_state_history non-empty).
    # Untraced means the FSM never moved while the record was pending, which
    # only happens on an immediate flush.
    n_load_traced = 0
    n_load_untraced = 0
    n_store_traced = 0
    n_store_untraced = 0
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
    stagelog(f"Phase 6a: LSU FSM traces. "
             f"loads {n_load_traced} traced / {n_load_untraced} untraced. "
             f"stores {n_store_traced} traced / {n_store_untraced} untraced",
             file=sys.stderr)

    # Phase 6b: attribute D$ events to records.
    if dcache_resolved:
        dc_stats = tracker.attribute_dc_events_to_records()
        stagelog(
            f"Phase 6b: D$ events. {dc_stats['total_dc_events']} total "
            f"alloc/check/refill_rsp pulses. "
            f"{dc_stats['rfsm_active_cycles']} refill-active cycles. "
            f"Per-record summary: "
            f"{dc_stats['n_primary_miss_loads']} primary-miss / "
            f"{dc_stats['n_coalesced_loads']} coalesced / "
            f"{dc_stats['n_refill_overlap_loads']} refill-overlap "
            f"(of {dc_stats['n_loads']} LOAD + "
            f"{dc_stats['n_stores']} STORE)",
            file=sys.stderr)
        # Perf-counter-equivalent miss breakdown by allocating adapter. The
        # store adapter typically dominates because loads coalesce onto
        # pending store misses via st1_mshr_hit_i.
        stagelog(
            f"Phase 6b: D$ miss events (perf counter view). "
            f"{dc_stats['n_dcache_miss_events_total']} total non-prefetch allocs "
            f"({dc_stats['n_dcache_miss_events_loads']} from LOAD adapter, "
            f"{dc_stats['n_dcache_miss_events_stores']} from STORE adapter, "
            f"{dc_stats['n_dcache_miss_events_other']} from PTW/accel/CMO)",
            file=sys.stderr)
    else:
        dc_stats = {}

    # Branch prediction stats. A branch is any fu=CTRL_FLOW record. "predicted"
    # means bp_predicted_cf is set and not 'NoCF', and "resolved" means
    # bp_resolution_cycle is set.
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
            # Flushed before the scan saw its resolution pulse. Possible when
            # the resolution cycle coincides with the flush handshake.
            n_misp_flushed_before_resolve += 1
    bp_hit_rate = (
        100.0 * (n_resolved - n_misp) / n_resolved if n_resolved else 0.0)
    stagelog(
        f"Phase 7a: branches. {n_cf} CTRL_FLOW records. "
        f"{n_pred} got a non-NoCF prediction "
        f"({n_pred_by_cf}). "
        f"{n_resolved} reached resolution. "
        f"{n_misp} mispredicts ({n_misp_by_cf}). "
        f"hit rate {bp_hit_rate:.1f}%"
        + (f". {n_misp_flushed_before_resolve} flushed before resolve"
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
        stagelog(
            f"Phase 7b: writebacks. {wb_stats['n_allocs']} alloc / "
            f"{wb_stats['n_sends']} send / {wb_stats['n_acks']} ack. "
            f"{wb_stats['matched_pairs']} paired "
            f"({wb_stats['acks_no_prior_send']} acks w/o send, "
            f"{wb_stats['sends_never_acked']} sends unacked). "
            f"AXI write latency: "
            f"min={awl.get('min')} median={awl.get('median')} "
            f"max={awl.get('max')} cyc",
            file=sys.stderr)
        stagelog(
            f"Phase 7b: writeback<->eviction linkage. "
            f"{wb_stats.get('n_evictions', 0)} eviction samples. "
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
            if via == "sb":
                n_via_sb += 1
                used = True
            elif via == "wb":
                n_via_wb += 1
                used = True
        if r.fwd_rs1_used:
            n_fwd_rs1 += 1
        if r.fwd_rs2_used:
            n_fwd_rs2 += 1
        if r.fwd_rs3_used:
            n_fwd_rs3 += 1
        if used:
            n_fwd_any += 1
    n_committed_seen = sum(1 for r in tracker.completed if not r.flushed)
    fwd_stats = {
        "n_committed_seen":   n_committed_seen,
        "n_with_any_forward": n_fwd_any,
        "n_rs1_forwarded":    n_fwd_rs1,
        "n_rs2_forwarded":    n_fwd_rs2,
        "n_rs3_forwarded":    n_fwd_rs3,
        "n_via_sb":           n_via_sb,
        "n_via_wb":           n_via_wb,
        # Ground truth for whether via=wb should ever fire: real forwards
        # (fwd_rsX_used=True) whose producer slot was on the wb bus that cycle.
        "n_issue_cycles":             tracker._diag_n_issue_cycles,
        "n_issue_cycles_with_any_wb": tracker._diag_n_issue_with_any_wb,
        "n_real_match_rs1":           tracker._diag_n_real_match_rs1,
        "n_real_match_rs2":           tracker._diag_n_real_match_rs2,
        "n_real_match_rs3":           tracker._diag_n_real_match_rs3,
    }
    if n_committed_seen:
        pct = 100.0 * n_fwd_any / n_committed_seen
        stagelog(
            f"Phase 8a: forwarding - {n_fwd_any}/{n_committed_seen} "
            f"committed records ({pct:.1f}%) used at least one forwarded "
            f"operand. Rs1={n_fwd_rs1} rs2={n_fwd_rs2} rs3={n_fwd_rs3}. "
            f"via sb/wb = {n_via_sb}/{n_via_wb}",
            file=sys.stderr)
        n_real_match_total = (
            tracker._diag_n_real_match_rs1
            + tracker._diag_n_real_match_rs2
            + tracker._diag_n_real_match_rs3)
        stagelog(
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
        # Scoreboard depth detected from the mem_q[N].sbe.fu presence scan.
        # Consumers should prefer this over the compile-time default in
        # CV64A6_HPDC_WB_DEFAULTS when reporting per-run configuration.
        "detected_nr_sb_entries": NR_SB,
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
        # Clock period in VCD timescale units (ps for cva6_testharness sims),
        # from the first two rising edges. None if fewer than two were seen.
        "clock_period_ts": clock_period_ts,
        "first_rising_edge_ts": first_re_ts,
        # CSR-equivalent access cycle lists: cycles where the request signal
        # was high. Counting entries in [cMin, cMax] matches the hardware perf
        # counters exactly. Empty when the signals weren't resolved.
        "ic_access_cycles": ic_access_cycles,
        "dc_access_cycles": dc_access_cycles,
        # I$ miss_o high cycles, where len() matches perf_counters.sv event 1,
        # wrong-path fills included.
        "icache_miss_cycles": icache_miss_cycles,
        "icache_miss_pulses": len(icache_miss_cycles),
    }
    return tracker, stats


# ============================================================================
# Disassembly listing
# ============================================================================
#
# Binds a human-readable disasm string onto each InstructionRecord from a
# pre-built objdump -dS listing passed via --disasm-list, so the tracer has
# no RISC-V toolchain dependency.
#
# The regex intentionally requires LEADING WHITESPACE on the PC line so the
# all-hex 64-bit address labels (which start at column 0) never match. Source
# lines, labels, section headers and directives start with characters outside
# [0-9a-f], so they never match either.

_DISASM_LINE_RE = re.compile(
    r'^\s+([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s+(.+)$'
)


def parse_disasm_list(path):
    """Parse an objdump-style disassembly listing into a PC→string map.

    Maps integer PC to a compact "mnemonic operands" string with whitespace
    runs collapsed. Permissive by design: non-instruction lines are ignored.
    Raises FileNotFoundError if the path doesn't exist."""
    disasm = {}
    with open(path) as f:
        for line in f:
            m = _DISASM_LINE_RE.match(line.rstrip('\n'))
            if not m:
                continue
            pc = int(m.group(1), 16)
            # group(3) is everything after the raw bytes: mnemonic + operands
            # + any objdump-resolved symbolic comment.
            text = re.sub(r'\s+', ' ', m.group(3)).strip()
            disasm[pc] = text
    return disasm


def apply_disasm(records, disasm_map):
    """Annotate each record's `disasm` field by PC lookup.

    Returns (n_annotated, n_no_pc, n_unmapped), where n_unmapped covers PCs
    outside the listing, e.g. bootrom code at 0x10000 not part of the user
    ELF."""
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
    # Mirrors the module-level Config block (which is the single source
    # of truth driving the whitelist + lookups). Cache geometry rows
    # are kept as literals because they only feed the viewer's config
    # panel and don't gate any tracer logic.
    "SuperscalarEn":       SUPERSCALAR_EN,
    "RVC":                 RVC_EN,
    "CvxifEn":             True,
    "NrIssuePorts":        NR_ISSUE_PORTS,
    "NrCommitPorts":       NR_COMMIT_PORTS,
    "NrWbPorts":           NR_WB_PORTS,
    "NrScoreboardEntries": NR_SB_ENTRIES,
    "TRANS_ID_BITS":       TRANS_ID_BITS,
    "FETCH_WIDTH":         FETCH_WIDTH,
    "INSTR_PER_FETCH":     INSTR_PER_FETCH,
    # I-cache geometry. cv64a6_imafdc_sv39_hpdcache_wb canonical values:
    # 16 KiB total, 4-way, 128-bit lines, 256 sets.
    "ICACHE_LINE_WIDTH":   128,
    "ICACHE_SET_ASSOC":    4,
    "ICACHE_NUM_SETS":     256,
    # D-cache geometry: 32 KiB, 8-way, 128-bit lines, 256 sets.
    "DCACHE_LINE_WIDTH":   128,
    "DCACHE_SET_ASSOC":    8,
    "DCACHE_NUM_SETS":     256,
}


# Subset of CV64A6_HPDC_WB_DEFAULTS emitted to the JSON's config_params. The
# rest are tracer assumptions rather than measurements, and stay out so the
# viewer's panel can't contradict the actual build (parameter sweeps vary
# DcacheSetAssoc, NrLoadBufEntries, etc.). Two tiers qualify a field:
#   Tier 1, auto-detected from the VCD: NrScoreboardEntries (probed from the
#     mem_q[N] enumeration) and TRANS_ID_BITS ($clog2 of it).
#   Tier 2, verified by trace success. A different value would break the
#     whitelist or produce garbage: NrCommitPorts, NrWbPorts, and
#     FETCH_WIDTH / INSTR_PER_FETCH (realign + wraps_line assume 32-bit
#     fetch with RVC pairs).
# To add a field: probe it (Tier 1) or argue structural verification (Tier 2).
VERIFIED_CONFIG_FIELDS = frozenset({
    # Tier 1, auto-detected from the VCD.
    "NrScoreboardEntries",
    "TRANS_ID_BITS",
    # Auto-detected from the largest probed commit_pointer_q / trans_id_i port
    # index plus one: a smaller build omits the high ports from the dump, so
    # these follow the actual build rather than the compile-time maxima.
    "NrCommitPorts",
    "NrWbPorts",
    "FETCH_WIDTH",
    "INSTR_PER_FETCH",
})


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
        # Time base: cycle duration in VCD timescale units plus the VCD's
        # $timescale value, together enough to convert cycles to real time.
        "clock_period_ts": stats.get("clock_period_ts"),
        "timescale_unit": stats.get("timescale_unit"),
        "stats": {
            "n_committed": tracker.n_committed,
            "n_flushed_if": tracker.n_flushed_if,
            "n_flushed_id": tracker.n_flushed_id,
            "n_flushed_ex": tracker.n_flushed_ex,
            "n_unmatched_writebacks": tracker.n_unmatched_writebacks,
            "n_unmatched_commits": tracker.n_unmatched_commits,
            "icache_event_count": stats.get("icache_event_count", 0),
            "icache_event_hits": stats.get("icache_event_hits", 0),
            "icache_event_misses": stats.get("icache_event_misses", 0),
            # miss_o high cycles = perf_counters.sv event 1, which unlike
            # icache_event_misses includes wrong-path fills squashed before
            # delivery. The per-cycle list is top-level.
            "icache_miss_pulses": stats.get("icache_miss_pulses", 0),
            "icache_records_matched": stats.get(
                "icache_records_matched", 0),
            "icache_records_unmatched": stats.get(
                "icache_records_unmatched", 0),
            "disasm_annotated": stats.get("disasm_annotated", 0),
            "disasm_unmapped": stats.get("disasm_unmapped", 0),
            "disasm_no_pc": stats.get("disasm_no_pc", 0),
            "lsu_load_records_traced": stats.get(
                "lsu_load_records_traced", 0),
            "lsu_store_records_traced": stats.get(
                "lsu_store_records_traced", 0),
            "lsu_load_records_untraced": stats.get(
                "lsu_load_records_untraced", 0),
            "lsu_store_records_untraced": stats.get(
                "lsu_store_records_untraced", 0),
            "phase6b": stats.get("phase6b", {}),   # D$ event attribution
            "phase7a": stats.get("phase7a", {}),   # branch prediction
            "phase7b": stats.get("phase7b", {}),   # writeback + AXI latency
            "phase8a": stats.get("phase8a", {}),   # forwarding aggregates
        },
    }
    # Compile-time defaults, then runtime-detected overrides, then filtered to
    # VERIFIED_CONFIG_FIELDS (see its comment for why unverified keys drop).
    config_params = dict(CV64A6_HPDC_WB_DEFAULTS)
    detected_sb = stats.get("detected_nr_sb_entries")
    if detected_sb is not None:
        config_params["NrScoreboardEntries"] = detected_sb
        config_params["TRANS_ID_BITS"] = (detected_sb - 1).bit_length()
    detected_cp = stats.get("detected_nr_commit_ports")
    if detected_cp is not None:
        config_params["NrCommitPorts"] = detected_cp
    detected_wb = stats.get("detected_nr_wb_ports")
    if detected_wb is not None:
        config_params["NrWbPorts"] = detected_wb
    config_params = {k: v for k, v in config_params.items()
                     if k in VERIFIED_CONFIG_FIELDS}
    with output_path.open("w") as f:
        f.write("{\n")
        f.write(f'  "metadata": {json.dumps(metadata, indent=2)},\n')
        f.write(f'  "config_params": {json.dumps(config_params, indent=2)},\n')
        f.write(f'  "buffer_maxima": {json.dumps({})},\n')
        f.write('  "instructions": [\n')
        recs = tracker.completed
        for i, rec in enumerate(recs):
            d = asdict(rec)
            comma = "," if i < len(recs) - 1 else ""
            f.write(f"    {json.dumps(d)}{comma}\n")
        f.write("  ],\n")
        # Dirty-victim writebacks are a separate track, not per-instruction: a
        # writeback is per-evicted-line, many stores coalesce into one line,
        # and it is decoupled in time from those stores.
        wbs = tracker.writeback_events
        f.write('  "writebacks": [\n')
        for i, wb in enumerate(wbs):
            comma = "," if i < len(wbs) - 1 else ""
            f.write(f"    {json.dumps(wb)}{comma}\n")
        f.write("  ],\n")
        # Flat dcache MSHR alloc array for the viewer's window-scoped
        # perf-counter-equivalent miss count, including PTW (sid=0), accel
        # (sid=2) and CMO misses that map to no instruction record. Only
        # allocs: check_hit and refill_rsp are not perf-counter sources.
        allocs = [ev for ev in tracker._dc_events if ev.get("type") == "alloc"]
        f.write('  "dcache_alloc_events": [\n')
        for i, ev in enumerate(allocs):
            comma = "," if i < len(allocs) - 1 else ""
            row = {"cycle": ev["cycle"], "sid": ev.get(
                "sid"), "pf": ev.get("pf", 0)}
            f.write(f"    {json.dumps(row)}{comma}\n")
        f.write("  ],\n")
        # Flat icache event array so the viewer can window icache access/miss
        # counts straight from the cache FSM signal, sidestepping any
        # record-derived dedup ambiguity.
        ic_events = tracker.icache_timeline.events
        f.write('  "icache_events": [\n')
        for i, ev in enumerate(ic_events):
            comma = "," if i < len(ic_events) - 1 else ""
            row = {"fe1": ev.fe1_cycle, "fe2": ev.fe2_cycle, "miss": ev.ic_miss}
            f.write(f"    {json.dumps(row)}{comma}\n")
        f.write("  ],\n")
        # CSR-equivalent access cycle lists (I$: icache_dreq_o.req, D$: any of
        # the three core ports' data_req). Filtering by [cMin, cMax] in the
        # viewer lines up exactly with mhpmevent 16/17
        # (perf_counters.sv:126-128).
        ic_acc = stats.get("ic_access_cycles") or []
        dc_acc = stats.get("dc_access_cycles") or []
        ic_miss_cyc = stats.get("icache_miss_cycles") or []
        f.write('  "ic_access_cycles": ' + json.dumps(ic_acc) + ',\n')
        f.write('  "dc_access_cycles": ' + json.dumps(dc_acc) + ',\n')
        f.write('  "icache_miss_cycles": ' + json.dumps(ic_miss_cyc) + '\n')
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
        # drop array index suffix for search
        last_seg = last_seg.split("[")[0]
        print(f"  - {m['whitelist_path']}", file=sys.stderr)
        cands = [p for p in path_to_id if last_seg in p]
        for c in cands[:5]:
            print(f"      candidate: {c}", file=sys.stderr)
        if len(cands) > 5:
            print(f"      ... And {len(cands) - 5} more", file=sys.stderr)
        if not cands:
            print(
                f"      (no VCD path contains '{last_seg}')", file=sys.stderr)
    return [m["whitelist_path"] for m in missing]


# ============================================================================
# Main
# ============================================================================

def main():
    global _SHOW_STAGES, _PROG
    parser = argparse.ArgumentParser(
        description="Extracts per-instruction pipeline data from a CVA6 "
                    "Verilator VCD and emits JSON for the CVA6Flow viewer.",
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
        help="Output JSON path. Defaults to <vcd_basename>.json.",
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
             "typically the `jal ra, <exit>`). Emitted to metadata.user_end_pc. "
             "the viewer's `Main code` button reads it as the upper bound of "
             "the user-program range.",
    )
    parser.add_argument(
        "--disasm-list",
        default=None,
        help="Path to an objdump -dS listing of the test ELF. When provided, "
             "each record's `disasm` field is populated by PC lookup. "
             "Records whose PC falls outside the listing (e.g. Bootrom) "
             "keep disasm=None.",
    )
    parser.add_argument(
        "--stages", action="store_true",
        help="Show the per-stage resolution diagnostics on stderr (verbose).",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the streaming progress indicator.",
    )
    args = parser.parse_args()
    _SHOW_STAGES = args.stages

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD file not found: {vcd_path}")
    args.vcd_path = vcd_path

    out_path = Path(
        args.output) if args.output else vcd_path.with_suffix(".json")

    n_wb_ports = CV64A6_HPDC_WB_DEFAULTS["NrWbPorts"]
    n_commit_ports = CV64A6_HPDC_WB_DEFAULTS["NrCommitPorts"]

    file_size = vcd_path.stat().st_size
    print(
        f"[INFO] Reading {vcd_path} ({file_size / (1024 ** 3):.3f} GB)", file=sys.stderr)
    if args.user_entry_pc:
        print(f"[INFO] User entry PC: {args.user_entry_pc}", file=sys.stderr)
    start = time.time()

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, timescale = parse_var_block(f)
        print(
            f"[INFO] Header: {len(path_to_id):,} signals, timescale={timescale}", file=sys.stderr)

        # Pre-flight: refuse VCDs whose scoreboard exceeds the compile-time
        # max. The SMALLER case is auto-handled in stream_and_extract. The
        # LARGER case cannot be, because the whitelist only enumerates slots
        # 0..NR_SB_ENTRIES-1 and higher slots would silently produce wrong
        # output.
        max_sb_slot = probe_max_scoreboard_slot(path_to_id)
        if max_sb_slot >= NR_SB_ENTRIES:
            actual_depth = max_sb_slot + 1
            # NrScoreboardEntries is enforced to be a power of 2 by
            # scoreboard.sv:323, but round up defensively.
            next_pow2 = 1 << (
                actual_depth - 1).bit_length() if actual_depth > 1 else 1
            print(file=sys.stderr)
            print(f"ERROR: VCD contains mem_q[{max_sb_slot}].sbe.fu, implying "
                  f"the build has NrScoreboardEntries >= {actual_depth}, but "
                  f"this tracer was compiled with NR_SB_ENTRIES="
                  f"{NR_SB_ENTRIES}. The whitelist only enumerates slots "
                  f"0..{NR_SB_ENTRIES-1}, so transactions assigned to slots "
                  f"{NR_SB_ENTRIES}..{actual_depth-1} would silently go "
                  f"untracked. The output JSON would have missing writebacks, "
                  f"displaced FU types, and incorrect branch prediction.",
                  file=sys.stderr)
            print(f"To fix: edit NR_SB_ENTRIES near the top of this file "
                  f"(currently {NR_SB_ENTRIES}) to at least {next_pow2}, then "
                  f"rerun. Must be a power of 2.",
                  file=sys.stderr)
            print("Aborting.", file=sys.stderr)
            return 2

        # Pre-flight: refuse superscalar builds. The decode+issue handshake,
        # IPTR tracking and per-cycle allocation all assume one instruction per
        # cycle. A superscalar build would silently drop port-1 instructions,
        # drift the fetched/decoded queues from the first multi-issue cycle,
        # and apply the FETCH_BYTES=4 wraps_line predicate to 8-byte blocks.
        if probe_superscalar(path_to_id):
            print(file=sys.stderr)
            print("ERROR: VCD contains decoded_instr_i[1].fu, implying the "
                  "build has SuperscalarEn=1 (NrIssuePorts > 1). This tracer "
                  "is hardcoded for single-issue and would silently produce "
                  "wrong output (port-1 instructions dropped, fetched/decoded "
                  "queues drifting, wraps_line predicate using FETCH_BYTES=4 "
                  "against 8-byte fetch blocks).",
                  file=sys.stderr)
            print("To fix: superscalar support is non-trivial. Required "
                  "changes include iterating decoded_instr_i[0..NrIssuePorts-1]"
                  " in the WHITELIST and decode+issue handler, reading "
                  "multiple trans_ids per cycle, and updating FETCH_WIDTH + "
                  "the wraps_line predicate for 64-bit fetches.",
                  file=sys.stderr)
            print("Aborting.", file=sys.stderr)
            return 2

        # Pre-flight: refuse builds with more commit ports than the whitelist
        # enumerates. Commits on the extra ports would silently vanish,
        # leaving records that never commit and inflated unmatched counters.
        # Smaller builds are fine (unused slots stay None at runtime).
        max_cp = probe_max_commit_port(path_to_id)
        if max_cp >= NR_COMMIT_PORTS:
            actual = max_cp + 1
            print(file=sys.stderr)
            print(f"ERROR: VCD contains commit_pointer_q[{max_cp}], implying "
                  f"the build has NrCommitPorts >= {actual}, but this tracer "
                  f"was compiled with NR_COMMIT_PORTS={NR_COMMIT_PORTS}. The "
                  f"whitelist only enumerates ports 0..{NR_COMMIT_PORTS-1}, "
                  f"so commits on ports {NR_COMMIT_PORTS}..{actual-1} would "
                  f"silently go untracked.",
                  file=sys.stderr)
            print(f"To fix: edit NR_COMMIT_PORTS near the top of this file "
                  f"(currently {NR_COMMIT_PORTS}) to {actual} and rerun.",
                  file=sys.stderr)
            print("Aborting.", file=sys.stderr)
            return 2

        # Same check for writeback ports (trans_id_i[0..NR_WB_PORTS-1]), where
        # unenumerated ports would leave records orphaned in flight.
        max_wb = probe_max_wb_port(path_to_id)
        if max_wb >= NR_WB_PORTS:
            actual = max_wb + 1
            print(file=sys.stderr)
            print(f"ERROR: VCD contains trans_id_i[{max_wb}], implying the "
                  f"build has NrWbPorts >= {actual}, but this tracer was "
                  f"compiled with NR_WB_PORTS={NR_WB_PORTS}. The whitelist "
                  f"only enumerates ports 0..{NR_WB_PORTS-1}, so writebacks "
                  f"on ports {NR_WB_PORTS}..{actual-1} would silently go "
                  f"untracked, leaving records orphaned in flight.",
                  file=sys.stderr)
            print(f"To fix: edit NR_WB_PORTS near the top of this file "
                  f"(currently {NR_WB_PORTS}) to {actual} and rerun.",
                  file=sys.stderr)
            print("Aborting.", file=sys.stderr)
            return 2

        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        missing_paths = report_missing(matches, path_to_id)

        found = {m["whitelist_path"] for m in matches if m["vcd_ids"]}
        missing_required = REQUIRED_SIGNALS - found
        if missing_required:
            print()
            for s in sorted(missing_required):
                print(
                    f"ERROR: required signal '{s}' not found.", file=sys.stderr)
            print("Aborting. Phase 3 cannot proceed.", file=sys.stderr)
            return 2

        tracked = sum(len(m["vcd_ids"]) for m in matches)
        print(f"[INFO] Tracking {tracked} signal IDs across "
              f"{len(matches) - len(missing_paths)}/{len(matches)} whitelist groups", file=sys.stderr)
        print("[parse] streaming VCD body\u2026", file=sys.stderr)
        _PROG = Progress('parse', enabled=not args.quiet)
        tracker, stats = stream_and_extract(
            f, matches, args, n_wb_ports, n_commit_ports)
        # The output writer builds metadata outside this `with` block and
        # doesn't otherwise see the timescale.
        stats["timescale_unit"] = timescale
        # Surface the probed port counts so the writer reports the build's
        # ACTUAL NrCommitPorts / NrWbPorts: a smaller build omits the high
        # ports from the VCD, so the compile-time defaults would overstate
        # them (a 1-commit-port build wrongly showing 2). The probe returns -1
        # when absent, in which case the default stands.
        if max_cp >= 0:
            stats["detected_nr_commit_ports"] = max_cp + 1
        if max_wb >= 0:
            stats["detected_nr_wb_ports"] = max_wb + 1

    if _PROG is not None:
        _PROG.done()
    elapsed = time.time() - start
    # Known limitation: the first-two-rising-edges interval can pick up a
    # sub-cycle artifact during reset / initial value setup instead of a real
    # cycle, so the pretty-print is gated on plausibility (period >= 1 ns,
    # i.e. clock < 1 GHz) to avoid nonsense like "2 ps / 500 GHz". Diagnostic
    # only: the viewer ignores this field and hardcodes 50 MHz.
    cp_ts = stats.get("clock_period_ts")
    if cp_ts is not None and cp_ts >= 1000:  # >= 1 ns, plausible cycle
        ts_unit = stats.get("timescale_unit", "1ps")
        # Best-effort timescale→ps conversion. Unrecognized units print raw.
        unit_to_ps = {"1fs": 1e-3, "1ps": 1, "1ns": 1e3,
                      "1us": 1e6, "1ms": 1e9, "1s": 1e12}
        ps = cp_ts * unit_to_ps.get(ts_unit.strip(), 1)
        if ps >= 1e6:
            period_disp = f"{ps/1e6:.3f} us"
        elif ps >= 1e3:
            period_disp = f"{ps/1e3:.3f} ns"
        else:
            period_disp = f"{ps:.0f} ps"
        freq_disp = (f"{1e6/ps:.3f} MHz" if ps > 0 else "?")
        print(f"[INFO] clock period {period_disp} ({freq_disp}), "
              f"timescale {ts_unit}", file=sys.stderr)
    elif cp_ts is not None:
        # Implausibly short: first-edge detection tripped on a reset-time
        # sub-cycle event, so don't pretty-print the bogus frequency.
        print(f"[INFO] clock period: detected {cp_ts} VCD ticks (implausibly "
              f"short. First-edge detection tripped on a sub-cycle "
              f"artifact). Viewer will use its hardcoded 50 MHz.",
              file=sys.stderr)
    else:
        print("[INFO] clock period: could not determine "
              "(need at least 2 rising edges)", file=sys.stderr)

    # Whole-trace totals. These should match hardware perf counters mhpmevent
    # 16 (l1_icache_access) and 17 (l1_dcache_access) exactly.
    ic_acc_total = len(stats.get("ic_access_cycles") or [])
    dc_acc_total = len(stats.get("dc_access_cycles") or [])
    if ic_acc_total or dc_acc_total:
        print(f"[INFO] CSR-equivalent accesses (whole trace): "
              f"I-cache={ic_acc_total:,}  D-cache={dc_acc_total:,}",
              file=sys.stderr)
    ic_miss_total = len(stats.get("icache_miss_cycles") or [])
    if ic_miss_total:
        print(f"[INFO] RTL-counter I-cache misses (miss_o pulses, whole "
              f"trace): {ic_miss_total:,}", file=sys.stderr)

    # Annotate with disassembly after the walk, so we cover exactly the
    # records that will be serialized (committed + flushed).
    if args.disasm_list:
        disasm_path = Path(args.disasm_list)
        if not disasm_path.exists():
            print(f"WARNING: --disasm-list {disasm_path} not found. "
                  "skipping disasm annotation.", file=sys.stderr)
            stats["disasm_annotated"] = 0
            stats["disasm_unmapped"] = 0
            stats["disasm_no_pc"] = 0
            stats["disasm_list_path"] = None
        else:
            disasm_map = parse_disasm_list(disasm_path)
            n_ann, n_no_pc, n_unmapped = apply_disasm(
                tracker.completed, disasm_map)
            stagelog(f"Phase 5: parsed {len(disasm_map):,} disasm entries from "
                     f"{disasm_path.name}. Annotated {n_ann:,} records "
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

    if len(tracker.completed) == 0:
        print("[WARNING] No CVA6 instructions were parsed from this VCD. It may "
              "not be a valid CVA6 Verilator VCD, or the expected pipeline and "
              "commit signals were not found in it. Check that the VCD was "
              "generated from a CVA6 simulation with the RVFI and scoreboard "
              "signals dumped.", file=sys.stderr)

    print(f"[write] writing JSON to {out_path}\u2026", file=sys.stderr)
    write_output_json(out_path, args, stats, tracker)

    mb = file_size / (1024 ** 2)
    speed = mb / elapsed if elapsed > 0 else 0.0

    print()
    print("=" * 78)
    print(" CVA6 Tracer. Summary")
    print("=" * 78)
    print(f" Input                 : {vcd_path}")
    print(f" Output                : {out_path}")
    print(
        f" File size             : {file_size:>15,} bytes ({file_size / (1024**3):.3f} GB)")
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
        print(
            f"   annotated records   : {stats.get('disasm_annotated', 0):>15,}")
        print(
            f"   unmapped (no entry) : {stats.get('disasm_unmapped', 0):>15,}")
        if stats.get('disasm_no_pc', 0):
            print(f"   without PC          : {stats['disasm_no_pc']:>15,}")

    if n_total:
        first_user = next(
            (r for r in tracker.completed if not r.is_warmup), None)
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
            print(
                f"   trans_id={first_user.trans_id}, flushed={first_user.flushed}")

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
        print(" FU category. Committed records")
        print(f"   {'category':<10} {'warmup':>8} {'user':>8}")
        cats = sorted(set(cat_warm) | set(cat_user))
        for c in cats:
            print(f"   {c:<10} {cat_warm.get(c, 0):>8} {cat_user.get(c, 0):>8}")
        if fu_user:
            print()
            print(" FU breakdown. User-code committed records")
            for fu, n in fu_user.most_common():
                print(f"   {fu:<12} {n:>5}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
