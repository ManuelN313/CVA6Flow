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

FSM_FLUSH = "000"
FSM_IDLE = "001"
FSM_READ = "010"
FSM_MISS = "011"
FSM_KILL_ATRANS = "100"
FSM_KILL_MISS = "101"


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

PHASE4A_POPULATES = PHASE3_POPULATES | {
    "fu", "fu_category", "rs1", "rs2", "rd"}


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
                        fu_val=None, rs1=None, rs2=None, rd=None):
        """Phase 4a v0.4: combined decode+issue handler. In non-superscalar
        CVA6 the scoreboard's issue_instr_o is a combinational passthrough
        of decoded_instr_i (scoreboard.sv:151), so DV/DA and IV/IA fire as
        a SINGLE handshake. Tracking them as two events causes the issued
        trans_id to be read from IPTR at the wrong cycle whenever the
        pipeline stalls between fetches, putting MY_TID +N ahead of the
        actual HW slot. This handler pops fetched and assigns trans_id in
        one step, using the IPTR value at the cycle the handshake fires —
        which equals the HW slot being allocated.

        ex_cycle is still cycle+1 (CVA6 ALU/FPU pipeline depth invariant).
        """
        if not self.fetched:
            return
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
        self.issued[trans_id] = rec
        # Phase 6a v0.4: no LSU pending-assignment needed here.
        # Correlation happens via lsu_ctrl.trans_id at FSM-transition
        # time in on_lsu_fsm_sample, looking up self.issued[prev_tid].

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
        r1_vid = single_id.get(
            f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs1")
        r2_vid = single_id.get(
            f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rs2")
        rd_vid = single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rd")
        MEMQ_FU[n] = f_vid
        MEMQ_RS1[n] = r1_vid
        MEMQ_RS2[n] = r2_vid
        MEMQ_RD[n] = rd_vid
        if all(v is not None for v in (f_vid, r1_vid, r2_vid, rd_vid)):
            memq_resolved += 1
    MEMQ_AVAILABLE = (memq_resolved == NR_SB)
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
    IC_VLD = single_id.get("i_frontend.icache_dreq_i.valid")
    IC_VADDR = single_id.get("i_frontend.icache_dreq_i.vaddr")
    IC_K2 = single_id.get("i_frontend.icache_dreq_o.kill_s2")
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
    LOAD_STATE = single_id.get("ex_stage_i.lsu_i.i_load_unit.state_q")
    STORE_STATE = single_id.get("ex_stage_i.lsu_i.i_store_unit.state_q")
    # Phase 6a v0.4: lsu_ctrl.trans_id for FSM admission correlation.
    LSU_CTRL_TID = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.trans_id")
    # Phase 6a v0.5: pop_ld / pop_st for admit-while-busy detection.
    POP_LD = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i")
    POP_ST = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i")
    lsu_resolved = (LOAD_STATE is not None and STORE_STATE is not None)
    if not lsu_resolved:
        missing = []
        if LOAD_STATE is None:
            missing.append("i_load_unit.state_q")
        if STORE_STATE is None:
            missing.append("i_store_unit.state_q")
        print("WARNING: Phase 6a LSU signals not all resolved — "
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
                      else f" — degraded (missing: {', '.join(extras)})")
        print("Phase 6a LSU FSM tracking enabled "
              f"(load_unit.state_q + store_unit.state_q + "
              f"lsu_ctrl.trans_id + pop_ld + pop_st){extras_msg}",
              file=sys.stderr)

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
                    ptr_id = CPTR_PORTS[port] if port < len(
                        CPTR_PORTS) else None
                    if ptr_id is not None:
                        tid = binary_to_int(state.get(ptr_id))
                        if tid is not None:
                            mq_fu = mq_rs1 = mq_rs2 = mq_rd = None
                            if MEMQ_AVAILABLE and 0 <= tid < NR_SB:
                                mq_fu = binary_to_int(state.get(MEMQ_FU[tid]))
                                mq_rs1 = binary_to_int(
                                    state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(
                                    state.get(MEMQ_RS2[tid]))
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
                                mq_rs1 = binary_to_int(
                                    state.get(MEMQ_RS1[tid]))
                                mq_rs2 = binary_to_int(
                                    state.get(MEMQ_RS2[tid]))
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
                    tracker.on_decode_issue(cycle, tid,
                                            fu_val, rs1, rs2, rd)

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
    print(f"Phase 6a: LSU FSM traces — "
          f"loads {n_load_traced} traced / {n_load_untraced} untraced; "
          f"stores {n_store_traced} traced / {n_store_untraced} untraced",
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
        "warmup_end_cycle": tracker.warmup_end_cycle,
        "tohost_cycle": None,
        "extractor_version": "phase6a-0.6",
        "vcd_scope_prefix": args.scope_prefix,
        "phase": "6a",
        "phase4a_populated_fields": sorted(PHASE4A_POPULATES),
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
        },
    }
    with output_path.open("w") as f:
        f.write("{\n")
        f.write(f'  "metadata": {json.dumps(metadata, indent=2)},\n')
        f.write(
            f'  "config_params": {json.dumps(CV64A6_HPDC_WB_DEFAULTS, indent=2)},\n')
        f.write(f'  "buffer_maxima": {json.dumps({})},\n')
        f.write('  "instructions": [\n')
        recs = tracker.completed
        for i, rec in enumerate(recs):
            d = asdict(rec)
            comma = "," if i < len(recs) - 1 else ""
            f.write(f"    {json.dumps(d)}{comma}\n")
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
        # drop array index suffix for search
        last_seg = last_seg.split("[")[0]
        print(f"  - {m['whitelist_path']}", file=sys.stderr)
        cands = [p for p in path_to_id if last_seg in p]
        for c in cands[:5]:
            print(f"      candidate: {c}", file=sys.stderr)
        if len(cands) > 5:
            print(f"      ... and {len(cands) - 5} more", file=sys.stderr)
        if not cands:
            print(
                f"      (no VCD path contains '{last_seg}')", file=sys.stderr)
    return [m["whitelist_path"] for m in missing]


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 3 pipeline tracer for the CVA6 pipeline viewer.",
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

    out_path = Path(args.output) if args.output else vcd_path.with_suffix(
        ".phase3.json")

    n_wb_ports = CV64A6_HPDC_WB_DEFAULTS["NrWbPorts"]
    n_commit_ports = CV64A6_HPDC_WB_DEFAULTS["NrCommitPorts"]

    file_size = vcd_path.stat().st_size
    print(f"Opening {vcd_path} ({file_size / (1024 ** 3):.3f} GB)...")
    if args.user_entry_pc:
        print(f"User entry PC: {args.user_entry_pc}")
    start = time.time()

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, timescale = parse_var_block(f)
        print(
            f"Header parsed: {len(path_to_id):,} signals, timescale={timescale}")

        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        missing_paths = report_missing(matches, path_to_id)

        found = {m["whitelist_path"] for m in matches if m["vcd_ids"]}
        missing_required = REQUIRED_SIGNALS - found
        if missing_required:
            print()
            for s in sorted(missing_required):
                print(
                    f"ERROR: required signal '{s}' not found.", file=sys.stderr)
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
