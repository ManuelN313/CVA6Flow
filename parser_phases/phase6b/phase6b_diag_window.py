#!/usr/bin/env python3
"""Phase 6b HPDcache miss/refill diagnostic.

Walks a CVA6 VCD over a specified cycle window and dumps per-cycle the
signals relevant to Phase 6b's D$ event correlation: MSHR allocation,
miss request FSM, refill FSM, and refill response.

The aim is to confirm two things before writing tracer code:

1. The signals are exposed in the VCD at the paths we expect
   (hierarchy: i_cache_subsystem.i_dcache.i_hpdcache.hpdcache_miss_handler_i.*)

2. The timing relationships hold: mshr_alloc_i pulses with a tid
   that maps to a known in-flight LOAD; later, refill_core_rsp_valid_o
   pulses with the same tid.

Usage:
  python3 p6b_diag_window.py fdiv.vcd --start 800 --end 850

Per-cycle columns:
  cyc    : cycle number
  LSU    : load_unit.state_q (for context — when admission happens)
  lsuTID : lsu_ctrl.trans_id (for context — which load is being presented)
  mAllo  : mshr_alloc_i           (1 when MSHR is being allocated)
  mTID   : mshr_alloc_tid_i       (trans_id of the allocating load)
  mNline : mshr_alloc_nline_i     (cache-line address; hex, low 16 bits)
  mFSM   : miss_req_fsm_q         (IDL=MISS_REQ_IDLE  SND=MISS_REQ_SEND)
  rFSM   : refill_fsm_q           (IDL=REFILL_IDLE  WR=REFILL_WRITE
                                   WD=REFILL_WRITE_DIR  IV=REFILL_INVAL)
  rRsp   : refill_core_rsp_valid_o (1 when refill is being sent to LSU)
  rTID   : refill_core_rsp_o.tid   (trans_id of the responded refill)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from phase3_pipeline_tracer import (
    parse_var_block, match_whitelist, binary_to_int,
    LOAD_FSM_NAMES,
)


# Names mirror what's declared in hpdcache_miss_handler.sv lines 149-159.
MISS_REQ_FSM = {0: "MISS_REQ_IDLE", 1: "MISS_REQ_SEND"}
REFILL_FSM   = {0: "REFILL_IDLE", 1: "REFILL_WRITE",
                2: "REFILL_WRITE_DIR", 3: "REFILL_INVAL"}


WHITELIST = [
    "clk_i",
    # Phase 6a context — keeps us oriented to which load is in the
    # LSU FSM when miss/refill events fire.
    "ex_stage_i.lsu_i.i_load_unit.state_q",
    "ex_stage_i.lsu_i.lsu_ctrl.trans_id",
    # Phase 6b signals. Hierarchy (note `gen_cache_hpd.` generate
    # block — there are 3 cache subsystem variants in cva6.sv lines
    # 1366/1426/1490 under different gen_cache_* blocks; this build
    # uses the HPDcache one):
    #   gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.
    #     hpdcache_miss_handler_i.*
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
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_check_i",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.mshr_check_hit_o",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.miss_req_fsm_q",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_fsm_q",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_core_rsp_valid_o",
    "gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.refill_core_rsp_o.tid",
    # Subsystem-level miss boolean (bonus diagnostic — fires on any
    # miss in the cache, not per-trans_id but useful for sanity).
    "gen_cache_hpd.i_cache_subsystem.dcache_miss_o",
]


_LOAD_COMPACT = {
    "IDLE": "IDL", "WAIT_GNT": "WGT", "SEND_TAG": "STG",
    "WAIT_PAGE_OFFSET": "WPO",
    "ABORT_TRANSACTION": "ABT", "ABORT_TRANSACTION_NI": "ANI",
    "WAIT_TRANSLATION": "WTL", "WAIT_FLUSH": "WFL",
    "WAIT_WB_EMPTY": "WWE",
}

def fmt_load_state(s):
    if s is None: return ' ? '
    n = binary_to_int(s)
    if n is None: return ' X '
    name = LOAD_FSM_NAMES.get(n, f'?{n}')
    return _LOAD_COMPACT.get(name, name[:3])


_MREQ_COMPACT = {"MISS_REQ_IDLE": "IDL", "MISS_REQ_SEND": "SND"}
_REFILL_COMPACT = {
    "REFILL_IDLE": "IDL", "REFILL_WRITE": " WR",
    "REFILL_WRITE_DIR": " WD", "REFILL_INVAL": " IV",
}

def fmt_miss_req(s):
    if s is None: return ' ? '
    n = binary_to_int(s)
    if n is None: return ' X '
    return _MREQ_COMPACT.get(MISS_REQ_FSM.get(n, f"?{n}"), f"?{n}")

def fmt_refill(s):
    if s is None: return ' ? '
    n = binary_to_int(s)
    if n is None: return ' X '
    return _REFILL_COMPACT.get(REFILL_FSM.get(n, f"?{n}"), f"?{n}")


def fmt_tid(s):
    if s is None: return '-'
    n = binary_to_int(s)
    return str(n) if n is not None else 'X'


def fmt_nline_low16(s):
    """Show only low 16 bits of nline for column width."""
    if s is None: return '----'
    n = binary_to_int(s)
    if n is None: return 'XXXX'
    return f"{n & 0xFFFF:04x}"


def main():
    ap = argparse.ArgumentParser(
        description="Phase 6b HPDcache miss/refill diagnostic")
    ap.add_argument("vcd_path")
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end",   type=int, required=True)
    ap.add_argument("--scope-prefix",
                    default="TOP.ariane_testharness.i_ariane.i_cva6")
    args = ap.parse_args()

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD not found: {vcd_path}")

    print(f"# {vcd_path.name} cycles {args.start}..{args.end}",
          file=sys.stderr)

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, _ts = parse_var_block(f)
        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        single_id = {m["whitelist_path"]: m["vcd_ids"][0]
                     for m in matches if len(m["vcd_ids"]) == 1}

        CLK     = single_id.get("clk_i")
        LDST    = single_id.get("ex_stage_i.lsu_i.i_load_unit.state_q")
        LCTID   = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.trans_id")
        _BASE   = ("gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
                   "hpdcache_miss_handler_i.")
        MALLO   = single_id.get(_BASE + "mshr_alloc_i")
        MTID    = single_id.get(_BASE + "mshr_alloc_tid_i")
        MSID    = single_id.get(_BASE + "mshr_alloc_sid_i")
        MPF     = single_id.get(_BASE + "mshr_alloc_is_prefetch_i")
        MNLINE  = single_id.get(_BASE + "mshr_alloc_nline_i")
        MCHK    = single_id.get(_BASE + "mshr_check_i")
        MCHKH   = single_id.get(_BASE + "mshr_check_hit_o")
        MFSM    = single_id.get(_BASE + "miss_req_fsm_q")
        RFSM    = single_id.get(_BASE + "refill_fsm_q")
        RRSP    = single_id.get(_BASE + "refill_core_rsp_valid_o")
        RTID    = single_id.get(_BASE + "refill_core_rsp_o.tid")
        DMISS   = single_id.get(
            "gen_cache_hpd.i_cache_subsystem.dcache_miss_o")

        if CLK is None:
            sys.exit("FATAL: clk_i not resolved")

        signals = {
            "load_unit.state_q":          LDST,
            "lsu_ctrl.trans_id":          LCTID,
            "mshr_alloc_i":               MALLO,
            "mshr_alloc_tid_i":           MTID,
            "mshr_alloc_sid_i":           MSID,
            "mshr_alloc_is_prefetch_i":   MPF,
            "mshr_alloc_nline_i":         MNLINE,
            "mshr_check_i":               MCHK,
            "mshr_check_hit_o":           MCHKH,
            "miss_req_fsm_q":             MFSM,
            "refill_fsm_q":               RFSM,
            "refill_core_rsp_valid_o":    RRSP,
            "refill_core_rsp_o.tid":      RTID,
            "dcache_miss_o (subsystem)":  DMISS,
        }
        for name, vid in signals.items():
            marker = "OK" if vid else "MISS"
            print(f"# [{marker}] {name}", file=sys.stderr)

        tracked = {x for x in signals.values() if x}
        tracked.add(CLK)

        state = {}
        cycle = -1
        first_ts_seen = False
        clk_at_ts_start = "0"

        # Header — wider layout. Groups:
        #   ALLOC   = mAllo mTID mSID mPF mNline
        #   CHECK   = mChk mChkHit  (coalesced-miss detection)
        #   FSMs    = mFSM rFSM
        #   RSP     = rRsp rTID
        #   GLOBAL  = dMiss (subsystem)
        print()
        print("  cyc | LSU lsuTID | mAllo mTID mSID mPF mNline | "
              "mChk mChkHit | mFSM | rFSM | rRsp rTID | dMiss")
        print("------+------------+----------------------------+"
              "--------------+------+------+----------+------")

        def at_rising_edge():
            nonlocal cycle
            cycle += 1
            if not (args.start <= cycle <= args.end):
                return
            lst   = fmt_load_state(state.get(LDST))
            lctid = fmt_tid(state.get(LCTID))
            mallo = state.get(MALLO, "0") if MALLO else "?"
            mtid  = fmt_tid(state.get(MTID))
            msid  = fmt_tid(state.get(MSID))     # sid is small int too
            mpf   = state.get(MPF, "0") if MPF else "?"
            mnline = fmt_nline_low16(state.get(MNLINE))
            mchk  = state.get(MCHK, "0") if MCHK else "?"
            mchkh = state.get(MCHKH, "0") if MCHKH else "?"
            mfsm  = fmt_miss_req(state.get(MFSM))
            rfsm  = fmt_refill(state.get(RFSM))
            rrsp  = state.get(RRSP, "0") if RRSP else "?"
            rtid  = fmt_tid(state.get(RTID))
            dmiss = state.get(DMISS, "0") if DMISS else "?"
            print(f"{cycle:>5} | "
                  f"{lst} {lctid:>5}    | "
                  f"  {mallo:>2}  {mtid:>3}  {msid:>3}  {mpf:>2}  {mnline} | "
                  f"  {mchk:>2}    {mchkh:>2}    | "
                  f"{mfsm}  | {rfsm}  | "
                  f"  {rrsp}  {rtid:>3} | "
                  f"  {dmiss}")

        for line in f:
            line = line.rstrip()
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                if first_ts_seen:
                    curr_clk = state.get(CLK, "0")
                    if clk_at_ts_start == "0" and curr_clk == "1":
                        at_rising_edge()
                        if cycle > args.end:
                            return
                else:
                    first_ts_seen = True
                clk_at_ts_start = state.get(CLK, "0")
                continue
            if c0 in "01xXzZ":
                value = c0; vcd_id = line[1:]
            elif c0 in "bBrR":
                sp = line.find(" ")
                if sp <= 0: continue
                value = line[1:sp]; vcd_id = line[sp+1:]
            else:
                continue
            if vcd_id in tracked:
                state[vcd_id] = value


if __name__ == "__main__":
    main()
