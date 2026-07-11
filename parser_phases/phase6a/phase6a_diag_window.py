#!/usr/bin/env python3
"""Phase 6a warmup-gap LSU diagnostic.

Walks a CVA6 VCD over a specified cycle window and dumps per-cycle the
signals relevant to Phase 6a's LSU FSM tracking and the drain logic.
Use this to figure out why specific warmup loads aren't getting their
FSM history captured.

Reuses parse_var_block, match_whitelist, and the helper formatters
from phase3_pipeline_tracer so the dump uses the same enum names and
binary→int decoding as the production tracer.

Usage:
  python3 p6a_diag_window.py fdiv.vcd --start 605 --end 625
  python3 p6a_diag_window.py fdiv.vcd --start 735 --end 745  # for id=193 loop
  python3 p6a_diag_window.py fdiv.vcd --start 4165 --end 4175 # known-good (post-warmup)

Per-cycle columns:
  cyc  : cycle number at this rising edge
  DV   : decoded_instr_valid_i  (1 when scoreboard sees a decoded instr)
  DA   : decoded_instr_ack_o    (1 when scoreboard accepts it; DV&DA = issue)
  IV   : issue_instr_valid_o    (scoreboard offering to an FU)
  IA   : issue_ack_i            (FU accepting; IV&IA = FU admission)
  IPTR : issue_pointer_q        (trans_id about to be allocated)
  pFU  : decoded_instr_i[0].fu  (the unreliable pre-edge fu — Phase 4a fallback path)
  FUI  : flush_unissued_instr_i (when 1, the decode is silently dropped)
  mem_q[0..7].fu  : the AUTHORITATIVE scoreboard slot fu (registered;
                    visible one cycle after the decode write)
  LSU  : load_unit.state_q      (FSM state, abbreviated)
  STU  : store_unit.state_q     (FSM state, abbreviated)
  flush: flush_ctrl_{if,id,ex}

LOAD FSM:  IDL=IDLE WGT=WAIT_GNT STG=SEND_TAG WPO=WAIT_PAGE_OFFSET
           ABT/ANI=ABORT WTL=WAIT_TRANSLATION WFL=WAIT_FLUSH WWE=WAIT_WB_EMPTY
STORE FSM: IDL=IDLE VST=VALID_STORE WTL=WAIT_TRANSLATION WSR=WAIT_STORE_READY
FU codes:  ALU LD ST CSR MUL CF FPU
"""

import argparse
import sys
from pathlib import Path

# Reuse parser/helpers from the main tracer.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from phase3_pipeline_tracer import (
    parse_var_block, match_whitelist, binary_to_int,
    FU_NAME, LOAD_FSM_NAMES, STORE_FSM_NAMES,
)


WHITELIST = [
    "clk_i",
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",
    "issue_stage_i.i_scoreboard.decoded_instr_i[0].fu",
    "issue_stage_i.i_scoreboard.flush_unissued_instr_i",
    "ex_stage_i.lsu_i.i_load_unit.state_q",
    "ex_stage_i.lsu_i.i_store_unit.state_q",
    # Phase 6a v0.4 candidate: lsu_ctrl is the wire feeding both
    # load_unit and store_unit FSMs. Its .trans_id is the ID being
    # presented to the FSM on this cycle.
    "ex_stage_i.lsu_i.lsu_ctrl.valid",
    "ex_stage_i.lsu_i.lsu_ctrl.trans_id",
    "ex_stage_i.lsu_i.lsu_ctrl.fu",
    # lsu_bypass FIFO internals (for verification / understanding)
    "ex_stage_i.lsu_i.lsu_bypass_i.status_cnt_q",
    "ex_stage_i.lsu_i.lsu_bypass_i.read_pointer_q",
    "ex_stage_i.lsu_i.lsu_bypass_i.write_pointer_q",
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i",
    "ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i",
    "flush_ctrl_if",
    "flush_ctrl_id",
    "flush_ctrl_ex",
]
for n in range(8):
    WHITELIST.append(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.fu")


# Compact 3-char FU name for column width
_FU_COMPACT = {
    "NONE": "---", "LOAD": " LD", "STORE": " ST", "ALU": "ALU",
    "CTRL_FLOW": " CF", "MULT": "MUL", "CSR": "CSR", "FPU": "FPU",
    "FPU_VEC": "VEC", "CVXIF": "CVX", "ACCEL": "ACC", "AES": "AES",
}

def fmt_fu(s):
    if s is None: return ' - '
    n = binary_to_int(s)
    if n is None: return ' X '
    name = FU_NAME.get(n, f'?{n}')
    return _FU_COMPACT.get(name, name[:3].upper())


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


_STORE_COMPACT = {
    "IDLE": "IDL", "VALID_STORE": "VST",
    "WAIT_TRANSLATION": "WTL", "WAIT_STORE_READY": "WSR",
}

def fmt_store_state(s):
    if s is None: return ' ? '
    n = binary_to_int(s)
    if n is None: return ' X '
    name = STORE_FSM_NAMES.get(n, f'?{n}')
    return _STORE_COMPACT.get(name, name[:3])


def main():
    parser = argparse.ArgumentParser(
        description="Phase 6a warmup-gap LSU diagnostic")
    parser.add_argument("vcd_path", help="Path to the .vcd")
    parser.add_argument("--start", type=int, required=True,
                        help="First cycle to dump (inclusive)")
    parser.add_argument("--end", type=int, required=True,
                        help="Last cycle to dump (inclusive)")
    parser.add_argument(
        "--scope-prefix",
        default="TOP.ariane_testharness.i_ariane.i_cva6",
        help="VCD scope prefix; same default as the main tracer.")
    args = parser.parse_args()

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD not found: {vcd_path}")

    print(f"# {vcd_path.name} cycles {args.start}..{args.end}", file=sys.stderr)

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, _ts = parse_var_block(f)
        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        single_id = {m["whitelist_path"]: m["vcd_ids"][0]
                     for m in matches if len(m["vcd_ids"]) == 1}

        CLK  = single_id.get("clk_i")
        DV   = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_valid_i")
        DA   = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_ack_o")
        IV   = single_id.get("issue_stage_i.i_scoreboard.issue_instr_valid_o")
        IA   = single_id.get("issue_stage_i.i_scoreboard.issue_ack_i")
        IPTR = single_id.get("issue_stage_i.i_scoreboard.issue_pointer_q")
        DFU  = single_id.get("issue_stage_i.i_scoreboard.decoded_instr_i[0].fu")
        FUI  = single_id.get("issue_stage_i.i_scoreboard.flush_unissued_instr_i")
        LDST = single_id.get("ex_stage_i.lsu_i.i_load_unit.state_q")
        STST = single_id.get("ex_stage_i.lsu_i.i_store_unit.state_q")
        # Phase 6a v0.4 candidate signals
        LCV  = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.valid")
        LCTID = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.trans_id")
        LCFU = single_id.get("ex_stage_i.lsu_i.lsu_ctrl.fu")
        BPSC = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.status_cnt_q")
        BPRP = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.read_pointer_q")
        BPWP = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.write_pointer_q")
        BPPL = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_ld_i")
        BPPS = single_id.get("ex_stage_i.lsu_i.lsu_bypass_i.pop_st_i")
        FIF  = single_id.get("flush_ctrl_if")
        FID  = single_id.get("flush_ctrl_id")
        FEX  = single_id.get("flush_ctrl_ex")
        MEMQ_FU = [single_id.get(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.fu")
                   for n in range(8)]

        # Sanity
        missing = []
        if CLK  is None: missing.append("clk_i")
        if LDST is None: missing.append("i_load_unit.state_q")
        if STST is None: missing.append("i_store_unit.state_q")
        if missing:
            sys.exit(f"FATAL: signals missing: {missing}")
        n_memq = sum(1 for x in MEMQ_FU if x is not None)
        print(f"# Resolved {n_memq}/8 mem_q.sbe.fu slots", file=sys.stderr)
        # Report what new signals we did/didn't find
        new_signals = {
            "lsu_ctrl.valid": LCV,
            "lsu_ctrl.trans_id": LCTID,
            "lsu_ctrl.fu": LCFU,
            "bypass.status_cnt_q": BPSC,
            "bypass.read_pointer_q": BPRP,
            "bypass.write_pointer_q": BPWP,
            "bypass.pop_ld_i": BPPL,
            "bypass.pop_st_i": BPPS,
        }
        for name, vid in new_signals.items():
            marker = "OK" if vid else "MISS"
            print(f"# [{marker}] {name}", file=sys.stderr)

        tracked = {x for x in (CLK,DV,DA,IV,IA,IPTR,DFU,FUI,LDST,STST,
                               LCV,LCTID,LCFU,BPSC,BPRP,BPWP,BPPL,BPPS,
                               FIF,FID,FEX) if x}
        tracked.update(x for x in MEMQ_FU if x)

        state = {}
        cycle = -1
        first_ts_seen = False
        clk_at_ts_start = "0"

        # Header — two-line for compactness
        print()
        print("  cyc | DV DA IPTR pFU | LSU STU | lsuCtrl(V,tid,fu) | "
              "byp(cnt,rd,wr,popL,popS) | mem_q[0..7].fu")
        print("------+----------------+---------+-------------------+"
              "-------------------------+----------------------------------")

        def at_rising_edge():
            nonlocal cycle
            cycle += 1
            if not (args.start <= cycle <= args.end):
                return
            dv   = state.get(DV, "0") if DV   else "?"
            da   = state.get(DA, "0") if DA   else "?"
            iptr = binary_to_int(state.get(IPTR)) if IPTR else None
            iptr_s = str(iptr) if iptr is not None else '-'
            dfu_s = fmt_fu(state.get(DFU)) if DFU else " - "
            lst = fmt_load_state(state.get(LDST))
            sst = fmt_store_state(state.get(STST))
            # lsu_ctrl signals
            lcv = state.get(LCV, "?") if LCV else "?"
            lctid = binary_to_int(state.get(LCTID)) if LCTID else None
            lctid_s = str(lctid) if lctid is not None else '-'
            lcfu_s = fmt_fu(state.get(LCFU)) if LCFU else " - "
            # bypass internals
            bpsc = binary_to_int(state.get(BPSC)) if BPSC else None
            bpsc_s = str(bpsc) if bpsc is not None else '-'
            bprp = state.get(BPRP, "?") if BPRP else "?"
            bpwp = state.get(BPWP, "?") if BPWP else "?"
            bppl = state.get(BPPL, "0") if BPPL else "?"
            bpps = state.get(BPPS, "0") if BPPS else "?"
            memq_s = " ".join(fmt_fu(state.get(m)) if m else " - "
                              for m in MEMQ_FU)
            print(f"{cycle:>5} | "
                  f"{dv:>2} {da:>2} {iptr_s:>4} {dfu_s} | "
                  f"{lst} {sst} | "
                  f"v={lcv} tid={lctid_s:>2} {lcfu_s} | "
                  f"cnt={bpsc_s} rd={bprp} wr={bpwp} "
                  f"pL={bppl} pS={bpps} | "
                  f"{memq_s}")

        # Walk body
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
