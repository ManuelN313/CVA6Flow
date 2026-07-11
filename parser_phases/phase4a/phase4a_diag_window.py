#!/usr/bin/env python3
"""Phase 4a v0.2 diagnostic: print raw mem_q + trans_id_i + issue_pointer_q
state at every rising edge in a small cycle window.

Uses the exact same header parser as the main tracer for compatibility.

Usage:
    python3 p4a_diag_window.py fdiv.vcd > p4a_diag_window.out
    python3 p4a_diag_window.py fdiv.vcd --start 3845 --end 3855
"""
from __future__ import annotations
import argparse
import re
import sys
from collections import defaultdict


def parse_var_block(f):
    """Mirrors phase3_pipeline_tracer.py parse_var_block exactly."""
    scope_stack = []
    path_to_id = {}
    id_to_path = {}
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith("$enddefinitions"):
            return path_to_id, id_to_path
        if line.startswith("$scope"):
            tokens = line.split()
            if len(tokens) >= 3:
                scope_stack.append(tokens[2])
        elif line.startswith("$upscope"):
            if scope_stack:
                scope_stack.pop()
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
    return path_to_id, id_to_path


STRIP_BIT_RANGE = re.compile(r"\[\d+:\d+\]$")


def strip_bit_range(path):
    while True:
        new = STRIP_BIT_RANGE.sub("", path)
        if new == path:
            return path
        path = new


def fmt(s):
    if s is None:
        return "?"
    if "x" in s.lower() or "z" in s.lower():
        return "X"
    try:
        return str(int(s, 2))
    except ValueError:
        return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--start", type=int, default=3845)
    ap.add_argument("--end", type=int, default=3855)
    ap.add_argument("--scope-prefix",
                    default="TOP.ariane_testharness.i_ariane.i_cva6")
    args = ap.parse_args()

    P = args.scope_prefix.rstrip(".")

    with open(args.vcd, "r", buffering=4 << 20) as f:
        path_to_id, _ = parse_var_block(f)

        # Diagnostic info on what's in the header
        print(f"# total paths in header: {len(path_to_id)}", file=sys.stderr)
        sample = [k for k in path_to_id if "issue_pointer_q" in k][:5]
        print(
            f"# sample paths containing issue_pointer_q: {sample}", file=sys.stderr)
        sample2 = [k for k in path_to_id if "mem_q[0].sbe.fu" in k][:3]
        print(
            f"# sample paths containing 'mem_q[0].sbe.fu': {sample2}", file=sys.stderr)
        # Print the top-level scopes (first few unique prefixes)
        prefixes = set()
        for k in path_to_id:
            parts = k.split(".")
            if len(parts) >= 3:
                prefixes.add(".".join(parts[:3]))
            if len(prefixes) >= 8:
                break
        print(f"# top-level scope prefixes seen: {prefixes}", file=sys.stderr)

        # Build stripped lookup
        by_stripped = defaultdict(list)
        for full_path, vcd_id in path_to_id.items():
            by_stripped[strip_bit_range(full_path)].append((full_path, vcd_id))

        def find(suffix):
            hits = by_stripped.get(f"{P}.{suffix}", [])
            return hits[0][1] if hits else None

        CLK = find("clk_i")
        if CLK is None:
            for k, v in path_to_id.items():
                if k.endswith(".clk_i"):
                    CLK = v
                    print(
                        f"# CLK fallback (suffix match): {k}", file=sys.stderr)
                    break

        IPTR = find("issue_stage_i.i_scoreboard.issue_pointer_q")
        WTV = find("issue_stage_i.i_scoreboard.wt_valid_i")
        TID = [
            find(f"issue_stage_i.i_scoreboard.trans_id_i[{p}]") for p in range(5)]
        MEMQ_FU = [
            find(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.fu") for n in range(8)]
        MEMQ_RD = [
            find(f"issue_stage_i.i_scoreboard.mem_q[{n}].sbe.rd") for n in range(8)]
        DV = find("issue_stage_i.i_scoreboard.decoded_instr_valid_i")
        DA = find("issue_stage_i.i_scoreboard.decoded_instr_ack_o")
        FUI = find("issue_stage_i.i_scoreboard.flush_unissued_instr_i")
        FI = find("issue_stage_i.i_scoreboard.flush_i")

        print(f"# resolved CLK={CLK!r} IPTR={IPTR!r}")
        print(f"# WTV={WTV!r} flush_unissued_instr_i={FUI!r} flush_i={FI!r}")
        print(f"# TID ports = {TID}")
        print(f"# MEMQ_FU slots = {MEMQ_FU}")
        sys.stdout.flush()

        if CLK is None:
            print("# FATAL: CLK not found.", file=sys.stderr)
            sys.exit(2)

        state = {}
        cycle = -1
        first = False
        clk_at_start = "0"

        print()
        print(f"{'cyc':>5} {'IPTR':>4} {'WTV':>5} "
              f"{'t0':>2} {'t1':>2} {'t2':>2} {'t3':>2} {'t4':>2} "
              f"{'fu0':>3} {'fu1':>3} {'fu2':>3} {'fu3':>3} "
              f"{'fu4':>3} {'fu5':>3} {'fu6':>3} {'fu7':>3} "
              f"{'rd0':>3} {'rd1':>3} {'rd2':>3} {'rd3':>3} "
              f"{'rd4':>3} {'rd5':>3} {'rd6':>3} {'rd7':>3} "
              f"{'DV':>2} {'DA':>2} {'fui':>3} {'fi':>2}")

        def at_edge():
            nonlocal cycle
            cycle += 1
            if not (args.start <= cycle <= args.end):
                return
            iptr = fmt(state.get(IPTR)) if IPTR else "?"
            wtv = state.get(WTV, "0") if WTV else "0"
            tids = [fmt(state.get(v)) if v else "?" for v in TID]
            fus = [fmt(state.get(v)) if v else "?" for v in MEMQ_FU]
            rds = [fmt(state.get(v)) if v else "?" for v in MEMQ_RD]
            dv = fmt(state.get(DV)) if DV else "?"
            da = fmt(state.get(DA)) if DA else "?"
            fui = fmt(state.get(FUI)) if FUI else "?"
            fi = fmt(state.get(FI)) if FI else "?"
            print(f"{cycle:>5} {iptr:>4} {wtv:>5} "
                  f"{tids[0]:>2} {tids[1]:>2} {tids[2]:>2} {tids[3]:>2} {tids[4]:>2} "
                  f"{fus[0]:>3} {fus[1]:>3} {fus[2]:>3} {fus[3]:>3} "
                  f"{fus[4]:>3} {fus[5]:>3} {fus[6]:>3} {fus[7]:>3} "
                  f"{rds[0]:>3} {rds[1]:>3} {rds[2]:>3} {rds[3]:>3} "
                  f"{rds[4]:>3} {rds[5]:>3} {rds[6]:>3} {rds[7]:>3} "
                  f"{dv:>2} {da:>2} {fui:>3} {fi:>2}")

        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                if first:
                    curr = state.get(CLK, "0")
                    if clk_at_start == "0" and curr == "1":
                        at_edge()
                else:
                    first = True
                clk_at_start = state.get(CLK, "0")
                if cycle > args.end:
                    break
                continue
            if c0 in "01xz":
                state[line[1:]] = c0
            elif c0 == "b":
                sp = line.find(" ")
                if sp > 0:
                    state[line[sp + 1:]] = line[1:sp]


if __name__ == "__main__":
    main()
