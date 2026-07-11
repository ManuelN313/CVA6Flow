#!/usr/bin/env python3
"""Phase 6b global alloc-by-SID counter.

Sweeps the entire VCD (no record correlation) and counts every mshr_alloc_i
pulse by sid and is_prefetch flag. Used to confirm whether sid=1 (the LSU
load_unit's HPDcache load adapter) ever fires across the whole trace, in
case the per-record window in Phase 6b's attribution is too narrow.

Usage:
  python3 p6b_global_alloc_count.py fdiv.vcd
"""

from phase3_pipeline_tracer import (
    parse_var_block, match_whitelist, binary_to_int,
)
import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


SCOPE = "TOP.ariane_testharness.i_ariane.i_cva6"
BASE = ("gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache."
        "hpdcache_miss_handler_i.")

WHITELIST = [
    "clk_i",
    BASE + "mshr_alloc_i",
    BASE + "mshr_alloc_tid_i",
    BASE + "mshr_alloc_sid_i",
    BASE + "mshr_alloc_is_prefetch_i",
    BASE + "mshr_alloc_nline_i",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd_path")
    args = ap.parse_args()

    p = Path(args.vcd_path)
    if not p.exists():
        sys.exit(f"VCD not found: {p}")

    print(f"# Scanning {p.name}", file=sys.stderr)
    with p.open("r", errors="replace") as f:
        path_to_id, _id_to_path, _ = parse_var_block(f)
        matches = match_whitelist(WHITELIST, path_to_id, SCOPE)
        single_id = {m["whitelist_path"]: m["vcd_ids"][0]
                     for m in matches if len(m["vcd_ids"]) == 1}

        CLK = single_id.get("clk_i")
        MALLO = single_id.get(BASE + "mshr_alloc_i")
        MTID = single_id.get(BASE + "mshr_alloc_tid_i")
        MSID = single_id.get(BASE + "mshr_alloc_sid_i")
        MPF = single_id.get(BASE + "mshr_alloc_is_prefetch_i")

        if not (CLK and MALLO and MSID):
            sys.exit("FATAL: required signals not resolved")

        tracked = {CLK, MALLO, MTID, MSID, MPF}

        state = {}
        cycle = -1
        first_ts_seen = False
        clk_at_ts_start = "0"
        by_sid = Counter()
        by_sid_pf = Counter()
        by_sid_tid = Counter()   # (sid, tid) pairs
        first_seen_cycle = {}

        def at_rising_edge():
            nonlocal cycle
            cycle += 1
            if state.get(MALLO) == "1":
                sid = binary_to_int(state.get(MSID, "0"))
                tid = binary_to_int(state.get(MTID, "0"))
                pf = binary_to_int(state.get(MPF, "0"))
                by_sid[sid] += 1
                by_sid_pf[(sid, pf)] += 1
                by_sid_tid[(sid, tid)] += 1
                if sid not in first_seen_cycle:
                    first_seen_cycle[sid] = cycle

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
                else:
                    first_ts_seen = True
                clk_at_ts_start = state.get(CLK, "0")
                continue
            if c0 in "01xXzZ":
                value = c0
                vcd_id = line[1:]
            elif c0 in "bBrR":
                sp = line.find(" ")
                if sp <= 0:
                    continue
                value = line[1:sp]
                vcd_id = line[sp+1:]
            else:
                continue
            if vcd_id in tracked:
                state[vcd_id] = value

        total = sum(by_sid.values())
        print(f"\nTotal cycles: {cycle + 1}")
        print(f"Total mshr_alloc pulses: {total}\n")

        print("Allocations by SID:")
        print("  sid | role             | count | first_cycle")
        print("------+------------------+-------+------------")
        role_map = {
            0: "PTW",
            1: "LOAD_UNIT",
            2: "ACCEL_LOAD",
            3: "STORE",
            4: "CMO",
            5: "HWPF_PREFETCH",
        }
        for sid in sorted(by_sid):
            role = role_map.get(sid, f"unknown(sid={sid})")
            first = first_seen_cycle.get(sid, "-")
            print(f"  {sid:>3} | {role:16s} | {by_sid[sid]:>5} | {first}")

        print("\nAllocations by (SID, prefetch):")
        for (sid, pf), n in sorted(by_sid_pf.items()):
            role = role_map.get(sid, f"sid{sid}")
            print(f"  sid={sid} ({role}) pf={pf}: {n}")

        print("\nUnique (SID, TID) pairs (top 20 by count):")
        for (sid, tid), n in by_sid_tid.most_common(20):
            role = role_map.get(sid, f"sid{sid}")
            print(f"  sid={sid} ({role:13s}) tid={tid}: {n}")


if __name__ == "__main__":
    main()
