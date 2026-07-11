#!/usr/bin/env python3
"""Phase 6b D$ event correlation spot-check / coverage tool.

Loads a tracer JSON output and reports:

  1. Per-record breakdown of LOAD instructions sorted by lsu latency
     (lsu_complete_cycle - lsu_admit_cycle), showing the three Phase 6b
     booleans and a compact event summary. Pass --top N to see only
     the N highest-latency records; default is 20.

  2. Classification histogram across all LOAD records:
       primary_miss    : true primary load misses
       coalesced       : rode along another miss
       refill_overlap  : delayed by concurrent refill but otherwise hit
       clean_hit       : none of the above
     Plus the per-LOAD-adapter-SID alloc breakdown to verify sid=0 is
     the LSU's load_unit path in this build.

  3. Optional --records id1,id2,...  spot-checks specific record IDs by
     printing their full Phase 6a + Phase 6b context.

Usage:
  python3 p6b_spot_check.py fdiv_phase6b.json
  python3 p6b_spot_check.py fdiv_phase6b.json --top 30
  python3 p6b_spot_check.py fdiv_phase6b.json --records 139,142,140
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def latency(rec):
    a = rec.get("lsu_admit_cycle")
    c = rec.get("lsu_complete_cycle")
    if a is None or c is None:
        return None
    return c - a


def classify(rec):
    """Return one of: primary_miss / coalesced / refill_overlap / clean_hit.
    Strict precedence: primary_miss > coalesced > refill_overlap > clean."""
    if rec.get("dc_primary_miss"):
        return "primary_miss"
    if rec.get("dc_coalesced"):
        return "coalesced"
    if rec.get("dc_refill_overlap"):
        return "refill_overlap"
    return "clean_hit"


def fmt_events(events, limit=4):
    """Compact summary of an event list. Show at most `limit` events."""
    if not events:
        return "-"
    parts = []
    for ev in events[:limit]:
        t = ev["type"]
        c = ev["cycle"]
        if t == "alloc":
            sid = ev.get("sid")
            tid = ev.get("tid")
            pf = ev.get("pf")
            parts.append(f"@{c} A[s{sid}/t{tid}/p{pf}]")
        elif t == "check_hit":
            parts.append(f"@{c} CH")
        elif t == "check_miss":
            parts.append(f"@{c} CM")
        elif t == "refill_rsp":
            parts.append(f"@{c} R[t{ev.get('tid')}]")
        else:
            parts.append(f"@{c} {t}")
    if len(events) > limit:
        parts.append(f"...+{len(events)-limit}")
    return " ".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Phase 6b spot-check")
    ap.add_argument("json_path")
    ap.add_argument("--top", type=int, default=20,
                    help="show top N highest-latency LOAD records")
    ap.add_argument("--records", default="",
                    help="comma-separated record IDs to spot-check fully")
    ap.add_argument("--include-stores", action="store_true",
                    help="also show STORE records in the listing")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")
    with p.open() as f:
        data = json.load(f)

    instructions = data.get("instructions", [])
    print(f"# {p.name}: {len(instructions)} records")
    print(
        f"#   tracer phase6b stats: {data.get('metadata',{}).get('phase6b','?')}")
    print()

    # === Histogram across all LOAD (and optionally STORE) records ===
    mem_records = [r for r in instructions
                   if r.get("fu") in (("LOAD", "STORE")
                                      if args.include_stores else ("LOAD",))]
    cls_counts = Counter()
    sid_alloc_counts = Counter()
    pf_alloc_counts = Counter()  # split by sid → was it a prefetch?
    n_with_events = 0
    n_no_lsu_trace = 0

    for r in mem_records:
        if r.get("lsu_admit_cycle") is None:
            n_no_lsu_trace += 1
            continue
        cls_counts[classify(r)] += 1
        events = r.get("dc_events") or []
        if events:
            n_with_events += 1
        for ev in events:
            if ev["type"] == "alloc":
                sid = ev.get("sid")
                pf = ev.get("pf")
                sid_alloc_counts[sid] += 1
                if pf == 1:
                    pf_alloc_counts[sid] += 1

    print("=== Classification histogram "
          f"({'LOAD+STORE' if args.include_stores else 'LOAD'} records "
          f"with LSU trace) ===")
    total = sum(cls_counts.values())
    for cls in ("primary_miss", "coalesced", "refill_overlap", "clean_hit"):
        n = cls_counts.get(cls, 0)
        pct = (100.0 * n / total) if total else 0
        print(f"  {cls:18s} {n:>6d}  ({pct:5.1f}%)")
    print(f"  {'TOTAL':18s} {total:>6d}")
    print(f"  ({n_no_lsu_trace} skipped: no LSU trace; "
          f"{n_with_events} records have ≥1 D$ event)")
    print()

    print("=== Alloc-by-SID breakdown (events in record windows) ===")
    print("  sid 0..2 = LOAD adapters | sid 3 = STORE | sid 4 = CMO | sid 5 = HWPF")
    for sid in sorted(sid_alloc_counts):
        nalloc = sid_alloc_counts[sid]
        npf = pf_alloc_counts.get(sid, 0)
        label = ("LOAD" if 0 <= sid <= 2
                 else "STORE" if sid == 3
                 else "CMO" if sid == 4
                 else "HWPF" if sid == 5
                 else "?")
        print(f"  sid={sid} ({label:5s}) : {nalloc:>5d} alloc events "
              f"({npf} flagged prefetch)")
    print()

    # === Top-N highest-latency LOAD records ===
    sortable = [(latency(r), r) for r in mem_records
                if latency(r) is not None]
    sortable.sort(key=lambda x: -x[0])
    print(f"=== Top {min(args.top, len(sortable))} by LSU latency"
          f" (lsu_complete - lsu_admit) ===")
    print(f"{'id':>5} {'tid':>3} {'fu':5} {'lat':>4} "
          f"{'class':>14}  {'pc':>11}  events")
    print("-" * 100)
    for lat, r in sortable[:args.top]:
        ident = r.get("id")
        tid = r.get("trans_id")
        fu = r.get("fu")
        pc = r.get("pc") or "?"
        cls = classify(r)
        ev_str = fmt_events(r.get("dc_events") or [])
        print(f"{ident:>5} {tid:>3} {fu:5} {lat:>4} "
              f"{cls:>14}  {pc:>11}  {ev_str}")
    print()

    # === Per-id deep dives ===
    if args.records:
        ids = {int(x) for x in args.records.split(",") if x.strip()}
        by_id = {r.get("id"): r for r in instructions}
        for ident in sorted(ids):
            r = by_id.get(ident)
            if not r:
                print(f"=== id={ident}: NOT FOUND ===")
                continue
            print(f"=== id={ident} (tid={r.get('trans_id')}, "
                  f"fu={r.get('fu')}, pc={r.get('pc')}) ===")
            print(f"  is_cycle = {r.get('is_cycle')}")
            print(f"  lsu_admit_cycle    = {r.get('lsu_admit_cycle')}")
            print(f"  lsu_complete_cycle = {r.get('lsu_complete_cycle')}")
            lat = latency(r)
            print(f"  lsu latency        = {lat}")
            hist = r.get("lsu_state_history") or []
            print(f"  lsu_state_history  = {hist}")
            print(f"  dc_primary_miss    = {r.get('dc_primary_miss')}")
            print(f"  dc_coalesced       = {r.get('dc_coalesced')}")
            print(f"  dc_refill_overlap  = {r.get('dc_refill_overlap')}")
            print(f"  classification     = {classify(r)}")
            events = r.get("dc_events") or []
            print(f"  dc_events ({len(events)}):")
            for ev in events:
                print(f"    {ev}")
            print()


if __name__ == "__main__":
    main()
