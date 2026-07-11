#!/usr/bin/env python3
"""Phase 6a spot-check + histogram.

Reads a tracer JSON and reports LSU FSM coverage:

  - per-fu totals (LOAD / STORE)
  - traced vs untraced (has lsu_state_history vs not)
  - warmup vs user-code split for the untraced
  - state-name histogram across all captured histories
  - admit/complete latency distributions
  - per-id spot-checks for known interesting records

Usage:
  python3 p6a_spot_check.py fdiv_phase6a_v03.json
  python3 p6a_spot_check.py fdiv_phase6a_v03.json --ids 140 193 194 2092
  python3 p6a_spot_check.py fdiv_phase6a_v03.json --show-untraced 10

Default spot-check IDs are the ones we've been investigating
(140, 151, 193, 194, 2092). Pass --ids to override.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def fmt(v):
    """None → '-' so f-string lineups stay aligned."""
    return '-' if v is None else v


def fmt_history(hist):
    """Pretty-print lsu_state_history list. None → '-'."""
    if not hist:
        return '-'
    return ", ".join(f"{e['state']}@{e['cycle']}" for e in hist)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path")
    ap.add_argument("--ids", nargs="+", type=int,
                    default=[140, 151, 193, 194, 2092],
                    help="Record IDs to spot-check in detail")
    ap.add_argument("--show-untraced", type=int, default=10,
                    help="Show first N untraced LOAD records "
                         "(default 10, 0 to disable)")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"JSON not found: {p}")

    with p.open() as f:
        data = json.load(f)

    records = data["instructions"]
    metadata = data.get("metadata", {})
    warmup_end = metadata.get("warmup_end_cycle", 0)
    user_entry_pc = metadata.get("user_entry_pc")

    print(f"=== Phase 6a spot-check: {p.name} ===")
    print(f"  extractor_version : {metadata.get('extractor_version')}")
    print(f"  phase             : {metadata.get('phase')}")
    print(f"  warmup_end_cycle  : {warmup_end}")
    print(f"  user_entry_pc     : {user_entry_pc}")
    print(f"  total records     : {len(records):,}")
    print()

    # ---- Coverage by fu ----
    by_fu = defaultdict(list)
    for r in records:
        by_fu[r.get("fu")].append(r)

    print("=== LSU coverage by fu ===")
    print(f"  {'fu':<6}  {'total':>6}  {'traced':>6}  "
          f"{'untraced':>8}  {'%traced':>8}")
    print(f"  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*8}  {'-'*8}")
    for fu in ("LOAD", "STORE"):
        recs = by_fu.get(fu, [])
        traced = [r for r in recs if r.get("lsu_state_history")]
        untraced = [r for r in recs if not r.get("lsu_state_history")]
        pct = (100.0 * len(traced) / len(recs)) if recs else 0.0
        print(f"  {fu:<6}  {len(recs):>6}  {len(traced):>6}  "
              f"{len(untraced):>8}  {pct:>7.2f}%")
    print()

    # ---- Untraced split: warmup vs user-code ----
    print("=== Untraced split: warmup vs user-code vs flushed ===")
    for fu in ("LOAD", "STORE"):
        recs = by_fu.get(fu, [])
        untraced = [r for r in recs if not r.get("lsu_state_history")]
        if not untraced:
            print(f"  {fu}: 0 untraced ✓")
            continue
        warmup = [r for r in untraced
                  if (r.get("is_cycle") or 0) < warmup_end]
        user = [r for r in untraced
                if (r.get("is_cycle") or 0) >= warmup_end]
        flushed = [r for r in untraced if r.get("flushed")]
        print(f"  {fu}: {len(untraced)} untraced  "
              f"(warmup={len(warmup)}  user={len(user)}  "
              f"flushed={len(flushed)})")
    print()

    # ---- State histogram across all histories ----
    print("=== State-name histogram across all histories ===")
    for fu in ("LOAD", "STORE"):
        recs = by_fu.get(fu, [])
        counter = Counter()
        for r in recs:
            for e in (r.get("lsu_state_history") or []):
                counter[e["state"]] += 1
        n_hist = sum(1 for r in recs if r.get("lsu_state_history"))
        if not counter:
            print(f"  {fu}: (no history entries)")
            continue
        print(f"  {fu}: {n_hist} records with history, "
              f"{sum(counter.values())} total state entries")
        for state, n in counter.most_common():
            print(f"    {state:<20}  {n:>6}")
    print()

    # ---- Admit→complete latency distribution ----
    print("=== Admit→complete latency (cycles) ===")
    for fu in ("LOAD", "STORE"):
        recs = by_fu.get(fu, [])
        latencies = []
        for r in recs:
            a = r.get("lsu_admit_cycle")
            c = r.get("lsu_complete_cycle")
            if a is not None and c is not None:
                latencies.append(c - a)
        if not latencies:
            print(f"  {fu}: (no admit+complete pairs)")
            continue
        latencies.sort()
        n = len(latencies)
        p50 = latencies[n // 2]
        p95 = latencies[min(n - 1, int(n * 0.95))]
        print(f"  {fu}: n={n}  min={latencies[0]}  "
              f"p50={p50}  p95={p95}  max={latencies[-1]}")
        # Mini-histogram of small latencies
        buckets = Counter(min(l, 20) for l in latencies)
        for k in sorted(buckets):
            label = f"{k}" if k < 20 else "20+"
            bar = "#" * min(50, buckets[k])
            print(f"    {label:>3}c  {buckets[k]:>5}  {bar}")
    print()

    # ---- Per-id spot checks ----
    print(f"=== Per-id spot-check (ids: {args.ids}) ===")
    by_id = {r["id"]: r for r in records}
    for rid in args.ids:
        r = by_id.get(rid)
        if r is None:
            print(f"  id={rid}: not found")
            continue
        print(f"  id={rid:<5}  pc={r.get('pc')}  fu={r.get('fu')}  "
              f"tid={r.get('trans_id')}")
        print(f"    id={fmt(r.get('id_cycle'))}  "
              f"is={fmt(r.get('is_cycle'))}  "
              f"ex={fmt(r.get('ex_cycle'))}  "
              f"wb={fmt(r.get('wb_cycle'))}  "
              f"co={fmt(r.get('co_cycle'))}")
        print(f"    lsu_admit={fmt(r.get('lsu_admit_cycle'))}  "
              f"lsu_complete={fmt(r.get('lsu_complete_cycle'))}  "
              f"flushed={r.get('flushed')}")
        print(f"    history: {fmt_history(r.get('lsu_state_history'))}")
    print()

    # ---- First N untraced LOAD records ----
    if args.show_untraced > 0:
        untraced_loads = [r for r in by_fu.get("LOAD", [])
                          if not r.get("lsu_state_history")]
        if untraced_loads:
            print(f"=== First {args.show_untraced} untraced LOAD records ===")
            print(f"  {'id':>5}  {'pc':<12}  {'tid':>3}  "
                  f"{'is':>5}  {'wb':>5}  {'admit':>5}  "
                  f"{'cmpl':>5}  {'flushed':>7}  warmup?")
            for r in untraced_loads[:args.show_untraced]:
                in_warmup = (r.get("is_cycle") or 0) < warmup_end
                print(f"  {r['id']:>5}  {str(r.get('pc')):<12}  "
                      f"{fmt(r.get('trans_id')):>3}  "
                      f"{fmt(r.get('is_cycle')):>5}  "
                      f"{fmt(r.get('wb_cycle')):>5}  "
                      f"{fmt(r.get('lsu_admit_cycle')):>5}  "
                      f"{fmt(r.get('lsu_complete_cycle')):>5}  "
                      f"{str(r.get('flushed')):>7}  "
                      f"{'Y' if in_warmup else 'N'}")
            print()


if __name__ == "__main__":
    main()
