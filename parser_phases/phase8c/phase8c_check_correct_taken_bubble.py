#!/usr/bin/env python3
"""Check whether correctly-predicted taken branches introduce a fetch bubble
on CVA6, by measuring the if1_lo delta from each such branch to its next
non-flushed instruction.

Usage:
  python3 check_correct_taken_bubble.py daxpy.json compress.json fdiv.json
"""

import json
import sys
from collections import Counter
from pathlib import Path
from statistics import mean, median


def analyze(json_path: Path):
    with json_path.open() as f:
        data = json.load(f)
    records = data["instructions"]
    ids = sorted(r["id"] for r in records if r.get("id") is not None)
    by_id = {r["id"]: r for r in records}
    id_to_idx = {iid: i for i, iid in enumerate(ids)}

    # Find correctly-predicted taken control-flow records.
    correct_taken = []
    for r in records:
        if r.get("flushed"):
            continue
        if r.get("if1_lo") is None:
            continue
        pcf = r.get("bp_predicted_cf")
        if pcf in (None, "NoCF"):
            continue
        if r.get("bp_mispredict"):
            continue
        if not r.get("bp_resolved_taken"):
            continue  # we want resolved-taken; not-taken fall-throughs are a separate case
        correct_taken.append(r)

    print(f"\n=== {json_path.name} ===")
    print(f"  Correctly-predicted taken control flow: {len(correct_taken)} records")
    if not correct_taken:
        return

    # Bucket by bp_predicted_cf kind so jumps vs branches show separately.
    by_kind = {}
    for r in correct_taken:
        by_kind.setdefault(r["bp_predicted_cf"], []).append(r)
    print(f"  By predicted_cf kind: " +
          ", ".join(f"{k}={len(v)}" for k, v in sorted(by_kind.items())))

    # For each, walk forward in id order to find the next non-flushed
    # instruction with an if1_lo. Compute the delta. Note: we walk in id
    # order (commit order), which matches how the tracer indexes records.
    rows = []  # (delta, branch_record, next_record)
    for r in correct_taken:
        idx = id_to_idx[r["id"]]
        nxt = None
        for j in range(idx + 1, min(idx + 50, len(ids))):
            cand = by_id[ids[j]]
            if cand.get("flushed"):
                continue
            if cand.get("if1_lo") is None:
                continue
            nxt = cand
            break
        if nxt is None:
            continue
        delta = nxt["if1_lo"] - r["if1_lo"]
        rows.append((delta, r, nxt))

    if not rows:
        print("  No deltas computable")
        return

    deltas = [d for d, _, _ in rows]
    counts = Counter(deltas)
    print(f"\n  FE1 delta (branch.if1_lo → next.if1_lo) across {len(rows)} pairs:")
    print(f"    min={min(deltas)}, median={median(deltas)}, mean={mean(deltas):.2f}, max={max(deltas)}")
    print(f"    distribution:")
    for d in sorted(counts.keys()):
        bar = "█" * min(40, counts[d])
        print(f"      delta={d:>3}: {counts[d]:>5}  {bar}")

    # Surface any outliers (delta > 2) for inspection.
    outliers = [(d, br, nx) for d, br, nx in rows if d > 2]
    if outliers:
        outliers.sort(key=lambda t: -t[0])
        print(f"\n  Outliers (delta > 2 cycles) — first 10 by descending delta:")
        for d, br, nx in outliers[:10]:
            nx_wraps = " ↪" if nx.get("wraps_line") else ""
            nx_miss  = " IC-miss" if nx.get("ic_miss") else ""
            nx_dis   = (nx.get("disasm") or "")[:32]
            print(f"    Δ={d:>3}c  branch #{br['id']:>5} {br['pc']} "
                  f"→  next #{nx['id']:>5} {nx['pc']}{nx_wraps}{nx_miss}  {nx_dis}")
    else:
        print("\n  No outliers (no delta > 2c)")


def main():
    paths = sys.argv[1:]
    if not paths:
        paths = ["daxpy.json", "compress.json", "fdiv.json"]
    for p in paths:
        path = Path(p)
        if not path.exists():
            print(f"Skipping (not found): {p}")
            continue
        analyze(path)
    print()


if __name__ == "__main__":
    main()
