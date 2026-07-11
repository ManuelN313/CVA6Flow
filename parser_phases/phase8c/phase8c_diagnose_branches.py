#!/usr/bin/env python3
"""Diagnostic: break down CTRL_FLOW records by their predictor/resolution
state, so we can see exactly what's happening with the daxpy data.

The mystery: 4262 CTRL_FLOW records, only 142 with non-NoCF predictions,
and yet 4252 of them seem to have bp_resolved_taken=True. Architecturally
this should be impossible for plain conditional branches — let's see what's
in there.

Usage:
    python3 diagnose_branches.py path/to/daxpy.json
"""
import json
import sys
from collections import Counter, defaultdict


def main(path):
    with open(path) as f:
        data = json.load(f)
    recs = data["instructions"]
    cf = [r for r in recs if not r.get("flushed") and r.get("fu") == "CTRL_FLOW"]
    print(f"=== {path} ===")
    print(f"Total CTRL_FLOW non-flushed records: {len(cf)}")
    print()

    # --- Breakdown by (predicted_cf, mispredict, resolved_taken) ---
    buckets = Counter()
    for r in cf:
        key = (
            r.get("bp_predicted_cf"),
            r.get("bp_mispredict"),
            r.get("bp_resolved_taken"),
        )
        buckets[key] += 1
    print(f"--- by (predicted_cf, mispredict, resolved_taken) ---")
    print(f"{'count':>6}  {'predicted_cf':>13}  {'mispred':>8}  {'taken':>6}")
    for key, c in sorted(buckets.items(), key=lambda x: -x[1]):
        pcf, mis, tk = key
        print(f"{c:6d}  {str(pcf):>13}  {str(mis):>8}  {str(tk):>6}")
    print()

    # --- For each (predicted_cf, mispredict, taken) bucket, sample 2 records ---
    samples = defaultdict(list)
    for r in cf:
        key = (
            r.get("bp_predicted_cf"),
            r.get("bp_mispredict"),
            r.get("bp_resolved_taken"),
        )
        if len(samples[key]) < 2:
            samples[key].append(r)

    print(f"--- sample records (up to 2 per bucket) ---")
    for key in sorted(samples.keys(), key=lambda k: -buckets[k])[:8]:
        pcf, mis, tk = key
        print(f"\n  Bucket: predicted_cf={pcf!r}  mispredict={mis!r}  taken={tk!r}  ({buckets[key]} records)")
        for r in samples[key]:
            disasm = (r.get("disasm") or "")[:60]
            print(f"    id={r.get('id'):>5}  pc={r.get('pc')}  if1_lo={r.get('if1_lo')}  "
                  f"ex={r.get('ex_cycle')}  resolved_cf={r.get('bp_resolved_cf')!r}  "
                  f"disasm={disasm!r}")
    print()

    # --- Per-bucket mnemonic breakdown — THE KEY TABLE for figuring out
    # what's in each bucket. Per RTL, a blt with NoCF prediction that
    # actually fires (taken) MUST have mispredict=True. So if we see
    # blts in ('NoCF', False, True), that's an architectural contradiction
    # and we know we have a tracer-capture bug. ---
    def mnem(r):
        d = r.get("disasm") or ""
        return d.split()[0] if d else "(no disasm)"

    bucket_mnem = defaultdict(Counter)
    for r in cf:
        key = (
            r.get("bp_predicted_cf"),
            r.get("bp_mispredict"),
            r.get("bp_resolved_taken"),
        )
        bucket_mnem[key][mnem(r)] += 1

    print(f"--- per-bucket mnemonic breakdown ---")
    for key in sorted(bucket_mnem.keys(), key=lambda k: -buckets[k]):
        pcf, mis, tk = key
        total = buckets[key]
        top = bucket_mnem[key].most_common(5)
        top_str = ", ".join(f"{m}×{c}" for m, c in top)
        print(f"  {total:5d}  pcf={str(pcf):>8} mis={str(mis):>5} taken={str(tk):>5}  → {top_str}")
    print()

    # --- Per-mnemonic bucket breakdown — same data from the other angle.
    # For each instruction type, where does it land? blt should NEVER appear
    # in ('NoCF', False, True) if the tracer captures bp.cf correctly. ---
    mnem_bucket = defaultdict(Counter)
    for r in cf:
        key = (
            r.get("bp_predicted_cf"),
            r.get("bp_mispredict"),
            r.get("bp_resolved_taken"),
        )
        mnem_bucket[mnem(r)][key] += 1

    print(f"--- per-mnemonic bucket distribution (top mnemonics) ---")
    for m in [m for m, _ in Counter(mnem(r) for r in cf).most_common(8)]:
        total = sum(mnem_bucket[m].values())
        print(f"  {m} ({total} records):")
        for key, c in mnem_bucket[m].most_common(5):
            pcf, mis, tk = key
            print(f"      {c:5d}  pcf={str(pcf):>8} mis={str(mis):>5} taken={str(tk):>5}")
    print()

    # --- Sanity: count by current bubble_kind to see classification result ---
    bk = Counter(r.get("bubble_kind") for r in cf if r.get("bubble_kind"))
    print(f"--- current bubble_kind tags on CTRL_FLOW records ---")
    for k, c in sorted(bk.items(), key=lambda x: -x[1]):
        print(f"  {k}: {c}")


if __name__ == "__main__":
    paths = sys.argv[1:] if len(sys.argv) > 1 else ["daxpy.json"]
    for p in paths:
        main(p)
        print()
