#!/usr/bin/env python3
"""Phase 6b distribution analysis — multi-view summary of Phase 6b results.

Loads a tracer JSON output and produces five views to surface patterns
that the aggregate histogram alone hides:

  1. Latency histogram (text bar chart) per classification — shows how
     latency distributes within each class. Is clean_hit really all
     1-cycle? Are refill_overlap loads bunched at one latency? Are
     coalesced loads bimodal?

  2. PC hotspots — PCs with the most non-clean classifications. If 9
     records at the same PC all classify as refill_overlap with lat=6,
     that's a hot loop body. The table groups by PC and shows the
     latency distribution + classification mix per PC.

  3. Cycle-band temporal pattern — coarse buckets across the trace to
     show when non-clean events cluster. Cache-warmup region vs steady
     state typically look different.

  4. Coalesce target analysis — for each coalesced load, which cacheline
     was it riding? Helps see if a single hot store-allocated line
     absorbs many subsequent loads.

  5. Cross-tabulation — classification × functional unit category, just
     to sanity-check that the classifier never flips bits on non-Mem
     records.

Usage:
  python3 p6b_distribution_analysis.py fdiv_phase6b.json
  python3 p6b_distribution_analysis.py fdiv_phase6b.json --bands 8
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


CLASSES = ["primary_miss", "coalesced", "refill_overlap", "clean_hit"]


def latency(rec):
    a = rec.get("lsu_admit_cycle")
    c = rec.get("lsu_complete_cycle")
    if a is None or c is None:
        return None
    return c - a


def classify(rec):
    if rec.get("dc_primary_miss"):
        return "primary_miss"
    if rec.get("dc_coalesced"):
        return "coalesced"
    if rec.get("dc_refill_overlap"):
        return "refill_overlap"
    return "clean_hit"


def text_bar(n, scale, width=40):
    """Render n as a unicode bar relative to `scale` (max value)."""
    if scale == 0:
        return ""
    blocks = " ▏▎▍▌▋▊▉█"
    full = width * n / scale
    n_full = int(full)
    frac = full - n_full
    bar = "█" * n_full
    if n_full < width:
        bar += blocks[int(frac * (len(blocks) - 1))]
    return bar


def main():
    ap = argparse.ArgumentParser(description="Phase 6b distribution analysis")
    ap.add_argument("json_path")
    ap.add_argument("--bands", type=int, default=10,
                    help="number of cycle bands for temporal view")
    ap.add_argument("--top-pcs", type=int, default=12,
                    help="how many PC hotspots to show")
    ap.add_argument("--max-lat", type=int, default=20,
                    help="cap latency histogram at this value (last bucket aggregates ≥)")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")
    with p.open() as f:
        data = json.load(f)

    instructions = data.get("instructions", [])
    loads = [r for r in instructions if r.get("fu") == "LOAD"
             and r.get("lsu_admit_cycle") is not None]
    total = len(loads)
    print(f"# {p.name}")
    print(f"# {len(instructions)} records, {total} LOAD records with LSU trace")
    print()

    # ========================================================
    # View 1 — Latency histogram per classification
    # ========================================================
    print("=" * 78)
    print("[1] LATENCY HISTOGRAM PER CLASSIFICATION")
    print("=" * 78)
    print()

    by_class_lat = defaultdict(Counter)
    for r in loads:
        cls = classify(r)
        lat = latency(r)
        bucket = min(lat, args.max_lat)
        by_class_lat[cls][bucket] += 1

    for cls in CLASSES:
        counts = by_class_lat.get(cls, Counter())
        n_total = sum(counts.values())
        pct = (100.0 * n_total / total) if total else 0
        print(f"  {cls:14s}  n={n_total:>4}  ({pct:>5.1f}%)")
        if n_total == 0:
            print(f"    (none)")
            print()
            continue
        max_c = max(counts.values())
        for lat in sorted(counts):
            n = counts[lat]
            label = f"{lat:>2}" if lat < args.max_lat else f"≥{args.max_lat}"
            bar = text_bar(n, max_c, width=40)
            print(f"    lat={label} : {n:>4} {bar}")
        print()

    # ========================================================
    # View 2 — PC hotspots
    # ========================================================
    print("=" * 78)
    print(f"[2] PC HOTSPOTS — top {args.top_pcs} by non-clean count")
    print("=" * 78)
    print()

    pc_records = defaultdict(list)
    for r in loads:
        pc = r.get("pc")
        if pc is not None:
            pc_records[pc].append(r)

    # Build PC summary, sort by non-clean count then by occurrences
    pc_summary = []
    for pc, recs in pc_records.items():
        cls_counts = Counter(classify(r) for r in recs)
        non_clean = sum(v for k, v in cls_counts.items() if k != "clean_hit")
        lat_set = Counter(latency(r) for r in recs)
        pc_summary.append({
            "pc": pc,
            "n_total": len(recs),
            "n_non_clean": non_clean,
            "classes": cls_counts,
            "lats": lat_set,
            "disasm": recs[0].get("disasm", ""),
        })
    pc_summary.sort(key=lambda x: (-x["n_non_clean"], -x["n_total"]))

    print(f"  {'pc':>11}  {'tot':>4}  {'!clean':>6}  "
          f"{'P':>2} {'C':>3} {'R':>3} {'H':>4}  "
          f"{'lats (count)':30}  disasm")
    print(f"  " + "-" * 110)
    shown = 0
    for s in pc_summary:
        if s["n_non_clean"] == 0:
            continue
        cls = s["classes"]
        lats_fmt = ",".join(f"{l}:{c}" for l, c in sorted(s["lats"].items()))
        print(f"  {s['pc']:>11}  {s['n_total']:>4}  {s['n_non_clean']:>6}  "
              f"{cls.get('primary_miss',0):>2} "
              f"{cls.get('coalesced',0):>3} "
              f"{cls.get('refill_overlap',0):>3} "
              f"{cls.get('clean_hit',0):>4}  "
              f"{lats_fmt:30}  {s['disasm'][:35]}")
        shown += 1
        if shown >= args.top_pcs:
            break
    if shown == 0:
        print("  (no PCs with non-clean classifications)")
    print()
    print("  Legend: P=primary_miss  C=coalesced  R=refill_overlap  H=clean_hit")
    print()

    # ========================================================
    # View 3 — Temporal cycle-band pattern
    # ========================================================
    print("=" * 78)
    print(f"[3] TEMPORAL PATTERN — {args.bands} cycle bands")
    print("=" * 78)
    print()

    # Use lsu_admit_cycle as the temporal anchor. min/max across LOADs.
    admits = [r.get("lsu_admit_cycle") for r in loads]
    if not admits:
        print("  (no admits)")
    else:
        cmin, cmax = min(admits), max(admits)
        span = max(cmax - cmin, 1)
        band_size = max(span // args.bands, 1)
        band_data = [Counter() for _ in range(args.bands + 1)]
        for r in loads:
            b = (r.get("lsu_admit_cycle") - cmin) // band_size
            b = min(b, args.bands)
            band_data[b][classify(r)] += 1

        print(f"  cycle range = [{cmin}, {cmax}], band size = {band_size}")
        print()
        print(f"  {'band':>4}  {'cyc lo':>8}  {'cyc hi':>8}  "
              f"{'P':>3} {'C':>3} {'R':>3} {'H':>5}  bar (non-clean)")
        print(f"  " + "-" * 78)
        # Compute max non-clean for bar scaling
        max_nc = max(
            (sum(v for k, v in bd.items() if k != "clean_hit")
             for bd in band_data),
            default=1)
        max_nc = max(max_nc, 1)
        for i, bd in enumerate(band_data):
            if not bd:
                continue
            lo = cmin + i * band_size
            hi = lo + band_size - 1
            nc = sum(v for k, v in bd.items() if k != "clean_hit")
            bar = text_bar(nc, max_nc, width=28)
            print(f"  {i:>4}  {lo:>8}  {hi:>8}  "
                  f"{bd.get('primary_miss',0):>3} "
                  f"{bd.get('coalesced',0):>3} "
                  f"{bd.get('refill_overlap',0):>3} "
                  f"{bd.get('clean_hit',0):>5}  {bar}")
    print()

    # ========================================================
    # View 4 — Coalesce target nlines
    # ========================================================
    print("=" * 78)
    print("[4] COALESCE TARGETS — nlines that loads rode along")
    print("=" * 78)
    print()

    # For each coalesced load, find the check_hit events and their nlines.
    # Also collect the store-allocated nlines (sid=3 alloc events) that
    # appear in the same record's dc_events — these are likely the
    # cacheline that drove the coalesce.
    coalesce_nline_counts = Counter()
    store_alloc_nlines = Counter()
    refill_only_lats = Counter()
    for r in loads:
        cls = classify(r)
        events = r.get("dc_events") or []
        if cls == "coalesced":
            for ev in events:
                if ev["type"] == "check_hit":
                    coalesce_nline_counts[ev.get("nline")] += 1
                if ev["type"] == "alloc" and ev.get("sid") == 3:
                    store_alloc_nlines[ev.get("nline")] += 1
        elif cls == "refill_overlap":
            refill_only_lats[latency(r)] += 1

    if coalesce_nline_counts:
        print("  check_hit nlines hit by coalesced loads:")
        for nline, n in coalesce_nline_counts.most_common(10):
            print(f"    nline=0x{nline:x}  ({nline})  hits={n}")
        print()
        print("  store-alloc'd nlines seen in coalesced records' windows:")
        for nline, n in store_alloc_nlines.most_common(10):
            print(f"    nline=0x{nline:x}  ({nline})  allocs={n}")
    else:
        print("  (no coalesced loads)")
    print()

    if refill_only_lats:
        print("  refill_overlap loads — latency distribution:")
        for lat, n in sorted(refill_only_lats.items()):
            print(f"    lat={lat:>2}  n={n}")
    print()

    # ========================================================
    # View 5 — Cross-tabulation: classification × fu
    # ========================================================
    print("=" * 78)
    print("[5] CROSS-TAB: classification × functional unit")
    print("=" * 78)
    print()

    xtab = defaultdict(Counter)
    for r in instructions:
        if r.get("fu_category") != "Mem":
            continue
        if r.get("lsu_admit_cycle") is None:
            continue
        xtab[r.get("fu", "?")][classify(r)] += 1

    print(f"  {'fu':10s}  {'P':>4} {'C':>4} {'R':>4} {'H':>6}  total")
    print(f"  " + "-" * 50)
    for fu, counts in sorted(xtab.items()):
        tot = sum(counts.values())
        print(f"  {fu:10s}  "
              f"{counts.get('primary_miss',0):>4} "
              f"{counts.get('coalesced',0):>4} "
              f"{counts.get('refill_overlap',0):>4} "
              f"{counts.get('clean_hit',0):>6}  {tot:>5}")
    print()
    print("  Sanity check: STORE records should be predominantly clean_hit")
    print("  (their LSU FSM window is short; no refill/check events overlap).")
    print()


if __name__ == "__main__":
    main()
