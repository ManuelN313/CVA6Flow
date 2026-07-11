#!/usr/bin/env python3
"""Phase 7a branch-prediction spot-check.

Loads a tracer JSON output and reports:

  1. Per-CTRL_FLOW summary:
     - total / predicted / resolved / mispredicted counts
     - per-cf breakdown of predictions
     - per-cf breakdown of mispredicts (using resolved_cf)
     - hit rate

  2. Top-N mispredicts with full context (predicted vs resolved cf,
     target, taken, plus the disasm and flush_reason where applicable).

  3. All records with a non-NoCF prediction — show what was predicted
     and whether it was correct. Useful for validating the small-count
     case (e.g., only 1 prediction in fdiv — what was it?).

  4. Per-PC mispredict frequency — branches that mispredict more than
     once are interesting hot spots.

Usage:
  python3 p7a_spot_check.py fdiv_phase7a.json
  python3 p7a_spot_check.py fdiv_phase7a.json --top-misp 20
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def fmt_target(t):
    if t is None: return "—"
    return f"0x{t:x}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path")
    ap.add_argument("--top-misp", type=int, default=15,
                    help="show up to N mispredicts with full context")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")
    with p.open() as f:
        data = json.load(f)

    instructions = data.get("instructions", [])
    cf = [r for r in instructions if r.get("fu") == "CTRL_FLOW"]
    print(f"# {p.name}: {len(instructions)} records, {len(cf)} CTRL_FLOW")
    print()

    # === Summary ===
    print("=" * 78)
    print("[1] SUMMARY")
    print("=" * 78)
    predicted     = [r for r in cf if r.get("bp_predicted_cf")
                     and r["bp_predicted_cf"] != "NoCF"]
    resolved      = [r for r in cf if r.get("bp_resolution_cycle") is not None]
    mispredicts   = [r for r in resolved if r.get("bp_mispredict")]
    flushed_pre   = [r for r in cf if r.get("flushed")
                     and r.get("bp_resolution_cycle") is None]

    pred_by_cf = Counter(r["bp_predicted_cf"] for r in predicted)
    misp_by_predcf = Counter(r.get("bp_predicted_cf") or "None" for r in mispredicts)
    misp_by_rescf  = Counter(r.get("bp_resolved_cf") or "None" for r in mispredicts)

    print(f"  Total CTRL_FLOW         : {len(cf)}")
    print(f"  Predicted (non-NoCF)    : {len(predicted)}   {dict(pred_by_cf)}")
    print(f"  Reached resolution      : {len(resolved)}")
    print(f"  Flushed before resolve  : {len(flushed_pre)}")
    print(f"  Mispredicts             : {len(mispredicts)}")
    print(f"    by predicted_cf       : {dict(misp_by_predcf)}")
    print(f"    by resolved_cf        : {dict(misp_by_rescf)}")
    hit = (len(resolved) - len(mispredicts)) / len(resolved) if resolved else 0
    print(f"  Hit rate                : {100*hit:.2f}%")
    print()

    # === Non-NoCF predictions ===
    print("=" * 78)
    print(f"[2] ALL NON-NoCF PREDICTIONS (n={len(predicted)})")
    print("=" * 78)
    print(f"  {'id':>5}  {'pc':>11}  {'pred_cf':>8} {'pred_tgt':>11}  "
          f"{'res_cf':>8} {'res_tgt':>11}  {'tk':>2}  {'mp':>2}  disasm")
    print("  " + "-" * 100)
    for r in predicted[:30]:
        print(f"  {r.get('id'):>5}  "
              f"{r.get('pc') or '—':>11}  "
              f"{r.get('bp_predicted_cf') or '—':>8} "
              f"{fmt_target(r.get('bp_predicted_target')):>11}  "
              f"{r.get('bp_resolved_cf') or '—':>8} "
              f"{fmt_target(r.get('bp_resolved_target')):>11}  "
              f"{'T' if r.get('bp_resolved_taken') else 'N':>2}  "
              f"{'Y' if r.get('bp_mispredict') else '.':>2}  "
              f"{(r.get('disasm') or '')[:35]}")
    print()

    # === Top mispredicts with full context ===
    print("=" * 78)
    print(f"[3] MISPREDICTS — top {min(args.top_misp, len(mispredicts))}")
    print("=" * 78)
    print(f"  {'id':>5}  {'pc':>11}  {'pred_cf':>8} {'pred_tgt':>11}  "
          f"{'res_cf':>8} {'res_tgt':>11}  {'tk':>2}  disasm")
    print("  " + "-" * 100)
    for r in mispredicts[:args.top_misp]:
        print(f"  {r.get('id'):>5}  "
              f"{r.get('pc') or '—':>11}  "
              f"{r.get('bp_predicted_cf') or '—':>8} "
              f"{fmt_target(r.get('bp_predicted_target')):>11}  "
              f"{r.get('bp_resolved_cf') or '—':>8} "
              f"{fmt_target(r.get('bp_resolved_target')):>11}  "
              f"{'T' if r.get('bp_resolved_taken') else 'N':>2}  "
              f"{(r.get('disasm') or '')[:35]}")
    print()

    # === Per-PC mispredict frequency ===
    print("=" * 78)
    print("[4] PER-PC MISPREDICT FREQUENCY (recurring offenders)")
    print("=" * 78)
    misp_by_pc = Counter(r.get("pc") for r in mispredicts)
    pc_total = Counter(r.get("pc") for r in cf)
    rows = []
    for pc, n_misp in misp_by_pc.most_common():
        n_total = pc_total.get(pc, 0)
        rate = (100.0 * n_misp / n_total) if n_total else 0
        # Find disasm (first record with this pc)
        disasm = ""
        for r in cf:
            if r.get("pc") == pc:
                disasm = r.get("disasm") or ""
                break
        rows.append((pc, n_misp, n_total, rate, disasm))
    print(f"  {'pc':>11}  {'#misp':>5}  {'#tot':>5}  {'rate':>6}  disasm")
    print("  " + "-" * 70)
    for pc, n_misp, n_total, rate, disasm in rows[:20]:
        print(f"  {pc:>11}  {n_misp:>5}  {n_total:>5}  {rate:>5.1f}%  {disasm[:40]}")
    print()


if __name__ == "__main__":
    main()
