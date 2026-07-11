#!/usr/bin/env python3
"""Phase 8c focused dump — show full record context around a given id range
or around every bubble causer.

Usage:
  # Dump records in id range [30, 45]
  python3 p8c_dump_range.py daxpy.json --range 30 45

  # Dump records around every flush_other bubble causer (id-7 to id+5)
  python3 p8c_dump_range.py daxpy.json --kind flush_other

  # Dump every bubble (any kind)
  python3 p8c_dump_range.py daxpy.json --all-bubbles
"""

import argparse
import json
import sys
from pathlib import Path


COLS = ["id", "pc", "fu", "is_compressed",
        "fe_cycle", "id_cycle", "is_cycle", "ex_cycle", "wb_cycle", "co_cycle",
        "flushed", "flush_reason",
        "bp_predicted_cf", "bp_resolved_cf", "bp_mispredict",
        "bubble_kind", "bubble_caused_cycles", "bubble_recovery_id",
        "bubble_from_branch_id", "bubble_cycles",
        "disasm"]


def fmt(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "T" if v else "F"
    if isinstance(v, str):
        return v
    return str(v)


def dump_range(by_id, lo, hi, max_disasm=42):
    """Print records[lo..hi] in a compact form, one record per line group."""
    print(f"  {'id':>3}  {'pc':>11}  {'fu':>9}  {'rvc':>3}  "
          f"{'is':>4}{'ex':>4}{'wb':>4}{'co':>4}  "
          f"{'fl':>2}  {'pred':>5} {'res':>5} {'mp':>2}  "
          f"{'bub_kind':>11} {'caused':>6} {'rec':>4}  "
          f"{'from':>4} {'b_cyc':>5}  disasm")
    print("  " + "-" * 130)
    for i in range(lo, hi + 1):
        r = by_id.get(i)
        if r is None:
            print(f"  {i:>3}  (no record with this id)")
            continue
        print(
            f"  {r.get('id'):>3}  "
            f"{r.get('pc') or '—':>11}  "
            f"{(r.get('fu') or '—'):>9}  "
            f"{'Y' if r.get('is_compressed') else 'N':>3}  "
            f"{fmt(r.get('is_cycle')):>4}{fmt(r.get('ex_cycle')):>4}"
            f"{fmt(r.get('wb_cycle')):>4}{fmt(r.get('co_cycle')):>4}  "
            f"{fmt(r.get('flushed')):>2}  "
            f"{(r.get('bp_predicted_cf') or '—')[:5]:>5} "
            f"{(r.get('bp_resolved_cf') or '—')[:5]:>5} "
            f"{fmt(r.get('bp_mispredict')):>2}  "
            f"{(r.get('bubble_kind') or '—'):>11} "
            f"{fmt(r.get('bubble_caused_cycles')):>6} "
            f"{fmt(r.get('bubble_recovery_id')):>4}  "
            f"{fmt(r.get('bubble_from_branch_id')):>4} "
            f"{fmt(r.get('bubble_cycles')):>5}  "
            f"{(r.get('disasm') or '')[:max_disasm]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path")
    ap.add_argument("--range", nargs=2, type=int, metavar=("LO", "HI"),
                    help="dump records in id range [LO, HI]")
    ap.add_argument("--kind", choices=["mispred", "unpred", "flush_other"],
                    help="dump records around every causer of this kind")
    ap.add_argument("--all-bubbles", action="store_true",
                    help="dump records around every bubble causer")
    ap.add_argument("--window", type=int, default=7,
                    help="records before/after the causer (default 7)")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")
    with p.open() as f:
        data = json.load(f)
    instructions = data.get("instructions", [])
    by_id = {r["id"]: r for r in instructions if r.get("id") is not None}

    if args.range:
        lo, hi = args.range
        print(f"# {p.name}: records {lo}..{hi}")
        dump_range(by_id, lo, hi)
        return

    # Find bubble causers
    causers = []
    for r in instructions:
        kind = r.get("bubble_kind")
        if not kind:
            continue
        if args.kind and kind != args.kind:
            continue
        if not args.all_bubbles and not args.kind:
            continue
        causers.append(r)

    if not causers:
        sys.exit("specify --range LO HI, --kind KIND, or --all-bubbles")

    w = args.window
    for c in causers:
        lo = max(0, c["id"] - w)
        hi = c["id"] + w
        print()
        print(f"# {p.name}: bubble at id={c['id']} ({c.get('bubble_kind')}), "
              f"showing ±{w}")
        dump_range(by_id, lo, hi)


if __name__ == "__main__":
    main()
