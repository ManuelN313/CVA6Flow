#!/usr/bin/env python3
"""Phase 8 spot-check — 8a forwarding, 8b wraps_line, 8c branch bubbles.

Loads a tracer JSON output and:

  1. Counts every Phase 8 tag and prints a summary.

  2. Runs CONSISTENCY ASSERTIONS that catch any per-record field
     inconsistency (each wraps_line=True record must have PC&7==6 and
     non-None if1_hi/if2_hi with if2_hi > if2_lo; each bubble causer's
     bubble_recovery_id must point to a recovery whose
     bubble_from_branch_id round-trips back; each fwd_rsX_via must be
     either 'sb' or 'wb' and only set when fwd_rsX_used is True; etc.).

  3. Shows instructive INDIVIDUAL records:
     - 5 wraps_line records with their PC + all four fetch cycles
     - the bubble causer for each kind (mispred, unpred, flush_other)
       paired with its recovery
     - 5 forwarding records with via=wb plus 2 with via=sb, showing
       the producer trans_id and the consumer's stage timing

Usage:
  python3 p8_spot_check.py daxpy.json
  python3 p8_spot_check.py daxpy.json --max-wraps 10
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def fmt_pc(pc):
    if pc is None: return "—"
    return pc if isinstance(pc, str) else f"0x{pc:x}"


def fmt_int(v, w=6):
    return f"{v:>{w}}" if v is not None else f"{'—':>{w}}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path")
    ap.add_argument("--max-wraps", type=int, default=5,
                    help="show up to N wraps_line records (default 5)")
    ap.add_argument("--max-fwd",   type=int, default=5,
                    help="show up to N forwarding records per via (default 5)")
    args = ap.parse_args()

    p = Path(args.json_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")
    with p.open() as f:
        data = json.load(f)

    instructions = data.get("instructions", [])
    by_id = {r["id"]: r for r in instructions if r.get("id") is not None}
    print(f"# {p.name}: {len(instructions)} records "
          f"({sum(1 for r in instructions if r.get('flushed')):d} flushed)")
    print()

    # ========================================================================
    # [1] SUMMARY
    # ========================================================================
    print("=" * 78)
    print("[1] PHASE 8 TAG COUNTS")
    print("=" * 78)
    n_wraps         = sum(1 for r in instructions if r.get("wraps_line"))
    n_wraps_cmtd    = sum(1 for r in instructions
                          if r.get("wraps_line") and not r.get("flushed"))
    n_wraps_flushed = n_wraps - n_wraps_cmtd
    n_with_if_hi    = sum(1 for r in instructions
                          if r.get("if1_hi") is not None)
    bubble_kinds    = Counter(r.get("bubble_kind") for r in instructions
                              if r.get("bubble_kind"))
    n_recoveries    = sum(1 for r in instructions
                          if r.get("bubble_from_branch_id") is not None)
    fwd_via         = Counter()
    n_fwd_records   = 0
    for r in instructions:
        any_used = False
        for s in ("rs1", "rs2", "rs3"):
            if r.get(f"fwd_{s}_used"):
                any_used = True
                via = r.get(f"fwd_{s}_via")
                fwd_via[via or "None"] += 1
        if any_used:
            n_fwd_records += 1

    print(f"  Phase 8a forwarding:")
    print(f"    Records with any forward     : {n_fwd_records}")
    print(f"    Per-source via counts        : {dict(fwd_via)}")
    print()
    print(f"  Phase 8b wraps_line:")
    print(f"    Records with wraps_line=True : {n_wraps}  "
          f"({n_wraps_cmtd} committed, {n_wraps_flushed} flushed)")
    print(f"    Records with if1_hi set      : {n_with_if_hi}")
    print()
    print(f"  Phase 8c bubbles:")
    print(f"    Causers by kind              : {dict(bubble_kinds)}")
    print(f"    Recovery records             : {n_recoveries}")
    print()

    # ========================================================================
    # [2] CONSISTENCY ASSERTIONS
    # ========================================================================
    print("=" * 78)
    print("[2] CONSISTENCY CHECKS")
    print("=" * 78)
    errors = []

    # ----- 8b: every wraps_line=True must satisfy PC test and have both fetches
    for r in instructions:
        if not r.get("wraps_line"):
            continue
        pc = r.get("pc")
        if pc is None:
            errors.append(f"id={r['id']}: wraps_line=True but pc is None")
            continue
        try:
            pc_int = int(pc, 16)
        except (TypeError, ValueError):
            errors.append(f"id={r['id']}: pc not parseable: {pc!r}")
            continue
        if (pc_int & 0x7) != 0x6:
            errors.append(f"id={r['id']} pc={pc}: wraps_line=True "
                          f"but pc&7 = {pc_int & 7}, not 6")
        if r.get("is_compressed"):
            errors.append(f"id={r['id']} pc={pc}: wraps_line=True "
                          f"but is_compressed=True (RVC can't wrap)")
        if r.get("if1_hi") is None or r.get("if2_hi") is None:
            errors.append(f"id={r['id']} pc={pc}: wraps_line=True "
                          f"but if1_hi/if2_hi not bound")
        elif r.get("if2_hi") <= r.get("if2_lo", -1):
            errors.append(f"id={r['id']} pc={pc}: wraps_line=True "
                          f"but if2_hi ({r['if2_hi']}) <= if2_lo "
                          f"({r.get('if2_lo')})")

    # ----- 8b: records without wraps_line must NOT have if1_hi populated
    for r in instructions:
        if not r.get("wraps_line") and r.get("if1_hi") is not None:
            errors.append(f"id={r['id']}: wraps_line=False but "
                          f"if1_hi={r['if1_hi']} (should be None)")

    # ----- 8c: every bubble causer must round-trip to its recovery
    for r in instructions:
        if r.get("bubble_kind") is None:
            continue
        rec_id = r.get("bubble_recovery_id")
        if rec_id is None:
            errors.append(f"id={r['id']}: bubble_kind={r['bubble_kind']} "
                          f"but bubble_recovery_id is None")
            continue
        recovery = by_id.get(rec_id)
        if recovery is None:
            errors.append(f"id={r['id']}: recovery_id={rec_id} not in records")
            continue
        if recovery.get("bubble_from_branch_id") != r["id"]:
            errors.append(f"id={r['id']}: recovery.from_branch_id="
                          f"{recovery.get('bubble_from_branch_id')} "
                          f"!= causer.id ({r['id']})")
        if recovery.get("bubble_cycles") != r.get("bubble_caused_cycles"):
            errors.append(f"id={r['id']}: "
                          f"caused_cycles={r.get('bubble_caused_cycles')} "
                          f"!= recovery.cycles={recovery.get('bubble_cycles')}")
        if recovery.get("flushed"):
            errors.append(f"id={r['id']}: recovery is flushed (impossible)")

    # ----- 8c: every recovery's from_branch_id must round-trip to causer
    for r in instructions:
        if r.get("bubble_from_branch_id") is None:
            continue
        causer = by_id.get(r["bubble_from_branch_id"])
        if causer is None:
            errors.append(f"id={r['id']}: from_branch_id="
                          f"{r['bubble_from_branch_id']} not in records")
            continue
        if causer.get("bubble_recovery_id") != r["id"]:
            errors.append(f"id={r['id']}: causer.recovery_id="
                          f"{causer.get('bubble_recovery_id')} != self ({r['id']})")

    # ----- 8a: fwd_rsX_via only meaningful when fwd_rsX_used=True
    for r in instructions:
        for s in ("rs1", "rs2", "rs3"):
            used = r.get(f"fwd_{s}_used", False)
            via  = r.get(f"fwd_{s}_via")
            ftid = r.get(f"fwd_{s}_from_tid")
            if used:
                if via not in ("sb", "wb"):
                    errors.append(f"id={r['id']} {s}: used=True but "
                                  f"via={via!r} (must be sb or wb)")
                if ftid is None:
                    errors.append(f"id={r['id']} {s}: used=True but "
                                  f"from_tid is None")
            else:
                if via is not None:
                    errors.append(f"id={r['id']} {s}: used=False but "
                                  f"via={via!r} (should be None)")
                if ftid is not None:
                    errors.append(f"id={r['id']} {s}: used=False but "
                                  f"from_tid={ftid} (should be None)")

    if not errors:
        print("  ✓ All assertions passed.")
    else:
        print(f"  ✗ {len(errors)} consistency error(s):")
        for e in errors[:20]:
            print(f"      {e}")
        if len(errors) > 20:
            print(f"      ... and {len(errors) - 20} more")
    print()

    # ========================================================================
    # [3] WRAPS_LINE EXAMPLES
    # ========================================================================
    print("=" * 78)
    print(f"[3] WRAPS_LINE EXAMPLES (first {args.max_wraps})")
    print("=" * 78)
    wraps_recs = [r for r in instructions if r.get("wraps_line")][:args.max_wraps]
    if wraps_recs:
        print(f"  {'id':>5}  {'pc':>11}  {'rvc':>3}  "
              f"{'if1_lo':>6} {'if2_lo':>6}  {'if1_hi':>6} {'if2_hi':>6}  "
              f"{'fe':>5}  {'fl':>2}  disasm")
        print("  " + "-" * 90)
        for r in wraps_recs:
            print(f"  {r['id']:>5}  {fmt_pc(r.get('pc')):>11}  "
                  f"{'Y' if r.get('is_compressed') else 'N':>3}  "
                  f"{fmt_int(r.get('if1_lo'))} {fmt_int(r.get('if2_lo'))}  "
                  f"{fmt_int(r.get('if1_hi'))} {fmt_int(r.get('if2_hi'))}  "
                  f"{fmt_int(r.get('fe_cycle'), 5)}  "
                  f"{'F' if r.get('flushed') else '.':>2}  "
                  f"{(r.get('disasm') or '')[:30]}")
    else:
        print("  (no wraps_line records)")
    print()

    # ========================================================================
    # [4] BUBBLE CAUSERS — one example per kind
    # ========================================================================
    print("=" * 78)
    print("[4] BUBBLE CAUSER ↔ RECOVERY (sample by kind)")
    print("=" * 78)
    seen_kinds = set()
    for r in instructions:
        kind = r.get("bubble_kind")
        if kind is None or kind in seen_kinds:
            continue
        seen_kinds.add(kind)
        rec = by_id.get(r.get("bubble_recovery_id"))
        print(f"\n  [{kind.upper()}]")
        print(f"    Causer:   id={r['id']}  pc={fmt_pc(r.get('pc'))}  "
              f"fu={r.get('fu')}  "
              f"pred_cf={r.get('bp_predicted_cf')}  "
              f"res_cf={r.get('bp_resolved_cf')}  "
              f"mispredict={r.get('bp_mispredict')}")
        print(f"              bubble_caused_cycles={r.get('bubble_caused_cycles')}"
              f"  bubble_recovery_id={r.get('bubble_recovery_id')}")
        if r.get("disasm"):
            print(f"              disasm: {r['disasm']}")
        if rec is not None:
            print(f"    Recovery: id={rec['id']}  pc={fmt_pc(rec.get('pc'))}  "
                  f"fu={rec.get('fu')}")
            print(f"              bubble_from_branch_id="
                  f"{rec.get('bubble_from_branch_id')}  "
                  f"bubble_cycles={rec.get('bubble_cycles')}")
            if rec.get("disasm"):
                print(f"              disasm: {rec['disasm']}")
            # Show flushed records in between
            n_flushed = 0
            flushed_ids = []
            for between_id in range(r["id"] + 1, rec["id"]):
                between = by_id.get(between_id)
                if between and between.get("flushed"):
                    n_flushed += 1
                    flushed_ids.append(between_id)
            print(f"              {n_flushed} flushed records in between: "
                  f"ids {flushed_ids[:6]}"
                  + ("..." if len(flushed_ids) > 6 else ""))
    print()

    # ========================================================================
    # [5] FORWARDING SAMPLE
    # ========================================================================
    print("=" * 78)
    print(f"[5] FORWARDING — first {args.max_fwd} via=wb plus {args.max_fwd//2} via=sb")
    print("=" * 78)
    wb_recs = []
    sb_recs = []
    for r in instructions:
        if r.get("flushed"):
            continue
        for s in ("rs1", "rs2", "rs3"):
            if r.get(f"fwd_{s}_used"):
                via = r.get(f"fwd_{s}_via")
                entry = (r, s, via, r.get(f"fwd_{s}_from_tid"))
                if via == "wb" and len(wb_recs) < args.max_fwd:
                    wb_recs.append(entry)
                elif via == "sb" and len(sb_recs) < max(2, args.max_fwd // 2):
                    sb_recs.append(entry)
        if len(wb_recs) >= args.max_fwd and len(sb_recs) >= 2:
            break

    print(f"  {'id':>5}  {'pc':>11}  {'fu':>9}  {'rs':>3}  "
          f"{'via':>3} {'src_tid':>7}  {'is':>5} {'ex':>5} {'wb':>5}  disasm")
    print("  " + "-" * 90)
    for r, s, via, ftid in wb_recs + sb_recs:
        print(f"  {r['id']:>5}  {fmt_pc(r.get('pc')):>11}  "
              f"{r.get('fu') or '—':>9}  {s:>3}  "
              f"{via:>3} {fmt_int(ftid, 7)}  "
              f"{fmt_int(r.get('is_cycle'), 5)} "
              f"{fmt_int(r.get('ex_cycle'), 5)} "
              f"{fmt_int(r.get('wb_cycle'), 5)}  "
              f"{(r.get('disasm') or '')[:30]}")
    print()

    # Final pass/fail signal for shell automation
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
