#!/usr/bin/env python3
"""Phase 4a v0.2 validator: extract the minimal signal needed to confirm
that mem_q-indexed decoded-field capture is working end-to-end.

Usage:
    python3 p4a_validate.py fdiv_phase3.json

Prints (paste this back, ~30 lines):
  1. Header: version, total counts, throughput, user-code count.
  2. First 12 user-code (non-warmup, non-flushed) records' decoded fields.
  3. FU category distribution over all user-code records.
  4. Sanity: stage ordering invariant violations and ex==is+1 violations.
"""
from __future__ import annotations
import json
import sys
from collections import Counter


def main(path: str) -> None:
    with open(path, "r") as f:
        data = json.load(f)

    meta = data.get("metadata", {})
    recs = data.get("instructions", [])

    print(f"=== Phase 4a v0.2 validation: {path} ===")
    print(f"extractor_version: {meta.get('extractor_version')!r}")
    print(f"phase:             {meta.get('phase')!r}")
    print(f"warmup_end_cycle:  {meta.get('warmup_end_cycle')}")
    print(f"total records:     {len(recs)}")

    committed = [r for r in recs if not r.get("flushed") and r.get("co_cycle") is not None]
    flushed = [r for r in recs if r.get("flushed")]
    user = [r for r in committed if r.get("is_warmup") is False]
    print(f"committed:         {len(committed)}")
    print(f"flushed:           {len(flushed)}  "
          f"(if={sum(1 for r in flushed if r.get('flush_reason','').startswith('flush_if'))}"
          f" id={sum(1 for r in flushed if r.get('flush_reason','').startswith('flush_id'))}"
          f" ex={sum(1 for r in flushed if r.get('flush_reason','').startswith('flush_ex'))})")
    print(f"user-code:         {len(user)}")
    print()

    # --- First 12 user-code records' decoded fields ---
    print("=== First 12 user-code records (decoded fields) ===")
    print(f"{'id':>5}  {'pc':<12}  {'iw':<10}  {'rvc':<3}  {'fu':<9}  "
          f"{'cat':<5}  {'rd':>3}  {'rs1':>3}  {'rs2':>3}  tid")
    for r in user[:12]:
        rvc = "C" if r.get("is_compressed") else "-"
        fu = r.get("fu") or "?"
        cat = r.get("fu_category") or "?"
        rd = r.get("rd")
        rs1 = r.get("rs1")
        rs2 = r.get("rs2")
        print(f"{r.get('id'):>5}  {r.get('pc') or '-':<12}  "
              f"{(r.get('instr_word') or '-'):<10}  {rvc:<3}  {fu:<9}  "
              f"{cat:<5}  {('x'+str(rd)) if rd is not None else '-':>3}  "
              f"{('x'+str(rs1)) if rs1 is not None else '-':>3}  "
              f"{('x'+str(rs2)) if rs2 is not None else '-':>3}  "
              f"{r.get('trans_id')}")
    print()

    # --- FU category distribution over user code ---
    print("=== User-code FU + category distribution ===")
    fu_ctr = Counter(r.get("fu") or "None" for r in user)
    cat_ctr = Counter(r.get("fu_category") or "None" for r in user)
    print(f"by fu:       {dict(sorted(fu_ctr.items(), key=lambda x: -x[1]))}")
    print(f"by category: {dict(sorted(cat_ctr.items(), key=lambda x: -x[1]))}")
    print()

    # --- Sanity invariants ---
    print("=== Sanity invariants (user code) ===")
    n_order_viol = 0
    n_exis_viol = 0
    n_unset_fu = 0
    for r in user:
        cycles = [r.get(k) for k in ("fe_cycle", "id_cycle", "is_cycle",
                                     "ex_cycle", "wb_cycle", "co_cycle")]
        # Check monotonicity, ignoring None
        prev = None
        for c in cycles:
            if c is None:
                continue
            if prev is not None and c < prev:
                n_order_viol += 1
                break
            prev = c
        if r.get("is_cycle") is not None and r.get("ex_cycle") is not None:
            if r["ex_cycle"] != r["is_cycle"] + 1:
                n_exis_viol += 1
        if r.get("fu") is None:
            n_unset_fu += 1
    print(f"stage ordering violations:  {n_order_viol}")
    print(f"ex != is + 1 violations:    {n_exis_viol}")
    print(f"records with fu unset:      {n_unset_fu}  (expect 0 — flag for fallback)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: p4a_validate.py <fdiv_phase3.json>")
    main(sys.argv[1])
