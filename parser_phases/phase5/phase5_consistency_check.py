#!/usr/bin/env python3
"""Phase 5 fu↔disasm consistency checker.

Walks every record in a Phase 5+ pipeline tracer JSON and verifies
that the recorded `fu` (Phase 4a, sourced from the scoreboard's
mem_q.sbe.fu signal) matches the functional-unit category implied
by the `disasm` mnemonic (Phase 5, sourced from objdump output).

These two paths are completely independent. fu comes from CVA6's
decoder via the in-VCD scoreboard signals. disasm comes from the
toolchain's objdump pass over the ELF. If they ever disagree, one
of three things is wrong:

  1. A Phase 4a regression — wrong fu attribution. The +1 slot drift
     bug that lived in phase4a-0.3 was exactly this kind of mismatch:
     every record's fu was the NEXT slot's fu, so disasm said `addi`
     but fu said CSR (or vice versa). The checker would have flagged
     ~all records on that JSON.
  2. A Phase 5 parse error — objdump line misread. Rare; the regex
     is conservative.
  3. A new ISA-extension mnemonic this script doesn't know about.
     Treated as a soft warning ("unknown mnemonic"), not a failure.

Mapping table is grounded in the actual RTL:
  - decoder.sv:447    OpcodeMiscMem (fence, fence.i) → CSR
  - decoder.sv:1527   OpcodeAmo     (amo*)           → STORE
  - ariane_pkg.sv:189 fu_t enum     (canonical names)

Usage:
  python3 phase5_consistency_check.py fdiv_phase5.json
  python3 phase5_consistency_check.py fdiv_phase5.json --all
  python3 phase5_consistency_check.py fdiv_phase5.json --include-flushed

Exit code: 0 if all-match-or-unknown, 1 if any genuine mismatches.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


# ============================================================================
# Mnemonic → fu mapping
# ============================================================================
# Built from the RV64IMAFDC + Zicsr + Zifencei ISA used by the
# cv64a6_imafdc_sv39_hpdcache_wb config. Pseudo-instructions are
# included where objdump emits them (li, mv, ret, j, nop, etc.).
# Compressed forms have the c. prefix stripped before lookup.

ALU_MNEM = {
    # Integer arithmetic — RV32I / RV64I
    "add", "addi", "addw", "addiw", "sub", "subw",
    "and", "andi", "or", "ori", "xor", "xori",
    "sll", "slli", "sllw", "slliw",
    "srl", "srli", "srlw", "srliw",
    "sra", "srai", "sraw", "sraiw",
    "slt", "slti", "sltu", "sltiu",
    "lui", "auipc",
    # Common pseudo-instructions
    "li", "mv", "neg", "negw", "not", "nop",
    "sext.b", "sext.h", "sext.w",
    "seqz", "snez", "sltz", "sgtz",
    "zext.b", "zext.h", "zext.w",
}

LOAD_MNEM = {
    "lb", "lbu", "lh", "lhu", "lw", "lwu", "ld",
    # FP loads
    "flw", "fld", "flh",
    # Atomic load-reserved (LR.W / LR.D, possibly with .aq/.rl suffixes —
    # those are caught by the regex in classify_mnemonic).
}

STORE_MNEM = {
    "sb", "sh", "sw", "sd",
    # FP stores
    "fsw", "fsd", "fsh",
    # Atomic store-conditional (SC.W / SC.D — base forms; suffixed forms
    # caught by regex)
}

CTRL_FLOW_MNEM = {
    "jal", "jalr", "j", "jr", "ret", "call", "tail",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    "ble", "bleu", "bgt", "bgtu",
}

CSR_MNEM = {
    # Direct CSR ops + pseudos
    "csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci",
    "csrr", "csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci",
    # FP CSR access pseudos (write/read fcsr/frm/fflags) — note these
    # start with 'f' but are explicitly CSR, not FPU.
    "fscsr", "frcsr", "fsrm", "frrm", "fsflags", "frflags",
    # SYSTEM ops route through the CSR functional unit in CVA6
    "ecall", "ebreak", "mret", "sret", "uret", "dret", "wfi",
    "sfence.vma", "hfence.vvma", "hfence.gvma",
    # Memory fences — decoder.sv:447 OpcodeMiscMem.fu = CSR
    "fence", "fence.i",
}

MULT_MNEM = {
    "mul", "mulh", "mulhsu", "mulhu", "mulw",
    "div", "divu", "divw", "divuw",
    "rem", "remu", "remw", "remuw",
}

# Atomic memory ops cover amo{swap,add,xor,or,and,min,max,minu,maxu}.{w,d}
# with optional .aq / .rl / .aqrl suffixes. CVA6 routes them all through
# the STORE unit (decoder.sv:1527 OpcodeAmo.fu = STORE) — including LR
# and SC, since they share the same opcode group.
_AMO_OR_LRSC_RE = re.compile(
    r'^(?:amo(?:swap|add|xor|or|and|min|max|minu|maxu)|lr|sc)'
    r'\.(?:w|d)'
    r'(?:\.(?:aq|rl|aqrl))?$'
)


def classify_mnemonic(mn):
    """Return expected fu string for `mn`, or 'UNKNOWN' if unrecognized.

    `mn` should already be lowercased and have any `c.` prefix stripped."""
    if mn in ALU_MNEM:
        return "ALU"
    if mn in LOAD_MNEM:
        return "LOAD"
    if mn in STORE_MNEM:
        return "STORE"
    if mn in CTRL_FLOW_MNEM:
        return "CTRL_FLOW"
    if mn in CSR_MNEM:
        return "CSR"
    if mn in MULT_MNEM:
        return "MULT"
    # Atomic group (AMOs + LR/SC with optional ordering suffixes).
    if _AMO_OR_LRSC_RE.match(mn):
        # LR.W/LR.D are technically LOAD per the ISA, but CVA6 routes
        # all OpcodeAmo (including LR/SC) through the STORE unit.
        return "STORE"
    # Anything else starting with 'f' that wasn't caught by the explicit
    # FP load/store/csr sets above is taken to be an FPU op.
    if mn.startswith("f"):
        return "FPU"
    return "UNKNOWN"


def extract_mnemonic(disasm):
    """Pull lowercase mnemonic from a disasm string, stripping `c.`."""
    if not disasm:
        return None
    mn = disasm.split(None, 1)[0].lower()
    if mn.startswith("c."):
        mn = mn[2:]
    return mn


# ============================================================================
# Driver
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Verify each record's fu matches the disasm mnemonic.")
    parser.add_argument("json_path", help="Phase 5+ pipeline tracer output.")
    parser.add_argument(
        "--all", action="store_true",
        help="Print every mismatch (default: first 20).")
    parser.add_argument(
        "--include-flushed", action="store_true",
        help="Include flushed records (default: skip — their decoded fields "
             "are typically pre-edge captures that may differ from the "
             "final decoded form).")
    args = parser.parse_args()

    path = Path(args.json_path)
    if not path.exists():
        sys.exit(f"Not found: {path}")

    with open(path) as f:
        d = json.load(f)
    recs = d.get('instructions', [])
    meta = d.get('metadata', {})

    print(f"Checking {path.name}")
    print(f"  extractor_version : {meta.get('extractor_version')}")
    print(f"  phase             : {meta.get('phase')}")
    print(f"  disasm_list       : {meta.get('disasm_list_path')}")
    print(f"  total records     : {len(recs):,}")
    print()

    n_checked = 0
    n_no_disasm = 0
    n_no_fu = 0
    n_skipped_flushed = 0
    n_match = 0
    mismatches = []
    unknown_mnemonics = Counter()
    matched_by_fu = Counter()

    for r in recs:
        if r.get('flushed') and not args.include_flushed:
            n_skipped_flushed += 1
            continue
        disasm = r.get('disasm')
        fu = r.get('fu')
        if not disasm:
            n_no_disasm += 1
            continue
        if not fu or fu == "NONE" or (isinstance(fu, str) and fu.startswith("UNK_")):
            n_no_fu += 1
            continue

        mn = extract_mnemonic(disasm)
        if mn is None or not re.match(r'^[0-9a-z.]+$', mn):
            # objdump emitted a raw hex word like '0x80787bb' (custom /
            # unrecognized instruction). Not a parse failure, just nothing
            # to classify.
            unknown_mnemonics[mn or '<empty>'] += 1
            continue
        expected = classify_mnemonic(mn)
        n_checked += 1

        if expected == "UNKNOWN":
            unknown_mnemonics[mn] += 1
            continue

        if expected == fu:
            n_match += 1
            matched_by_fu[fu] += 1
        else:
            mismatches.append({
                'id': r['id'], 'pc': r.get('pc'), 'mnemonic': mn,
                'disasm': disasm, 'fu_actual': fu, 'fu_expected': expected,
            })

    print(f"=== Summary ===")
    print(f"  checked             : {n_checked:>8,}")
    print(f"  matched             : {n_match:>8,}   ", end="")
    if n_checked:
        print(f"({100.0 * n_match / n_checked:.2f}%)")
    else:
        print()
    print(f"  MISMATCHED          : {len(mismatches):>8,}")
    print(f"  unknown mnemonic    : {sum(unknown_mnemonics.values()):>8,}")
    print(f"  no disasm           : {n_no_disasm:>8,}  "
          f"(records without an entry in the .list)")
    print(f"  no fu / NONE / UNK  : {n_no_fu:>8,}")
    if n_skipped_flushed:
        print(f"  flushed (skipped)   : {n_skipped_flushed:>8,}  "
              f"(use --include-flushed to check these too)")
    print()

    if matched_by_fu:
        print(f"=== Matched-record distribution by fu ===")
        for fu, n in sorted(matched_by_fu.items(), key=lambda x: -x[1]):
            print(f"  {fu:<12} {n:>8,}")
        print()

    if mismatches:
        print(f"=== Mismatches grouped by (expected, actual) ===")
        by_pair = Counter()
        for m in mismatches:
            by_pair[(m['fu_expected'], m['fu_actual'])] += 1
        for (exp, act), n in sorted(by_pair.items(), key=lambda x: -x[1]):
            print(f"  expected {exp:<10}  got {act:<10}  {n:>6,} records")
        print()
        limit = len(mismatches) if args.all else min(20, len(mismatches))
        print(f"=== First {limit} mismatches ===")
        for m in mismatches[:limit]:
            print(f"  id={m['id']:>5}  pc={m['pc']:<12}  "
                  f"mnemonic={m['mnemonic']:<14}  "
                  f"expected={m['fu_expected']:<10} actual={m['fu_actual']}")
        if not args.all and len(mismatches) > limit:
            print(
                f"  ... ({len(mismatches) - limit:,} more, use --all to show)")
        print()

    if unknown_mnemonics:
        print(f"=== Unknown mnemonics "
              f"(not in classifier; soft warning, not a failure) ===")
        for mn, n in unknown_mnemonics.most_common():
            # Find a sample record using this mnemonic to surface the
            # fu CVA6 actually assigned — useful for extending the map.
            sample = next(
                (r for r in recs
                 if extract_mnemonic(r.get('disasm') or '') == mn),
                None)
            actual_fu = sample.get('fu') if sample else '?'
            print(f"  {mn:<22}  {n:>5} records  "
                  f"(CVA6 assigned fu={actual_fu})")
        print()

    # Verdict + exit code
    if mismatches:
        print(f"FAIL: {len(mismatches):,} mismatches detected.")
        return 1
    elif unknown_mnemonics:
        print(f"PASS: 0 mismatches "
              f"({sum(unknown_mnemonics.values())} unknown mnemonics — "
              f"consider extending the map).")
        return 0
    else:
        print(f"PASS: all {n_match:,} records consistent.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
