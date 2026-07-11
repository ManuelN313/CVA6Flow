#!/usr/bin/env python3
"""Phase 7b VCD path survey.

Scans the VCD header (everything before the first `$dumpvars` /
`#0` timestamp) and prints the full hierarchical paths of every
signal whose final name matches the patterns we care about for
Phase 7b (write-buffer and memory-side AXI interfaces).

Usage:
  python3 p7b_path_survey.py fdiv.vcd

The output is grouped into categories so we can quickly decide
which to whitelist in the extractor.
"""

import argparse
import re
import sys
from pathlib import Path

# Signal-name patterns we want to locate. Each entry is
# (category_label, list_of_regex_patterns). The regex matches the
# final name only (after the last dot); the surrounding hierarchy is
# preserved in the output.
CATEGORIES = [
    ("MISS_HANDLER / MEMORY READ", [
        r"^mem_req_valid_o$",
        r"^mem_req_ready_i$",
        r"^mem_resp_valid_i$",
        r"^mem_resp_ready_o$",
        r"^mem_req_o$",            # the request struct, if dumped
        r"^mem_resp_i$",
        r"^refill_fsm_q$",         # already in whitelist; sanity
        r"^mshr_alloc_.*$",        # already in whitelist; sanity
    ]),
    ("WRITE-BUFFER (wbuf)", [
        r"^wbuf_flush_i$",
        r"^wbuf_empty_o$",
        r"^wbuf_full_o$",
        r"^wbuf_write_(?:valid|ready)_i$",
        r"^wbuf_write_(?:valid|ready)_o$",
        r"^wbuf_read_(?:valid|ready)_i$",
        r"^wbuf_read_(?:valid|ready)_o$",
        r"^.*wbuf.*(?:valid|ready|ack|tid|addr|data|be)$",
    ]),
    ("MEMORY WRITE / AXI WRITE", [
        r"^mem_req_write_.*$",
        r"^mem_resp_write_.*$",
        r"^aw_.*$",
        r"^w_.*$",
        r"^b_.*$",
    ]),
    ("MEMORY READ / AXI READ", [
        r"^ar_.*$",
        r"^r_(?:valid|ready|data|id|last|resp)$",
        r"^mem_req_read_.*$",
        r"^mem_resp_read_.*$",
    ]),
    ("REFILL / MSHR (Phase 6b cross-ref)", [
        r"^refill_.*$",
        r"^miss_mshr_.*$",
    ]),
]


def vcd_walk_header(path):
    """Yield (full_dotted_path, signal_width, vcd_id, final_name) for
    every $var line in the VCD header. Stops at the first `#` or
    `$dumpvars` line."""
    scope_stack = []
    # Match either $scope module NAME $end (single line) or split.
    scope_re = re.compile(r"\$scope\s+\S+\s+(\S+)\s+\$end")
    upscope_re = re.compile(r"\$upscope\s+\$end")
    var_re = re.compile(
        r"\$var\s+\S+\s+(\d+)\s+(\S+)\s+(\S+)(?:\s*\[[^\]]+\])?\s+\$end")

    with open(path) as f:
        for line in f:
            ls = line.strip()
            if not ls:
                continue
            if ls.startswith("#") or ls.startswith("$dumpvars"):
                return
            m = scope_re.search(ls)
            if m:
                scope_stack.append(m.group(1))
                continue
            if upscope_re.search(ls):
                if scope_stack:
                    scope_stack.pop()
                continue
            m = var_re.search(ls)
            if m:
                width, vcd_id, name = m.group(1), m.group(2), m.group(3)
                full = ".".join(scope_stack + [name])
                yield (full, int(width), vcd_id, name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd_path")
    ap.add_argument(
        "--max-per-cat", type=int, default=40,
        help="cap matches shown per category (default 40)")
    ap.add_argument(
        "--scope-filter", default="hpdcache",
        help="only print paths containing this substring (default 'hpdcache')")
    args = ap.parse_args()

    p = Path(args.vcd_path)
    if not p.exists():
        sys.exit(f"file not found: {p}")

    # Compile all regexes per category
    cat_compiled = [(label, [re.compile(pat) for pat in pats])
                    for label, pats in CATEGORIES]
    matches = {label: [] for label, _ in CATEGORIES}

    n_total = 0
    for full, width, vid, name in vcd_walk_header(p):
        n_total += 1
        if args.scope_filter and args.scope_filter not in full:
            continue
        for label, regs in cat_compiled:
            if any(r.match(name) for r in regs):
                matches[label].append((full, width, vid))
                break

    print(f"# {p.name}: scanned {n_total} $var lines")
    print(f"# scope filter: '{args.scope_filter}'")
    print()

    for label, items in matches.items():
        if not items:
            continue
        # Deduplicate by full path; keep order
        seen = set()
        unique = []
        for it in items:
            if it[0] in seen:
                continue
            seen.add(it[0])
            unique.append(it)
        print("=" * 78)
        print(f"  {label}  ({len(unique)} unique paths)")
        print("=" * 78)
        for full, width, vid in unique[: args.max_per_cat]:
            print(f"  [{width:>4}b]  id={vid:>6}   {full}")
        if len(unique) > args.max_per_cat:
            print(f"  ... ({len(unique) - args.max_per_cat} more truncated)")
        print()


if __name__ == "__main__":
    main()
