#!/usr/bin/env python3
"""
CVA6 Pipeline Viewer — Phase 1 streaming VCD reader.

Stream a Verilator-generated VCD line-by-line, parse the $var declaration block
to identify whitelisted signals, count transitions on each, and report a
histogram.

This is Phase 1 of the build outlined in `cva6_viewer_phase0_spec.md`. The goal
is not to do pipeline reasoning. It is to prove three things:

  1. We can chew through a 29 GB VCD in finite time with bounded memory.
  2. The signal paths in the spec actually appear in the VCD (modulo scope
     prefix and bit-range expansion). Misses are surfaced loudly with
     candidate paths to help diagnose mismatches.
  3. The per-cycle transition rates on our anchor signals are in plausible
     orders of magnitude for the trace.

Usage:
    python3 phase1_vcd_reader.py <path-to.vcd>
    python3 phase1_vcd_reader.py <path-to.vcd> --scope-prefix TOP.tb.dut.i_cva6

What "success" looks like:

  - Script completes without errors on the target VCD.
  - "Found" count covers most or all of the WHITELIST entries. A few misses
    are normal at this stage and indicate signals to investigate, not a
    broken script.
  - Handshake-bit signals (valid/ready/ack) show <= 2 transitions per cycle.
  - Bus signals may show several transitions per cycle when active.
  - Numbers scale roughly with the number of dynamic instructions in the
    user-code window.

What "failure" looks like:

  - "No whitelisted signals matched" — `--scope-prefix` is wrong. The script
    will print the first 20 VCD signal paths it found so you can adjust.
  - All counts zero with non-zero "Value changes seen" — body iteration is
    broken or the matching index has a bug.
  - OOM kill — streaming logic regressed; we should never hold more than a
    few MB resident.
"""

import argparse
import re
import sys
import time
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Whitelist of signal paths relative to the CVA6 module scope.
# Bit ranges and array indices are stripped during matching, so "wt_valid_i"
# here matches "wt_valid_i[0]", "wt_valid_i[4:0]", "wt_valid_i[0][3]", etc.
# Keep this list in sync with cva6_viewer_phase0_spec.md §4.2.
# ---------------------------------------------------------------------------
WHITELIST = [
    # I$ request / response
    "i_frontend.icache_dreq_o.req",
    "i_frontend.icache_dreq_o.vaddr",
    "i_frontend.icache_dreq_o.kill_s1",
    "i_frontend.icache_dreq_o.kill_s2",
    "i_frontend.icache_dreq_i.valid",
    "i_frontend.icache_dreq_i.vaddr",

    # Fetch handshake (frontend → id_stage)
    "id_stage_i.fetch_entry_valid_i",
    "id_stage_i.fetch_entry_ready_o",
    "id_stage_i.rvfi_is_compressed_o",

    # Decode handshake (id_stage → scoreboard)
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",

    # Issue handshake (scoreboard → IRO)
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",

    # Writeback (EX → scoreboard)
    "issue_stage_i.i_scoreboard.wt_valid_i",
    "issue_stage_i.i_scoreboard.trans_id_i",

    # Commit
    "commit_stage_i.commit_ack_o",

    # Flush detection — wires at i_cva6 top level, not inside controller_i
    "flush_ctrl_if",
    "flush_ctrl_id",
    "flush_ctrl_ex",
    "flush_ctrl_bp",
]

# Strip trailing [n] or [hi:lo] groups; recursive (we apply it in a loop).
_BIT_RANGE_RE = re.compile(r"\[\d+(?::\d+)?\]$")


def strip_bit_range(path):
    """Strip every trailing [n] or [hi:lo] off `path` (handles nested arrays)."""
    while True:
        new = _BIT_RANGE_RE.sub("", path)
        if new == path:
            return path
        path = new


# ---------------------------------------------------------------------------
# VCD header parsing
# ---------------------------------------------------------------------------

def parse_var_block(file_iter):
    """Parse the VCD header up to and including `$enddefinitions`.

    Returns (path_to_id, id_to_path, timescale). The file iterator is left
    positioned at the first line of the body.
    """
    scope_stack = []
    path_to_id = {}
    id_to_path = {}
    timescale = "unknown"

    for line in file_iter:
        line = line.strip()
        if not line:
            continue

        if line.startswith("$enddefinitions"):
            return path_to_id, id_to_path, timescale

        if line.startswith("$scope"):
            # "$scope module NAME $end"
            tokens = line.split()
            if len(tokens) >= 3:
                scope_stack.append(tokens[2])
            continue

        if line.startswith("$upscope"):
            if scope_stack:
                scope_stack.pop()
            continue

        if line.startswith("$timescale"):
            rest = line[len("$timescale"):].split("$end")[0].strip()
            if rest:
                timescale = rest
            continue

        if line.startswith("$var"):
            # "$var TYPE WIDTH ID NAME [BIT_RANGE] $end"
            tokens = line.split()
            if len(tokens) < 6:
                continue
            vcd_id = tokens[3]
            sig_name = tokens[4]
            # Optional bit-range token before $end
            if len(tokens) >= 7 and tokens[5] != "$end":
                sig_name = sig_name + tokens[5]
            full_path = ".".join(scope_stack + [sig_name])
            path_to_id[full_path] = vcd_id
            id_to_path[vcd_id] = full_path

    # EOF without $enddefinitions
    return path_to_id, id_to_path, timescale


def match_whitelist(whitelist, path_to_id, scope_prefix):
    """For each whitelist entry, find every VCD signal whose path (with bit
    ranges stripped) equals `<scope_prefix>.<entry>`.

    Returns a list of dicts: {whitelist_path, full_paths, vcd_ids}.
    """
    # Index VCD signals by their stripped path.
    by_stripped = defaultdict(list)
    for full_path, vcd_id in path_to_id.items():
        by_stripped[strip_bit_range(full_path)].append((full_path, vcd_id))

    matches = []
    for entry in whitelist:
        target = f"{scope_prefix}.{entry}" if scope_prefix else entry
        hits = by_stripped.get(target, [])
        matches.append({
            "whitelist_path": entry,
            "full_paths": [h[0] for h in hits],
            "vcd_ids": [h[1] for h in hits],
        })
    return matches


# ---------------------------------------------------------------------------
# VCD body streaming
# ---------------------------------------------------------------------------

def count_transitions(file_iter, whitelist_ids):
    """Stream the VCD body; count transitions for any VCD ID in `whitelist_ids`.

    Returns (counts, total_lines, total_changes, last_timestamp, cycles_seen).
    """
    counts = defaultdict(int)
    total_lines = 0
    total_changes = 0
    last_timestamp = 0
    cycles_seen = 0
    last_report = 0
    start = time.time()

    for line in file_iter:
        total_lines += 1
        line = line.rstrip()
        if not line:
            continue
        first = line[0]

        if first == "#":
            try:
                last_timestamp = int(line[1:])
                cycles_seen += 1
            except ValueError:
                pass
        elif first in "01xXzZ":
            # Single-bit value change: "<value><id>"
            total_changes += 1
            vcd_id = line[1:]
            if vcd_id in whitelist_ids:
                counts[vcd_id] += 1
        elif first in "bBrR":
            # Bus or real: "b<bits> <id>" or "r<real> <id>"
            sp = line.find(" ")
            if sp > 0:
                total_changes += 1
                vcd_id = line[sp + 1:]
                if vcd_id in whitelist_ids:
                    counts[vcd_id] += 1

        # Lightweight progress report every 10 M lines.
        if total_lines - last_report >= 10_000_000:
            elapsed = time.time() - start
            print(
                f"  ... {total_lines:>15,} lines | "
                f"{total_changes:>15,} changes | "
                f"cycle ~{last_timestamp:>12,} | "
                f"{elapsed:6.1f}s",
                file=sys.stderr,
            )
            last_report = total_lines

    return counts, total_lines, total_changes, last_timestamp, cycles_seen


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(args, path_to_id, matches, counts, total_lines, total_changes,
                 last_timestamp, cycles_seen, elapsed, file_size, timescale):
    """Render the human-readable Phase 1 summary to stdout."""
    print()
    print("=" * 78)
    print(" Phase 1 VCD Reader — Summary")
    print("=" * 78)

    gb = file_size / (1024 ** 3)
    mb = file_size / (1024 ** 2)
    speed = mb / elapsed if elapsed > 0 else 0.0

    print(f" VCD file              : {args.vcd_path}")
    print(f" File size             : {file_size:>15,} bytes ({gb:.2f} GB)")
    print(f" Timescale             : {timescale}")
    print(f" Scope prefix          : {args.scope_prefix or '(none)'}")
    print(f" Total signals in VCD  : {len(path_to_id):>15,}")
    print(f" Lines processed       : {total_lines:>15,}")
    print(f" Value changes seen    : {total_changes:>15,}")
    print(f" Timestamps (cycles)   : {cycles_seen:>15,}")
    print(f" Final timestamp       : {last_timestamp:>15,}")
    print(f" Elapsed               : {elapsed:>14.1f}s ({speed:.1f} MB/s)")

    found = [m for m in matches if m["vcd_ids"]]
    missing = [m for m in matches if not m["vcd_ids"]]

    print()
    print("-" * 78)
    print(" Whitelist coverage")
    print("-" * 78)
    print(
        f" Found    : {len(found):>3} / {len(matches)} whitelisted signal groups")
    print(f" Missing  : {len(missing):>3}")

    if missing:
        print()
        print(" Missing entries (with candidate VCD paths for debugging):")
        for m in missing:
            last_seg = m["whitelist_path"].rsplit(".", 1)[-1]
            print(f"   - {m['whitelist_path']}")
            cands = [p for p in path_to_id if last_seg in p]
            for c in cands[:5]:
                print(f"       candidate: {c}")
            if len(cands) > 5:
                print(f"       ... and {len(cands) - 5} more")
            if not cands:
                print(f"       (no VCD signal path contains '{last_seg}')")

    if not found:
        return

    print()
    print("-" * 78)
    print(" Transition histogram (whitelist entries; sorted by total transitions)")
    print("-" * 78)
    rows = []
    for m in matches:
        if not m["vcd_ids"]:
            continue
        total = sum(counts[v] for v in m["vcd_ids"])
        per_cycle = (total / cycles_seen) if cycles_seen > 0 else 0.0
        rows.append((total, m["whitelist_path"], len(m["vcd_ids"]), per_cycle))
    rows.sort(reverse=True)

    max_path = max(len(r[1]) for r in rows)
    for total, path, n_sig, per_cycle in rows:
        print(f"   {path:<{max_path}}   [{n_sig:>2} sig]   "
              f"{total:>14,} trans   ({per_cycle:6.3f} / cycle)")
    print()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Phase 1: streaming VCD reader for the CVA6 pipeline viewer.",
    )
    parser.add_argument("vcd_path", help="Path to the .vcd file.")
    parser.add_argument(
        "--scope-prefix",
        default="TOP.ariane_testharness.i_ariane.i_cva6",
        help="Hierarchical prefix to prepend to each whitelist entry. "
             "Defaults to the standard CVA6 testharness path.",
    )
    args = parser.parse_args()

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD file not found: {vcd_path}")

    file_size = vcd_path.stat().st_size
    print(f"Opening {vcd_path} ({file_size / (1024 ** 3):.2f} GB)...")
    start = time.time()

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, id_to_path, timescale = parse_var_block(f)
        print(f"Header parsed: {len(path_to_id):,} signals declared, "
              f"timescale={timescale}")

        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        whitelist_ids = set()
        for m in matches:
            whitelist_ids.update(m["vcd_ids"])
        print(f"Whitelist match: tracking {len(whitelist_ids)} VCD signal IDs")

        if not whitelist_ids:
            print("\n!! No whitelisted signals matched. Check --scope-prefix.\n")
            print("   First 20 VCD signal paths discovered:")
            for p in list(path_to_id.keys())[:20]:
                print(f"     {p}")
            return 2

        print("Streaming body...")
        counts, total_lines, total_changes, last_ts, cycles_seen = \
            count_transitions(f, whitelist_ids)

    elapsed = time.time() - start
    print_report(args, path_to_id, matches, counts, total_lines, total_changes,
                 last_ts, cycles_seen, elapsed, file_size, timescale)
    return 0


if __name__ == "__main__":
    sys.exit(main())
