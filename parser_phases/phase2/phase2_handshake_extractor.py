#!/usr/bin/env python3
"""
CVA6 Pipeline Viewer — Phase 2 handshake extractor.

Stream a Verilator VCD, maintain the current value of whitelisted signals,
detect rising clk_i edges, and emit one record per cycle on which the
fetch handshake fires (`fetch_entry_valid_i && fetch_entry_ready_o`).

Output is a real JSON file matching the schema in cva6_viewer_phase0_spec.md
§5. Post-fetch stage fields (`id_cycle`, `is_cycle`, ...) are populated with
null at this phase. Later phases fill them in.

Cycle-detection correctness: a VCD timestamp can contain many value changes
in arbitrary order, including clk_i and the combinational signals derived
from it. Checking the handshake the instant we see the clk transition would
race with those companion changes. Instead, the script snapshots clk_i at
the *start* of each timestamp and evaluates the rising-edge predicate at
the next timestamp marker, by which point the timestamp's changes have all
settled. The handshake check uses those settled values.

Usage:
    python3 phase2_handshake_extractor.py <path-to.vcd>
    python3 phase2_handshake_extractor.py <path-to.vcd> \\
        --scope-prefix TOP.tb.dut.cva6 \\
        --output fdiv.phase2.json
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path


# ============================================================================
# Whitelist (Phase 2 = Phase 1 set + clk + PC/instruction signals).
# Keep in sync with cva6_viewer_phase0_spec.md §4.2.
# ============================================================================

WHITELIST = [
    # Clock (Phase 2 addition — required for cycle detection)
    "clk_i",

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

    # Per-instruction payload from the frontend. These wires live at the
    # i_cva6 parent scope (named fetch_entry_if_id), not inside id_stage_i —
    # same pattern as flush_ctrl_*. The [0] is the issue-port index;
    # NrIssuePorts=1 so only port 0 exists.
    "fetch_entry_if_id[0].address",
    "fetch_entry_if_id[0].instruction",

    # Decode handshake
    "issue_stage_i.i_scoreboard.decoded_instr_valid_i",
    "issue_stage_i.i_scoreboard.decoded_instr_ack_o",

    # Issue handshake
    "issue_stage_i.i_scoreboard.issue_instr_valid_o",
    "issue_stage_i.i_scoreboard.issue_ack_i",
    "issue_stage_i.i_scoreboard.issue_pointer_q",

    # Writeback
    "issue_stage_i.i_scoreboard.wt_valid_i",
    "issue_stage_i.i_scoreboard.trans_id_i",

    # Commit
    "commit_stage_i.commit_ack_o",

    # Flush
    "flush_ctrl_if",
    "flush_ctrl_id",
    "flush_ctrl_ex",
    "flush_ctrl_bp",
]

# Signals this phase MUST find — script aborts cleanly if any are missing.
REQUIRED_SIGNALS = {
    "clk_i",
    "id_stage_i.fetch_entry_valid_i",
    "id_stage_i.fetch_entry_ready_o",
}

# All instruction-record fields per spec §5.5. Anything not in PHASE2_POPULATES
# is emitted as null and will be filled by a later phase.
ALL_INSTRUCTION_FIELDS = [
    "id", "pc", "instr_word", "disasm", "is_compressed", "is_warmup",
    "fu", "fu_category", "rd", "rs1", "rs2", "trans_id", "fetch_port",
    "if1_cycle", "if2_cycle", "fe_cycle", "id_cycle", "is_cycle",
    "ex_cycle", "wb_cycle", "co_cycle", "flushed", "flush_reason",
    "lsu_state_history",
]

PHASE2_POPULATES = {
    "id", "pc", "instr_word", "is_compressed", "is_warmup",
    "fe_cycle", "fetch_port",
}


# ============================================================================
# VCD header parsing (reused from Phase 1)
# ============================================================================

_BIT_RANGE_RE = re.compile(r"\[\d+(?::\d+)?\]$")


def strip_bit_range(path):
    while True:
        new = _BIT_RANGE_RE.sub("", path)
        if new == path:
            return path
        path = new


def parse_var_block(f):
    """Parse VCD header. Returns (path_to_id, id_to_path, timescale).
    Leaves the file iterator positioned at the first line of the body."""
    scope_stack = []
    path_to_id = {}
    id_to_path = {}
    timescale = "unknown"

    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith("$enddefinitions"):
            return path_to_id, id_to_path, timescale
        if line.startswith("$scope"):
            tokens = line.split()
            if len(tokens) >= 3:
                scope_stack.append(tokens[2])
        elif line.startswith("$upscope"):
            if scope_stack:
                scope_stack.pop()
        elif line.startswith("$timescale"):
            rest = line[len("$timescale"):].split("$end")[0].strip()
            if rest:
                timescale = rest
        elif line.startswith("$var"):
            tokens = line.split()
            if len(tokens) < 6:
                continue
            vcd_id = tokens[3]
            sig_name = tokens[4]
            if len(tokens) >= 7 and tokens[5] != "$end":
                sig_name += tokens[5]
            full_path = ".".join(scope_stack + [sig_name])
            path_to_id[full_path] = vcd_id
            id_to_path[vcd_id] = full_path

    return path_to_id, id_to_path, timescale


def match_whitelist(whitelist, path_to_id, scope_prefix):
    """For each whitelist entry, find VCD signals whose stripped path equals
    `<scope_prefix>.<entry>`. Returns a list of dicts."""
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


# ============================================================================
# Streaming extraction
# ============================================================================

def binary_to_hex(s):
    """Convert binary value string (e.g. '0011') to '0x3'. Returns None for
    x/z values or empty input."""
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    if any(c in s.lower() for c in "xz"):
        return None
    try:
        return f"0x{int(s, 2):x}"
    except ValueError:
        return None


def stream_and_extract(f, matches):
    """Stream the VCD body and emit records on fetch handshakes.

    Returns (records, stats).
    """
    id_to_role = {}
    role_state = {m["whitelist_path"]: None for m in matches}
    for m in matches:
        for vcd_id in m["vcd_ids"]:
            id_to_role[vcd_id] = m["whitelist_path"]

    K_CLK = "clk_i"
    K_VALID = "id_stage_i.fetch_entry_valid_i"
    K_READY = "id_stage_i.fetch_entry_ready_o"
    K_PC = "fetch_entry_if_id[0].address"
    K_INSTR = "fetch_entry_if_id[0].instruction"
    K_RVC = "id_stage_i.rvfi_is_compressed_o"

    cycle = -1                # bumps to 0 on first rising clk edge
    first_ts_seen = False
    clk_at_ts_start = "0"     # snapshot of clk at the start of the active ts

    records = []
    next_id = 0

    n_lines = 0
    n_changes = 0
    last_ts = 0
    last_report = 0
    start = time.time()

    def maybe_emit_for_just_finished_ts():
        """Called when we see a new '#' marker. The state now reflects the END
        of the just-finished timestamp. If clk transitioned 0→1 during it,
        that timestamp contained a rising edge and we check the handshake."""
        nonlocal cycle, next_id
        curr_clk = role_state.get(K_CLK)
        if clk_at_ts_start == "0" and curr_clk == "1":
            cycle += 1
            if (role_state.get(K_VALID) == "1"
                    and role_state.get(K_READY) == "1"):
                rec = {field: None for field in ALL_INSTRUCTION_FIELDS}
                rec["id"] = next_id
                rec["pc"] = binary_to_hex(role_state.get(K_PC))
                rec["instr_word"] = binary_to_hex(role_state.get(K_INSTR))
                rec["is_compressed"] = (role_state.get(K_RVC) == "1")
                rec["is_warmup"] = False    # Phase 3 will compute properly
                rec["fe_cycle"] = cycle
                rec["fetch_port"] = 0       # single-issue in this config
                records.append(rec)
                next_id += 1

    for line in f:
        n_lines += 1
        line = line.rstrip()
        if not line:
            continue
        c0 = line[0]

        if c0 == "#":
            if first_ts_seen:
                maybe_emit_for_just_finished_ts()
            else:
                first_ts_seen = True
            try:
                last_ts = int(line[1:])
            except ValueError:
                pass
            # Snapshot clk for the new timestamp.
            clk_at_ts_start = role_state.get(K_CLK) or "0"

            if n_lines - last_report >= 10_000_000:
                elapsed = time.time() - start
                print(
                    f"  ... {n_lines:>15,} lines | "
                    f"{n_changes:>15,} changes | "
                    f"cycle {cycle:>10,} | "
                    f"records {len(records):>10,} | "
                    f"{elapsed:6.1f}s",
                    file=sys.stderr,
                )
                last_report = n_lines
            continue

        # Value change line
        if c0 in "01xXzZ":
            value = c0
            vcd_id = line[1:]
        elif c0 in "bBrR":
            sp = line.find(" ")
            if sp <= 0:
                continue
            value = line[1:sp]
            vcd_id = line[sp + 1:]
        else:
            continue
        n_changes += 1

        role = id_to_role.get(vcd_id)
        if role is not None:
            role_state[role] = value

    # EOF: flush whatever the final timestamp contained.
    if first_ts_seen:
        maybe_emit_for_just_finished_ts()

    stats = {
        "n_lines": n_lines,
        "n_changes": n_changes,
        "last_ts": last_ts,
        "n_cycles": cycle + 1,
    }
    return records, stats


# ============================================================================
# Output
# ============================================================================

# Defaults derived in cva6_viewer_phase0_spec.md §5.3. Phase 3 will read these
# from the config package at run time.
CV64A6_HPDC_WB_DEFAULTS = {
    "SuperscalarEn": False,
    "RVC": True,
    "CvxifEn": True,
    "NrIssuePorts": 1,
    "NrCommitPorts": 2,
    "NrWbPorts": 5,
    "NrScoreboardEntries": 8,
    "TRANS_ID_BITS": 3,
    "FETCH_WIDTH": 32,
    "INSTR_PER_FETCH": 2,
}


def write_output_json(output_path, args, stats, records):
    """Write the output JSON. One record per line in `instructions` for
    grep-friendliness on large traces."""
    metadata = {
        "config_name": "cv64a6_imafdc_sv39_hpdcache_wb",
        "elf_path": None,
        "vcd_path": str(args.vcd_path),
        "user_entry_pc": args.user_entry_pc,
        "warmup_end_cycle": None,
        "tohost_cycle": None,
        "extractor_version": "phase2-0.1",
        "vcd_scope_prefix": args.scope_prefix,
        "phase": 2,
        "phase2_populated_fields": sorted(PHASE2_POPULATES),
        "invariants_verified": [],
    }

    with output_path.open("w") as f:
        f.write("{\n")
        f.write(f'  "metadata": {json.dumps(metadata, indent=2)},\n')
        f.write(f'  "config_params": {json.dumps(CV64A6_HPDC_WB_DEFAULTS, indent=2)},\n')
        f.write(f'  "buffer_maxima": {json.dumps({})},\n')
        f.write('  "instructions": [\n')
        for i, rec in enumerate(records):
            comma = "," if i < len(records) - 1 else ""
            f.write(f"    {json.dumps(rec)}{comma}\n")
        f.write("  ]\n")
        f.write("}\n")


# ============================================================================
# Diagnostics
# ============================================================================

def report_missing(matches, path_to_id):
    """Print missing whitelist entries with candidate paths. Returns the list
    of missing whitelist_paths."""
    missing = [m for m in matches if not m["vcd_ids"]]
    if not missing:
        return []

    print(file=sys.stderr)
    print("Missing whitelist entries:", file=sys.stderr)
    for m in missing:
        last_seg = m["whitelist_path"].rsplit(".", 1)[-1]
        print(f"  - {m['whitelist_path']}", file=sys.stderr)
        cands = [p for p in path_to_id if last_seg in p]
        for c in cands[:5]:
            print(f"      candidate: {c}", file=sys.stderr)
        if len(cands) > 5:
            print(f"      ... and {len(cands) - 5} more", file=sys.stderr)
        if not cands:
            print(f"      (no VCD path contains '{last_seg}')", file=sys.stderr)
    return [m["whitelist_path"] for m in missing]


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 2 handshake extractor for the CVA6 pipeline viewer.",
    )
    parser.add_argument("vcd_path", help="Path to the .vcd file.")
    parser.add_argument(
        "--scope-prefix",
        default="TOP.ariane_testharness.i_ariane.i_cva6",
        help="Hierarchical prefix to prepend to each whitelist entry.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON path. Defaults to <vcd_basename>.phase2.json.",
    )
    parser.add_argument(
        "--user-entry-pc",
        default=None,
        help="(Reserved for Phase 3.) Hex PC of `main` for warmup detection.",
    )
    args = parser.parse_args()

    vcd_path = Path(args.vcd_path)
    if not vcd_path.exists():
        sys.exit(f"VCD file not found: {vcd_path}")
    args.vcd_path = vcd_path

    out_path = Path(args.output) if args.output else vcd_path.with_suffix(".phase2.json")

    file_size = vcd_path.stat().st_size
    print(f"Opening {vcd_path} ({file_size / (1024 ** 3):.3f} GB)...")
    start = time.time()

    with vcd_path.open("r", errors="replace") as f:
        path_to_id, _id_to_path, timescale = parse_var_block(f)
        print(f"Header parsed: {len(path_to_id):,} signals, timescale={timescale}")

        matches = match_whitelist(WHITELIST, path_to_id, args.scope_prefix)
        missing_paths = report_missing(matches, path_to_id)

        found = {m["whitelist_path"] for m in matches if m["vcd_ids"]}
        missing_required = REQUIRED_SIGNALS - found
        if missing_required:
            print()
            for s in sorted(missing_required):
                print(f"ERROR: required signal '{s}' not found.", file=sys.stderr)
            print("Aborting — Phase 2 cannot proceed.", file=sys.stderr)
            return 2

        tracked = sum(len(m["vcd_ids"]) for m in matches)
        print(f"Tracking {tracked} VCD signal IDs across "
              f"{len(matches) - len(missing_paths)}/{len(matches)} whitelist groups")
        print("Streaming body, emitting records on fetch handshakes...")
        records, stats = stream_and_extract(f, matches)

    elapsed = time.time() - start
    write_output_json(out_path, args, stats, records)

    mb = file_size / (1024 ** 2)
    speed = mb / elapsed if elapsed > 0 else 0.0

    print()
    print("=" * 78)
    print(" Phase 2 Extractor — Summary")
    print("=" * 78)
    print(f" Input                 : {vcd_path}")
    print(f" Output                : {out_path}")
    print(f" File size in          : {file_size:>15,} bytes ({file_size / (1024**3):.3f} GB)")
    print(f" Lines processed       : {stats['n_lines']:>15,}")
    print(f" Value changes seen    : {stats['n_changes']:>15,}")
    print(f" Cycles seen (rising)  : {stats['n_cycles']:>15,}")
    print(f" Final timestamp       : {stats['last_ts']:>15,}")
    print(f" Elapsed               : {elapsed:>14.1f}s ({speed:.1f} MB/s)")
    print()
    print(f" Records emitted       : {len(records):>15,}")

    if records:
        first = records[0]
        last = records[-1]
        n_with_pc = sum(1 for r in records if r["pc"] is not None)
        n_compressed = sum(1 for r in records if r["is_compressed"])

        print(f" Records with PC       : {n_with_pc:>15,} / {len(records)}")
        print(f" Compressed (RVC)      : {n_compressed:>15,} / {len(records)}")
        print(f" fe_cycle span         : {first['fe_cycle']:,} → {last['fe_cycle']:,}")
        print()
        print(f" First record          : id={first['id']}, pc={first['pc']}, "
              f"instr={first['instr_word']}, compressed={first['is_compressed']}")
        print(f" Last record           : id={last['id']}, pc={last['pc']}, "
              f"instr={last['instr_word']}, compressed={last['is_compressed']}")

        if n_with_pc == 0:
            print()
            print(" !! No records have a PC. The fetch_entry_i.address signal didn't")
            print("    match. Check the 'Missing whitelist entries' diagnostic above")
            print("    and update the K_PC path in the script.")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
