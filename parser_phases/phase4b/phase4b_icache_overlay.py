#!/usr/bin/env python3
"""Phase 4b v0.1 I$ overlay: augment v0.5 instruction JSON with
per-instruction fe1_cycle, fe2_cycle, and ic_miss fields.

Reads:
    - fdiv.vcd  (or whichever VCD the v0.5 JSON was extracted from)
    - fdiv_phase3.json  (v0.5 output from phase3_pipeline_tracer.py)

Writes:
    - fdiv_phase3_overlay.json  (same schema + 3 new fields per record)

Design (per Phase 4b plan):

    Per-instruction attribution rule, derived from the warmup-window
    diag (see p4b_diag_user_entry.out):

      fe1_cycle = first cycle dreq_i.vaddr == (PC & ~3) with dreq_i.req=1
                  (the cycle the frontend ISSUED the request)

      fe2_cycle = first cycle dreq_o.valid==1 with dreq_o.vaddr matching
                  (PC & ~3) and kill_s2==0 (the cycle the I$ DELIVERED)

      ic_miss   = True iff state_q == MISS at fe2_cycle
                  (the I$ went to memory for THIS line, vs. a hit
                  that may have been stuck behind a prior miss)

    Records that have no matching I$ event (squashed accesses, fetches
    dropped by fui, etc.) get fe1_cycle/fe2_cycle/ic_miss = None.

    RVC pair sharing: two RVC records at offsets 0 and 2 within the
    same 4-byte word share a single I$ delivery. Both bind to the
    same event (the matcher uses 4-byte-aligned word lookup, so this
    falls out naturally).

This script is a standalone overlay during Phase 4b development. Once
the model is validated, the I$ tracking logic will be merged into
phase3_pipeline_tracer.py so a single VCD pass produces the full JSON
(per Manu's direction: avoid multi-script pipelines in the final form).
"""

from __future__ import annotations
import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict


# ---------------------------------------------------------------------------
# VCD header parser (mirrors phase3_pipeline_tracer.py)
# ---------------------------------------------------------------------------

def parse_var_block(f):
    scope_stack = []
    path_to_id = {}
    id_to_path = {}
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line.startswith("$enddefinitions"):
            return path_to_id, id_to_path
        if line.startswith("$scope"):
            tokens = line.split()
            if len(tokens) >= 3:
                scope_stack.append(tokens[2])
        elif line.startswith("$upscope"):
            if scope_stack:
                scope_stack.pop()
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
    return path_to_id, id_to_path


STRIP_BIT_RANGE = re.compile(r"\[\d+:\d+\]$")


def strip_bit_range(path):
    while True:
        new = STRIP_BIT_RANGE.sub("", path)
        if new == path:
            return path
        path = new


# ---------------------------------------------------------------------------
# I$ FSM state constants (from cva6_icache.sv:122)
# ---------------------------------------------------------------------------

FSM_FLUSH = "000"
FSM_IDLE = "001"
FSM_READ = "010"
FSM_MISS = "011"
FSM_KILL_ATRANS = "100"
FSM_KILL_MISS = "101"


# ---------------------------------------------------------------------------
# I$ event timeline
# ---------------------------------------------------------------------------

@dataclass
class ICacheEvent:
    fe1_cycle: int
    fe2_cycle: int
    vaddr_word: int   # 4-byte aligned
    ic_miss: bool


class ICacheTimeline:
    """Walks the VCD's I$ signal stream and emits one ICacheEvent per
    successful (non-killed) data delivery.

    fe1 attribution rule (v0.3):

      A NEW I$ ACCESS starts at the cycle when EITHER:
        (a) vaddr_o transitions to a different value (consecutive
            fetches to distinct addresses), or
        (b) state_q transitions to READ from a non-READ state
            (a fresh access after an IDLE/KILL_*/FLUSH dwell).

      fe1_cycle = (cycle the new access started) - 1

    Rationale: both paths represent the I$ pipeline accepting a new
    request. Path (a) is the common case (one hit per cycle, vaddr_o
    advances). Path (b) catches re-fetches where the frontend reissues
    the SAME vaddr_o after a transient idle — most commonly the
    branch-misprediction recovery path where kill_s1 voids the
    in-flight access and the frontend re-requests the same PC.

    Without path (b), the v0.2 rule would attribute fe1 to the
    ORIGINAL transition cycle even for the re-fetch, since vaddr_o
    never changes during the IDLE dwell. That inflates lat from 1 to
    (idle_dwell + 1), producing the lat=5/10/16 "hit" outliers
    observed in v0.2.

    Examples (verified against p4b_diag_user_entry.out and the
    cycle 813-825 diag of id=243):

      Clean hit (consecutive hits in a line):
        Cycle 311: state=READ, vaddr_o=0x80000004 (transition from
        0x80000000). Path (a) fires. access_start=311.
        Cycle 311: vld=1. fe1=310, fe2=311, lat=1.

      Real cacheable miss (id=1959, PC 0x80003000):
        Cycle 3840: vaddr_o transitions to 0x80003000. Path (a).
        access_start=3840. fe1=3839.
        Cycle 3844: state=MISS, vld=1. fe2=3844. lat=5.

      Branch-mispredict re-fetch (id=243, PC 0x80004134):
        Cycle 818: vaddr_o transitions to 0x80004134. Path (a).
        access_start=818. vld=1 same cycle. Event A: fe1=817, fe2=818.
        Cycle 819-821: state=IDLE, vaddr_o unchanged.
        Cycle 822: state=READ (was IDLE). Path (b) fires.
        access_start=822. vld=1 same cycle. Event B: fe1=821, fe2=822.

        Both events live in the timeline; the matcher binds id=243 to
        Event B (its FE handshake at cycle 831 is closest to fe2=822).
        Event A becomes an orphan (no record corresponds to the
        flushed delivery), which is correct.

      NC bypass (id=0, PC 0x10000):
        Cycle 270: vaddr_o transitions to 0x10000. Path (a).
        access_start=270. fe1=269.
        Cycle 273: state=MISS, vld=1. fe2=273. lat=4.
    """

    # state_q values that count as "non-READ" for the path-(b) detector.
    # Any state_q != READ qualifies, but we list them explicitly for
    # clarity. Note that we explicitly include None (the initial value
    # before VCD assigns) to handle the very first cycle.
    NON_READ_STATES = frozenset({
        FSM_FLUSH, FSM_IDLE, FSM_MISS, FSM_KILL_ATRANS, FSM_KILL_MISS, None,
    })

    def __init__(self):
        self.events = []
        self.last_vaddr_o_str = None
        self.last_state_q = None
        self.last_access_start_cycle = None

    def on_cycle(self, cycle, state_q_str, vld, vaddr_o_str, k2):
        """Process one rising clock edge."""

        # --- Detect new access (either path) ---
        vaddr_o_changed = (vaddr_o_str != self.last_vaddr_o_str)
        state_to_read = (state_q_str == FSM_READ
                         and self.last_state_q in self.NON_READ_STATES)

        if vaddr_o_changed or state_to_read:
            self.last_access_start_cycle = cycle

        self.last_vaddr_o_str = vaddr_o_str
        self.last_state_q = state_q_str

        # --- Emit event on delivery ---
        if vld == "1" and k2 != "1" and vaddr_o_str is not None:
            try:
                vaddr_o = int(vaddr_o_str, 2)
            except ValueError:
                return
            if self.last_access_start_cycle is not None:
                fe1 = self.last_access_start_cycle - 1
            else:
                fe1 = cycle - 1
            fe1 = max(0, fe1)
            ic_miss = (state_q_str == FSM_MISS)
            self.events.append(ICacheEvent(
                fe1_cycle=fe1,
                fe2_cycle=cycle,
                vaddr_word=vaddr_o & ~0x3,
                ic_miss=ic_miss,
            ))


# ---------------------------------------------------------------------------
# Matching records to events
# ---------------------------------------------------------------------------

def match_records_to_events(records, events):
    """Bind fe1_cycle / fe2_cycle / ic_miss onto each record.

    Strategy: for each record with PC P and fetch-handshake cycle
    fe_cycle, find the I$ event for word (P & ~3) whose fe2_cycle is
    the maximum value still <= fe_cycle. That's the most recent
    delivery for this word before the FE handshake to id_stage.

    Multiple records sharing the same word in the same iteration (an
    RVC pair) will both find the same event under this rule. Records
    in different loop iterations naturally bind to their own
    iteration's event because their fe_cycles differ.

    Records with no matching event (squashed fetches, fui drops) get
    fe1/fe2/ic_miss = None.

    Returns (n_matched, n_unmatched) for diagnostics."""

    by_word = defaultdict(list)
    for ev in events:
        by_word[ev.vaddr_word].append(ev)
    # Pre-sort each word's events by fe2 (events already arrive in
    # cycle order from the walker, but be defensive).
    for word in by_word:
        by_word[word].sort(key=lambda e: e.fe2_cycle)

    n_matched = 0
    n_unmatched = 0

    for rec in records:
        pc_str = rec.get("pc")
        fe_cycle = rec.get("fe_cycle")
        if pc_str is None or fe_cycle is None:
            rec["fe1_cycle"] = None
            rec["fe2_cycle"] = None
            rec["ic_miss"] = None
            n_unmatched += 1
            continue
        try:
            pc_int = int(pc_str, 16)
        except (TypeError, ValueError):
            rec["fe1_cycle"] = None
            rec["fe2_cycle"] = None
            rec["ic_miss"] = None
            n_unmatched += 1
            continue
        word = pc_int & ~0x3
        candidates = by_word.get(word, [])
        # Binary-search-ish: find max fe2 <= fe_cycle. Linear scan
        # since lists are small per word.
        best = None
        for ev in candidates:
            if ev.fe2_cycle > fe_cycle:
                break
            best = ev
        if best is not None:
            rec["fe1_cycle"] = best.fe1_cycle
            rec["fe2_cycle"] = best.fe2_cycle
            rec["ic_miss"] = best.ic_miss
            n_matched += 1
        else:
            rec["fe1_cycle"] = None
            rec["fe2_cycle"] = None
            rec["ic_miss"] = None
            n_unmatched += 1

    return n_matched, n_unmatched


# ---------------------------------------------------------------------------
# VCD walker
# ---------------------------------------------------------------------------

def build_icache_timeline(vcd_path, scope_prefix, icache_scope):
    P = scope_prefix.rstrip(".")
    IC = f"{P}.{icache_scope}".rstrip(".")

    with open(vcd_path, "r", buffering=4 << 20) as f:
        path_to_id, _ = parse_var_block(f)

        # Build stripped-suffix lookup, scope-restricted to IC.
        by_stripped = defaultdict(list)
        for full_path, vcd_id in path_to_id.items():
            by_stripped[strip_bit_range(full_path)].append(
                (full_path, vcd_id))

        def find_suffix(suffix):
            target = "." + suffix
            for stripped, entries in by_stripped.items():
                if not stripped.startswith(IC + "."):
                    continue
                if stripped.endswith(target):
                    return entries[0][1], entries[0][0]
            return None, None

        # Top-level CLK
        CLK = None
        for k, v in path_to_id.items():
            if k == f"{P}.clk_i":
                CLK = v
                break
        if CLK is None:
            for k, v in path_to_id.items():
                if k.endswith(".clk_i"):
                    CLK = v
                    break
        if CLK is None:
            raise RuntimeError("clk_i not found in VCD header")

        # I$ signals (v0.2: only output-side + state needed)
        STATE_Q,    _ = find_suffix("state_q")
        KILL_S2,    _ = find_suffix("dreq_i.kill_s2")
        DRSP_VLD,   _ = find_suffix("dreq_o.valid")
        DRSP_VADDR, _ = find_suffix("dreq_o.vaddr")
        # Underscored fallbacks
        if KILL_S2 is None:
            KILL_S2,    _ = find_suffix("dreq_i_kill_s2")
        if DRSP_VLD is None:
            DRSP_VLD,   _ = find_suffix("dreq_o_valid")
        if DRSP_VADDR is None:
            DRSP_VADDR, _ = find_suffix("dreq_o_vaddr")

        missing = []
        for name, sig in [
            ("state_q",        STATE_Q),
            ("dreq_i.kill_s2", KILL_S2),
            ("dreq_o.valid",   DRSP_VLD),
            ("dreq_o.vaddr",   DRSP_VADDR),
        ]:
            if sig is None:
                missing.append(name)
        if missing:
            raise RuntimeError(
                f"Could not resolve I$ signals under {IC!r}: {missing}. "
                f"Pass --icache-scope to override.")

        print(f"# resolved all I$ signals under {IC}", file=sys.stderr)

        # ---- Walker ----
        timeline = ICacheTimeline()
        state = {}
        cycle = -1
        first = False
        clk_at_start = "0"

        def at_edge():
            nonlocal cycle
            cycle += 1
            timeline.on_cycle(
                cycle,
                state.get(STATE_Q),
                state.get(DRSP_VLD),
                state.get(DRSP_VADDR),
                state.get(KILL_S2),
            )

        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                if first:
                    curr = state.get(CLK, "0")
                    if clk_at_start == "0" and curr == "1":
                        at_edge()
                else:
                    first = True
                clk_at_start = state.get(CLK, "0")
                continue
            if c0 in "01xz":
                state[line[1:]] = c0
            elif c0 == "b":
                sp = line.find(" ")
                if sp > 0:
                    state[line[sp + 1:]] = line[1:sp]

        return timeline.events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--input-json", default="fdiv_phase3.json",
                    help="v0.5 JSON to augment (default: fdiv_phase3.json)")
    ap.add_argument("--output-json", default="fdiv_phase3_overlay.json",
                    help="Output path for augmented JSON "
                         "(default: fdiv_phase3_overlay.json)")
    ap.add_argument("--scope-prefix",
                    default="TOP.ariane_testharness.i_ariane.i_cva6")
    ap.add_argument("--icache-scope",
                    default="gen_cache_hpd.i_cache_subsystem.i_cva6_icache")
    args = ap.parse_args()

    # Build I$ event timeline from VCD.
    print(f"# walking VCD {args.vcd}...", file=sys.stderr)
    events = build_icache_timeline(
        args.vcd, args.scope_prefix, args.icache_scope)
    print(f"# extracted {len(events)} I$ delivery events", file=sys.stderr)

    n_miss = sum(1 for ev in events if ev.ic_miss)
    n_hit = len(events) - n_miss
    print(f"# {n_hit} hits, {n_miss} misses (state_q == MISS at fe2)",
          file=sys.stderr)

    # Load v0.5 JSON.
    print(f"# loading {args.input_json}...", file=sys.stderr)
    with open(args.input_json, "r") as f:
        d = json.load(f)
    records = d.get("instructions", [])
    print(f"# {len(records)} instruction records", file=sys.stderr)

    # Match.
    n_matched, n_unmatched = match_records_to_events(records, events)
    print(f"# matched {n_matched} records, "
          f"{n_unmatched} unmatched", file=sys.stderr)

    # Annotate metadata.
    d["icache_overlay_version"] = "phase4b-0.3"
    d["icache_event_count"] = len(events)
    d["icache_event_hits"] = n_hit
    d["icache_event_misses"] = n_miss

    # Write.
    with open(args.output_json, "w") as f:
        json.dump(d, f, indent=2)
    print(f"# wrote {args.output_json}", file=sys.stderr)


if __name__ == "__main__":
    main()
