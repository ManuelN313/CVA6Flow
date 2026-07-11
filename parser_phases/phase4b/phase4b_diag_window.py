#!/usr/bin/env python3
"""Phase 4b v0.1 diagnostic: dump the I$ controller FSM + dreq/drsp
handshake state across a cycle window. Forked from p4a_diag_window.py
to keep the Phase 4a tooling untouched.

What this prints per rising edge in the window:

  - I$ FSM state_q (FLUSH/IDLE/READ/MISS/KILL_ATRANS/KILL_MISS, per
    cva6_icache.sv:122)
  - miss_o (I$ raises this when servicing a miss)
  - dreq_i.req, kill_s1, kill_s2, vaddr (frontend -> I$, per cva6.sv:65)
  - dreq_o.ready, valid, vaddr (I$ -> frontend, per cva6.sv:72)
  - mem_data_req_o, mem_data_ack_i (I$ -> next-level memory, miss path)
  - mem_rtrn_vld_i (memory -> I$, line fill arrival)

Also prints, on stderr, the list of paths it resolved (or didn't), so
we can iterate on signal names without re-running the whole VCD.

Usage:
    python3 p4b_diag_window.py fdiv.vcd > p4b_diag_window.out
    python3 p4b_diag_window.py fdiv.vcd --start 250 --end 320
    python3 p4b_diag_window.py fdiv.vcd --list-icache-paths   # signal discovery

Default window: 250..320 covers boot cold-start (first decode is at
cycle 276 per the Phase 4a boot diag, so 250..320 brackets the initial
I$ miss-and-fill sequence that delivered id=0's line).
"""
from __future__ import annotations
import argparse
import re
import sys
from collections import defaultdict


# ---------------------------------------------------------------------------
# VCD header parser (mirrors phase3_pipeline_tracer.py for compatibility)
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


def fmt_bin(s):
    """Format a binary VCD value to a short string."""
    if s is None:
        return "?"
    if "x" in s.lower() or "z" in s.lower():
        return "X"
    try:
        return str(int(s, 2))
    except ValueError:
        return s


def fmt_hex(s, width=4):
    """Format a binary VCD value as hex of the requested nibble width."""
    if s is None:
        return "?"
    if "x" in s.lower() or "z" in s.lower():
        return "X"
    try:
        return f"{int(s, 2):0{width}x}"
    except ValueError:
        return s


# Names matching the state_e enum in cva6_icache.sv:122
FSM_STATE_NAMES = {
    0: "FLUSH",
    1: "IDLE",
    2: "READ",
    3: "MISS",
    4: "KILLA",   # KILL_ATRANS, abbreviated
    5: "KILLM",   # KILL_MISS, abbreviated
}


def fmt_fsm(s):
    if s is None:
        return "?"
    if "x" in s.lower() or "z" in s.lower():
        return "X"
    try:
        return FSM_STATE_NAMES.get(int(s, 2), f"?{s}")
    except ValueError:
        return s


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--start", type=int, default=250)
    ap.add_argument("--end", type=int, default=320)
    ap.add_argument("--scope-prefix",
                    default="TOP.ariane_testharness.i_ariane.i_cva6")
    ap.add_argument("--icache-scope",
                    default="gen_cache_hpd.i_cache_subsystem.i_cva6_icache",
                    help="Path under scope-prefix to the cva6_icache "
                         "instance. The default matches the HPDcache config "
                         "(cv64a6_imafdc_sv39_hpdcache_wb), where cva6.sv "
                         "wraps the cache subsystem in a `generate` block "
                         "named gen_cache_hpd. For the WT cache config use "
                         "`i_cache_subsystem.i_cva6_icache`.")
    ap.add_argument("--list-icache-paths", action="store_true",
                    help="Print every VCD path under the icache scope and exit.")
    args = ap.parse_args()

    P = args.scope_prefix.rstrip(".")
    IC = f"{P}.{args.icache_scope}".rstrip(".")

    with open(args.vcd, "r", buffering=4 << 20) as f:
        path_to_id, _ = parse_var_block(f)

        # ---- Diagnostic header info ----
        print(f"# total paths in header: {len(path_to_id)}", file=sys.stderr)

        # In list-paths mode, dump everything under the icache scope and quit.
        if args.list_icache_paths:
            print(f"# === paths under {IC} ===", file=sys.stderr)
            ic_paths = sorted(p for p in path_to_id if p.startswith(IC + "."))
            for p in ic_paths:
                print(p, file=sys.stderr)
            print(f"# {len(ic_paths)} paths printed", file=sys.stderr)
            return

        # Sample-discover the icache scope (warn if it doesn't appear).
        sample_ic = [k for k in path_to_id if k.startswith(IC + ".")][:5]
        if not sample_ic:
            print(f"# WARNING: no paths found under {IC!r} — pass "
                  f"--icache-scope to override.", file=sys.stderr)
            # Also show what scopes DO exist under the cva6 prefix, to help.
            scopes_under_cva6 = set()
            for k in path_to_id:
                if k.startswith(P + "."):
                    tail = k[len(P) + 1:]
                    head = tail.split(".", 1)[0]
                    scopes_under_cva6.add(head)
                if len(scopes_under_cva6) >= 30:
                    break
            print(f"# scopes under {P!r}: "
                  f"{sorted(scopes_under_cva6)[:30]}", file=sys.stderr)
        else:
            print(f"# sample icache paths: {sample_ic}", file=sys.stderr)

        # ---- Build the stripped-suffix lookup table ----
        by_stripped = defaultdict(list)
        for full_path, vcd_id in path_to_id.items():
            by_stripped[strip_bit_range(full_path)].append((full_path, vcd_id))

        def find_exact(full_path):
            """Find a signal whose stripped path matches exactly."""
            hits = by_stripped.get(full_path, [])
            return hits[0][1] if hits else None

        def find_suffix(suffix):
            """Find a signal ending in `.<suffix>` strictly within the
            IC scope. Returns (vcd_id, full_path).

            Critical: this is INTENTIONALLY scope-restricted. Names
            like `state_q`, `req`, `valid`, `ready` are shared across
            many modules (FPU, branch unit, MMU, scoreboard, ...). A
            cross-scope fallback would silently bind the wrong signal
            and render as plausible-looking but completely wrong
            output. If the search returns (None, None), the caller
            sees a [??] in the resolver report and can pass
            --icache-scope to fix it or --list-icache-paths to
            discover the right name."""
            target = "." + suffix
            for stripped, entries in by_stripped.items():
                if not stripped.startswith(IC + "."):
                    continue
                if stripped.endswith(target):
                    return entries[0][1], entries[0][0]
            return None, None

        # ---- CLK (top-level, same as p4a_diag) ----
        CLK = find_exact(f"{P}.clk_i")
        if CLK is None:
            for k, v in path_to_id.items():
                if k.endswith(".clk_i"):
                    CLK = v
                    print(f"# CLK fallback (suffix match): {k}",
                          file=sys.stderr)
                    break
        if CLK is None:
            print("# FATAL: CLK not found.", file=sys.stderr)
            sys.exit(2)

        # ---- I$ FSM + miss flag ----
        # state_q is the registered state inside cva6_icache.
        STATE_Q, path_state = find_suffix("state_q")
        MISS_O,  path_miss = find_suffix("miss_o")

        # ---- dreq_i fields (frontend -> I$, per cva6.sv:65) ----
        # The packed struct fields appear as dreq_i.<field> in the VCD.
        DREQ_REQ,   p_dreq_req = find_suffix("dreq_i.req")
        KILL_S1,    path_ks1 = find_suffix("dreq_i.kill_s1")
        KILL_S2,    path_ks2 = find_suffix("dreq_i.kill_s2")
        SPEC,       path_spec = find_suffix("dreq_i.spec")
        DREQ_VADDR, p_dreq_va = find_suffix("dreq_i.vaddr")

        # Underscored fallbacks (some VCD dumpers flatten packed structs).
        if DREQ_REQ is None:
            DREQ_REQ, p_dreq_req = find_suffix("dreq_i_req")
        if KILL_S1 is None:
            KILL_S1, path_ks1 = find_suffix("dreq_i_kill_s1")
        if KILL_S2 is None:
            KILL_S2, path_ks2 = find_suffix("dreq_i_kill_s2")
        if DREQ_VADDR is None:
            DREQ_VADDR, p_dreq_va = find_suffix("dreq_i_vaddr")

        # ---- dreq_o fields (I$ -> frontend, per cva6.sv:72) ----
        DRSP_VLD,   p_drsp_vld = find_suffix("dreq_o.valid")
        DRSP_RDY,   p_drsp_rdy = find_suffix("dreq_o.ready")
        DRSP_VADDR, p_drsp_vaddr = find_suffix("dreq_o.vaddr")
        if DRSP_VLD is None:
            DRSP_VLD, p_drsp_vld = find_suffix("dreq_o_valid")
        if DRSP_RDY is None:
            DRSP_RDY, p_drsp_rdy = find_suffix("dreq_o_ready")

        # ---- I$ <-> memory (miss-handling) ----
        MEM_REQ_O,  p_mreq = find_suffix("mem_data_req_o")
        MEM_ACK_I,  p_mack = find_suffix("mem_data_ack_i")
        MEM_RTRN,   p_mrtrn = find_suffix("mem_rtrn_vld_i")

        # ---- Report what we resolved ----
        def show(label, vcd_id, path):
            mark = "OK " if vcd_id else "??"
            print(f"# [{mark}] {label:<24} id={vcd_id!r:<6}  path={path}",
                  file=sys.stderr)

        print("# === resolved I$ signals ===", file=sys.stderr)
        show("CLK",              CLK,        f"{P}.clk_i")
        show("state_q",          STATE_Q,    path_state)
        show("miss_o",           MISS_O,     path_miss)
        show("dreq_i.req",       DREQ_REQ,   p_dreq_req)
        show("dreq_i.kill_s1",   KILL_S1,    path_ks1)
        show("dreq_i.kill_s2",   KILL_S2,    path_ks2)
        show("dreq_i.spec",      SPEC,       path_spec)
        show("dreq_i.vaddr",     DREQ_VADDR, p_dreq_va)
        show("dreq_o.valid",     DRSP_VLD,   p_drsp_vld)
        show("dreq_o.ready",     DRSP_RDY,   p_drsp_rdy)
        show("dreq_o.vaddr",     DRSP_VADDR, p_drsp_vaddr)
        show("mem_data_req_o",   MEM_REQ_O,  p_mreq)
        show("mem_data_ack_i",   MEM_ACK_I,  p_mack)
        show("mem_rtrn_vld_i",   MEM_RTRN,   p_mrtrn)

        # ---- Header ----
        # Columns: cyc, state_q, miss_o, dreq_i.req, kill_s1, kill_s2,
        #          dreq_o.ready, dreq_o.valid, mem_data_req_o,
        #          mem_data_ack_i, mem_rtrn_vld_i, dreq_i.vaddr,
        #          dreq_o.vaddr.
        # vaddr_i = address the FRONTEND is currently presenting to the
        # I$ (the new requested PC). vaddr_o = address the I$ is
        # delivering data for in this cycle (the last accepted PC).
        # On a hit, vaddr_o (this cycle) typically matches vaddr_i (one
        # cycle earlier).
        print()
        print(f"{'cyc':>5} {'state_q':>7} {'miss':>4}  "
              f"{'rq':>2} {'k1':>2} {'k2':>2}  "
              f"{'rdy':>3} {'vld':>3}  "
              f"{'mreq':>4} {'mack':>4} {'mrtrn':>5}  "
              f"{'vaddr_i':>8} {'vaddr_o':>8}")

        # ---- Walker ----
        state = {}
        cycle = -1
        first = False
        clk_at_start = "0"

        def at_edge():
            nonlocal cycle
            cycle += 1
            if not (args.start <= cycle <= args.end):
                return
            print(f"{cycle:>5} "
                  f"{fmt_fsm(state.get(STATE_Q)) if STATE_Q else '?':>7} "
                  f"{fmt_bin(state.get(MISS_O)) if MISS_O else '?':>4}  "
                  f"{fmt_bin(state.get(DREQ_REQ)) if DREQ_REQ else '?':>2} "
                  f"{fmt_bin(state.get(KILL_S1)) if KILL_S1 else '?':>2} "
                  f"{fmt_bin(state.get(KILL_S2)) if KILL_S2 else '?':>2}  "
                  f"{fmt_bin(state.get(DRSP_RDY)) if DRSP_RDY else '?':>3} "
                  f"{fmt_bin(state.get(DRSP_VLD)) if DRSP_VLD else '?':>3}  "
                  f"{fmt_bin(state.get(MEM_REQ_O)) if MEM_REQ_O else '?':>4} "
                  f"{fmt_bin(state.get(MEM_ACK_I)) if MEM_ACK_I else '?':>4} "
                  f"{fmt_bin(state.get(MEM_RTRN)) if MEM_RTRN else '?':>5}  "
                  f"{fmt_hex(state.get(DREQ_VADDR), 8) if DREQ_VADDR else '?':>8} "
                  f"{fmt_hex(state.get(DRSP_VADDR), 8) if DRSP_VADDR else '?':>8}")

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
                if cycle > args.end:
                    break
                continue
            if c0 in "01xz":
                state[line[1:]] = c0
            elif c0 == "b":
                sp = line.find(" ")
                if sp > 0:
                    state[line[sp + 1:]] = line[1:sp]


if __name__ == "__main__":
    main()
