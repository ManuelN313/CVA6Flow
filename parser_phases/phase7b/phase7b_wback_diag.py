#!/usr/bin/env python3
"""Phase 7b (re-scoped) — dirty victim WRITEBACK lifecycle diagnostic.

This config (cv64a6_imafdc_sv39_hpdcache_wb) is WRITE-BACK: wtEn=0, the write
buffer is configured out (gen_no_wbuf). Stores retire to the CACHE (dirty); a
line reaches memory only when evicted, via the flush/wback unit (gen_flush,
exists iff wbEn). This tool traces that writeback path:

  ALLOC  flush_alloc && flush_alloc_ready          (nline = flush_alloc_nline)
         miss handler hands a dirty victim line to the flush unit
  SEND   mem_req_write_flush_valid && _ready        (id = .mem_req_id,
                                                      addr = .mem_req_addr)
         writeback request issued to memory
  ACK    mem_resp_write_flush_valid && _ready       (id = .mem_resp_w_id,
                                                      nline = flush_ack_nline)
         memory acknowledges the write

Correlation:
  send -> ack : EXACT, by flush slot index (mem_req_id == mem_resp_w_id).
                The flush channel carries the RAW slot id (0/1/2..); the high-bit
                source tag is only applied at the write arbiter, so no masking
                needed at this tap.
  alloc -> ack : by nline (alloc_nline == flush_ack_nline), time-ordered.

Key deliverable: the AXI write round-trip latency (ack - send), to compare
against the ~6-cycle read-refill dc_refill_overlap from Phase 6b.

Usage:
  python3 p7b_wback_diag.py daxpy.vcd
  python3 p7b_wback_diag.py daxpy.vcd --start-cycle 5000 --max-events 12
"""
import sys
import argparse
from collections import defaultdict, deque

# Resolved by hierarchical-path SUFFIX (config-identical across workloads).
TARGETS = {
    "alloc_valid": (".i_hpdcache.flush_alloc",                       "scalar"),
    "alloc_ready": (".i_hpdcache.flush_alloc_ready",                 "scalar"),
    "alloc_nline": (".i_hpdcache.flush_alloc_nline",                 "vector"),
    "send_valid": (".i_hpdcache.mem_req_write_flush_valid",         "scalar"),
    "send_ready": (".i_hpdcache.mem_req_write_flush_ready",         "scalar"),
    "send_id": (".i_hpdcache.mem_req_write_flush.mem_req_id",    "vector"),
    "send_addr": (".i_hpdcache.mem_req_write_flush.mem_req_addr",  "vector"),
    "ack_valid": (".i_hpdcache.mem_resp_write_flush_valid",        "scalar"),
    "ack_ready": (".i_hpdcache.mem_resp_write_flush_ready",        "scalar"),
    "ack_id": (".i_hpdcache.mem_resp_write_flush.mem_resp_w_id", "vector"),
    "ack_nline": (".i_hpdcache.flush_ack_nline",                   "vector"),
}

CLOCK_SUFFIX_PREFS = [".i_cva6.clk_i", ".i_ariane.clk_i",
                      ".ariane_testharness.clk_i", ".clk_i", ".clk"]


def parse_header(path):
    path_to_id = {}
    scope = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s.startswith("$scope"):
                p = s.split()
                if len(p) >= 3:
                    scope.append(p[2])
            elif s.startswith("$upscope"):
                if scope:
                    scope.pop()
            elif s.startswith("$var"):
                p = s.split()
                if len(p) >= 6:
                    sym = p[3]
                    name = p[4]
                    full = ".".join(scope + [name])
                    path_to_id[full] = sym
            elif s.startswith("$enddefinitions"):
                break
    return path_to_id


def resolve(path_to_id):
    roles, report = {}, []
    for role, (suffix, _kind) in TARGETS.items():
        hits = [p for p in path_to_id if p.endswith(suffix)]
        if len(hits) == 1:
            roles[role] = path_to_id[hits[0]]
            report.append(f"  OK    {role:<12} -> {hits[0]}")
        elif len(hits) == 0:
            report.append(f"  MISS  {role:<12} -> (suffix {suffix} not found)")
        else:
            best = min(hits, key=len)
            roles[role] = path_to_id[best]
            report.append(
                f"  AMBIG {role:<12} -> {best}  (+{len(hits)-1} others)")
    clk_id, clk_path = None, None
    for pref in CLOCK_SUFFIX_PREFS:
        hits = [p for p in path_to_id if p.endswith(pref)]
        if hits:
            clk_path = min(hits, key=len)
            clk_id = path_to_id[clk_path]
            break
    report.append(f"  CLOCK {'clk':<12} -> {clk_path}")
    return roles, clk_id, report


def vec(s):
    if s is None:
        return None
    if any(c in "xzXZ" for c in s):
        return None
    try:
        return int(s, 2)
    except ValueError:
        return None


def stream(path, roles, clk_id, start_cycle):
    """Proven p6b walker: state keyed by symbol id, edge at '#' boundary,
    read settled state by id per role."""
    tracked = set(roles.values()) | ({clk_id} if clk_id else set())
    state = {}
    cycle = -1
    first_ts_seen = False
    clk_at_ts_start = "0"
    allocs, sends, acks = [], [], []

    R = roles
    stats = {"timestamps": 0, "rising_edges": 0, "max_cycle": -1,
             "clk_changes": 0, "change_counts": {r: 0 for r in roles},
             "symbol": {r: roles[r] for r in roles},
             "values_seen": {r: set() for r in roles}}
    id_to_roles = {}
    for role, sym in roles.items():
        id_to_roles.setdefault(sym, []).append(role)

    def at_rising_edge():
        nonlocal cycle
        cycle += 1
        stats["rising_edges"] += 1
        stats["max_cycle"] = cycle
        if cycle < start_cycle:
            return
        if state.get(R.get("alloc_valid")) == "1" and state.get(R.get("alloc_ready")) == "1":
            allocs.append((cycle, vec(state.get(R.get("alloc_nline")))))
        if state.get(R.get("send_valid")) == "1" and state.get(R.get("send_ready")) == "1":
            sends.append((cycle, vec(state.get(R.get("send_id"))),
                          vec(state.get(R.get("send_addr")))))
        if state.get(R.get("ack_valid")) == "1" and state.get(R.get("ack_ready")) == "1":
            acks.append((cycle, vec(state.get(R.get("ack_id"))),
                         vec(state.get(R.get("ack_nline")))))

    in_body = False
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").rstrip()
            if not in_body:
                if line.strip().startswith("$enddefinitions"):
                    in_body = True
                continue
            if not line:
                continue
            c0 = line[0]
            if c0 == "#":
                stats["timestamps"] += 1
                if first_ts_seen:
                    if clk_at_ts_start == "0" and state.get(clk_id) == "1":
                        at_rising_edge()
                else:
                    first_ts_seen = True
                clk_at_ts_start = state.get(clk_id, "0")
                continue
            if c0 in "01xXzZ":
                value, vid = c0, line[1:]
            elif c0 in "bBrR":
                sp = line.find(" ")
                if sp <= 0:
                    continue
                value, vid = line[1:sp], line[sp + 1:]
            else:
                continue
            if vid in tracked:
                state[vid] = value
                if vid == clk_id:
                    stats["clk_changes"] += 1
                for role in id_to_roles.get(vid, ()):
                    stats["change_counts"][role] += 1
                    vs = stats["values_seen"][role]
                    if len(vs) < 8:
                        vs.add(value if len(value) <=
                               14 else value[:11] + "...")

    return allocs, sends, acks, stats


def fmt(v):
    return "x" if v is None else f"0x{v:x}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--start-cycle", type=int, default=0)
    ap.add_argument("--max-events", type=int, default=8)
    args = ap.parse_args()

    path_to_id = parse_header(args.vcd)
    roles, clk_id, report = resolve(path_to_id)

    print(f"# {args.vcd}  (Phase 7b re-scoped: dirty victim writeback path)")
    print("=== SIGNAL RESOLUTION ===")
    print("\n".join(report))
    if clk_id is None:
        sys.exit("\nFATAL: no clock resolved.")

    allocs, sends, acks, stats = stream(
        args.vcd, roles, clk_id, args.start_cycle)

    print("\n=== WALK STATS ===")
    print(f"  rising edges      : {stats['rising_edges']}")
    print(f"  max cycle reached : {stats['max_cycle']}")
    print("  per-signal change counts:")
    for role in TARGETS:
        if role in roles:
            vals = sorted(stats["values_seen"].get(role, set()))
            print(f"    {role:<12} sym={stats['symbol'][role]!r:<8} "
                  f"changes={stats['change_counts'].get(role, 0):<6} values={vals}")

    print(f"\n=== EVENT COUNTS (cycle >= {args.start_cycle}) ===")
    print(f"  writeback allocs : {len(allocs)}")
    print(f"  mem write sends  : {len(sends)}")
    print(f"  mem write acks   : {len(acks)}")

    # --- send <-> ack pairing by flush slot id (FIFO per id) => AXI write latency ---
    print("\n=== SEND <-> ACK PAIRING (by flush slot id) ===")
    out = defaultdict(deque)
    for c, sid, _a in sends:
        out[sid].append(c)
    latencies, unmatched_acks = [], 0
    for c, sid, _n in acks:
        if out[sid]:
            latencies.append(c - out[sid].popleft())
        else:
            unmatched_acks += 1
    leftover = sum(len(q) for q in out.values())
    print(f"  matched send/ack pairs   : {len(latencies)}")
    print(f"  acks with no prior send  : {unmatched_acks}  (expect 0)")
    print(f"  sends never acked        : {leftover}  (expect 0, modulo tail)")
    if latencies:
        latencies.sort()
        from statistics import median
        print(f"  AXI WRITE latency (cyc): min={latencies[0]} "
              f"median={int(median(latencies))} max={latencies[-1]}")
        hist = defaultdict(int)
        for L in latencies:
            hist[L] += 1
        print("  latency histogram (compare to read-refill ~6 cyc):")
        for L in sorted(hist):
            print(f"    {L:>3} cyc : {hist[L]}")

    # --- lifecycle windows: alloc -> send -> ack ---
    print(f"\n=== WRITEBACK LIFECYCLES (first {args.max_events} allocs) ===")
    sends_by_id = defaultdict(list)
    for c, sid, a in sends:
        sends_by_id[sid].append((c, a))
    acks_by_id = defaultdict(list)
    for c, sid, n in acks:
        acks_by_id[sid].append((c, n))
    # acks indexed by nline for the alloc->ack join
    acks_by_nline = defaultdict(list)
    for c, sid, n in acks:
        acks_by_nline[n].append(c)

    for i, (ac, anl) in enumerate(allocs[:args.max_events]):
        # next ack of this nline at/after alloc -> total writeback completion
        cand_ack = [c for c in acks_by_nline.get(anl, []) if c >= ac]
        ack_c = min(cand_ack) if cand_ack else None
        print(f"  [{i}] ALLOC cyc={ac} nline={fmt(anl)}")
        if ack_c is not None:
            print(
                f"      ACK   cyc={ack_c}  (alloc->ack residency {ack_c-ac} cyc)")
        else:
            print(
                f"      ACK   none found for nline={fmt(anl)} (still pending at EOT?)")

    print("\n# Done. Non-zero counts + send/ack pairing closing + a latency cluster "
          "validate the writeback path; then we wire the extractor.")


if __name__ == "__main__":
    main()
