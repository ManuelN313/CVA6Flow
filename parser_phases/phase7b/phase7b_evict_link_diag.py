#!/usr/bin/env python3
"""Phase 7b linkage diag — writeback <-> eviction coupling.

In write-back mode a dirty victim writeback is triggered when the miss handler
allocates a miss whose selected victim way is dirty. The controller (st2) drives
BOTH the miss allocation (mshr_alloc_i with mshr_alloc_wback_i=1, victim way,
incoming nline X) AND the dirty-victim flush_alloc (flush_alloc_nline = victim Y,
flush_alloc_way). X and Y share the cache set; the victim way matches.

This diag observes the coupling so we can choose the correct join rule before
wiring it into the extractor:
  - counts of eviction-allocs vs flush-allocs
  - the cycle delta (flush_alloc - eviction) distribution under time-order pairing
  - the (set, way) match rate
  - whether any flush_allocs have no matching eviction (CMO flushes / key gaps)

Geometry (cv64a6 hpdcache_wb): 256 sets, 8 ways -> setWidth=8 (set = nline & 0xff).
Victim way is one-hot on both sides, compared as integers.

Usage:
  python3 p7b_evict_link_diag.py daxpy.vcd
  python3 p7b_evict_link_diag.py daxpy.vcd --set-bits 8 --window 4
"""
import sys
import argparse
from collections import defaultdict

TARGETS = {
    # eviction side (miss handler)
    "m_alloc_v": (".hpdcache_miss_handler_i.mshr_alloc_i",          "scalar"),
    "m_wback": (".hpdcache_miss_handler_i.mshr_alloc_wback_i",    "scalar"),
    "m_nline": (".hpdcache_miss_handler_i.mshr_alloc_nline_i",    "vector"),
    # one-hot
    "m_vway": (".hpdcache_miss_handler_i.mshr_alloc_victim_way_i", "vector"),
    # flush/writeback alloc side (i_hpdcache level)
    "f_alloc_v": (".i_hpdcache.flush_alloc",                        "scalar"),
    "f_alloc_r": (".i_hpdcache.flush_alloc_ready",                  "scalar"),
    "f_nline": (".i_hpdcache.flush_alloc_nline",                  "vector"),
    # one-hot
    "f_way": (".i_hpdcache.flush_alloc_way",                    "vector"),
}
CLOCK_SUFFIX_PREFS = [".i_cva6.clk_i", ".i_ariane.clk_i",
                      ".ariane_testharness.clk_i", ".clk_i", ".clk"]


def parse_header(path):
    path_to_id, scope = {}, []
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
                    path_to_id[".".join(scope + [p[4]])] = p[3]
            elif s.startswith("$enddefinitions"):
                break
    return path_to_id


def resolve(path_to_id):
    roles, report = {}, []
    for role, (suffix, _k) in TARGETS.items():
        hits = [p for p in path_to_id if p.endswith(suffix)]
        if len(hits) == 1:
            roles[role] = path_to_id[hits[0]]
            report.append(f"  OK    {role:<10} -> {hits[0]}")
        elif not hits:
            report.append(f"  MISS  {role:<10} -> ({suffix})")
        else:
            best = min(hits, key=len)
            roles[role] = path_to_id[best]
            report.append(f"  AMBIG {role:<10} -> {best} (+{len(hits)-1})")
    clk = None
    for pref in CLOCK_SUFFIX_PREFS:
        hits = [p for p in path_to_id if p.endswith(pref)]
        if hits:
            clk = path_to_id[min(hits, key=len)]
            break
    return roles, clk, report


def vec(s):
    if s is None or any(c in "xzXZ" for c in s):
        return None
    try:
        return int(s, 2)
    except ValueError:
        return None


def stream(path, roles, clk_id):
    tracked = set(roles.values()) | ({clk_id} if clk_id else set())
    state, cycle = {}, -1
    first, clk0 = False, "0"
    evicts, fallocs = [], []
    R = roles

    def edge():
        nonlocal cycle
        cycle += 1
        # eviction: mshr_alloc pulse with wback=1
        if state.get(R.get("m_alloc_v")) == "1" and state.get(R.get("m_wback")) == "1":
            evicts.append((cycle, vec(state.get(R.get("m_nline"))),
                           vec(state.get(R.get("m_vway")))))
        # flush alloc handshake
        if state.get(R.get("f_alloc_v")) == "1" and state.get(R.get("f_alloc_r")) == "1":
            fallocs.append((cycle, vec(state.get(R.get("f_nline"))),
                            vec(state.get(R.get("f_way")))))

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
                if first:
                    if clk0 == "0" and state.get(clk_id) == "1":
                        edge()
                else:
                    first = True
                clk0 = state.get(clk_id, "0")
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
        if first and clk0 == "0":     # flush final edge if last block rose
            pass
    return evicts, fallocs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--set-bits", type=int, default=8)
    ap.add_argument("--window", type=int, default=4,
                    help="max |cycle delta| for key-based join")
    args = ap.parse_args()
    setmask = (1 << args.set_bits) - 1

    p2i = parse_header(args.vcd)
    roles, clk, report = resolve(p2i)
    print(f"# {args.vcd}  (writeback <-> eviction linkage diag)")
    print("=== SIGNAL RESOLUTION ===")
    print("\n".join(report))
    if clk is None:
        sys.exit("FATAL: no clock.")

    evicts, fallocs = stream(args.vcd, roles, clk)
    print(f"\n=== COUNTS ===")
    print(f"  eviction allocs (mshr_alloc & wback=1) : {len(evicts)}")
    print(f"  flush allocs (flush_alloc & ready)     : {len(fallocs)}")

    def setof(nl):
        return None if nl is None else (nl & setmask)

    # (A) time-order pairing: k-th eviction <-> k-th flush alloc
    print(f"\n=== (A) TIME-ORDER PAIRING (k-th evict <-> k-th flush) ===")
    n = min(len(evicts), len(fallocs))
    deltas = defaultdict(int)
    setway_match = 0
    set_match = 0
    for i in range(n):
        ec, enl, eway = evicts[i]
        fc, fnl, fway = fallocs[i]
        deltas[fc - ec] += 1
        if setof(enl) == setof(fnl):
            set_match += 1
        if setof(enl) == setof(fnl) and eway == fway:
            setway_match += 1
    print(f"  paired (min count)         : {n}")
    print(f"  set(X)==set(Y)             : {set_match}/{n}")
    print(f"  set AND way match          : {setway_match}/{n}")
    print(f"  cycle-delta (flush - evict) distribution:")
    for d in sorted(deltas):
        print(f"    delta {d:>3} : {deltas[d]}")

    # (B) key-based join: each flush alloc -> nearest prior eviction with
    #     matching (set, way) within +/- window
    print(f"\n=== (B) KEY JOIN by (set,way) within +/-{args.window} cyc ===")
    ev_by_key = defaultdict(list)
    for ec, enl, eway in evicts:
        ev_by_key[(setof(enl), eway)].append((ec, enl))
    for v in ev_by_key.values():
        v.sort()
    matched, unmatched = 0, 0
    examples = []
    used = defaultdict(set)
    for fc, fnl, fway in fallocs:
        key = (setof(fnl), fway)
        cands = ev_by_key.get(key, [])
        best = None
        for idx, (ec, enl) in enumerate(cands):
            if idx in used[key]:
                continue
            if abs(fc - ec) <= args.window:
                if best is None or abs(fc - ec) < abs(fc - best[2]):
                    best = (idx, enl, ec)
        if best is not None:
            used[key].add(best[0])
            matched += 1
            if len(examples) < 8:
                examples.append((fc, fnl, fway, best[2], best[1]))
        else:
            unmatched += 1
    print(f"  flush allocs matched to an eviction : {matched}/{len(fallocs)}")
    print(f"  flush allocs with NO eviction match : {unmatched}  "
          f"(CMO flushes or key gaps)")
    print(f"  examples (flush_alloc -> linked eviction):")
    for fc, fnl, fway, ec, enl in examples:
        print(f"    flush@{fc} victimY={hex(fnl) if fnl is not None else 'x'} "
              f"set={hex(setof(fnl)) if fnl is not None else 'x'} way={fway} "
              f"<- evict@{ec} incomingX={hex(enl) if enl is not None else 'x'}")

    print("\n# Read: if (A) shows a tight constant delta + ~100% set&way match,")
    print("#   the join is simply time-order. If not, (B)'s key match rate tells")
    print("#   us (set,way)+window is the rule. Either way, we then annotate each")
    print("#   writeback with its incoming line X.")


if __name__ == "__main__":
    main()
