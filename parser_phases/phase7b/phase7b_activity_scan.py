#!/usr/bin/env python3
"""Phase 7b — write-path activity scan.

The diag window found the data nets (wbuf_write_addr, mem_resp_write_wbuf.w_id)
LIVE but every valid/ready/id qualifier on the mem_req_write_wbuf channel STUCK.
So the live drain path is on different nets. This scans every write/response-
related net under i_hpdcache, counts how often each actually toggles in the body,
and ranks them — the real handshake nets are the ones with high change counts.

Usage:
  python3 p7b_activity_scan.py daxpy.vcd
  python3 p7b_activity_scan.py daxpy.vcd --min-changes 2   # hide constants
"""
import sys
import argparse

HPD = "i_hpdcache"
# A net is a candidate if its path is under i_hpdcache and the leaf/path mentions
# any of these. Broad on purpose so the live nets can't hide.
KEYWORDS = ("wbuf", "mem_req_write", "mem_resp_write", "arb_mem_req_write",
            "write_valid", "write_ready")


def parse_header(path):
    path_to_id = {}
    id_meta = {}
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
                    width = int(p[2])
                    sym = p[3]
                    name = p[4]
                    full = ".".join(scope + [name])
                    path_to_id[full] = sym
                    id_meta[sym] = (full, width)
            elif s.startswith("$enddefinitions"):
                break
    return path_to_id, id_meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vcd")
    ap.add_argument("--min-changes", type=int, default=1,
                    help="only show nets with >= this many body changes")
    args = ap.parse_args()

    path_to_id, _ = parse_header(args.vcd)

    # candidate paths and the set of their symbol ids
    cand_paths = {}  # path -> id
    for p, sym in path_to_id.items():
        if HPD in p and any(k in p for k in KEYWORDS):
            cand_paths[p] = sym
    cand_ids = set(cand_paths.values())

    print(f"# {args.vcd}: {len(cand_paths)} candidate paths, "
          f"{len(cand_ids)} unique symbols")

    # one body pass: count changes + collect sample values per symbol
    changes = {sym: 0 for sym in cand_ids}
    vals = {sym: set() for sym in cand_ids}
    in_body = False
    with open(args.vcd, "r", errors="replace") as f:
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
                continue
            if c0 in "01xXzZ":
                value = c0
                vid = line[1:]
            elif c0 in "bBrR":
                sp = line.find(" ")
                if sp <= 0:
                    continue
                value = line[1:sp]
                vid = line[sp + 1:]
            else:
                continue
            if vid in cand_ids:
                changes[vid] += 1
                if len(vals[vid]) < 6:
                    vals[vid].add(value if len(value) <=
                                  12 else value[:9] + "..")

    # report: rank PATHS by their symbol's change count (desc)
    rows = []
    for p, sym in cand_paths.items():
        rows.append((changes[sym], p, sym, sorted(vals[sym])))
    rows.sort(key=lambda r: (-r[0], r[1]))

    print(f"\n{'changes':>8}  {'sym':<8} path   [values]")
    print("-" * 100)
    shown = 0
    for cnt, p, sym, vs in rows:
        if cnt < args.min_changes:
            continue
        leaf = p.split(HPD + ".", 1)[-1]   # trim the long common prefix
        print(f"{cnt:>8}  {sym:<8} {leaf}  {vs}")
        shown += 1
    print(f"\n# shown {shown} nets with >= {args.min_changes} changes "
          f"(of {len(cand_paths)} candidates)")
    print("# Look for: a *_valid with high count + matching *_ready + an id that "
          "takes small slot values. That triple is the live drain handshake.")


if __name__ == "__main__":
    main()
