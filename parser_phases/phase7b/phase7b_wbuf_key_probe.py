#!/usr/bin/env python3
"""Phase 7b — wbuf correlation-key observability probe.

Determines whether the ideal STORE correlation key (the wbuf directory slot
index, used as the AXI write transaction ID) is present in the VCD dump.

RTL basis (hpdcache_wbuf.sv):
  - wbuf_meta_pend[i].meta_id = i                     (line 574)  static slot idx
  - mem_req_write_o.mem_req_id = meta_id              (line 657)  drain -> AXI id
  - ack_id = mem_resp_write_i.mem_resp_w_id[..]       (line 265)  ack  -> slot idx
  - assert wbuf_dir_state_q[ack_id] == WBUF_SENT      (line 718)  HW-checked

Usage:
  python3 p7b_wbuf_key_probe.py fdiv.vcd
"""
import sys
import re

# Signals that would let us use the slot-index key, in priority order.
# Tier 1: the AXI write id itself (drain + ack). If present at ANY scope we win.
TIER1 = [
    "mem_req_id",          # mem_req_write_o.mem_req_id  (drain side)
    "mem_resp_w_id",       # mem_resp_write_i.mem_resp_w_id (ack side)
    "mem_req_write_o",     # whole struct dumped packed (would contain the id)
    "mem_resp_write_i",    # whole struct dumped packed (would contain the id)
    "ack_id",              # internal decoded ack slot index
]
# Tier 2: wbuf-internal state. Lets us reconstruct slot lifecycle even without id.
TIER2 = [
    "wbuf_dir_state_q",    # per-slot FREE/OPEN/PEND/SENT
    "wbuf_dir_q",          # per-slot dir entry (tag/ptr/uc)
    "meta_id",
    "wbuf_meta_send",
    "wbuf_dir_free_ptr",
    "wbuf_write_hit_open_dir_ptr",
]
# Tier 3 (fallback, already known present): the address path.
TIER3 = [
    "wbuf_write_addr",
    "write_addr_i",
]

WBUF_SCOPE = "hpdcache_wbuf_i"


def main(path):
    tier1_hits, tier2_hits, tier3_hits = [], [], []
    wbuf_scope_seen = False
    n_var = 0

    var_re = re.compile(r"\$var\s+\S+\s+\d+\s+\S+\s+(\S+)")
    # We track scope to build full hierarchical paths.
    scope_stack = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s.startswith("$scope"):
                parts = s.split()
                if len(parts) >= 3:
                    scope_stack.append(parts[2])
                    if parts[2] == WBUF_SCOPE:
                        wbuf_scope_seen = True
            elif s.startswith("$upscope"):
                if scope_stack:
                    scope_stack.pop()
            elif s.startswith("$var"):
                n_var += 1
                m = var_re.search(s)
                if not m:
                    continue
                name = m.group(1)
                full = ".".join(scope_stack + [name])
                for kw in TIER1:
                    if kw in name:
                        tier1_hits.append(full)
                for kw in TIER2:
                    if kw in name:
                        tier2_hits.append(full)
                for kw in TIER3:
                    if kw in name:
                        tier3_hits.append(full)
            elif s.startswith("$enddefinitions"):
                break

    def dump(title, hits):
        print(f"\n=== {title}  ({len(set(hits))} unique) ===")
        for h in sorted(set(hits)):
            print(f"  {h}")

    print(f"# {path}: scanned {n_var} $var lines")
    print(f"# '{WBUF_SCOPE}' scope present in hierarchy: {wbuf_scope_seen}")
    dump("TIER 1 — AXI write id (slot-index key, IDEAL)", tier1_hits)
    dump("TIER 2 — wbuf-internal state (reconstructable key)", tier2_hits)
    dump("TIER 3 — address fallback (known present)", tier3_hits)

    print("\n--- VERDICT ---")
    if tier1_hits:
        print("USE SLOT-INDEX KEY (tier 1): correlate drain/ack by AXI write id.")
    elif tier2_hits:
        print("USE SLOT-INDEX KEY (tier 2): reconstruct from wbuf_dir_state_q + meta_id.")
    elif tier3_hits:
        print("FALL BACK TO ADDRESS (tier 3): wbuf_write_addr. "
              "NOTE: lossy under store coalescing.")
    else:
        print("NO KEY FOUND. VCD dump scope likely excludes the wbuf entirely.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
