#!/usr/bin/env python3
"""Shorten a CVA6Flow trace JSON to its first N instruction records.

The MinorFlow shortener only knows MinorFlow's keys, so run on a CVA6Flow trace
it keeps a truncated instructions array but drops everything else. This one is
CVA6-aware: it keeps the first N instruction records and filters every other
top-level array (writebacks, dcache_alloc_events, icache_events, and the two
access-cycle lists) to the cycle window those N instructions span. The result
renders in the viewer exactly like the prefix of the full trace, with the
aggregate ICache and DCache panels and the writeback track all populated.

Usage:
    python3 CVA6Flow_shorten.py full_trace.json -n 2000
    python3 CVA6Flow_shorten.py full_trace.json -n 2000 -o short.json

The cycle window is [0, cMax], where cMax is the latest cycle reached by any of
the kept instructions (across every per-cycle field, including the nested
dc_events and lsu_state_history). Auxiliary events are kept when they begin
inside that window, so a writeback or a miss that starts late but finishes after
cMax is still included. Metadata and config_params are carried over unchanged,
with a shortened_to_instructions note added so the file is self-describing. The
metadata stats block still reflects the full trace, which is intentional, since
recomputing it would require the whole run.
"""
import argparse
import json
import sys


def rec_max_cycle(r):
    """Latest cycle touched by one instruction record."""
    m = -1
    for k, v in r.items():
        if isinstance(v, int) and (k.endswith('_cycle')
                                   or k in ('if1_lo', 'if2_lo', 'if1_hi', 'if2_hi')):
            if v > m:
                m = v
    for ev in (r.get('dc_events') or []):
        c = ev.get('cycle')
        if isinstance(c, int) and c > m:
            m = c
    for st in (r.get('lsu_state_history') or []):
        c = st.get('cycle')
        if isinstance(c, int) and c > m:
            m = c
    return m


def wb_start(w):
    """Cycle a writeback begins. Mirrors the viewer's alloc_cycle ?? send_cycle."""
    s = w.get('alloc_cycle')
    return s if s is not None else w.get('send_cycle')


def ic_start(e):
    """Cycle an icache event begins (the request, or the earliest present field)."""
    vs = [v for v in (e.get('fe1'), e.get('fe2')) if isinstance(v, int)]
    return min(vs) if vs else None


def main():
    ap = argparse.ArgumentParser(
        description="Shorten a CVA6Flow trace to its first N instructions, "
                    "keeping all per-cycle data for that prefix.")
    ap.add_argument('input', help='full CVA6Flow trace .json')
    ap.add_argument('-n', '--num', type=int, default=2000,
                    help='number of leading instruction records to keep (default 2000)')
    ap.add_argument('-o', '--out', default=None,
                    help='output path (default <input>.first<N>.json)')
    args = ap.parse_args()

    with open(args.input) as f:
        d = json.load(f)

    inst = d.get('instructions')
    if not isinstance(inst, list) or not inst:
        sys.exit('No non-empty "instructions" array found. Is this a CVA6Flow trace?')

    kept = inst[:args.num]
    cmax = max((rec_max_cycle(r) for r in kept), default=-1)
    if cmax < 0:
        sys.exit('Could not find any cycle fields in the kept instructions.')

    out = dict(d)
    out['instructions'] = kept

    wbs = d.get('writebacks') or []
    out['writebacks'] = [w for w in wbs
                         if wb_start(w) is not None and wb_start(w) <= cmax]

    allocs = d.get('dcache_alloc_events') or []
    out['dcache_alloc_events'] = [e for e in allocs
                                  if isinstance(e.get('cycle'), int) and e['cycle'] <= cmax]

    ics = d.get('icache_events') or []
    out['icache_events'] = [e for e in ics
                            if ic_start(e) is not None and ic_start(e) <= cmax]

    icacc = d.get('ic_access_cycles') or []
    out['ic_access_cycles'] = [c for c in icacc if isinstance(c, int) and c <= cmax]

    dcacc = d.get('dc_access_cycles') or []
    out['dc_access_cycles'] = [c for c in dcacc if isinstance(c, int) and c <= cmax]

    md = dict(out.get('metadata') or {})
    md['shortened_to_instructions'] = len(kept)
    out['metadata'] = md

    out_path = args.out or (args.input[:-5] if args.input.endswith('.json')
                            else args.input) + f'.first{len(kept)}.json'
    with open(out_path, 'w') as f:
        json.dump(out, f)

    def line(name):
        return f"  {name:20} {len(out[name]):>8,} / {len(d.get(name) or []):>8,}"

    print(f"kept {len(kept):,} instructions, cycle window 0..{cmax:,}")
    for name in ('writebacks', 'dcache_alloc_events', 'icache_events',
                 'ic_access_cycles', 'dc_access_cycles'):
        print(line(name))
    print(f"wrote {out_path}")


if __name__ == '__main__':
    main()
