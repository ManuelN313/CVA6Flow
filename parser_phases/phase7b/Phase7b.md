# Phase 7b — dirty victim writeback + eviction linkage (LOCKED, validated on daxpy)

`extractor_version: phase7b-0.2`

## What Phase 7b is (and the premise correction that produced it)

Phase 7b was originally scoped as "track each STORE through the write buffer to
memory." That premise was **wrong for this config**. `cv64a6_imafdc_sv39_hpdcache_wb`
sets `CVA6ConfigDcacheType = HPDCACHE_WB` → **write-back** (`wtEn = 0`, `wbEn = 1`).
The write buffer is configured out via the `gen_no_wbuf` black-hole branch
(`hpdcache.sv`): `wbuf_write_ready` tied `1`, `mem_req_write_wbuf_valid` tied `0`,
`mem_resp_write_wbuf_ready` tied `1`. (The *icache* is write-through; that is a
separate, unrelated fact.)

In write-back there is no per-store memory transaction: a store retires to the
**cache** (line goes dirty); the line reaches memory only when evicted, as a
**dirty victim writeback** issued by the flush/wback unit (`gen_flush.flush_i`,
which exists iff `wbEn`), triggered by the miss handler eviction path
(`mshr_alloc_wback_i` / `refill_wback_q`). Phase 7b therefore traces the
**writeback lifecycle**, not a per-instruction store path.

## Lifecycle traced (all signals at the `i_hpdcache` level)

```
ALLOC  flush_alloc && flush_alloc_ready        nline = flush_alloc_nline
SEND   mem_req_write_flush_valid && _ready      id = .mem_req_id, addr = .mem_req_addr
ACK    mem_resp_write_flush_valid && _ready     id = .mem_resp_w_id, nline = flush_ack_nline
```

Correlation:
- **send -> ack : EXACT, by flush slot id** (`mem_req_id == mem_resp_w_id`). The
  flush channel carries the *raw* slot id (0/1/2…); the high-bit source tag is
  applied only at the write arbiter (`sel_id`: wbuf=high-bit 0 (off here),
  flush/wback=high-bit 1 → ids 8/9/10, uc=all-ones), so no masking at this tap.
- **alloc -> ack : by nline** (FIFO per nline, ack-time order).

Output: a top-level `writebacks[]` array (one entry per completed writeback,
**not** per-instruction) with `{send_cycle, ack_cycle, alloc_cycle, flush_slot,
nline, addr, axi_write_latency, residency}`, plus
`metadata.stats.phase7b.axi_write_latency` (min/median/max/histogram).

## Validated result (daxpy.vcd, 1.207 GB)

- writebacks: **1313 alloc / 1312 send / 1312 ack; 1312 paired
  (0 acks w/o send, 0 sends unacked).**
- **AXI write latency: min=6, median=6 (≈90%), max=9.**
- `alloc -> ack` residency = 7 = 1 (flush FSM IDLE→SEND) + 6 (memory round-trip).

### Headline finding
The write round-trip (6 cyc) **matches** the Phase 6b read-refill
`dc_refill_overlap` (6 cyc). Strong evidence the 6 cycles is the **AXI/memory
round-trip itself** (symmetric read/write), not anything cache-internal. This
answers the Phase 6b open question. (Linkage in 0.2 further confirms the cause:
each writeback is a dirty victim displaced by a refill into the same set/way.)

### Why 1313 alloc vs 1312 send/ack (NOT a bug)
The integrated tracer flushes a final rising edge after the value-change loop
(`at_rising_edge()` post-loop); the standalone diag does not. So the tracer sees
one extra (final) cycle (90,398 vs 90,397), which held one `flush_alloc` pulse —
a writeback allocated in the last cycle whose send had not issued before the
trace ended. It is a legitimately in-flight writeback at end-of-trace. The event
list still has exactly 1312 entries (events are built from acks).

## Regression on locked phases (daxpy, never-before-tested VCD) — CLEAN
- Phase 6a: loads 8932 / stores 4414, **0 untraced**.
- Phase 6b: 25697 D$ events; 1025 primary-miss / 4 coalesced / 433 refill-overlap.
- Phase 7a: 4262 CTRL_FLOW, 4261 resolved, 11 mispredict, 99.7% hit rate.
- 42,839 committed, 23 flushed (IF=19, EX=4), 16,687 RVC. 2 unmatched commits
  (pre-existing, unrelated to 7b).

## Writeback <-> eviction linkage (0.2, validated on daxpy)

Each writeback is tied to the eviction that caused it: "refill X evicts dirty
victim Y -> writeback Y." The controller (st2) drives the dirty-victim
`flush_alloc` together with the miss allocation (`mshr_alloc_i` with
`mshr_alloc_wback_i=1`, one-hot `mshr_alloc_victim_way_i`, incoming line X =
`mshr_alloc_nline_i`) on the **same cycle** (validated delta=0).

Join key: **(set, victim_way)**. X and Y share the cache set (256 sets ->
`set = nline & 0xff`); the victim way matches (one-hot on both sides, compared
directly). Match each writeback to the eviction with the same (set, way)
nearest within a +/-4-cycle window (window absorbs handshake skew; per-key
used-set prevents double-binding).

Added signals: `mshr_alloc_wback_i`, `mshr_alloc_victim_way_i`
(`hpdcache_miss_handler_i`), `flush_alloc_way` (`i_hpdcache`). `mshr_alloc_i`
and `mshr_alloc_nline_i` are reused from the Phase 6b group.

Event fields added: `way` (victim way index), `evict_incoming_nline` (X),
`evict_cycle`, `linked` (bool). Stats added: `n_evictions`, `n_linked`,
`n_unlinked`.

### Validated result (daxpy)
- **1312 writebacks linked / 0 unlinked** (every writeback is a dirty-eviction
  writeback; no CMO traffic in daxpy).
- 6170 eviction *samples* — `mshr_alloc_i` is held high across stall cycles, so
  the raw count is inflated (~4858 duplicates). The (set,way)+window join is
  robust to this: each writeback links to its same-cycle eviction; duplicates go
  unused. (No ready-gate needed; verified 1312/1312.)
- Writeback pairing unchanged from 0.1 (1313 alloc / 1312 send / 1312 ack,
  latency 6/6/9). Linkage is purely additive.

NOTE on the linkage diag: time-order pairing (k-th evict <-> k-th flush) does
NOT work (the eviction stream is inflated and unordered vs flushes) — the
(set,way) key join is the correct rule. See `p7b_evict_link_diag.py` sections
(A) [fails] vs (B) [1312/1312].

## Files
- `phase3_pipeline_tracer.py` — integrated tracer at phase7b-0.2 (this snapshot).
- `p7b_wback_diag.py` — standalone writeback-lifecycle diagnostic / spot-check.
- `p7b_evict_link_diag.py` — eviction-linkage coupling diagnostic (chose the
  (set,way) join rule; (A) time-order fails, (B) key join = 1312/1312).
