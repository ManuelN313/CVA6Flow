# Phase 6b 0.2 — LOCKED

Version 0.2 supersedes 0.1. The single change from 0.1 is restricting
`dc_primary_miss` / `dc_coalesced` / `dc_refill_overlap` booleans to
LOAD records only (STOREs keep their `dc_events` list but their
booleans stay False) — see "Architectural finding 3" below for why.

## Goal

Per-LOAD/STORE record D$ event correlation: classify each LOAD as
primary_miss / coalesced / refill_overlap / clean_hit and attach the
raw HPDcache event list. STOREs get the raw events for context but
are not classified.

## Per-record fields added to InstructionRecord

- `dc_primary_miss   : bool` — LOAD only; load_unit (sid=1) allocated MSHR with this trans_id
- `dc_coalesced      : bool` — LOAD only; mshr_check_hit fired in [admit, complete]
- `dc_refill_overlap : bool` — LOAD only; refill_fsm_q ≠ IDLE for ≥1 cycle in window
- `dc_events         : list` — LOAD+STORE; raw chronological {cycle, type, sid?, tid?, pf?, nline?}

## Signals tracked

Under `gen_cache_hpd.i_cache_subsystem.i_dcache.i_hpdcache.hpdcache_miss_handler_i.`:

1. `mshr_alloc_i`, `mshr_alloc_tid_i`, `mshr_alloc_sid_i`,
   `mshr_alloc_is_prefetch_i`, `mshr_alloc_nline_i` — primary miss alloc
2. `mshr_check_i`, `mshr_check_nline_i`, `mshr_check_hit_o` — coalesce detection
3. `refill_fsm_q` — refill activity tracking
4. `refill_core_rsp_valid_o`, `refill_core_rsp_o.tid` — refill response

## HPDcache SID assignment (NumPorts=4)

- sid 0 : PTW load adapter (page table walker)
- sid 1 : **LSU load_unit** (the only SID that flips dc_primary_miss)
- sid 2 : Accelerator load adapter
- sid 3 : STORE adapter (constant tid=0, dominant in our workloads)
- sid 4 : CMO adapter
- sid 5 : hwpf_stride prefetcher

Derived from cva6.sv:1321-1327 → load_store_unit.sv:315/586/545 →
cva6_hpdcache_wrapper.sv:164.

## Architectural finding 1: load primary-allocates are rare

Across both fdiv (4279 cyc) and compress (5177 cyc), the ONLY SID
observed firing `mshr_alloc_i` is sid=3 (STORE), with exactly 20
events each. The LSU load_unit (sid=1) NEVER primary-allocates MSHR
in either workload.

Reason: `hpdcache_ctrl_pe.sv:498-590` routes load misses through a
cascade of "go to replay table" conditions before falling through to
`st2_mshr_alloc_o = 1'b1`. The dominant condition `st1_mshr_hit_i`
(line already pending an MSHR entry, typically from a preceding store)
catches loads in load/store-interleaved workloads. Loads coalesce
instead of allocating.

## Architectural finding 2: shared runtime dominates the histogram

fdiv and compress produced identical classification counts
(803 clean / 4 coalesced / 11 refill_overlap / 0 primary_miss).
Distribution analysis showed they coalesce on the same four
cachelines (0x80025f9, 0x80025f7, 0x80025f3, 0x80025f2 — contiguous
in physical memory), and both have a hot inner-loop load at the same
relative position in the disassembly:

```
fdiv     pc=0x8000410e  ld a5,-32(s0)  156 instances  ->  147 clean + 9 refill_overlap (lat=6)
compress pc=0x800048b4  ld a5,-32(s0)  156 instances  ->  147 clean + 9 refill_overlap (lat=6)
```

This is the shared runtime/test-framework. The same library function
runs in both benchmarks; the dynamic behavior is dominated by it.

## Architectural finding 3: why STOREs are not classified (v0.2 fix)

v0.1 set `dc_coalesced=True` on STOREs whenever any check_hit fired
in their LSU FSM window — produced 6 non-clean STORE classifications
in fdiv (3 coalesced + 3 refill_overlap) and 6 in compress.

These were false positives:

- STOREs don't typically emit `mshr_check_i` (stores allocate, not coalesce).
- A check_hit in a STORE's short FSM window (1-3 cycles) is almost
  always from a concurrent LOAD or prefetcher, not from this store.
- Same logic for `dc_refill_overlap`: a refill happening during a
  STORE's window has no causal relationship to the store.

The signal `mshr_check_i` has no source-ID input, so we can't filter
by requestor. For LOADs the issue is moot: the LSU load_unit FSM is
single-threaded, so at most one load is in WGT at a time and a
check_hit in its window is overwhelmingly its own check.

v0.2 fix: only LOAD records get the bool flips. STOREs keep their
`dc_events` list as context (the events did happen in their window),
but their `dc_*` bools stay at the default False.

## Architectural finding 4: clean_hit tail is non-D$ delay

A few records classify as `clean_hit` but have lat=4 or lat=5
(2 records in fdiv at lat=4, 1 at lat=5; 1 at lat=2 and 2 at lat=5
in compress). These are non-D$ delays — `WAIT_PAGE_OFFSET` from
store-buffer match, or `WAIT_TRANSLATION` from a TLB miss. Phase 6a's
`lsu_state_history` exposes which.

Phase 6b is correctly silent on these: the classification axis is
"was the D$ involved?" and the answer is no. The pipeline visualization
should layer both Phase 6a (FSM state path) and Phase 6b (D$ events)
to fully explain long latencies.

## Per-record classification results (LOADs, v0.2)

| Test     | LOADs | primary_miss | coalesced | refill_overlap | clean_hit   |
| -------- | ----- | ------------ | --------- | -------------- | ----------- |
| fdiv     | 818   | 0 (0%)       | 4 (0.5%)  | 11 (1.3%)      | 803 (98.2%) |
| compress | 818   | 0 (0%)       | 4 (0.5%)  | 11 (1.3%)      | 803 (98.2%) |

STOREs in v0.2: all 350 classified clean (no bool flips); dc_events
list still populated per record.

## Validation

- All 818 LOAD records got an LSU trace (Phase 6a foundation solid)
- id=139 fdiv: alloc@594 (sid=3 STORE) -> check_hit@598 (coalesce on
  same nline) -> classified `coalesced`, lat=18
- id=140 fdiv: alloc@612 + check_hit@613 (1-cycle-old coalesce)
  -> classified `coalesced`, lat=3
- id=142 fdiv: refill in progress at 617-618, no alloc/coalesce
  in window -> classified `refill_overlap`, lat=6
- Synthetic test: sid=1 alloc with matching tid flips `dc_primary_miss`,
  sid=0 (PTW) does not even with same tid
- v0.2 STORE-classification suppression: STORE record with check_hit
  in window has `dc_coalesced=False` but `dc_events` includes the event
- LIMITATION: `dc_primary_miss` code path empirically unobserved in
  fdiv/compress — validated only synthetically. Future workloads with
  read-only or post-flush access patterns would exercise it.

## Files in this archive

- `phase3_pipeline_tracer.py` v0.2 — extractor with Phase 6b integrated
- `p6b_diag_window.py` — per-cycle diagnostic (all 11 dcache signals)
- `p6b_spot_check.py` — classification histogram + top-N + per-record deep dive
- `p6b_global_alloc_count.py` — global alloc-by-SID counter
- `p6b_distribution_analysis.py` — 5-view distribution analyzer:
  1. latency histogram per classification (text bar chart)
  2. PC hotspots table
  3. cycle-band temporal pattern
  4. coalesce-target nline analysis
  5. classification x functional-unit cross-tabulation
