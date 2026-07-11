# CVA6 Pipeline Viewer — Phase 0 Specification

**Status:** v1.1 — incorporates sign-off feedback. Phase 1 ready.
**Target config:** `cv64a6_imafdc_sv39_hpdcache_wb`
**Frozen base:** ManuelN313/cva6 fork

This document is the contract between the Python VCD extractor and the HTML/JS viewer. Previous attempts failed in part because no such contract existed — extraction, instruction tracking, and rendering were fused, so a bug at any layer required understanding all three. Phase 0 makes that impossible to repeat.

### Revision log

- **v1.1** — Frontend split into three sub-stages (`if1`, `if2`, `fe`). Config parameter section now reflects verified values from `cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv` and shows the derivation formulas (several are computed from other parameters, so the spec carries the formulas, not just the numbers).
- **v1.0** — Initial draft.

---

## 1. Purpose

Produce a MinorFlow-style timeline view of dynamic instruction lifecycle in a Verilator-simulated CVA6 core, so that:

1. The same program run on gem5 MinorCPU (visualized in MinorFlow) and on CVA6 (visualized here) can be compared side-by-side.
2. Stall causes can be identified at the same fidelity MinorFlow provides — stage occupancy, inter-stage buffer depths, FU categorization — without claiming full causal chains we cannot honestly produce.
3. The viewer is auditable end-to-end. Every cycle shown is traceable to a specific VCD signal transition.

---

## 2. Architecture

Two components, one wire:

```
┌─────────────┐     ┌──────────────────┐     ┌──────────┐     ┌─────────────┐
│  Verilator  │────▶│  Python          │────▶│  trace   │────▶│  HTML/JS    │
│  29 GB VCD  │     │  extractor       │     │  .json   │     │  viewer     │
└─────────────┘     │  (streaming)     │     │ (~5 MB)  │     │             │
                    └──────────────────┘     └──────────┘     └─────────────┘
```

- **Extractor:** linear forward scan over VCD; whitelist-filtered signals only; emits one record per dynamic instruction.
- **Viewer:** reads the JSON, renders timeline. No client-side cycle corrections, no caches, no "fix-ups." The JSON is the source of truth.

The JSON file is the _only_ coupling between the two halves. Either can be rewritten without the other knowing, provided the schema below is honored.

---

## 3. Pipeline Stages and Their Anchors

CVA6 is a 6-stage pipeline. We expose 8 sub-stages in the JSON because the frontend is internally multi-cycle and the comparison-with-MinorFlow goal benefits from showing the I$-request / I$-response phases explicitly.

| #   | Stage            | JSON field  | Anchor event in VCD                                                           |
| --- | ---------------- | ----------- | ----------------------------------------------------------------------------- |
| 1   | Fetch1 (I$ req)  | `if1_cycle` | `icache_dreq_o.req` asserted for the line containing this instruction's PC    |
| 2   | Fetch2 (I$ resp) | `if2_cycle` | `icache_dreq_i.valid` asserted with the line containing this instruction's PC |
| 3   | Frontend out     | `fe_cycle`  | `fetch_entry_valid` AND `fetch_entry_ready` both 1 (handed to ID)             |
| 4   | Decode           | `id_cycle`  | `decoded_instr_valid` AND `decoded_instr_ack` both 1 (handed to scoreboard)   |
| 5   | Issue            | `is_cycle`  | `issue_instr_valid` AND `issue_ack` both 1 (handed to IRO + FU)               |
| 6   | Execute          | `ex_cycle`  | `is_cycle + 1` (FU begins computation; VCD-verified relation)                 |
| 7   | Writeback        | `wb_cycle`  | `wt_valid_i[port]` AND `trans_id_i[port] == captured_trans_id`                |
| 8   | Commit           | `co_cycle`  | `commit_ack_o[port]` AND `rvfi_instr_o[port].valid` AND `pc_rdata == pc`      |

**Notes on Frontend.** I$ fetches happen at the line level (`FETCH_WIDTH` bits per request), but instructions may be 32-bit or 16-bit (RVC). A single I$ request can yield multiple instructions if RVC is enabled. When two instructions come from the same fetched line, they **share** `if1_cycle` and `if2_cycle`. They will, however, have **distinct** `fe_cycle` values, because with `NrIssuePorts = 1` only one instruction can emerge from the frontend per cycle. The extractor maintains a per-line bookkeeping table keyed by `vaddr` to associate I$ request/response cycles back to instructions as they later emerge.

**Notes on Execute.** `ex_cycle = is_cycle + 1` is a CVA6 microarchitectural invariant: the IRO only asserts `issue_ack` when operands are ready AND the FU is ready, so the next cycle is always FU dispatch. Variable FU latency is captured by `wb_cycle - ex_cycle`. For loads, `wb_cycle - ex_cycle` is bounded by the cache/MSHR/refill path; the optional `lsu_state_history` field (Phase 5+) explains where the cycles went.

**Notes on Writeback.** Captured combinationally between clock edges across all writeback ports (`NrWbPorts = 5` for this config). The `used_wb` set per scoreboard slot prevents a writeback from being reassigned to a different instance that later occupied the same slot. Port 4 is the CVXIF writeback port; in our config it's wired but no accelerator is attached, so it should remain idle. The extractor monitors it but expects it never to fire.

**Notes on Commit.** Two commit ports. The RVFI `pc_rdata` is the authoritative match for binding a commit event back to an in-flight instance. If two instances in flight share the same PC (loop iterations), program order is used as the tiebreaker.

---

## 4. VCD Signal Whitelist

### 4.1 Scope conventions

VCD scope paths depend on the testbench. The extractor accepts `--vcd-scope-prefix` as a configuration argument; all paths below are relative to the `cva6` module instance. Typical full prefix in the standard CVA6 testharness:

```
TOP.ariane_testharness.i_ariane.i_cva6
```

The exact sub-instance names (e.g., `id_stage_i` vs `i_id_stage`) need to be confirmed against a sample VCD during Phase 1. The signal _names_ are stable; the instance prefixes may need a one-line config tweak.

### 4.2 Core anchor signals (Phase 1–4)

```
# I$ request / response (frontend → icache)
frontend_i.icache_dreq_o.req                         # if1 anchor: request asserted
frontend_i.icache_dreq_o.vaddr                       # line address (for matching instructions to fetches)
frontend_i.icache_dreq_o.kill_s1                     # in-flight fetch killed at stage 1
frontend_i.icache_dreq_o.kill_s2                     # in-flight fetch killed at stage 2
frontend_i.icache_dreq_i.valid                       # if2 anchor: response valid
frontend_i.icache_dreq_i.vaddr                       # echo of returned line address
frontend_i.icache_dreq_i.ex                          # cache/translation exception

# Fetch handshake (frontend → id_stage)
id_stage_i.fetch_entry_valid_i[NrIssuePorts-1:0]
id_stage_i.fetch_entry_ready_o[NrIssuePorts-1:0]
id_stage_i.fetch_entry_i[NrIssuePorts-1:0]           # bundle: pc, instruction, branch_predict, ex

# Decode handshake (id_stage → scoreboard)
issue_stage_i.i_scoreboard.decoded_instr_valid_i[NrIssuePorts-1:0]
issue_stage_i.i_scoreboard.decoded_instr_ack_o[NrIssuePorts-1:0]
issue_stage_i.i_scoreboard.decoded_instr_i[NrIssuePorts-1:0]  # scoreboard_entry_t: pc, fu, op, rd, rs1, rs2, ...
issue_stage_i.i_scoreboard.orig_instr_i[NrIssuePorts-1:0]     # raw 32-bit instruction word

# Issue handshake (scoreboard → IRO)
issue_stage_i.i_scoreboard.issue_instr_valid_o[NrIssuePorts-1:0]
issue_stage_i.i_scoreboard.issue_ack_i[NrIssuePorts-1:0]
issue_stage_i.i_scoreboard.issue_pointer_q[TRANS_ID_BITS-1:0]  # trans_id slot (single-issue: only port 0 used)

# Writeback (EX → scoreboard)
issue_stage_i.i_scoreboard.wt_valid_i[NrWbPorts-1:0]
issue_stage_i.i_scoreboard.trans_id_i[NrWbPorts-1:0][TRANS_ID_BITS-1:0]

# Commit
commit_stage_i.commit_ack_o[NrCommitPorts-1:0]
cva6_rvfi_probes_i.rvfi_instr_o[NrCommitPorts-1:0].valid
cva6_rvfi_probes_i.rvfi_instr_o[NrCommitPorts-1:0].pc_rdata

# Flush detection
controller_i.flush_ctrl_if
controller_i.flush_ctrl_id
controller_i.flush_ctrl_ex
controller_i.flush_ctrl_bp

# RVC detection (from id_stage RVFI hook)
id_stage_i.rvfi_is_compressed_o[NrIssuePorts-1:0]
```

### 4.3 Auxiliary signals (Phase 5+, optional)

```
# LSU FSM (for memory stall annotations)
ex_stage_i.lsu_i.i_load_unit.state_q
ex_stage_i.lsu_i.i_store_unit.state_q

# HPDcache state (for cache miss annotations) — exact paths TBD in Phase 5
i_cache_subsystem.i_cva6_hpdcache_wrapper.* (FSM states)

# RVC bundling (for compressed instruction pairing)
frontend_i.instr_realign_i.realign_valid
```

These are deferred. The Phase 1–4 build does not need them.

### 4.4 Signal extraction in the streaming reader

The VCD format declares all signal IDs upfront in the `$var` block, then emits transitions cycle-by-cycle. The extractor:

1. Reads the `$var` block, builds a dict `{vcd_id: signal_path}` for every signal.
2. Computes the inverse for whitelist entries: `{signal_path: vcd_id}`.
3. Streams the body. For each transition `<value><vcd_id>`, looks up the VCD ID in the whitelist. If not present, discards. If present, updates that signal's current value.
4. At each `#<timestamp>` line, evaluates handshake predicates and emits/updates instance records.

Memory footprint stays bounded by `len(whitelist)`, not file size.

---

## 5. JSON Schema

### 5.1 Top-level structure

```json
{
  "metadata": { ... },
  "config_params": { ... },
  "buffer_maxima": { ... },
  "instructions": [ ... ]
}
```

### 5.2 `metadata`

```json
{
  "config_name": "cv64a6_imafdc_sv39_hpdcache_wb",
  "elf_path": "daxpy.elf",
  "vcd_path": "daxpy.vcd",
  "user_entry_pc": "0x80000000",
  "warmup_end_cycle": 1247,
  "tohost_cycle": 82481,
  "extractor_version": "1.0.0",
  "vcd_scope_prefix": "TOP.ariane_testharness.i_ariane.i_cva6",
  "invariants_verified": [
    "monotonic_fe_cycle",
    "if1_le_if2_le_fe",
    "unique_trans_id_per_inflight_window",
    "all_instances_committed_or_flushed",
    "ex_cycle_equals_is_cycle_plus_one",
    "commit_count_matches_rvfi"
  ]
}
```

`warmup_end_cycle` is the VCD cycle of the first `rvfi.valid` whose `pc_rdata == user_entry_pc`. All instance cycles in the file are **VCD-absolute**, not user-relative; the viewer is responsible for subtracting `warmup_end_cycle` for display. This keeps the JSON immune to re-interpretation of where "cycle 0" lives.

### 5.3 `config_params`

These come from `cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv`. Several are derived from other parameters via SV `localparam` expressions — the spec records both the formula and the value, since the formula tells the extractor how to recompute correctly if the config ever changes (e.g., `SuperscalarEn` flipped to 1).

**Source parameters** (set explicitly in the config package):

| Parameter             | Value | Source                                                    |
| --------------------- | ----- | --------------------------------------------------------- |
| `XLEN`                | 64    | `CVA6ConfigXlen`                                          |
| `SuperscalarEn`       | 0     | `cva6_cfg.SuperscalarEn` (off by default; can be enabled) |
| `RVC`                 | 1     | `CVA6ConfigCExtEn`                                        |
| `CvxifEn`             | 1     | `CVA6ConfigCvxifEn`                                       |
| `NrCommitPorts`       | 2     | `cva6_cfg.NrCommitPorts` (hardcoded to 2 in user config)  |
| `NrScoreboardEntries` | 8     | `CVA6ConfigNrScoreboardEntries`                           |
| `NrLoadBufEntries`    | 8     | `CVA6ConfigNrLoadBufEntries`                              |
| `EnableAccelerator`   | 0     | (not enabled in this config)                              |

**Derived parameters** (computed from source parameters):

| Parameter         | Formula                                    | Value |
| ----------------- | ------------------------------------------ | ----- |
| `NrIssuePorts`    | `SuperscalarEn ? 2 : 1`                    | 1     |
| `FETCH_WIDTH`     | `SuperscalarEn ? 64 : 32`                  | 32    |
| `INSTR_PER_FETCH` | `FETCH_WIDTH / (RVC ? 16 : 32)`            | 2     |
| `NrWbPorts`       | `(CvxifEn \|\| EnableAccelerator) ? 5 : 4` | 5     |
| `TRANS_ID_BITS`   | `$clog2(NrScoreboardEntries)`              | 3     |

**Final emitted JSON for our target config:**

```json
{
  "SuperscalarEn": false,
  "RVC": true,
  "CvxifEn": true,
  "NrIssuePorts": 1,
  "NrCommitPorts": 2,
  "NrWbPorts": 5,
  "NrScoreboardEntries": 8,
  "TRANS_ID_BITS": 3,
  "FETCH_WIDTH": 32,
  "INSTR_PER_FETCH": 2
}
```

**Implementation note:** The extractor reads the config package (or accepts these values via CLI flags) and applies the derivation formulas itself. It must not hardcode the value-column above; it must compute them. This is what lets us flip `SuperscalarEn` to `1` and re-run without code changes — `NrIssuePorts` becomes 2, `FETCH_WIDTH` becomes 64, and `INSTR_PER_FETCH` becomes 4, all automatically.

### 5.4 `buffer_maxima`

Observed maxima over the user window, mirroring MinorFlow's reporting. Several of these buffers have config-dependent maximum depths; the spec notes the bound where one exists, and the extractor reports the _observed_ max.

```json
{
  "instr_queue_depth": 4,
  "issue_fifo_depth": 1,
  "scoreboard_occupancy": 6,
  "load_buffer_occupancy": 3,
  "issue_width_observed": 1,
  "commit_width_observed": 2,
  "memory_ops_per_cycle_observed": 1
}
```

Bounds derived from `config_params`:

| Buffer                  | Hard bound                                                |
| ----------------------- | --------------------------------------------------------- |
| `scoreboard_occupancy`  | `NrScoreboardEntries` (= 8)                               |
| `load_buffer_occupancy` | `NrLoadBufEntries` (= 8)                                  |
| `issue_width_observed`  | `NrIssuePorts` (= 1)                                      |
| `commit_width_observed` | `NrCommitPorts` (= 2)                                     |
| `instr_queue_depth`     | fixed inside `instr_queue.sv`; observed-only              |
| `issue_fifo_depth`      | 2 (with `SuperscalarEn`), 1 (single-issue); observed-only |

The extractor should _assert_ that observed values stay within the hard bounds and fail loudly if they don't (it would indicate a signal-mapping bug).

### 5.5 Per-instruction record (`instructions[i]`)

```json
{
  "id": 42,
  "pc": "0x80000110",
  "instr_word": "0x02d50533",
  "disasm": "add a0,a0,a3",
  "is_compressed": false,
  "is_warmup": false,
  "fu": "ALU",
  "fu_category": "Int",
  "rd": 10,
  "rs1": 10,
  "rs2": 13,
  "trans_id": 3,
  "fetch_port": 0,
  "if1_cycle": 1447,
  "if2_cycle": 1449,
  "fe_cycle": 1450,
  "id_cycle": 1451,
  "is_cycle": 1452,
  "ex_cycle": 1453,
  "wb_cycle": 1453,
  "co_cycle": 1454,
  "flushed": false,
  "flush_reason": null,
  "lsu_state_history": null
}
```

### 5.6 Field reference

| Field               | Type           | Description                                                                                                                   |
| ------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `id`                | int            | Monotonic 0-indexed instance counter; unique per record.                                                                      |
| `pc`                | hex string     | Instruction PC from `scoreboard_entry_t.pc`.                                                                                  |
| `instr_word`        | hex string     | Raw 32-bit instruction (post-decompression) from `orig_instr_i`.                                                              |
| `disasm`            | string \| null | Optional disassembly. Null if extractor not built with disassembler.                                                          |
| `is_compressed`     | bool           | From `rvfi_is_compressed_o`.                                                                                                  |
| `is_warmup`         | bool           | True iff `fe_cycle < warmup_end_cycle`.                                                                                       |
| `fu`                | string         | CVA6 `fu_t` enum value: `ALU`, `MULT`, `CTRL_FLOW`, `CSR`, `FPU`, `LOAD_UNIT`, `STORE_UNIT`, `NONE`.                          |
| `fu_category`       | string         | MinorFlow-comparable bucket: `Int`, `FP`, `Mem`, `MemFP`. See §5.7.                                                           |
| `rd`, `rs1`, `rs2`  | int            | Register addresses from `scoreboard_entry_t`.                                                                                 |
| `trans_id`          | int \| null    | Scoreboard slot captured at `is_cycle` from `issue_pointer_q`. Null if flushed before issue.                                  |
| `fetch_port`        | int            | 0 or 1: which `NrIssuePorts` lane this instance came through. Always 0 in single-issue.                                       |
| `if1_cycle`         | int \| null    | VCD-absolute cycle when this instance's I$ line was requested. Null if frontend bypassed (e.g. NOP from a flush replay path). |
| `if2_cycle`         | int \| null    | VCD-absolute cycle when this instance's I$ line was returned. Null if the request was killed (`kill_s1`/`kill_s2`).           |
| `fe_cycle`          | int            | VCD-absolute cycle of frontend→ID handshake. The instance _exists_ iff this is set.                                           |
| `id_cycle`          | int \| null    | VCD-absolute cycle of decode handshake. Null if flushed before decode.                                                        |
| `is_cycle`          | int \| null    | VCD-absolute cycle of issue handshake. Null if flushed before issue.                                                          |
| `ex_cycle`          | int \| null    | `is_cycle + 1`. Null if not issued.                                                                                           |
| `wb_cycle`          | int \| null    | VCD-absolute cycle of writeback. Null if not yet written back.                                                                |
| `co_cycle`          | int \| null    | VCD-absolute cycle of commit. Null if flushed before commit.                                                                  |
| `flushed`           | bool           | True if this instance was killed before commit.                                                                               |
| `flush_reason`      | string \| null | One of `branch_mispredict`, `exception`, `fence`, `csr_side_effect`, `unknown`.                                               |
| `lsu_state_history` | array \| null  | Optional Phase 5+ enrichment. For memory ops: array of `{cycle, state}` showing LSU FSM transitions.                          |

### 5.7 `fu_category` derivation

| CVA6 `fu_t`                               | Notes                              | Category |
| ----------------------------------------- | ---------------------------------- | -------- |
| `ALU`, `MULT`, `CTRL_FLOW`, `CSR`, `NONE` | Integer arithmetic, branches, CSRs | `Int`    |
| `FPU`                                     | Floating-point arithmetic          | `FP`     |
| `LOAD_UNIT`, `STORE_UNIT` with int rd/rs  | Integer load/store                 | `Mem`    |
| `LOAD_UNIT`, `STORE_UNIT` with FP rd/rs   | FP load/store                      | `MemFP`  |

The FP-or-int discrimination for memory ops uses `scoreboard_entry_t.fu == LOAD_UNIT/STORE_UNIT` combined with the `is_rd_fpr_flag` from the scoreboard's `mem_n` entry (or, equivalently, decoding the opcode: `flw`/`fld`/`fsw`/`fsd` → MemFP, else Mem).

### 5.8 Worked example

A single integer ADD instruction in the daxpy loop, fetched at VCD cycle 1450 (fetch line requested at 1447, returned at 1449):

```json
{
  "id": 42,
  "pc": "0x80000110",
  "instr_word": "0x02d50533",
  "disasm": "add a0,a0,a3",
  "is_compressed": false,
  "is_warmup": false,
  "fu": "ALU",
  "fu_category": "Int",
  "rd": 10,
  "rs1": 10,
  "rs2": 13,
  "trans_id": 3,
  "fetch_port": 0,
  "if1_cycle": 1447,
  "if2_cycle": 1449,
  "fe_cycle": 1450,
  "id_cycle": 1451,
  "is_cycle": 1452,
  "ex_cycle": 1453,
  "wb_cycle": 1453,
  "co_cycle": 1454,
  "flushed": false,
  "flush_reason": null,
  "lsu_state_history": null
}
```

A flushed branch-mispredict victim that was fetched but killed before decode. Note that `if1_cycle`/`if2_cycle`/`fe_cycle` are still populated — the frontend did real work that the viewer should show:

```json
{
  "id": 51,
  "pc": "0x80000200",
  "instr_word": "0x00000013",
  "disasm": "nop",
  "is_compressed": false,
  "is_warmup": false,
  "fu": "ALU",
  "fu_category": "Int",
  "rd": 0,
  "rs1": 0,
  "rs2": 0,
  "trans_id": null,
  "fetch_port": 0,
  "if1_cycle": 1497,
  "if2_cycle": 1499,
  "fe_cycle": 1500,
  "id_cycle": null,
  "is_cycle": null,
  "ex_cycle": null,
  "wb_cycle": null,
  "co_cycle": null,
  "flushed": true,
  "flush_reason": "branch_mispredict",
  "lsu_state_history": null
}
```

A pair of RVC instructions from the same 32-bit fetch line. Note the shared `if1`/`if2` and consecutive `fe_cycle` values (single-issue):

```json
[
  {
    "id": 100,
    "pc": "0x80000300",
    "instr_word": "0x00000513",
    "is_compressed": true,
    "fu": "ALU",
    "fu_category": "Int",
    "if1_cycle": 1600,
    "if2_cycle": 1602,
    "fe_cycle": 1603,
    "id_cycle": 1604,
    "is_cycle": 1605,
    "ex_cycle": 1606,
    "wb_cycle": 1606,
    "co_cycle": 1607,
    "flushed": false
  },
  {
    "id": 101,
    "pc": "0x80000302",
    "instr_word": "0x00100613",
    "is_compressed": true,
    "fu": "ALU",
    "fu_category": "Int",
    "if1_cycle": 1600,
    "if2_cycle": 1602,
    "fe_cycle": 1604,
    "id_cycle": 1605,
    "is_cycle": 1606,
    "ex_cycle": 1607,
    "wb_cycle": 1607,
    "co_cycle": 1608,
    "flushed": false
  }
]
```

---

## 6. Extractor Invariants

The extractor must verify these at end-of-run and refuse to emit JSON if any fail. They are listed in `metadata.invariants_verified` only when they pass.

1. **`monotonic_fe_cycle`** — `instructions[i].fe_cycle >= instructions[i-1].fe_cycle` for all i, after sorting by `id`. (Equality allowed only with `SuperscalarEn` and same `if1`/`if2`.)
2. **`if1_le_if2_le_fe`** — for every instance with non-null `if1_cycle` and `if2_cycle`: `if1_cycle <= if2_cycle <= fe_cycle`.
3. **`unique_trans_id_per_inflight_window`** — between `is_cycle` and `co_cycle` (or flush) of an instance, no other instance shares its `trans_id`.
4. **`all_instances_committed_or_flushed`** — every instance has either `co_cycle != null` or `flushed == true`.
5. **`ex_cycle_equals_is_cycle_plus_one`** — for every instance with non-null `is_cycle`.
6. **`stage_partial_order`** — `if1 ≤ if2 ≤ fe ≤ id ≤ is ≤ ex ≤ wb ≤ co` on non-null cycles per instance.
7. **`commit_count_matches_rvfi`** — the number of `co_cycle != null` instances equals the count of `rvfi.valid` pulses in the user window.
8. **`buffer_maxima_within_bounds`** — every observed buffer maximum is `<=` its config-derived hard bound (§5.4).

The pre-built forward `stall_map` is computed in the same single pass and stored separately (not in the per-instance record) for the viewer to reference when explaining stage gaps.

---

## 7. Open Questions

These are decisions deferred to discuss before or during Phase 1, not blockers for committing this spec.

1. **Integer load/store coverage in the benchmark suite.** The `daxpy` prologue may suffice; if not, a 15-line C microbenchmark closes the gap. Resolution: inspect the `daxpy` disassembly during Phase 2.
2. **Compressed instruction pairing semantics in the viewer.** When two RVC instructions come from the same 32-bit fetch word (shared `if1`/`if2`), how to visually indicate the pairing (a thin connecting line? shared cell shading?) is a viewer-side decision deferred to Phase 6.
3. **HPDcache state instrumentation.** Phase 5+ work. The exact FSM signal paths inside `cva6_hpdcache_wrapper` need investigation; we'll inventory those once Phases 1–4 are running.
4. **Killed fetch handling.** `icache_dreq_o.kill_s1`/`kill_s2` can cancel an in-flight fetch. When a kill fires, no instruction emerges from that fetch — there's no `fe_cycle` to bind the `if1`/`if2` to. The extractor needs a small grace period (a few cycles) to confirm a kill before discarding the line-tracking entry. Concrete policy: drop the entry if no `fe_cycle` is observed within `MAX_FETCH_LATENCY` cycles of `if1_cycle` _and_ a `kill_*` signal fired in the interim.

---

## 8. Out of Scope for Phase 0

To prevent scope creep before we have a working extractor:

- **Causal stall chains** ("instruction X stalled because Y held the FPU"). MinorFlow doesn't provide them; neither do we.
- **Branch predictor accuracy analytics.** A worthy follow-on but not part of the timeline view.
- **Vector / accelerator instruction tracking.** This config doesn't enable them in any wired sense.
- **Real-time / live streaming.** The extractor is offline post-processing.
- **Multi-hart support.** Single-hart only.

---

## 9. Sign-off

- [x] Stage names and anchor signal choices (Manu: honest CVA6 names; frontend sub-stages added per follow-up).
- [x] JSON field names and FU-categorization rules.
- [x] Invariant list (expanded in v1.1 to cover `if1`/`if2` ordering and buffer bounds).
- [x] `config_params` values verified against `cv64a6_imafdc_sv39_hpdcache_wb_config_pkg.sv`, with derivation formulas captured.

**Proceeding to Phase 1:** the minimal streaming VCD reader. Scope: stream the VCD, parse the `$var` block, build the whitelist signal→ID map, count transitions on each whitelisted signal over the user window, print a histogram. No pipeline reasoning, no JSON output beyond a summary. Validation: runs on the `fdiv` trace in reasonable time and memory, and the transition counts are sane (e.g., `fetch_entry_valid_i` fires roughly as many times as expected commits + flushes).
