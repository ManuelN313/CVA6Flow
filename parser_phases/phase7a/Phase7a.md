# Phase 7a 0.2 — LOCKED

Version 0.2 supersedes 0.1. The fix from 0.1 is critical: switching the
prediction-capture path from `mem_q[tid].sbe.bp` post-edge reads (which
returned stale data from the previous slot occupant) to pre-edge
snapshots of `decoded_instr_i[0].bp` (the same pattern Phase 4a uses
for fu/rs1/rs2/rd) — see "Architectural finding 2" below.

## Goal

Per-CTRL_FLOW record branch prediction & resolution: capture what the
predictor said at fetch time (cf type + predicted target) and what
the branch_unit actually resolved (cf type + target + taken +
mispredict). Compute hit rate; surface per-PC mispredict patterns.

## Per-record fields added to InstructionRecord

- `bp_predicted_cf      : str` — "NoCF" / "Branch" / "Jump" / "JumpR" / "Return"
- `bp_predicted_target  : int` — VLEN-bit predicted target (None for NoCF)
- `bp_resolved_cf       : str` — actual cf_type from branch_unit
- `bp_resolved_target   : int` — actual computed target
- `bp_resolved_taken    : bool` — actual taken/not-taken outcome
- `bp_mispredict        : bool` — HW-authoritative is_mispredict
- `bp_resolution_cycle  : int` — cycle resolved_branch_i.valid=1 fired

## cf_t enum mapping (ariane_pkg.sv:170-176)

- NoCF = 0 : no prediction made (or predicted not-taken)
- Branch = 1 : BHT-predicted taken conditional branch
- Jump = 2 : direct unconditional jump (frontend-resolved)
- JumpR = 3 : indirect jump, BTB-predicted target
- Return = 4 : RAS-predicted return

The cf value at issue also identifies the predictor source.

## Signals tracked

- 2 prediction signals (decoded_instr_i[0].bp.{cf,predict_address}) via
  pre-edge snapshot at the decode handshake.
- 6 resolution signals (i_scoreboard.resolved_branch_i.{valid, pc,
  target_address, is_taken, is_mispredict, cf_type}) at per-cycle scan.

## Architectural finding 1: workload behavior visible in the data

**fdiv hot loop (PC 0x80004134, `bltu a4,a5,8000410e <memset+0x98>`):**

- 157 total occurrences
- 156 predicted Branch → 0x8000410e correctly (BHT trained)
- 2 mispredicts:
  - cold start (predicted NoCF, actually taken)
  - loop exit (predicted Branch, actually not-taken)

This is the canonical BHT pattern: cold miss → train → many correct
predictions → one exit miss.

**Mispredict distribution (11 total in fdiv):**

- 9 NoCF→{Branch×6, Return×2, JumpR×1}: cold predictor at first
  encounter
- 2 Branch→Branch with taken=N: loop-exit mispredicts (BHT predicted
  T, actual NT)

Hit rate: **94.09%** in fdiv.

## Architectural finding 2: the pre-edge snapshot fix (v0.1 → v0.2)

v0.1 read `mem_q[tid].sbe.bp.{cf,predict_address}` at the post-edge
of the issue rising edge. This is broken because:

- `issue_pointer_q` advances on the issue rising edge.
- At post-edge, `tid = state.get(IPTR)` returns the NEW value of
  issue_pointer_q — pointing at the NEXT slot, not the one just
  allocated.
- `mem_q[tid]` therefore holds the previous occupant's bp data, not
  the new instruction's bp.

The smoking gun was id=1958 (a `jal ra,80003000`) showing
`bp_predicted_cf=Branch, bp_predicted_target=0x800036b4` — a JAL
mistakenly tagged as a conditional branch to a loop target from an
earlier instruction. The HW correctly didn't flag it as mispredict
(JAL uses immediate-computed target, ignores BHT), but our tracer's
attribution was wrong.

v0.2 fix: pre-edge snapshot of `decoded_instr_i[0].bp.{cf,
predict_address}` — the combinational outputs that carry the new
instruction's data right BEFORE the rising edge advances both
issue_q and issue_pointer_q. Same pattern as Phase 4a uses for
fu/rs1/rs2/rd.

After the fix: 159 non-NoCF predictions vs 1 before (a 159× increase).
The single previous "Branch on JAL" prediction is gone; JAL records
now show their actual bp.cf cleanly.

## Architectural finding 3: branch_unit ignores BHT for direct jumps

Even after the v0.2 fix, JALs with bp.cf=Jump don't generate
mispredicts because the branch_unit (branch_unit.sv:84) uses
fu_data_i.imm to compute the target — it never compares against
branch_predict_i for JALs. Only conditional branches (op_is_branch)
and JALRs trigger the mispredict comparison. This is a design choice;
JALs always have known targets.

## Per-record classification results (fdiv, v0.2)

| Metric                  | Value                     |
| ----------------------- | ------------------------- |
| Total CTRL_FLOW records | 187                       |
| Predicted (non-NoCF)    | 159 (157 Branch + 2 Jump) |
| Reached resolution      | 186                       |
| Flushed before resolve  | 1                         |
| Mispredicts             | 11                        |
| Hit rate                | 94.09%                    |

## Validation

- 159 non-NoCF predictions in fdiv — up from 1 in v0.1; pre-edge
  snapshot fix verified end-to-end
- 156/157 memset loop branches predicted Branch with correct target
  (0x8000410e) — strongest cross-validation of the prediction capture
- Synthetic tests cover: correct prediction, mispredict, NoCF
  prediction (no target attached), loop-body PC collision
  (oldest-in-flight gets the resolution)
- Cross-check with flush counts: 11 mispredicts × ~2.3 records flushed
  per mispredict = 25 records flushed (matches IF=21 + EX=4)
- Cross-check id=155: predicted Branch → 0x80003ff6 (memcpy loop top),
  resolved → 0x80004024 (next PC, fall-through). HW agrees this is a
  mispredict because predicted_address != resolved_address for a
  conditional branch with predicted T.

## Files in this archive

- `phase3_pipeline_tracer.py` v0.2 — extractor with Phase 7a integrated
- `p7a_spot_check.py` — 4-view spot-check tool:
  1. summary (totals, hit rate, by_cf cross-tables)
  2. all non-NoCF predictions with cross-validation against resolution
  3. top-N mispredicts with full context
  4. per-PC mispredict frequency (recurring offenders)
