# 2026-03-31 R4 Seed Fix Summary

## Background
The current SyzDirect V3 agent loop for `case_0 = tcindex_alloc_perfect_hash` was repeatedly stalling at `dist=2010` even after multiple R4 rounds, proactive seeds, and longer `dist_stall_timeout` values. Earlier issues such as target mismatch (`teql_destroy` contamination) and R3/R4 misclassification were already reduced, but the remaining failure mode was a semantic barrier near `tcindex_change`.

## Core Problem
The system was no longer failing because it chose the wrong subsystem. Instead, it was reaching the right traffic-control / rtnetlink area but failing to keep the seed and scoring logic aligned with the actual target path.

Two root causes were identified:
1. Seed selection was over-rewarding candidates that merely contained `kind=tcindex`, even when they were qdisc-only paths and not valid classifier/filter paths.
2. Stale target metadata (for example `sch_teql.c` instead of `cls_tcindex.c`) could still leak into later stages, causing the scorer and deterministic generator to treat a classifier target as a qdisc target.

## Earlier Problems Already Addressed
- Target consistency was improved so the target function stayed aligned with `tcindex_alloc_perfect_hash`.
- `dist_stall_timeout` and coverage stall were separated, which fixed the earlier R3/R4 confusion.
- Relevant distance tracking, `primary/secondary/evidence` triage, and baseline callfile reset were added.
- Per-round seed candidate logging was added so selection and rejection reasons became visible.

## New Findings From Raw Candidate Logging
Raw logging showed that the seed scorer was still selecting candidates such as:
- `new_tcindex_qdisc`
- `new_then_change_tcindex_qdisc`

These candidates were being selected because:
- `target_type` was sometimes computed as `qdisc`
- `kind=tcindex` still gave positive score
- broad `multi_stage` and `repeated_target_kind` bonuses favored qdisc-only paths

This was wrong for `tcindex_alloc_perfect_hash`, which is a classifier/filter target and should require filter-path evidence such as `RTM_NEWTFILTER` and `TCA_OPTIONS`.

## Code Changes Made
### 1. Persist corrected target metadata
`agent_loop.py`
- `_sync_target_metadata()` now not only resolves the effective target metadata but also rewrites `tpa/case_X/target_functions_info.txt` with the corrected `function` and `func_path`.
- R4/proactive logs now print the effective target metadata (`function` and `file`) that the loop is actually using.

Why:
- This prevents stale metadata from being silently re-read by downstream logic.

### 2. Make seed scoring snippet-aware
`llm_enhance.py`
- Added snippet-based target-type inference from source snippet headers.
- `_seed_requirements()` now prefers the snippet-derived type when the direct `target_file` metadata is stale or inconsistent.
- The seed selection basis now logs both `target_type` and `snippet_type`.

Why:
- Even if `target_file` temporarily says `sch_teql.c`, a snippet from `cls_tcindex.c` can still force the scorer to treat the target as `filter`.

### 3. Make validator snippet-aware
`llm_enhance.py`
- `_validate_seed_programs()` now uses the snippet-aware target type instead of relying only on `target_file`.

Why:
- Validation must use the same target-path assumption as scoring; otherwise bad qdisc-only seeds can still survive into later stages.

### 4. Make deterministic TC seed generation snippet-aware
`llm_enhance.py`
- `_generate_tc_seed_programs()` now uses the snippet-derived type too.

Why:
- If generation uses stale qdisc metadata while scoring uses filter metadata, the system keeps producing candidates it later has to reject.

### 5. Narrow multi-stage scoring
`llm_enhance.py`
- `multi_stage` scoring was changed from a generic “3 messages is good” rule to path-specific rules.
- For filter/action targets, multi-stage bonus now only applies when there are repeated `RTM_NEWTFILTER` messages.
- For qdisc targets, it applies only to repeated qdisc operations.

Why:
- `new qdisc -> change qdisc` should not beat `qdisc -> filter -> filter(update)` for a classifier target.

### 6. Narrow repeated-kind scoring
`llm_enhance.py`
- Repeated target-kind bonuses are now path-specific.
- Filter targets only get the bonus when the repeated target kind appears in repeated filter messages.
- Qdisc targets only get it on repeated qdisc messages.

Why:
- Repeating the word `tcindex` in the wrong netlink operation should not look like semantic progress.

### 7. Tighten R4 callfile broadening
`agent_loop.py`
- R4 now rejects broadening from an already-specific syscall variant to a bare base call during target expansion.
- Example: if `sendmsg$nl_route_sched` already exists, broadening to a generic `sendmsg` / base-form target is rejected unless it is already explicitly grounded.

Why:
- The current bottleneck is payload/state shape, not a lack of generic syscall family coverage.

## Validation Performed
- `python3 -m py_compile llm_enhance.py agent_loop.py pipeline_new_cve.py`
- Manual check that stale metadata plus classifier snippets now produce `target_type=filter`.
- Manual check that bare-base R4 broadening is rejected when a more specific current variant already exists.

## Current Expected Runtime Signals
After these fixes, the next run should show:
- `[R4] Target metadata: function=tcindex_alloc_perfect_hash file=net/sched/cls_tcindex.c`
- `[LLM-seed] Seed selection basis: target_type=filter ... snippet_type=filter`
- qdisc-only seeds such as `new_tcindex_qdisc` rejected instead of selected

## Remaining Open Question
These changes make the loop more consistent and remove several false-positive seed candidates, but they do not yet prove that `dist < 2010` will be reached. If the loop still stalls, the remaining issue is likely not metadata drift or naive scoring, but the difficulty of constructing and preserving the exact semantic filter update path needed to cross the final branch condition.

## Takeaway
The main lesson from this debugging cycle is that semantic-gated targets do not fail because of one isolated bug. They fail when target metadata, seed generation, validation, selection, and R4 enhancement all drift apart. The recent fixes focused on making those layers use the same target-path assumptions and exposing their decisions clearly in logs.
