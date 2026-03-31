# R4 Seed Selection / Metadata Fix Notes (2026-03-31)

## Goal
- Stop R4 from selecting qdisc-only seeds for filter targets.
- Stop stale target metadata from silently turning filter targets into qdisc targets.
- Make validator/generator/scorer use the same target-type basis.
- Reduce R4 callfile broadening when the problem is payload/state shape, not syscall family.

## Observed Problems
- `target_file` can become stale (`sch_teql.c`) even when the effective target function is `tcindex_alloc_perfect_hash`.
- Seed scorer then computes `target_type=qdisc`, so qdisc-only seeds get selected.
- `_validate_seed_programs()` still uses only `target_file`, so stale metadata also weakens validation.
- `_generate_tc_seed_programs()` also uses only `target_file`, so deterministic generation can still produce wrong qdisc seeds.
- `multi_stage` scoring is too broad: any 3-message program gets bonus, even if the extra step is the wrong path.
- `repeated_target_kind` is too broad: repeated `tcindex` in qdisc messages can score, even when no filter-update path exists.
- R4 may still widen the callfile with broad base syscalls like `sendmsg$nl_route`, which is usually not the real bottleneck here.

## Planned Fixes
1. Persist corrected target metadata to `tpa/case_X/target_functions_info.txt` during agent-loop sync.
2. Log effective `target_function` and `target_file` at proactive and R4 seed generation time.
3. Make seed requirements snippet-aware and use snippet-derived target type when metadata is stale.
4. Make `_validate_seed_programs()` snippet-aware so validation matches scoring.
5. Make `_generate_tc_seed_programs()` snippet-aware so deterministic generation matches scoring.
6. Narrow `multi_stage` scoring to same-path state transitions:
   - filter/action: repeated `RTM_NEWTFILTER`
   - qdisc: repeated qdisc ops only
7. Narrow `repeated_target_kind` scoring to the target path type, not just repeated kind strings anywhere.
8. Tighten R4 target expansion so broad base-syscall widening is rejected when a more specific current variant already exists.

## Expected Outcome
- Filter targets should be scored as `target_type=filter` consistently.
- Qdisc-only candidates should be rejected for classifier targets.
- Raw logs should explain candidate structure and reject reasons clearly.
- R4 should focus more on seed/state/path quality and less on broadening syscall space.
