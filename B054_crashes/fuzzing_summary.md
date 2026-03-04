# B054 Fuzzing Summary — R2 (Object/Parameter Generation Failure)

## Target
- **Bug ID**: B054
- **Target Function**: `xfrm_user_rcv_msg_compat`
- **File**: `net/xfrm/xfrm_compat.c:571`
- **Kernel Commit**: `3cea11cd5e3b00d61e4f5c2b7f370ed7a5c7bd6d` (v5.13)
- **Expected Failure Type**: R2 (Object/parameter generation — near target, wrong params)

## Fuzzing Configuration
- **Fuzzer**: SyzDirect
- **Duration**: 4 hours
- **VM**: QEMU x86_64, 4GB RAM, 4 procs
- **Distance Dir**: `analysis_result/distance_xidx0/` (6521 files)
- **Entry Syscall**: `sendmsg` (XFRM netlink)
- **Port**: 56744

## Results
| Metric | Value |
|--------|-------|
| Executed programs | 819,447 |
| Code coverage (blocks) | 55,802 |
| Signal (found/total) | 94,849 / 107,730 |
| Crashes | 1 |
| **Smash operations** | **2,290** |
| Corpus entries | 0 (detailCorpus empty) |

## Crash Analysis
- **Type**: `SYZFATAL: executor failed N times — broken pipe`
- **Interpretation**: Infrastructure crash only; no kernel bug triggered at target
- **Target reached**: Near-miss (high smash indicates proximity)

## R2 Behavior Evidence
- **Smash count 2,290 — 19.6× higher than B040 (R3)** — key distinguishing signal
- Smash operations indicate fuzzer repeatedly finds paths close to target and attempts parameter mutation
- Highest execution count (819,447) among all three bugs → maximum throughput suggesting good syscall reach
- `xfrm_user_rcv_msg_compat` handles 32-bit compat XFRM messages; fuzzer reaches XFRM subsystem but generates wrong compat message format (EINVAL at compat boundary)
- **Consistent with R2**: Fuzzer reaches the target vicinity but fails to generate correct object structure (compat message layout)

## Comparison: R1 vs R2 vs R3 Smash Count
| Bug | Type | Smash | Executed | Cover |
|-----|------|-------|----------|-------|
| B029 | R1 | ~12 | 665,390 | 52,198 |
| B040 | R3 | 117 | 611,165 | 46,929 |
| B054 | R2 | **2,290** | 819,447 | 55,802 |

## Files
- `description.txt` — crash type
- `report.txt` — full crash report
- `log_excerpt.txt` — first 50 lines of executor log
