# B040 Fuzzing Summary — R3 (Insufficient Syscall Context)

## Target
- **Bug ID**: B040
- **Target Function**: `sta_apply_parameters`
- **File**: `net/mac80211/cfg.c:1681`
- **Kernel Commit**: `e0756cfc7d7cd08c98a53b6009c091a3f6a50be6` (v5.11)
- **Expected Failure Type**: R3 (Insufficient syscall context — high error rate)

## Fuzzing Configuration
- **Fuzzer**: SyzDirect
- **Duration**: 4 hours
- **VM**: QEMU x86_64, 4GB RAM, 4 procs
- **Distance Dir**: `analysis_result/distance_xidx0/` (6521 files)
- **Entry Syscall**: `sendmsg` (NL80211 generic netlink)
- **Port**: 56743

## Results
| Metric | Value |
|--------|-------|
| Executed programs | 611,165 |
| Code coverage (blocks) | 46,929 |
| Signal (found/total) | 76,655 / 88,356 |
| Crashes | 2 |
| Smash operations | 117 |
| Corpus entries | 0 (detailCorpus empty) |

## Crash Analysis
- **Type**: `SYZFATAL: executor failed N times — broken pipe`
- **Interpretation**: Infrastructure crash only; no kernel bug triggered at target
- **Target reached**: No

## R3 Behavior Evidence
- Coverage plateau: cover stabilized ~46,900 in final hour (46,913 → 46,929, Δ=16)
- Very low smash count (117) relative to execution count → fuzzer cannot find new interesting paths
- `candidate=0` consistently in final phase → triage queue exhausted
- mac80211 `sta_apply_parameters` requires: nl80211 family registration + station management context (interface up, BSS associated) — syscall context insufficient for deep penetration
- **Consistent with R3**: Cover ceiling hit due to missing syscall setup context

## Files
- `description.txt` — crash type
- `report.txt` — full crash report
- `log_excerpt.txt` — first 50 lines of executor log
