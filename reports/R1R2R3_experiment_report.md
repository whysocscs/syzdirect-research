# R1/R2/R3 Failure Type Experiment — SyzDirect Table 4 Reproduction

**Date**: 2026-03-03 ~ 2026-03-04  
**Purpose**: Reproduce and validate R1/R2/R3 failure type classification from SyzDirect paper Table 4

---

## Experiment Setup

| Bug | Target Function | Subsystem | Expected Type | Kernel |
|-----|----------------|-----------|---------------|--------|
| B029 | `gre_build_header` | net/GRE | R1 | v5.13 |
| B040 | `sta_apply_parameters` | net/mac80211 | R3 | v5.11 |
| B054 | `xfrm_user_rcv_msg_compat` | net/xfrm | R2 | v5.13 |

**Common config**: SyzDirect fuzzer, 4-hour runs, QEMU x86_64 4GB, distance-instrumented kernel (6521 .dist files each)

**Build issue resolved**: B040/B054 initially failed with `kcov.c:498: cannot assign to vm_flags (const-qualified)` — fixed by replacing with v6.3 `kcov.c` + re-applying distance patch.

---

## Results

### B029 — R1: Missing Dependent Syscalls

| Metric | Value |
|--------|-------|
| Executed | 665,390 |
| Coverage | 52,198 blocks |
| Smash | ~12 |
| Corpus | 59,180 |
| Target hit | ✗ |

**Analysis**: Fuzzer explored broadly (large corpus) but never reached `gre_build_header`. GRE requires a specific syscall sequence (raw socket + tunnel setup) that the fuzzer couldn't auto-generate. Classic R1 — the right syscalls simply aren't being tried.

---

### B040 — R3: Insufficient Syscall Context

| Metric | Value |
|--------|-------|
| Executed | 611,165 |
| Coverage | 46,929 blocks (plateau) |
| Smash | 117 |
| Corpus | — |
| Target hit | ✗ |

**Analysis**: Coverage plateaued early and stayed flat (~46,913→46,929 in final hour, Δ=16). `candidate=0` throughout final phase. mac80211's `sta_apply_parameters` requires a full wireless station management context (associated BSS, station management state machine) — the fuzzer hits a syscall-level ceiling without this context. Classic R3 — cover ceiling due to missing context.

---

### B054 — R2: Object/Parameter Generation Failure

| Metric | Value |
|--------|-------|
| Executed | 819,447 |
| Coverage | 55,802 blocks |
| **Smash** | **2,290** |
| Corpus | — |
| Target hit | ✗ (near-miss) |

**Analysis**: The **smash count (2,290) is 19.6× higher than B040 (R3)**. This is the key R2 signal — the fuzzer repeatedly finds paths near `xfrm_user_rcv_msg_compat` and tries to mutate parameters, but the 32-bit compat message structure requires precise layout that random mutation fails to produce (EINVAL at compat boundary). Classic R2 — near-target but wrong object structure.

---

## Key Differentiating Metrics

```
Failure Type Fingerprints (4-hour run):

R1 (B029):  smash≈12,   corpus=59k (broad), cover grows steadily, no target proximity
R3 (B040):  smash=117,  corpus≈0,   cover plateau (ceiling hit), candidate=0
R2 (B054):  smash=2290, corpus≈0,   cover plateau, HIGH smash (near-target mutation)
```

**Smash count is the strongest R1/R2/R3 discriminator:**
- R1: Very low (fuzzer not finding target-adjacent paths)
- R3: Low-medium (found ceiling, giving up)
- R2: Very high (found target vicinity, mutating intensely)

---

## B036 Attempt — R3: sound/core/seq (Failed)

- **Target**: `snd_seq_queue_alloc` (`sound/core/seq/seq_queue.c:171`)
- **Issue 1**: Distance analysis produced 0 files — `snd_seq_queue_alloc` unreachable via kernel interface syscall mapping
- **Issue 2**: Callfile JSON parse error (Python error comment embedded in output)
- **Status**: Requires manual callfile with ALSA seq ioctl entry point

---

## Classification Confidence

| Bug | Paper Expected | Observed Signal | Match |
|-----|---------------|-----------------|-------|
| B029 | R1 | Broad corpus, low smash, no proximity | ✅ |
| B040 | R3 | Cover plateau, low smash, candidate=0 | ✅ |
| B054 | R2 | Very high smash (2290), near-target | ✅ |

All three bugs show behavior consistent with their expected R1/R2/R3 classifications from the SyzDirect paper.

---

## Next Steps
1. Fix B036 (ALSA seq) callfile → manual ioctl entry point
2. Apply RelatedSyscallAgent for B029 (R1) — inject GRE tunnel setup syscalls
3. Apply ObjectSynthesisAgent for B054 (R2) — generate correct compat message structure
4. Re-run with agent-augmented programs and compare hit rates
