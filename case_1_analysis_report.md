# Case_1 분석 보고서: sound/core/seq/seq_timer.c:300

## 1. 타겟 개요

| 항목 | 값 |
|------|-----|
| Case | case_1 |
| 타겟 파일 | sound/core/seq/seq_timer.c |
| 타겟 라인 | 300 |
| 타겟 함수 | `snd_seq_timer_open()` |
| 커밋 | 83e197a8414c |
| 커널 버전 | 6.1.0 |
| 서브시스템 | ALSA Sequencer (sound) |

## 2. 타겟 코드 분석

`snd_seq_timer_open()` (lines 259-313)은 ALSA sequencer queue에 대한 타이머 인스턴스를 여는 함수:

```c
int snd_seq_timer_open(struct snd_seq_queue *q)
{
    struct snd_seq_timer *tmr = q->timer;
    struct snd_timer_instance *t;
    // ...
    err = snd_timer_open(t, &tmr->alsa_id, q->queue);
    if (err < 0 && tmr->alsa_id.dev_sclass != SNDRV_TIMER_SCLASS_SEQUENCER) {
        // fallback to system timer
    }
    // line 300: kcov_mark_block(0);  ← TARGET POINT
    spin_lock_irq(&tmr->lock);
    tmr->timeri = t;  // 타이머 인스턴스 할당
    // ...
}
```

타겟 포인트는 `snd_timer_open()` 성공 후, 타이머 인스턴스를 queue에 할당하기 직전에 위치.

## 3. 파이프라인 실행 결과

### Step 1: PrepareSourceCode
- kcov 패치: case_0에서 복사 (동일 커널 6.1.0)
- `include/linux/kcov.h`, `kernel/kcov.c` 복사
- `sound/core/seq/seq_timer.c:300`에 `kcov_mark_block(0)` 삽입

### Step 2: CompileKernelToBitcode
- 결과: **6,856개 .llbc 파일** (case_0의 2,358개 대비 2.9배)
- 빌드: `make -j2` 정상 완료

### Step 3: AnalyzeKernelInterface
- 35개 청크로 분할 실행
- 성공: 31/35 청크
- 실패: 4개 (chunk_017, 021, 022, 032) → segfault, 서브분할로 복구
- **kernel_signature_full**: 9,682개 시그니처
- **kernelCode2syscall.json**: 1,184개 핸들러 매핑

### Step 4: AnalyzeTargetPoints (TPA)
- 전체 6,856 파일 → OOM (14GB RSS 초과)
- **subset 전략**: drivers/ 제외 4,128 파일로 재실행 → **성공**
- **distance_xidx0/**: 3,676개 distance 파일 생성
- **CompactOutput.json**: 6개 target syscall 매핑

## 4. R1 분석 결과: **SUCCESS**

### 발견된 Target Syscall (6개)

| Syscall | Rank | Constraints | 평가 |
|---------|------|------------|------|
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER` | 0 | 없음 | **정확** - 직접 경로 |
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT` | 0 | 없음 | **정확** - snd_seq_queue_use 경유 |
| `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_INFO` | 0 | 없음 | **정확** - locked=1일 때 경유 |
| `ioctl$SNDRV_SEQ_IOCTL_CREATE_QUEUE` | 0 | 없음 | **전제조건** - 직접 도달 불가 |
| `delete_module` | 0 | KERNEL_CLIENT=2 | **부정확** - 관련 없음 |
| `kexec_load` | 0 | KERNEL_CLIENT=2 | **부정확** - 관련 없음 |

### 실제 호출 체인

**주요 경로 (SET_QUEUE_TIMER)**:
```
ioctl(fd, SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER, ...)
  → snd_seq_ioctl_set_queue_timer()    [seq_clientmgr.c:1760]
    → snd_seq_queue_timer_open()       [seq_queue.c:436]
      → snd_seq_timer_open()           [seq_timer.c:259]
        → [line 300: TARGET]
```

**보조 경로 (SET_QUEUE_CLIENT)**:
```
ioctl(fd, SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT, ...)
  → snd_seq_ioctl_set_queue_client()   [seq_clientmgr.c:1813]
    → snd_seq_queue_use()              [seq_queue.c:517]
      → snd_seq_timer_open()           [seq_timer.c:259]
        → [line 300: TARGET]
```

### R1 성공 요인

case_0 (TC subsystem, netlink 기반)과 달리, case_1의 ALSA sequencer는:
1. **표준 ioctl 인터페이스** 사용 → interface_generator가 정상 인식
2. **직접적인 함수 호출 체인** → 콜그래프 추적 용이
3. **sound 서브시스템**의 등록 패턴이 SyzDirect가 지원하는 형태

## 5. Case_0 vs Case_1 비교

| 항목 | Case_0 | Case_1 |
|------|--------|--------|
| 서브시스템 | net/sched (TC) | sound/seq (ALSA) |
| 인터페이스 | netlink (sendmsg) | ioctl |
| R1 결과 | **FAIL** | **SUCCESS** |
| 원인 | rtnl_register 패턴 미인식 | 표준 ioctl 패턴 인식 |
| syscall 매핑 | 0개 | 6개 (유효 3개) |
| distance 파일 | 2,358개 | 3,676개 |
| bitcode 파일 | 2,358개 | 6,856개 |

## 6. 정밀도 이슈

- 6개 중 유효한 매핑은 3개 (SET_QUEUE_TIMER, SET_QUEUE_CLIENT, SET_QUEUE_INFO)
- CREATE_QUEUE는 전제조건이지 직접 도달 경로가 아님
- delete_module, kexec_load는 false positive (KERNEL_CLIENT 관련 일반적 경로)
- **Precision: 50% (3/6)**, **Recall: 100% (핵심 경로 모두 발견)**

## 7. 다음 단계

- [x] R1 분석 완료 (SUCCESS)
- [ ] R2/R3 분석: 실제 fuzzing 실행 필요 (InstrumentDistance → Fuzz)
- [ ] Case_2 (drivers/block/nbd.c:2006) 분석 진행
- [ ] Case_3 (net/sched/sch_taprio.c:919) 분석 진행
