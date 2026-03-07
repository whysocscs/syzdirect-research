# Case_4 분석 보고서: drivers/block/nbd.c:1809

## 1. 타겟 개요

| 항목 | 값 |
|------|-----|
| Case | case_4 |
| 타겟 파일 | drivers/block/nbd.c |
| 타겟 라인 | 1809 |
| 타겟 함수 | `nbd_dev_add()` (caller: `nbd_genl_connect`) |
| 커널 버전 | 6.1.0 |
| 서브시스템 | drivers/block (NBD - Network Block Device) |

## 2. 타겟 코드 분석

`nbd_dev_add()`는 NBD 디바이스를 새로 할당/초기화하는 함수:

```c
static struct nbd_device *nbd_dev_add(int index, unsigned int refs)
{
    // alloc disk, init queues
    // ... (line 1809 근처)
    kcov_mark_block(0);  // ← TARGET (line 1809)
    mutex_init(&nbd->config_lock);
    ...
}
```

실제 호출 체인:
```
sendmsg(netlink, NBD_CMD_CONNECT)
  → nbd_genl_connect()
    → nbd_dev_add()        ← TARGET 함수
      → [line 1809: TARGET]
```

**Case_2와의 관계**: Case_2 타겟(nbd_genl_connect:2006)은 nbd_dev_add를 호출한 후의 코드이고, Case_4 타겟(nbd_dev_add:1809)은 한 단계 더 깊은 callee 함수 내부.

## 3. 파이프라인 실행 결과

### Step 2: CompileKernelToBitcode
- **6,856개 .llbc** (비어있지 않은 것: 6,767개)
- vmlinux/bzImage 링크 성공 (exit=0)

### Step 3: AnalyzeKernelInterface
- 28개 청크, 5개 실패 (chunk_001, 006, 016, 017, 018)
- **kernel_signature_full**: 9,054개 시그니처
- **kernelCode2syscall.json**: 648개 핸들러 매핑

### Step 4: AnalyzeTargetPoints (TPA)
- drivers/block만 포함 subset (3,094 파일)
- 성공 (186초)
- **distance_xidx0/**: 2,703개 distance 파일
- **CompactOutput.json**: 3개 target syscall 매핑

## 4. R1 분석 결과: **FAIL**

### 발견된 Target Syscall (3개)

| Syscall | Constraints | 평가 |
|---------|------------|------|
| `ioctl$SNAPSHOT_POWER_OFF` | SNAPSHOT_POWER_OFF=13072 | false positive |
| `ioctl$SNAPSHOT_S2RAM` | SNAPSHOT_S2RAM=13067 | false positive |
| `write$cgroup_int` | 없음 | false positive |

### 핵심 문제

**Precision: 0%** — 3개 매핑 모두 false positive.

TPA 디버그 로그에서 확인:
```
[DEBUG] Current cmdEntryFunc: nbd_dev_add in interface json: 0
```

`nbd_dev_add`가 interface_generator에서 진입점으로 인식되지 않음. 이유:
1. `nbd_dev_add`는 genl_ops에서 **직접** 등록된 핸들러가 아님 (그것은 `nbd_genl_connect`)
2. TPA가 `nbd_genl_connect → nbd_dev_add` 콜체인을 역추적해야 하지만, 이 연결을 찾지 못함
3. 대신 `update_flag` 등 무관한 경로를 통해 snapshot/cgroup syscall이 매핑됨

### Case_2와 비교 (같은 파일, 다른 함수 depth)

| 항목 | Case_2 (nbd_genl_connect) | Case_4 (nbd_dev_add) |
|------|--------------------------|---------------------|
| 타겟 함수 | nbd_genl_connect (직접 핸들러) | nbd_dev_add (callee) |
| 호출 깊이 | 0 (직접 등록 함수) | 1 (핸들러가 호출하는 함수) |
| R1 결과 | SUCCESS (sendmsg 1개) | FAIL (3개 false positive) |
| 유효 매핑 | 1/1 | 0/3 |

**패턴**: 동일 서브시스템이라도 타겟이 진입점 핸들러 자체(case_2)이면 매핑 성공, callee 함수(case_4)이면 콜체인 역추적 실패로 매핑 실패.

## 5. 전체 Case 비교 (Case 0~4)

| Case | 서브시스템 | 인터페이스 | 호출 깊이 | R1 | 유효 매핑 |
|------|-----------|-----------|----------|-----|----------|
| 0 | net/sched (TC) | rtnl_register | 간접 | FAIL | 0/0 |
| 1 | sound/seq (ALSA) | ioctl | 직접 | SUCCESS | 3/6 |
| 2 | drivers/block (NBD) | genetlink | 직접 핸들러 | SUCCESS | 1/1 |
| 3 | net/sched (TC) | rtnl_register | 간접 | NOISY | 0/16 |
| 4 | drivers/block (NBD) | genetlink callee | 1단계 callee | FAIL | 0/3 |

## 6. SyzDirect 실패 패턴 종합

1. **인터페이스 패턴 미인식** (case_0, case_3): rtnl_register → SyzDirect 일관 실패
2. **콜체인 깊이 문제** (case_4): 핸들러의 callee에 타겟이 있으면 역추적 실패
3. **성공 조건**: 직접 등록된 핸들러 함수 내부에 타겟이 있을 때만 성공 (case_1, case_2)

## 7. 다음 단계

- [x] R1 분석 완료 (FAIL)
- [ ] 전체 케이스 종합 보고서 작성
