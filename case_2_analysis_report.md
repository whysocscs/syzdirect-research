# Case_2 분석 보고서: drivers/block/nbd.c:2006

## 1. 타겟 개요

| 항목 | 값 |
|------|-----|
| Case | case_2 |
| 타겟 파일 | drivers/block/nbd.c |
| 타겟 라인 | 2006 |
| 타겟 함수 | `nbd_genl_connect()` |
| 커널 버전 | 6.1.0 |
| 서브시스템 | NBD (Network Block Device) |

## 2. 타겟 코드 분석

`nbd_genl_connect()`은 Generic Netlink를 통한 NBD 장치 연결 설정 함수:

```c
static int nbd_genl_connect(struct sk_buff *skb, struct genl_info *info)
{
    // ... device allocation, config setup ...
    if (info->attrs[NBD_ATTR_DEAD_CONN_TIMEOUT]) {
        config->dead_conn_timeout =
            nla_get_u64(info->attrs[NBD_ATTR_DEAD_CONN_TIMEOUT]);
        kcov_mark_block(0);  // ← TARGET POINT (line 2006)
        config->dead_conn_timeout *= HZ;
    }
    // ...
}
```

인터페이스 등록:
```c
static const struct genl_small_ops nbd_connect_genl_ops[] = {
    { .cmd = NBD_CMD_CONNECT, .doit = nbd_genl_connect },
    { .cmd = NBD_CMD_DISCONNECT, .doit = nbd_genl_disconnect },
    { .cmd = NBD_CMD_RECONFIGURE, .doit = nbd_genl_reconfigure },
    { .cmd = NBD_CMD_STATUS, .doit = nbd_genl_status },
};
// genl_register_family(&nbd_genl_family)
```

## 3. 파이프라인 실행 결과

### Step 1: PrepareSourceCode
- kcov 패치: case_1에서 복사 (동일 커널 6.1.0)
- `drivers/block/nbd.c`에 `#include <linux/kcov.h>` 추가
- line 2006에 `kcov_mark_block(0)` 삽입

### Step 2: CompileKernelToBitcode
- 초기 빌드 실패: CC 환경변수 vs make 인자 차이 (CC=... make → 무시됨, make CC=... → 적용)
- kcov 패치 누락으로 nbd.o 빌드 실패 → 패치 파일 복사 후 재빌드
- **최종 결과: 6,856개 .llbc (비어있지 않은 것: 6,767개)**

### Step 3: AnalyzeKernelInterface
- 34개 청크로 분할 (200 파일/청크)
- 성공: 30/34 청크
- 실패: 4개 (chunk_016, 021, 022, 026) → segfault
- **kernel_signature_full**: 16,240개 시그니처
- **kernelCode2syscall.json**: 1,154개 핸들러 매핑

### Step 4: AnalyzeTargetPoints (TPA)
- drivers/block만 포함 + non-drivers 전체 = 4,058 파일 subset
- TPA 성공 (381초)
- **distance_xidx0/**: 3,692개 distance 파일
- **CompactOutput.json**: 1개 target syscall 매핑

## 4. R1 분석 결과: **SUCCESS**

### 발견된 Target Syscall

| Syscall | Rank | Constraints | 평가 |
|---------|------|------------|------|
| `sendmsg` | 0 | NBD_ATTR_SIZE_BYTES=2, NBD_ATTR_SOCKETS=7 | **정확** - genetlink 경로 |

### 실제 호출 체인

```
sendmsg(fd, msg, flags)
  → netlink_sendmsg()
    → netlink_unicast()
      → genl_rcv_msg()
        → nbd_genl_connect()     [via genl_small_ops.doit]
          → [line 2006: TARGET]
```

### R1 성공 요인

예상과 달리 R1이 성공했습니다. 이유:
- NBD는 **Generic Netlink (genetlink)** 인터페이스를 사용
- interface_generator가 genetlink 패턴을 인식하여 `sendmsg` → `nbd_genl_connect` 매핑 생성
- Case_0 (TC subsystem)의 `rtnl_register` 패턴과 달리, genetlink의 `genl_small_ops` 패턴은 SyzDirect가 지원

### 주의사항
- `sendmsg`라는 generic syscall로 매핑됨 → syzkaller가 올바른 netlink 프로토콜/family를 선택해야 도달 가능
- Constraints에 NBD_ATTR 관련 값이 포함됨
- 실제 도달하려면: socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) → sendmsg(nbd family)

## 5. Case 비교 (0, 1, 2)

| 항목 | Case_0 | Case_1 | Case_2 |
|------|--------|--------|--------|
| 서브시스템 | net/sched (TC) | sound/seq (ALSA) | drivers/block (NBD) |
| 인터페이스 | rtnl_register | ioctl | genetlink |
| R1 결과 | **FAIL** | **SUCCESS** | **SUCCESS** |
| 원인 | rtnl 미인식 | ioctl 인식 | genetlink 인식 |
| syscall 매핑 | 0개 | 6개 (유효 3개) | 1개 (유효 1개) |
| distance 파일 | 2,358개 | 3,676개 | 3,692개 |
| bitcode 파일 | 2,358개 | 6,856개 | 6,767개 |
| signatures | 3,802개 | 9,682개 | 16,240개 |
| handlers | - | 1,184개 | 1,154개 |

## 6. 빌드 교훈

- **CC 전달 방식**: `CC=... make` (환경변수)는 Kbuild에서 무시됨, `make CC=...` (make 인자)를 사용해야 함
- **kcov 패치 확인**: kcov.h와 kcov.c 모두 패치되어야 함, 파일이 존재하더라도 내용을 확인할 것
- **CONFIG_CC_VERSION_TEXT**: .config 재생성 시 clang이 아닌 gcc로 기록되면 빌드가 gcc로 진행됨

## 7. 다음 단계

- [x] R1 분석 완료 (SUCCESS)
- [ ] R2/R3 분석: 실제 fuzzing 실행 필요
- [ ] Case_3 (net/sched/sch_taprio.c:919) 분석 진행
- [ ] Case_4 (drivers/block/nbd.c:1809) 분석 진행
