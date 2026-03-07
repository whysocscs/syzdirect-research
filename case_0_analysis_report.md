# Case 0 분석 보고서: SyzDirect R1 실패 분석

**타겟**: `net/sched/cls_tcindex.c:309` (Patch ID 1, Benign)
**커널 커밋**: `3f2db250099f`
**분석 일자**: 2026-02-07

---

## 1. 타겟 개요

`cls_tcindex.c:309`는 Linux TC(Traffic Control) 서브시스템의 tcindex classifier에서 perfect hash 테이블을 할당하는 함수 `tcindex_alloc_perfect_hash()`의 시작 지점이다.

```
실제 콜 체인:
  sendmsg(netlink)
    → rtnetlink_rcv_msg
      → tc_new_tfilter  (cls_api.c:1956, rtnl_register로 등록)
        → tp->ops->change  (cls_api.c:2147)
          → tcindex_change  (cls_tcindex.c:532)
            → tcindex_set_parms  (cls_tcindex.c:332)
              → tcindex_alloc_perfect_hash  (cls_tcindex.c:306)  ← 타겟
```

이 경로는 netlink 소켓을 통한 `RTM_NEWTFILTER` 메시지 전송으로 도달하며, 함수 포인터(`tp->ops->change`)를 통한 간접 호출을 포함한다.

---

## 2. 파이프라인 실행 결과

### 2.1 Step 1-2: 소스 준비 & Bitcode 컴파일

| 항목 | 값 |
|------|-----|
| kcov 패치 | 수동 적용 완료 |
| .llbc 파일 수 | 2,358개 |
| Bitcode 총 크기 | 752 MB |
| 빌드 디렉토리 크기 | 5.3 GB |
| bzImage | 생성 완료 |

### 2.2 Step 3: Interface 분석 (AnalyzeKernelInterface)

| 항목 | 값 |
|------|-----|
| kernel_signature_full | 3,802줄 |
| kernelCode2syscall.json | 43,767 bytes |
| 매핑된 handler 함수 | 275개 |
| 매핑된 block entry | 634개 |
| 매핑된 고유 syscall variant | 391개 |
| 고유 base syscall | 23개 |
| 청크 분할 | 35개 청크 (chunk_034 segfault → 10개 서브청크로 재분할 성공) |

**Interface 분석에서 식별된 23개 base syscall:**

| syscall | entry 수 | 직접 도달 | 조건부 도달 | 리소스 필요 |
|---------|----------|-----------|-------------|------------|
| ioctl | 3,390 | 106 | 3,284 | O (device) |
| write | 168 | 40 | 128 | O (device) |
| open | 50 | 50 | 0 | O (device) |
| read | 19 | 19 | 0 | O (device) |
| arch_prctl | 8 | 0 | 8 | X |
| ioprio_set | 7 | 0 | 7 | X |
| mount | 7 | 7 | 0 | O (device) |
| mmap | 6 | 6 | 0 | O (device) |
| ioprio_get | 6 | 0 | 6 | X |
| modify_ldt | 5 | 0 | 5 | X |
| setsockopt | 4 | 0 | 4 | O (socket) |
| getxattr | 2 | 2 | 0 | X |
| setxattr | 2 | 2 | 0 | X |
| accept/accept4 | 1/1 | 1/1 | 0/0 | O (socket) |
| bind | 1 | 1 | 0 | O (socket) |
| 기타 socket 계열 | 각 1 | 각 1 | 0 | O (socket) |

### 2.3 Step 4: Target Point 분석 (TPA)

| 항목 | 값 |
|------|-----|
| 타겟 함수 | `tcindex_alloc_perfect_hash` |
| 타겟 소스 | `/work/syzdirect_workdir/srcs/case_0/net/sched/cls_tcindex.c` |
| distance 파일 | 2,104개 생성 |
| CompactOutput.json | `"target syscall infos": []` **(비어있음)** |
| syscall_shrink.txt | 0줄 |

### 2.4 Step 5-6: Instrument Distance & Fuzz

**미진행** — Step 4에서 syscall entry 매핑이 비어있어 진행 불가.

---

## 3. 실패 분석

### 3.1 실패 분류: **R1 (Missing Dependencies)**

SyzDirect의 정적 분석이 `tcindex_alloc_perfect_hash`까지 도달하는 syscall 경로를 식별하지 못했다.

- `kernelCode2syscall.json`에 `tcindex` 관련 함수가 **전혀 없음**
- `kernel_signature_full`에서도 `tcindex` 관련 시그니처 **0건**

### 3.2 R1 실패 원인 분석

SyzDirect의 interface_generator는 커널의 `file_operations`, `proto_ops` 등 구조체의 함수 포인터를 분석하여 syscall → handler 매핑을 구축한다. 이 케이스에서 매핑이 실패한 이유:

#### 원인 1: 간접 호출 체인의 깊이

```
tc_new_tfilter (cls_api.c)
  → tp->ops->change   ← 함수 포인터 간접 호출
    → tcindex_change   ← tcindex_proto_ops.change로 등록됨
```

`tc_new_tfilter`는 `rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_new_tfilter, ...)`로 등록되는데, 이는 netlink rtnetlink 서브시스템을 통한 등록이다. interface_generator가 이 등록 패턴을 인식하지 못한 것으로 보인다.

#### 원인 2: Netlink 기반 등록 패턴

일반적인 syscall 경로(`file_operations.write`, `proto_ops.setsockopt` 등)와 달리, TC 서브시스템은 **rtnetlink 메시지 핸들러**로 등록된다:

```c
// cls_api.c:3749
rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_new_tfilter, NULL, ...);
```

이 패턴은 `sendmsg` syscall → netlink 소켓 → rtnetlink dispatch → tc_new_tfilter로 이어지는데, interface_generator의 분석 범위를 벗어난다.

#### 원인 3: setsockopt 매핑의 불완전성

interface 분석에서 `setsockopt`가 4개 entry로 잡혔지만, 모두 `alg_setsockopt` (AF_ALG crypto 소켓)에 매핑되어 있다. TC 서브시스템의 netlink 경로는 포착되지 않았다.

```
setsockopt 매핑 결과 (kernel_signature_full):
  setsockopt|D[socket-[38]-[0]-[0]]|...|C[1]|...  → alg_setsockopt
  setsockopt|D[socket-[38]-[0]-[0]]|...|C[5]|...  → alg_setsockopt
  setsockopt|D[socket-[38]-[0]-[0]]|...|C[6]|...  → alg_setsockopt
  setsockopt|D[socket-[38]-[0]-[0]]|...|C[1]|...|C[0] → alg_setkey
  (TC/netlink 경로: 없음)
```

### 3.3 R1 실패의 결정론적 특성

이 실패는 **결정적(deterministic)**이다:
- 동일한 bitcode와 분석 도구로 몇 번을 돌려도 결과 동일
- 정적 분석의 구조적 한계이므로 런타임 변동 없음
- R2/R3는 R1이 성공해야 평가 가능하므로 이 케이스에서는 측정 불가

---

## 4. LLM 에이전트 보완 방향 (R1 Agent)

### 4.1 필요한 보완 정보

LLM Related-syscall Agent가 제공해야 할 정보:

1. **진입 syscall**: `sendmsg` (netlink 소켓, AF_NETLINK/NETLINK_ROUTE)
2. **필요 리소스**:
   - `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` 생성
   - `RTM_NEWTFILTER` netlink 메시지 구성
3. **콜 체인**: `sendmsg` → `rtnetlink_rcv_msg` → `tc_new_tfilter` → `tcindex_change` → `tcindex_alloc_perfect_hash`
4. **syzkaller 매핑**: `sendmsg$nl_route` variant 사용

### 4.2 복잡도 프로파일 요약

complexity_profiler 분석 결과 (4축):

- **도달 거리**: 높음 (sendmsg → 5단계 간접 호출)
- **인자 복잡도**: 중간 (netlink 메시지 구조체 필요)
- **리소스 의존성**: 높음 (netlink 소켓 + TC qdisc 사전 설정 필요)
- **syzlang 복잡도**: 중간 (sendmsg 변종 1,006개 중 적절한 것 선택 필요)

---

## 5. 환경 및 이슈 기록

| 항목 | 내용 |
|------|------|
| VM RAM | 7GB → 15GB 증설 (OOM 해결) |
| interface_generator segfault | chunk_034에서 발생, 10개 서브청크 분할로 해결 (추가 시그니처 0) |
| TPA 청크 분할 시도 | 콜 그래프 단절로 실패, 전체 실행 필요 |
| 총 분석 시간 | ~반나절 (OOM/segfault 트러블슈팅 포함) |

---

## 6. 결론

Case 0은 **SyzDirect R1 실패의 전형적 케이스**이다. TC 서브시스템의 netlink 기반 함수 등록 패턴이 interface_generator의 분석 범위를 벗어나, 타겟 함수까지의 syscall 매핑이 완전히 누락되었다. 이는 간접 호출과 비표준 등록 메커니즘이 결합된 경우로, LLM 에이전트의 커널 코드 이해 능력으로 보완 가능한 대표적 시나리오이다.

---

*Report generated: 2026-02-07*
*Pipeline: SyzDirect (CCS'23) + Complexity Profiler*
*Target dataset: Patch ID 1 (3f2db250099f)*
