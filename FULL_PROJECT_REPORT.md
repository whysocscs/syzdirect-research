# SyzDirect + LLM Agent 보완 연구: 종합 보고서

**작성일**: 2026-02-08
**프로젝트**: SyzDirect (CCS 2023) R1/R2/R3 실패 지점 분석 및 LLM 에이전트 보완 연구
**커널 버전**: Linux 6.1.0
**Repository**: seclab-fudan/SyzDirect (`/work/SyzDirect/`)

---

## 1. 프로젝트 개요

### 1.1 목표
SyzDirect는 directed greybox fuzzing 도구로, 커널 소스의 특정 타겟 지점에 도달하는 syscall을 자동 식별하고 거리 기반 우선순위로 퍼징한다. 본 연구는:

1. **R1 (Related Syscall Discovery)**: 타겟에 도달 가능한 syscall을 정확히 찾는가?
2. **R2 (Argument Constraint Solving)**: 올바른 인자 조합을 생성하는가?
3. **R3 (Resource Dependency Setup)**: 필요한 리소스/상태를 올바르게 설정하는가?

세 단계에서 SyzDirect의 실패 패턴을 측정하고, LLM 에이전트로 보완할 수 있는 지점을 식별한다.

### 1.2 SyzDirect 파이프라인
```
Step 1: PrepareSourceCode    → kcov 패치 적용
Step 2: CompileKernelToBitcode → emit-llvm.sh로 .bc 생성
Step 3: AnalyzeKernelInterface → interface_generator → kernel_signature_full + kernelCode2syscall.json
Step 4: AnalyzeTargetPoints    → target_analyzer → CompactOutput.json + distance 파일
Step 5: InstrumentDistance     → 거리 기반 커널 빌드
Step 6: Fuzz                   → syzkaller 기반 퍼징
```

---

## 2. 실험 케이스 요약

5개 커널 취약점 타겟에 대해 Step 1~4 (R1 분석)까지 완료했다.

### 2.1 한눈에 보기

| Case | 타겟 파일:라인 | 서브시스템 | 인터페이스 패턴 | 콜 깊이 | R1 결과 | 유효/전체 매핑 | Precision |
|------|---------------|-----------|----------------|---------|---------|---------------|-----------|
| 0 | `net/sched/cls_tcindex.c:309` | TC (Traffic Control) | rtnl_register | 간접 | **FAIL** | 0/0 | N/A |
| 1 | `sound/core/seq/seq_timer.c:300` | ALSA Sequencer | ioctl (표준) | 직접 | **SUCCESS** | 3/6 | 50% |
| 2 | `drivers/block/nbd.c:2006` | NBD (Network Block) | genetlink | 직접 핸들러 | **SUCCESS** | 1/1 | 100% |
| 3 | `net/sched/sch_taprio.c:919` | TC (taprio qdisc) | rtnl_register | 간접 | **NOISY** | 0/16 | 0% |
| 4 | `drivers/block/nbd.c:1809` | NBD | genetlink (callee) | 1단계 깊음 | **FAIL** | 0/3 | 0% |

**R1 성공률: 40% (2/5)**

### 2.2 빌드 통계

| Case | Bitcode 파일 | Distance 파일 | Interface Signature | Subset 전략 |
|------|-------------|--------------|-------------------|------------|
| 0 | 2,358 | 2,104 (추정) | 3,802 | 없음 |
| 1 | 6,856 | 3,676 | 9,682 | drivers/ 제외 (4,128) |
| 2 | 6,767 | 3,692 | 16,240 | drivers/block만 포함 (4,058) |
| 3 | 6,737 | 3,672 | 11,328 | drivers/ 제외 |
| 4 | 6,767 | 2,703 | 9,054 | drivers/block만 포함 |

---

## 3. 케이스별 상세 분석

### Case 0: cls_tcindex.c:309 — R1 FAIL

**타겟 함수**: `tcindex_alloc_perfect_hash()`
**실제 콜체인**: `sendmsg(netlink)` → `rtnetlink_rcv_msg` → `tc_new_tfilter` → `tcindex_change` → 타겟

**실패 원인**: TC 서브시스템은 `rtnl_register(RTM_NEWTFILTER, tc_new_tfilter, ...)` 패턴으로 핸들러를 등록한다. SyzDirect의 interface_generator는 이 rtnetlink 등록 패턴을 인식하지 못해 syscall 매핑이 0개 생성됨.

**핵심**: 구조적 한계 — 지원되지 않는 등록 패턴으로 인한 결정론적 실패.

---

### Case 1: seq_timer.c:300 — R1 SUCCESS

**타겟 함수**: `snd_seq_timer_open()`
**인터페이스**: 표준 ioctl (`file_operations` → `unlocked_ioctl`)

**매핑 결과 (6개)**:
- ✅ `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER` — 직접 경로
- ✅ `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT` — `snd_seq_queue_use` 경유
- ✅ `ioctl$SNDRV_SEQ_IOCTL_SET_QUEUE_INFO` — 조건부 경로
- ❌ `ioctl$SNDRV_SEQ_IOCTL_CREATE_QUEUE` — 전제조건 (직접 아님)
- ❌ `delete_module` — 무관한 KERNEL_CLIENT 경로
- ❌ `kexec_load` — 무관한 KERNEL_CLIENT 경로

**Precision 50%, Recall 100%**: 모든 유효 경로를 찾았지만 false positive 3개 포함.

---

### Case 2: nbd.c:2006 — R1 SUCCESS

**타겟 함수**: `nbd_genl_connect()` (genl_ops 직접 핸들러)
**콜체인**: `sendmsg` → `netlink_sendmsg` → `genl_rcv_msg` → `nbd_genl_connect`

**매핑 결과 (1개)**:
- ✅ `sendmsg` (NBD_ATTR_SIZE_BYTES=2, NBD_ATTR_SOCKETS=7)

**Precision 100%, Recall 100%**: Generic Netlink (`genl_small_ops`) 패턴이 지원됨.

---

### Case 3: sch_taprio.c:919 — R1 NOISY (실질 FAIL)

**타겟 함수**: `parse_taprio_schedule()` (← `taprio_change`)
**실제 콜체인**: `sendmsg` → `rtnetlink` → `tc_modify_qdisc` → `taprio_change` → 타겟

**매핑 결과 (16개, 모두 false positive)**:
- `bind$xdp`, `getsockopt$inet_buf`, `setsockopt` 변형 등
- 대부분 문자열 "taprio" 매칭에 의한 노이즈

**Case 0과 동일 패턴**: rtnl_register 미인식. 차이점은 문자열 매칭으로 false positive가 대량 발생한 것으로, 깨끗한 실패(case 0)보다 더 나쁨 — 퍼징 자원을 낭비하게 됨.

---

### Case 4: nbd.c:1809 — R1 FAIL

**타겟 함수**: `nbd_dev_add()` (← `nbd_genl_connect`의 callee)
**콜체인**: `sendmsg` → ... → `nbd_genl_connect` → `nbd_dev_add`

**매핑 결과 (3개, 모두 false positive)**:
- `ioctl$SNAPSHOT_POWER_OFF`, `ioctl$SNAPSHOT_S2RAM`, `write$cgroup_int`

**핵심 비교**: Case 2와 **동일 파일**(nbd.c)이지만:
- Case 2: `nbd_genl_connect` = genl_ops 직접 핸들러 → **성공**
- Case 4: `nbd_dev_add` = 핸들러의 callee (1단계 깊음) → **실패**

TPA가 callee에서 등록된 핸들러로 역추적하지 못함.

---

## 4. 식별된 실패 패턴

### 패턴 1: 미지원 등록 패턴 (Case 0, 3)
- **원인**: `rtnl_register()` 패턴을 interface_generator가 인식 못함
- **영향**: 매핑 0개 (깨끗한 실패) 또는 노이즈 (false positive 대량)
- **해당 서브시스템**: net/sched (TC), 기타 rtnetlink 기반 서브시스템
- **결정론적**: 동일 패턴이면 항상 실패

### 패턴 2: 콜체인 깊이 한계 (Case 4)
- **원인**: 타겟 함수가 등록된 핸들러의 callee일 때 역추적 불가
- **영향**: 무관한 syscall로 잘못 매핑
- **비교**: 같은 파일이라도 핸들러 직접(Case 2 성공) vs callee(Case 4 실패)

### 성공 조건 (Case 1, 2)
- 타겟이 등록된 핸들러 함수이거나 매우 가까운 호출자
- 지원되는 등록 패턴: `file_operations`, `proto_ops`, `ioctl`, `genetlink`
- 표준적인 콜체인 (과도한 간접 참조 없음)

---

## 5. 개발한 도구

### 5.1 복잡도 프로파일러 (`/work/complexity_profiler.py`)
타겟의 4축 복잡도를 분석하여 SyzDirect 실패 가능성을 예측:

| 축 | 측정 내용 |
|----|----------|
| **Reaching Distance** | syscall 진입점에서 타겟까지의 콜 깊이, BB 거리 |
| **Argument Complexity** | 시그니처 인자 타입/개수, 리소스 의존성 |
| **Resource Dependency** | D[resource] 체인, 사전 설정 요구사항 |
| **Syzlang Complexity** | 변형 개수, 파라미터 수, 중첩 깊이 |

**출력**: 0-100 복합 점수 (높을수록 실패 가능성 높음)

### 5.2 빌드/분석 스크립트
- `/work/split_chunk034.sh` — interface_generator 청크 분할 실행
- `/work/split_tpa.sh` — TPA 청크 분할 (비권장, 콜그래프 분리 문제)

---

## 6. 핵심 기술 교훈

### 빌드 환경
| 교훈 | 설명 |
|------|------|
| CC 전달 | `make CC=...` 필수 (`CC=... make`는 무시됨) |
| kcov 패치 | kcov.h/kcov.c가 있어도 `mark_block` 함수 유무 별도 확인 필요 |
| RAM 요구량 | 7GB → 15GB로 증설 (OOM 회피) |
| interface_generator cwd | output을 현재 디렉토리에 생성 → `cd $WDIR` 필수 |

### SyzDirect 내부
| 교훈 | 설명 |
|------|------|
| TPA 바이너리 | `target_analyzer` (interface_generator 아님) |
| TPA 인자 | `--kernel-interface-file` (단일 대시도 동작) |
| TPA 탐색 방식 | bitcode에서 `kcov_mark_block()` 탐색 (--target-point 아님) |
| Subset 전략 | drivers/ 제외하거나 관련 디렉토리만 포함하여 메모리 절약 |
| kernel_signature_full | dist_flag=0: 3필드, dist_flag=1: 5필드 |

---

## 7. 디렉토리 구조

```
/work/
├── SyzDirect/                          # 원본 레포
│   └── syzdirect_kernel_analysis/
│       └── build/lib/
│           ├── target_analyzer         # TPA 바이너리
│           └── interface_generator     # 인터페이스 분석 바이너리
├── syzdirect_workdir/
│   ├── srcs/case_[0-4]/               # kcov 패치된 커널 소스
│   ├── bcs/case_[0-4]/                # Bitcode 빌드 결과
│   ├── interfaces/case_[0-4]/         # kernel_signature_full, kernelCode2syscall.json
│   └── tpa/case_[0-4]/               # CompactOutput.json, distance_xidx0/
├── reports/
│   ├── case_[0-4]_analysis_report.md  # 개별 케이스 보고서
│   └── FULL_PROJECT_REPORT.md         # 본 종합 보고서
├── complexity_profiler.py             # 복잡도 분석 도구
├── split_chunk034.sh                  # 청크 분할 스크립트
└── split_tpa.sh                       # TPA 분할 스크립트
```

---

## 8. 향후 계획

### 8.1 단기 과제: R2/R3 분석 (Step 5-6)
- R1 성공 케이스(Case 1, 2)에 대해 **InstrumentDistance + 실제 퍼징** 실행
- SyzDirect 가이던스 유무에 따른 커버리지/버그 발견율 비교
- R2(인자 제약 해결) 및 R3(리소스 의존성 설정) 실패 지점 측정

### 8.2 추가 케이스 분석
- 현재 5개로는 통계적 유의성 부족
- 다양한 복잡도 프로파일의 타겟 추가 필요:
  - 더 많은 지원 패턴 (file_operations, proto_ops 등)
  - 더 깊은 콜체인
  - 복잡한 리소스 의존성

### 8.3 LLM 에이전트 개발

#### R1 Agent (Related Syscall Discovery 보완)
- **입력**: 타겟 함수, 소스코드 컨텍스트
- **출력**: syscall 진입점, 리소스 설정 요구사항, 콜체인
- **대상 케이스**: 0, 3, 4 (R1 실패)
- **핵심 기능**:
  - rtnl_register 등 미지원 패턴 인식
  - callee에서 핸들러까지 역추적
  - false positive 필터링

#### R2 Agent (Argument Constraint Solving)
- 복잡한 인자 구조에 대한 제약 조건 해결
- 퍼징 데이터(Step 6) 기반 분석 필요

#### R3 Agent (Resource Dependency Setup)
- 리소스 의존성 순서 및 상태 설정
- 퍼징 데이터(Step 6) 기반 분석 필요

### 8.4 검증 전략
1. LLM이 제안한 syscall을 수동 검증 (실패 케이스 대상)
2. Precision/Recall 메트릭: LLM 출력 vs ground truth 비교
3. End-to-end 테스트: LLM 보완 → SyzDirect 파이프라인 → 실제 버그 트리거

---

## 9. 결론

5개 케이스 분석 결과, SyzDirect의 R1 단계는 **표준 인터페이스 패턴(ioctl, genetlink)의 직접 핸들러**에서만 안정적으로 동작한다. 두 가지 주요 실패 패턴 — **(1) 미지원 등록 패턴**(rtnl_register 등)과 **(2) 콜체인 깊이 한계** — 이 확인되었으며, 이는 LLM 에이전트가 보완할 수 있는 명확한 지점이다.

R1 성공률 40%(2/5)는 커널 취약점의 상당수가 SyzDirect만으로는 도달 불가능함을 시사하며, LLM 기반 보완의 필요성과 기회를 동시에 보여준다.
