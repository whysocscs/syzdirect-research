# SyzAgent: SyzDirect + LLM Agent Loop

SyzDirect(CCS 2023) 기반 directed kernel fuzzer에 **LLM 에이전트 루프**를 결합한 프로젝트.
퍼징 중 거리가 감소하지 않으면 실패를 분류(R1/R2/R3)하고, LLM으로 템플릿을 자동 강화하여 재퍼징한다.

---

## 구성 요소

### 1. SyzDirect 엔진 (`source/syzdirect/`)
- **Runner/run_hunt.py** — 통합 실행기 (3가지 모드)
- **Runner/Fuzz.py** — QEMU 멀티런 퍼징
- **Runner/Compilation.py** — 커널 빌드 호환성 (clang 버전 완화, kcov 패치)
- **syzdirect_function_model/** — LLVM 기반 syscall-to-target 정적 분석
- **syzdirect_fuzzer/** — 거리 기반 에너지 할당 syzkaller fork

### 2. Agent Loop (`source/agent/`)
- **fuzzing_health_monitor.py** — 퍼징 건강도 모니터링 (exec/s, cover/s, distance_delta)
- **failure_triage.py** — R1(syscall 오식별) / R2(인자 생성 실패) / R3(의존 체인 부족) 분류
- **related_syscall_agent.py** — R3 대응: 누락 syscall 체인 보강
- **object_synthesis_agent.py** — R2 대응: 복잡 오브젝트 생성 파이프라인

### 3. 분석 도구 (`source/analyzer/`, `source/distance/`, `source/template/`)
- syscall 정적 분석, BB 거리 계산, syzlang 템플릿 생성

---

## 실행 방법

### run_hunt.py — 3가지 모드

```bash
# 모드 1: dataset — xlsx 기반 배치 퍼징 (Main.py 대체)
python3 source/syzdirect/Runner/run_hunt.py dataset \
  --xlsx source/syzdirect/Runner/dataset_hunt.xlsx \
  --actions 1 2 3 4 5 6

# 모드 2: new — CVE 번호 하나로 원클릭 실행
python3 source/syzdirect/Runner/run_hunt.py new \
  --cve CVE-2023-XXXXX \
  --kernel-commit <commit-hash>

# 모드 3: fuzz — 이미 빌드된 타겟으로 퍼징만 실행
python3 source/syzdirect/Runner/run_hunt.py fuzz \
  --workdir /path/to/workdir
```

### Agent Loop 실행

```bash
# syzagent CLI — 전체 파이프라인
python3 -m syzagent.cli --full --case 74

# health monitor — 퍼징 중 거리 정체 감지 시 LLM hook 호출
python3 source/agent/fuzzing_health_monitor.py \
  --workdir /path/to/workdir \
  --llm-hook-cmd "python3 source/agent/failure_triage.py"
```

### 케이스 실행 (스크립트)

```bash
bash scripts/run_case.sh 74                    # 전체 실행
bash scripts/run_case.sh 74 --prepare-only     # 메타데이터만
BUDGET_HOURS=2 bash scripts/run_case.sh 74     # 시간 조정
```

---

## 타겟 데이터셋 (`dataset_hunt.xlsx`)

| idx | 타겟 | 커널 커밋 | syscall |
|-----|------|----------|---------|
| 0 | `net/sched/cls_tcindex.c:309` | ac0b8b327a56 | setsockopt |
| 1 | `sound/core/seq/seq_timer.c:300` | ac0b8b327a56 | ioctl |
| 2 | `drivers/block/nbd.c:2006` | ac0b8b327a56 | sendmsg |
| 3 | `net/sched/sch_taprio.c:919` | ac0b8b327a56 | setsockopt |
| 4 | `drivers/block/nbd.c:1809` | ac0b8b327a56 | ioctl |
| 5 | `net/xfrm/xfrm_compat.c:571` | ac0b8b327a56 | sendmsg |

---

## 실행 흐름

```
run_hunt.py (dataset/new/fuzz)
    │
    ├── 커널 빌드 (clang 버전 완화 + kcov 패치 자동 적용)
    ├── LLVM bitcode → syscall-to-target 정적 분석
    ├── BB 거리 계산 → 에너지 할당 맵
    ├── syzlang 템플릿 생성
    │
    ▼
QEMU 퍼징 (Fuzz.py → syz-manager)
    │
    ▼
Health Monitor (거리 정체 감지)
    │
    ├── 정체 없음 → 계속 퍼징
    └── 정체 감지 → failure_triage.py
         ├── R1 → syscall 재식별
         ├── R2 → object_synthesis_agent (복잡 오브젝트 생성)
         └── R3 → related_syscall_agent (의존 체인 보강)
              │
              └── 강화된 템플릿으로 재퍼징
```

---

## 주요 버그 수정

- **Fuzz.py 포트 충돌**: `runCount` 초기화 위치를 루프 밖으로 이동
- **kcov 패치 탭 이스케이프**: raw string(`r"""`) 제거로 실제 탭 삽입
- **SyscallAnalyze import**: `__init__.py` 추가 및 import 경로 수정
- **LLVM 15 호환성**: opaque pointer 대응, clang 버전 체크 완화

---

## 환경

- Ubuntu 22.04 / WSL2
- Python 3, Go, LLVM/Clang
- QEMU + KVM (없으면 TCG 폴백)

```bash
make bootstrap   # 의존성 설치
make doctor      # 환경 체크
```
