# SyzAgent: SyzDirect 기반 커널 퍼징 자동화 연구

> **SyzDirect (CCS 2023)** 의 실패 지점을 분석하고, 에이전트 루프로 보완한 Directed Greybox Fuzzing 연구 프로젝트

---

## 이 프로젝트가 무엇인가?

### 배경: SyzDirect란?

[SyzDirect](https://github.com/whysocscs/SyzDirect) 는 2023년 ACM CCS에 발표된 **리눅스 커널 대상 방향 그레이박스 퍼저**다.
기존 syzkaller가 커널 전체를 무작위로 탐색하는 것과 달리, SyzDirect는 **특정 취약점 위치(타겟 지점)에 도달하는 데 집중**한다.

핵심 아이디어:
- 타겟 코드까지의 **Basic Block 거리**를 미리 계산
- 거리가 가까운 시드에 **더 많은 퍼징 에너지**를 할당
- 타겟에 도달할 수 있는 **syscall을 정적 분석으로 자동 식별**

### 이 프로젝트가 하는 것

SyzDirect는 강력하지만 실패하는 케이스가 존재한다. 본 프로젝트는 다음을 목표로 한다:

1. **R1/R2/R3 실패 패턴 분류 및 측정**
   - R1: 관련 syscall을 잘못 찾거나 찾지 못하는 실패
   - R2: 복잡한 인자/오브젝트 생성 실패 (파일시스템 이미지 등)
   - R3: syscall 컨텍스트(의존 체인) 분석 부족 실패

2. **에이전트 루프로 실패 지점 자동 보완**
   퍼징 실패를 분류하고, 템플릿을 자동으로 강화하여 다음 라운드 퍼징에 피드백

3. **SyzDirect 데이터셋 100개 케이스의 재현 가능한 실험 환경 구축**
   한 명령으로 케이스 준비 → 커널 빌드 → 퍼징 실행까지 자동화

---

## 실험 결과 요약

5개 커널 취약점 케이스에 대해 SyzDirect R1 단계(syscall 식별)를 분석한 결과:

| Case | 타겟 | 서브시스템 | R1 결과 | Precision |
|------|------|-----------|---------|-----------|
| 0 | `net/sched/cls_tcindex.c:309` | TC (rtnl) | FAIL | N/A |
| 1 | `sound/core/seq/seq_timer.c:300` | ALSA | SUCCESS | 50% |
| 2 | `drivers/block/nbd.c:2006` | NBD (genl) | SUCCESS | 100% |
| 3 | `net/sched/sch_taprio.c:919` | TC (rtnl) | NOISY | 0% |
| 4 | `drivers/block/nbd.c:1809` | NBD callee | FAIL | 0% |

**R1 성공률: 40% (2/5)**

주요 실패 원인:
- `rtnl_register()` 등록 패턴 미인식 → TC 서브시스템 전체 실패
- 핸들러의 callee(1단계 더 깊은 함수)로 역추적 불가

---

## 전체 Flow

```
[사용자] bash scripts/run_case.sh 74
         │
         ▼
[1] run_dataset_case.py  ──── 케이스 준비
    ├── syzbot API에서 버그 메타데이터 fetch
    │   (commit hash, 파일 경로, 재현코드 .syz, 버그 리포트)
    ├── target.json 생성 (타겟 위치 + entry_syscalls 힌트)
    ├── 커널 소스 clone + bzImage 빌드 (LLVM/kcov 패치 적용)
    └── QEMU Debian 이미지 생성

         │
         ▼
[2] 정적 분석 파이프라인  ──── source/ 디렉토리
    │
    ├── analyzer/syscall_analyzer.py
    │   ├── target.json의 syscall 힌트 사용 (또는 콜그래프 역추적)
    │   ├── 리소스 타입 추론 (sock / fd / mmap)
    │   ├── 의존 syscall 체인 구성 (socket → bind → sendmsg 등)
    │   └── → templates.json
    │
    ├── distance/distance_calculator.py
    │   ├── 커널 소스 파싱 → 콜그래프 + CFG 빌드
    │   ├── BFS로 타겟 Basic Block까지 거리 계산 (AFLGo 방식)
    │   └── → distances.json (런타임 주소 → 거리 맵)
    │
    └── template/template_generator.py
        ├── templates.json + distances.json 합성
        ├── syzlang 시드 프로그램 생성
        │   예: r0 = socket$nl_xfrm(0x10, 0x3, 0x6)
        │       sendmsg$nl_xfrm(r0, ...)
        └── → .syz 시드 파일들

         │
         ▼
[3] QEMU 퍼징  ──── SyzDirect 퍼저 (syzkaller 기반)
    ├── 생성된 .syz 템플릿을 초기 시드로 로드
    ├── KCOV로 Basic Block 커버리지 수집
    ├── 거리 기반 에너지 할당
    │   (타겟에 가까운 시드 = 더 많은 mutation 기회)
    └── crash 발생 시 리포트 저장

         │
         ▼
[4] Agent Loop  ──── source/agent/ 디렉토리 (agent-loop 모드)
    │
    ├── agent/failure_triage.py
    │   ├── 퍼징 로그 분석
    │   ├── R1 / R2 / R3 중 어떤 실패인지 분류
    │   │   R1: 거리가 줄어들지 않음 → syscall 식별 실패
    │   │   R2: EINVAL/EFAULT 다수 → 인자 생성 실패
    │   │   R3: 거리 정체 + 컨텍스트 오류 → 의존 체인 부족
    │   └── → triage_result.json
    │
    ├── agent/related_syscall_agent.py  (R3 대응)
    │   ├── 누락된 predecessor syscall 추가
    │   │   예: recv 앞에 socket → bind → listen 삽입
    │   ├── 소켓 설정 syscall 보강 (setsockopt 등)
    │   ├── EINVAL율 높으면 인자 범위 제한 constraint 추가
    │   └── → enhanced_templates.json
    │
    ├── agent/object_synthesis_agent.py  (R2 대응)
    │   ├── 파일시스템 이미지 생성 파이프라인 구성
    │   │   (ext4/btrfs/f2fs 이미지 → mount → fd → ioctl)
    │   ├── 복잡한 오브젝트 생성 단계 자동화
    │   └── → object_pipeline.json
    │
    └── [강화된 템플릿으로 [3] 재실행]
```

---

## 빠른 시작

### 환경 요구사항 (Ubuntu / WSL2)

```bash
make bootstrap   # 의존성 자동 설치
make doctor      # 환경 체크
```

필요 패키지: `git`, `curl`, `golang-go`, `python3`, `build-essential`, `gcc`, `make`, `bc`, `flex`, `bison`, `libssl-dev`, `libelf-dev`, `libncurses-dev`, `dwarves`, `zstd`, `qemu-system-x86`, `qemu-utils`, `debootstrap`, `openssh-client`

### 케이스 실행

```bash
# 케이스 74번 전체 실행 (커널 빌드 + 퍼징)
bash scripts/run_case.sh 74

# 준비 단계만 확인 (커널 빌드 없이 메타데이터 fetch + 분석만)
bash scripts/run_case.sh 74 --prepare-only

# 퍼징 시간/CPU 수 조정
BUDGET_HOURS=2 VM_CPU=2 bash scripts/run_case.sh 74

# sudo 비밀번호 사전 지정 (이미지 생성 시)
SUDO_PASSWORD='your-password' bash scripts/run_case.sh 74
```

> **참고**: 처음 실행 시 커널 빌드 + QEMU 이미지 생성으로 수 시간 소요됩니다.
> `/dev/kvm` 이 없는 환경은 TCG 폴백으로 동작하며 속도가 느립니다.

### 직접 Python 분석 실행

```bash
# 1. syscall 분석 (템플릿 생성)
python3 source/analyzer/syscall_analyzer.py \
  --kernel /path/to/linux \
  --target .runtime/known-bugs/case_74/target.json \
  --output templates.json

# 2. 거리 계산
python3 source/distance/distance_calculator.py \
  --kernel /path/to/linux \
  --target-file net/xfrm/xfrmcompat.c \
  --target-line 571 \
  --output distances.json

# 3. 퍼징 템플릿 생성
python3 source/template/template_generator.py \
  --analysis templates.json \
  --distances distances.json \
  --output fuzz_templates/
```

---

## 디렉토리 구조

```
syzdirect-research/
├── scripts/
│   ├── run_case.sh            # 메인 진입점 (케이스 번호 하나로 전체 실행)
│   ├── run_dataset_case.py    # 케이스 준비 + 실험 실행 래퍼
│   ├── run_experiment.sh      # QEMU 퍼징 실행 스크립트
│   ├── bootstrap_host.sh      # 호스트 의존성 설치
│   └── doctor.py              # 환경 사전 검사
│
├── source/
│   ├── analyzer/
│   │   └── syscall_analyzer.py       # R1: 타겟 도달 syscall 정적 분석
│   ├── distance/
│   │   └── distance_calculator.py   # BB 거리 계산 (AFLGo 방식)
│   ├── template/
│   │   └── template_generator.py    # syzlang 시드 프로그램 생성
│   ├── agent/
│   │   ├── failure_triage.py         # R1/R2/R3 실패 분류
│   │   ├── related_syscall_agent.py  # R3 보완: 의존 syscall 체인 강화
│   │   └── object_synthesis_agent.py # R2 보완: 복잡 오브젝트 생성 파이프라인
│   └── benchmark/
│       ├── complexity_benchmark.py   # 타겟 복잡도 예측 도구
│       └── paper_benchmark.py        # SyzDirect 논문 수치 재현
│
├── configs/                   # 케이스별 설정 파일
├── targets/                   # 타겟 JSON 명세
├── reports/                   # 분석 보고서
├── deps/                      # SyzDirect 체크아웃 (자동 생성, git 제외)
└── .runtime/                  # 실험 런타임 아티팩트 (git 제외)
```

---

## 주요 기술 스택

| 항목 | 내용 |
|------|------|
| 기반 퍼저 | [SyzDirect (CCS 2023)](https://github.com/whysocscs/SyzDirect) / syzkaller |
| 퍼징 방식 | Directed Greybox Fuzzing (거리 기반 에너지 할당) |
| 커버리지 | KCOV (Basic Block 단위) |
| 거리 계산 | BFS on CFG (AFLGo 방식, 커널 적용) |
| 정적 분석 | LLVM bitcode + 콜그래프 분석 |
| 에이전트 | Rule-based (R1/R2/R3 분류 → 템플릿 강화 루프) |
| VM 환경 | QEMU + KVM, Debian Bullseye 게스트 |
| 언어 | Python 3, Bash, Go |
| 지원 OS | Ubuntu 22.04 / WSL2 |

---

## Git 업로드 전 주의사항

런타임 아티팩트는 `.gitignore`에 이미 포함됩니다. 혹시 과거에 추적된 파일이 있다면 제거:

```bash
git rm -r --cached .runtime deps logs runs results B029_crashes B040_crashes B054_crashes
```

---

## 참고 자료

- [SyzDirect 논문 (CCS 2023)](https://github.com/whysocscs/SyzDirect)
- [syzkaller](https://github.com/google/syzkaller)
- [syzbot](https://syzkaller.appspot.com/)
- [AFLGo](https://github.com/aflgo/aflgo)
