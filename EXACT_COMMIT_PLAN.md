# Exact Commit 분석 계획서 — SyzDirect 논문 재현

## 목표
논문 Table 4 (R1=19, R2=19, R3=20) 재현
방법: 각 버그의 **정확한 syzbot crash commit**에서 bitcode 빌드 → target_analyzer → PoC 기반 분류

## 현재 상태 (2026-03-02)
- **Phase 2 완료** (per-version stable tag): R1=9, R2=22, R3=27
- 논문과 차이 원인:
  1. 정확한 commit 대신 nearest stable tag 사용
  2. 분류 로직이 subsystem string 매칭 기반 (너무 부정확)
- **이번 Phase 3**: 정확한 commit + PoC 기반 분류로 논문 결과 재현

## 데이터 파일
| 파일 | 내용 |
|------|------|
| `/home/ai/bug_kernel_commits.json` | 58개 버그: commit hash, date, filepath, stable_ver |
| `/home/ai/phase1_pocs.json` | 58개 버그 PoC 텍스트 (실제 syscall sequence) |
| `/home/ai/static_analysis_exact_commit/` | 이번 분석 결과 저장 위치 (새로 생성) |
| `/home/ai/exact_commit_classifications.json` | 최종 분류 결과 |
| `/work/linux/` | Linux 소스 (v6.3 체크아웃, v5.10~v6.3 태그 있음) |
| `/work/linux_bc/` | 빌드 bitcode 디렉토리 |

## 실행 방법 (한 명령으로)

```bash
bash /home/ai/syzdirect_setup/08_exact_commit_analyze.sh 2>&1 | tee /home/ai/exact_commit_run.log
```

이후 분류만 재실행하려면:
```bash
python3 /home/ai/syzdirect_setup/09_classify_poc_based.py
```

## 실행 흐름

```
08_exact_commit_analyze.sh
├── Python으로 bug_kernel_commits.json 파싱
├── 58개 버그를 commit hash로 그룹핑 (→ commit_groups.txt)
└── 각 unique commit에 대해:
    ├── [1] 이미 완료된 버그는 스킵
    ├── [2] GitHub torvalds mirror에서 fetch
    │       실패 시 → shallow-since 방식
    │       실패 시 → nearest stable tag fallback
    ├── [3] git checkout + objtool patch
    ├── [4] mrproper + bigconfig + bitcode 빌드 (~8분)
    ├── [5] fix_bad_llbc_for_target.py로 크래시 llbc 제거
    │       (LLVM 13 버그: v5.16+ net/ipv4/devinet 등)
    └── [6] 이 commit의 각 버그에 target_analyzer 실행
            → /home/ai/static_analysis_exact_commit/B{NNN}/
            → CompactOutput.json + analysis.log

09_classify_poc_based.py
├── phase1_pocs.json에서 PoC syscall 추출
├── CompactOutput.json의 found syscall과 비교
├── R1: CompactOutput 비어있거나 PoC syscall과 불일치
├── R2: 올바른 syscall 찾았지만 constraints 없음
└── R3: 올바른 syscall + constraints 있음
    → exact_commit_classifications.json
```

## 예상 시간
- 58개 버그, 약 50~58개 unique commit
- 커밋당 약 8~12분 (빌드) + 분석
- **총 예상: 8~12시간**

## 알려진 기술적 문제 & 해결법

### 문제 1: LLVM 13 segfault on v5.16+ net/ 파일
- 원인: `net/ipv4/devinet.c` 등에 12000+ 자 ctl_table 초기화로 LLVM 13 string 버그 발생
- 해결: `fix_bad_llbc_for_target.py`가 자동으로 detect + blank → 재실행
- v5.16에서 13개 파일 영향: net/ipv4/{devinet,ipmr,nexthop}, net/core/{fib_rules,net_namespace},
  net/mpls/af_mpls, net/ipv6/{addrlabel,route,ip6mr,addrconf}, net/can/gw, net/bluetooth/{hci_sock,sco}

### 문제 2: git checkout 실패 (subcmd-util.h)
- 원인: objtool 패치 후 git checkout 시 "local changes would be overwritten"
- 해결: checkout 전 `git checkout -- .` 으로 초기화 (스크립트에 포함됨)

### 문제 3: CompactOutput.json 잘못된 위치에 저장
- 원인: target_analyzer가 CWD에 파일 저장
- 해결: 분석 전 반드시 `cd "$OUT_DIR"` (스크립트에 포함됨)

### 문제 4: GitHub에서 정확한 commit hash fetch 불가
- 증상: `git fetch --depth=1 github <hash>` 실패
- 해결: `--shallow-since` 방식 → 최후 fallback으로 nearest stable tag 사용
- fallback된 경우 분석 결과가 약간 부정확할 수 있음 (로그에 WARNING 출력)

## 분류 로직 (PoC 기반)

```
PoC syscall = phase1_pocs.json에서 추출한 실제 syscall
Found syscall = CompactOutput.json의 target syscall (분석 결과)

CompactOutput 없거나 비어있음  → R1
PoC syscall ∩ found syscall == ∅  → R1 (엉뚱한 syscall만 찾음)
PoC syscall ∩ found syscall ≠ ∅:
  매칭 syscall에 constraints 없음  → R2
  매칭 syscall에 constraints 있음  → R3

Syscall 매칭 기준: base name ($ 이전 부분) 소문자 비교
예: "openat$qrtrtun" ↔ "openat" → 매칭 (base 동일)
```

## 재개 방법 (중단 시)
스크립트가 자동으로 이미 완료된 버그는 스킵합니다.
- `CompactOutput.json`이 있으면 그 버그는 완료로 간주
- 중단된 경우 그냥 다시 실행하면 됩니다
