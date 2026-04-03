# Agent Loop LLM 활용 설계 문서

## 개요

SyzDirect Agent Loop은 distance-guided fuzzer(syzkaller 기반)가 target kernel function에 도달하지 못하고 stall될 때, LLM을 활용하여 fuzzing 전략을 개선하는 자동화 루프다.

**LLM 호출 방식**: `opencode` CLI → OpenAI API  
**모델**: `openai/gpt-4o-mini` (환경변수 `SYZDIRECT_LLM_MODEL`로 변경 가능)  
**호출 함수**: `_call_llm(prompt, timeout)` in `llm_enhance.py`

---

## Agent Loop 전체 흐름

```
시작
 │
 ├── [Proactive Seed] (선택적, --proactive-seed 플래그)
 │     LLM에게 target 함수에 맞는 syzkaller 프로그램 생성 요청
 │     → corpus.db로 패킹 → Round 1 fuzzer에 seed로 투입
 │
 └── Round 1..N 반복:
       ├── Fuzz (syz-manager 실행, uptime=30분~1시간)
       ├── Health Assessment (metrics.jsonl, manager.log 분석)
       ├── Triage (R1/R2/R3/R4 분류)
       │     R4 = distance stagnant → R4-WRONG / R4-STATE / R4-ARG 세분류
       └── Enhance (R4인 경우)
             ├── LLM syscall suggestion (callfile 업데이트)
             └── LLM seed program generation (다음 라운드 corpus 투입)
```

---

## LLM 호출 시점과 프롬프트

### 1. Proactive Seed Generation (라운드 시작 전)

**파일**: `llm_enhance.py::llm_generate_seed_program()`  
**시점**: Round 1 시작 전, `--proactive-seed` 플래그가 있을 때  
**목적**: target 함수에 도달하는 syzkaller 프로그램을 미리 생성해 initial corpus로 투입

**프롬프트 구조** (TC 서브시스템 예시):
```
You are a Linux kernel fuzzing expert. Generate syzkaller seed programs.

TARGET: {target_function} in {target_file}
CURRENT DIST: {current_dist} (stuck)

DISTANCE ROADMAP (closest stepping stones):
  dist=  1500  __dev_queue_xmit  (via: sendmsg$nl_route_sched)
  dist=  3000  qdisc_lookup
  ...

KERNEL SOURCE (key functions on path to target):
// net/sched/sch_api.c:123 (distance=1500)
static int qdisc_create(...) { ... }

PREREQUISITE RULES:
  - cls_*.c: MUST send RTM_NEWQDISC first, then RTM_NEWTFILTER
  - sch_*.c: RTM_NEWQDISC alone is sufficient
...

Generate 2 syzkaller programs that trigger the kernel path to {target_function}.

Return ONLY JSON:
{"programs": [{"name": "short_name", "text": "complete program text"}], "reasoning": "..."}
```

**프롬프트 구조** (비-TC 서브시스템, 예: bluetooth, mm, tcp):
```
You are a Linux kernel fuzzing expert. Generate syzkaller seed programs.

TARGET: sco_sock_create in net/bluetooth/sco.c
CURRENT DIST: 2010 (stuck)

DISTANCE ROADMAP:
  dist=   30  sco_sock_init  (via: socket$bt_sco)
  ...

CLOSEST PROGRAM IN CORPUS (achieved dist=30):
r0 = socket$bt_sco(0x1f, 0x5, 0x2)
...
(이 프로그램이 dist=30까지 갔는데, target까지 가려면 뭘 더 해야 해?)

CALL CHAIN ANALYSIS:
Reverse trace for bottleneck: sco_sock_init
  ← sco_sock_create (net/bluetooth/sco.c:412)  [reachable via: socket$bt_sco]

Target file: net/bluetooth/sco.c
Generate syzkaller programs using the correct syscall variants for this subsystem.
Think step by step:
1. What Linux subsystem does this belong to?
2. What syscalls reach sco_sock_create?
3. What setup steps are needed?
4. Write the program using syzkaller syntax.

Use syzkaller syntax:
  r0 = socket$bt_sco(0x1f, 0x5, 0x2)
  bind$bt_sco(r0, ...)

Return ONLY JSON: {"programs": [...], "reasoning": "..."}
```

---

### 2. R4 Syscall Enhancement (거리 stall 시)

**파일**: `llm_enhance.py::llm_enhance_callfile_for_distance()`  
**시점**: R4 triage 결과 + R4-WRONG 또는 R4-STATE 분류 시  
**목적**: callfile(fuzzer가 사용하는 syscall 목록)에 새로운 syscall 추가 또는 교체

**프롬프트 구조**:
```
You are a Linux kernel security researcher helping a distance-guided fuzzer.

TARGET FUNCTION: move_page_tables in mm/mremap.c (distance=0)
CURRENT STATE: Fuzzer's minimum distance is 2010. It has been stuck here.

CURRENT CALLFILE (syscalls being fuzzed):
[{"Target": "mremap", "Relate": ["mmap", "munmap"]}]

DISTANCE ROADMAP:
  dist=  1500  copy_page_range  (reachable via: mremap)
  dist=  2010  move_vma
  ...

KERNEL SOURCE (showing how stepping-stone functions are called):
// mm/mremap.c:256 (distance=1500)
static unsigned long move_vma(...) {
    ...move_page_tables(vma, old_addr, ...);
}

CLOSEST PROGRAM IN CORPUS (achieved dist=2010):
r0 = mmap(&(0x7f0000ff0000/0x4000)=nil, 0x4000, 0x3, 0x32, ...)
mremap(r0, 0x4000, 0x8000, 0x3, ...)
(이 프로그램이 dist=2010까지 갔는데, 뭐가 부족한지?)

CALL CHAIN ANALYSIS:
Reverse trace for bottleneck: copy_page_range
  ← move_vma (mm/mremap.c:256)
  ← mremap_to (mm/mremap.c:389)  [reachable via: mremap]

The fuzzer needs syscall sequences that execute kernel code paths to move_page_tables.

Analyze and think:
1. What Linux subsystem does mm/mremap.c belong to?
2. What syscalls trigger code paths here?
3. What setup is needed (device open, socket creation, mount, etc.)?
4. What sequence would reach move_page_tables?
5. Are current syscalls in the right subsystem?
6. If closest program given, what changes would help?

Return ONLY valid JSON:
{"syscalls": [{"Target": "name$variant", "Relate": ["setup1", ...]}], "reasoning": "..."}

Use exact syzkaller naming. 1-4 Target entries with 3-6 Relate syscalls each.
```

---

### 3. R4 Seed Generation (라운드 간)

**파일**: `llm_enhance.py::llm_generate_seed_program()`  
**시점**: R4 triage 후 (R4-ARG, R4-STATE, R4-WRONG 모두)  
**목적**: 다음 라운드에 투입할 seed corpus 생성

Proactive seed와 동일한 함수를 사용하되, 이번엔 corpus 분석 결과와 reverse trace가 추가로 포함됨.

---

### 4. CVE 초기 분석 (pipeline 시작 시)

**파일**: `llm_enhance.py::llm_analyze_cve()`  
**시점**: `run_hunt.py new` 모드에서 새 케이스 빌드 시  
**목적**: CVE 정보 → 초기 callfile(syscall 목록) 생성

**프롬프트**:
```
You are a Linux kernel security researcher.
CVE: CVE-2022-XXXX
Kernel commit: abc123
Target function: sco_sock_create
File: net/bluetooth/sco.c

Suggest the most relevant syzkaller syscalls to reach this function.
Return ONLY valid JSON:
{"syscalls": [{"Target": "name$variant", "Relate": ["setup1", "setup2"]}]}
Use exact syzkaller naming. 1-3 Target entries, 3-6 Relate each.
```

---

## R4 세분류 로직

R4 (distance stagnant) 판정 후 `classify_r4_cause()`로 세분류:

| 분류 | 조건 | 전략 |
|------|------|------|
| **R4-WRONG** | `relevant_prog_count=0` 또는 callfile과 stepping stone 간 syscall 겹침 없음 | LLM에 완전히 다른 syscall family 요청 |
| **R4-STATE** | dist가 이전보다 줄었으나 지금 stall, 또는 stepping stone에 init/alloc 패턴 | LLM에 prerequisite setup sequence 요청 |
| **R4-ARG** | dist < 1000이면서 coverage 증가 중 | Seed generation 우선 (callfile 변경 없이 argument 값만 조정) |

---

## LLM 응답 처리

### Syscall Suggestion 응답
```json
{
  "syscalls": [
    {"Target": "socket$bt_sco", "Relate": ["bind$bt_sco", "connect$bt_sco", "setsockopt$bt_sco"]},
    {"Target": "socket$bt_l2cap", "Relate": ["bind$bt_l2cap", "connect$bt_l2cap"]}
  ],
  "reasoning": "sco_sock_create is triggered by socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)"
}
```
→ callfile JSON으로 변환 후 저장, 다음 라운드 fuzzer에 전달

### Seed Program 응답
```json
{
  "programs": [
    {
      "name": "bt_sco_connect",
      "text": "r0 = socket$bt_sco(0x1f, 0x5, 0x2)\nbind$bt_sco(r0, &(0x7f0000000000)={0x1f}, 0x1e)\nconnect$bt_sco(r0, &(0x7f0000001000)={0x1f}, 0x1e)\n"
    }
  ],
  "reasoning": "SCO socket creation requires AF_BLUETOOTH family with BTPROTO_SCO protocol"
}
```
→ `syz-db pack`으로 corpus.db 생성 → 다음 라운드 syz-manager에 seed로 투입

---

## 컨텍스트 수집 파이프라인

LLM 호출 전 자동으로 수집하는 정보:

```
1. Distance roadmap
   - .dist 파일 파싱 → 0 < dist < current_dist_min인 함수 추출
   - k2s(kernel function → syzkaller syscall) 매핑으로 reachable_via 보강

2. Kernel source snippets
   - stepping stone 함수들의 소스코드 읽기 (grep으로 파일 위치 찾기)
   - 함수 정의 주변 40줄 추출

3. Closest corpus program (신규, 2026-04-03 추가)
   - corpus.db를 syz-db unpack으로 추출
   - detailCorpus.txt에서 최소 dist 달성 프로그램 식별

4. Reverse trace (신규, 2026-04-03 추가)
   - bottleneck 함수(가장 가까운 stepping stone)의 caller 역추적
   - 2단계까지 grep으로 추적 → syscall entry point 식별

5. Deterministic seed fallback (신규, 2026-04-03 추가)
   - 서브시스템별 하드코딩된 기본 프로그램
   - bluetooth: socket$bt_sco + bind + connect
   - mm: mmap + mremap / madvise
   - tcp/ip: socket$inet_tcp + bind + setsockopt
   - TC: sendmsg$nl_route_sched (기존)
```

---

## 파일 구조

```
llm_enhance.py          — 모든 LLM 호출, 프롬프트 생성, 응답 파싱
agent_loop.py           — AgentLoop 클래스, 라운드 관리, LLM 함수 오케스트레이션
agent_triage.py         — R1/R2/R3/R4 분류, R4-WRONG/STATE/ARG 세분류
agent_health.py         — 라운드 건강 지표 수집 (metrics.jsonl 파싱)
syscall_normalize.py    — LLM이 생성한 syscall 이름 검증/정규화
semantic_seed.py        — 의미적 seed 생성 (LLM 외 별도 경로)
```
