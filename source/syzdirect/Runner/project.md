# SyzDirect Runner — Project Log

## Overview

SyzDirect는 Linux 커널의 특정 함수(타겟)에 도달하도록 퍼징을 유도하는 **directed fuzzer**다.
Runner는 이 fuzzer를 감싸는 자동화 파이프라인으로, 커널 빌드부터 퍼징 실행, LLM 기반 시드 생성, 실패 분류 및 재시도까지 전 과정을 관리한다.

## Architecture

```
run_hunt.py                  # CLI entry point (dataset/new/fuzz 모드)
├── pipeline_dataset.py      # 다수 케이스 일괄 빌드 파이프라인
├── pipeline_new_cve.py      # 단일 CVE 분석 + pre-built 타겟 설정
├── agent_loop.py            # 핵심: fuzz → assess → triage → enhance → re-fuzz
│   ├── agent_health.py      # 퍼징 상태 평가 (exec/cover/dist 변화량)
│   ├── agent_triage.py      # R1/R2/R3/R4 실패 분류 + R4 하위 분류
│   ├── llm_enhance.py       # LLM 기반 callfile 개선 + stepping stone 분석
│   ├── semantic_seed.py     # 정적 분석 기반 seed 합성 파이프라인
│   ├── syzlang_parser.py    # syzlang resource dependency 파서
│   └── crash_triage.py      # crash 분류 + 기존 crash 필터링
├── Fuzz.py / Config.py      # 레거시 syz-manager 실행 래퍼
├── kernel_build.py          # 커널 빌드 유틸리티
└── paths.py                 # 경로 상수, WorkdirLayout, PREBUILT_TARGETS
```

## Key Concepts

- **Distance metric**: `callgraph_hops × 1000 + cfg_distance`. dist=0 = 타겟 함수 도달 성공.
- **Agent loop (V3)**: 퍼징 → 상태 평가 → 실패 분류(R1~R4) → LLM으로 callfile/seed 개선 → 재퍼징. 최대 N 라운드.
- **Failure classes**:
  - R1: 잘못된 syscall 이름 (fuzzer가 실행 불가)
  - R2: syscall은 맞지만 인자 오류 (EINVAL/EFAULT)
  - R3: coverage가 안 늘어남
  - R4: coverage는 늘지만 distance가 안 줄어듦 (가장 흔한 실패)
    - R4-WRONG: 완전히 다른 subsystem의 syscall
    - R4-STATE: 맞는 syscall이지만 prerequisite 부족
    - R4-ARG: 거의 다 왔지만 특정 인자값이 안 맞음
- **V2 vs V3**: V2 = agent loop 없이 1회 퍼징, V3 = agent loop + proactive seed

## File Organization

```
Runner/
├── *.py                           # 핵심 파이프라인 코드 (26개 모듈)
├── dataset_11cases.xlsx           # 현재 실험 데이터셋 (12 cases)
├── dataset_hunt.xlsx              # 이전 실험 데이터셋
├── known_crash_signatures.json
├── workdirs/                      # 모든 workdir 통합
│   ├── workdir_11cases/           # 11케이스 통합 빌드 (49G)
│   ├── workdir_11cases_v{2,3}_case*/  # V2/V3 퍼징 결과
│   └── workdir_v123/              # 이전 V1/V2/V3 비교 실험 결과 (23G)
├── SyscallAnalyze/                # syscall 분석 보조 도구
└── _archive/                      # 정리된 이전 노트, 로그, 스크립트
```

---

# Changelog

---

## V1 — Baseline Agent Loop (2026-03 ~ 04-03)

초기 agent loop 구현. R1/R2/R3/R4 실패 분류, LLM 기반 callfile enhance, proactive seed 생성.
4개 TC/TCP 케이스(case 0~3)로 V1/V2/V3 비교 실험 실행.

결과: V3가 V2 대비 유의미한 개선 없이 대부분 R4 stuck.

---

## V2 — 개선 A/B 구현 + 11케이스 실험 (2026-04-03 ~ 04-05)

### 구현 내용

**개선 A: Caller Condition Extraction (`llm_enhance.py`)**
- `_extract_caller_conditions()`: 타겟 함수 caller의 조건문(if/switch/while) 역추적 추출
- `read_stepping_stone_sources(include_caller_conditions=True)`: snippet에 `// CONDITIONS BEFORE CALL:` 섹션 추가
- LLM 프롬프트에 "CONDITIONS BEFORE CALL 섹션을 읽고 syscall 인수가 조건을 만족하도록 작성하라" 지침 추가

**개선 B: Syzlang Resource Dependency (`syzlang_parser.py` 신규)**
- syzlang sys/linux/*.txt 파싱 → 340 resources, 3736 syscalls, 256 producers
- `get_db().get_prerequisites("sendmsg$nl_route_sched")` → `["socket$nl_route"]`
- `agent_loop.py`에서 seed 생성 시 `syz_resource_chain` 프롬프트 주입
- `agent_triage.py`의 `callfile_to_templates()`에 syz_db 연동

**인프라**
- `dataset_11cases.xlsx`: 기존 6개 + 신규 5개 paper benchmark 케이스
- `setup_11cases_workdir.py`: 통합 workdir 세팅 (symlink + copy)
- `paths.py`: PREBUILT_TARGETS에 case 6~11 추가
- `run_v123_comparison.py`: symlink 절대경로 버그 수정

### 실험 결과 (2026-04-04~05)

| Case | Target | V2 dist | V3 R1 | V3 R2 | V3 R3 | V2 exec | V3 exec | Result |
|------|--------|:-------:|:-----:|:-----:|:-----:|--------:|--------:|--------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 2010 | 2010 | 2010 | 63K | 216K | FAIL |
| 1 | qdisc_create | 1010 | 1010 | 1010 | 1010 | 95K | 214K | FAIL |
| 2 | fifo_set_limit | 10 | 10 | 10 | 10 | 40K | 337K | FAIL |
| 3 | tcp_cleanup_congestion_control | 1010 | 1010 | **0** | **0** | 26K | 324K | **V3 성공** |
| 4 | move_page_tables | 2010 | 2010 | **0** | - | 6K | 183K | **V3 성공** |
| 5 | sco_sock_create | 30 | 30 | 30 | 30 | 35K | 124K | FAIL |
| 6 | tcf_exts_init_ex | 2010 | 2010 | 2010 | 2010 | 89K | 242K | FAIL |
| 7 | nf_tables_newrule | 10 | 10 | 10 | 10 | 22K | 207K | FAIL |
| 8 | sctp_sf_do_prm_asoc | **0** | - | - | - | 105K | - | **V2 성공** |
| 9 | xfrm_state_find | - | - | - | - | - | - | 미완료 |
| 10 | packet_snd | - | - | - | - | - | - | 빌드 실패 |
| 11 | llc_ui_sendmsg | - | - | - | - | - | - | 미완료 |

**성공: 3/9 (33%)** — V3 agent loop 기여 2개 (case 3, 4), V2 baseline 1개 (case 8).

### Root Cause Analysis

**Category A: Netlink Payload Precision (4 cases — case 0, 1, 2, 6)**
- 올바른 syscall을 사용하지만 netlink 메시지 내부 TCA/NLA attribute 값이 부정확
- Case 0: sendmsg 371개 실행, 전부 dist=2010. LLM seed 오타("tcindux") → validator reject
- Case 1: dist=1010. tc_modify_qdisc까지 도달하지만 qdisc_create 진입 실패
- Case 2: dist=10. 마지막 분기(limit/burst 값) 미충족. R4-ARG 올바르게 분류
- Case 6: Case 0과 같은 TC 서브시스템, 같은 문제

**Category B: Stateful Prerequisites (1 case — case 7)**
- nf_tables_newrule는 table, chain이 먼저 존재해야 함. 선행 오브젝트 생성 누락

**Category C: Hardware/Environment (1 case — case 5)**
- sco_sock_create는 Bluetooth HCI 디바이스 필요. VM에 없음

### 성공 케이스 분석

- Case 3: Agent loop R1에서 R4 분류 → callfile에 `close` 추가 → R2에서 `socket$inet_tcp` + `close`로 dist=0
- Case 4: V2는 exec=5747밖에 못 함 → Agent loop이 `mremap` syscall 시드 제공 → R2에서 dist=0
- Case 8: V2 baseline에서 자체 성공. `connect$inet_sctp` callfile이 올바르게 설정됨

### 교훈

- 개선 A/B는 "어떤 syscall을 써야 하는가"를 해결하지만, 실패 다수는 "syscall payload 내부 값이 뭐여야 하는가" 문제
- Seed validator의 typo rejection이 유망한 seed를 제거하는 부작용 발생
- V3 agent loop은 simple한 케이스(socket+close, mremap)에서는 효과적이나, 복잡한 netlink 구조체가 필요한 TC/netfilter 서브시스템에서는 무효

### 다음 단계 (V3 방향)

1. **Netlink/structured payload 정밀도** — syzlang type definition 파싱, 커널 소스 attribute check 역추적
2. **Seed validator typo tolerance** — fuzzy matching으로 오타 자동 수정
3. **다단계 prerequisite chain** — nftables table→chain→rule 자동 생성
4. **미완료 케이스** — case 9, 11 실행; case 10 빌드 실패 조사

---

## V3 — 4개 개선 구현 (2026-04-05)

V2 실험 실패 분석을 바탕으로 4개 개선 사항 구현.

### 개선 1: Seed Validator Fuzzy Matching 버그 수정 (`llm_enhance.py`)

`_score_seed_program()`에서 `_fuzzy_kind_match()`가 진단용 함수에만 쓰이고 실제 scoring에는 미연결된 버그 수정.
- 수정 전: target_kind가 all_kinds에 없으면 즉시 `return None`
- 수정 후: fuzzy match 시도 후 매칭되면 partial credit(+1), 실패 시에만 reject
- 영향: Case 0, 6에서 "tcindux" 같은 오타 seed가 reject되지 않음

### 개선 2: Syzlang Type Definition LLM 프롬프트 주입 (`syzlang_parser.py`, `llm_enhance.py`)

`SyzlangDB.extract_type_context()` 메서드 추가 — 타겟 syscall의 .txt 파일에서 type 계층을 raw syzlang text로 추출, LLM 프롬프트에 주입.
- syscall signature → 참조 type 이름 추출 → transitive하게 type 정의 블록 수집 (3단계, max 3000자)
- `llm_generate_seed_program()`에서 자동으로 `_get_syzlang_db().extract_type_context(target_syscall)` 호출
- 영향: LLM이 netlink 메시지 내부 구조(TCA_KIND, TCA_OPTIONS 중첩)를 직접 읽고 정확한 payload 생성 가능

### 개선 3: R4-ARG Closest Corpus Re-injection (`llm_enhance.py`, `agent_loop.py`)

R4-ARG 분류 시 이전 라운드 corpus에서 dist 가장 가까운 프로그램 최대 20개 추출, 다음 라운드 seed로 재주입.
- `extract_closest_programs()` 추가: detailCorpus.txt 파싱 → dist 기준 정렬 → corpus.db unpack → 텍스트 반환
- `pack_programs_to_corpus()` 추가: 프로그램 리스트 → corpus.db 패킹
- agent_loop.py R4-ARG 분기에서 `dist_threshold = current_dist * 2` 이하 프로그램만 선별
- 영향: Case 2 (dist=10), Case 7 (dist=10)에서 fuzzer가 close program 우선 mutation 가능

### 개선 4: Prerequisite Chain BFS 확장 (`syzlang_parser.py`)

`get_prerequisites()`를 depth=1 수동 unroll에서 BFS(max_depth=4)로 재작성.
- 영향: nftables처럼 socket→table→chain→rule (3단계) 필요한 케이스에서 full prerequisite chain 생성

### V3 실험 결과 (2026-04-05)

`workdir_v3_unified` 통합 workdir에서 8케이스 동시 V3 실행.
설정: `-j 8 -uptime 2 --agent-rounds 3 --agent-uptime 1 --proactive-seed --hunt-mode hybrid`

| Case | Target | V2 dist | V3 dist | 결과 | R4 분류 |
|------|--------|:-------:|:-------:|------|---------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 2010 | ❌ FAIL | R4-STATE |
| 1 | qdisc_create | 1010 | 1010 | ❌ FAIL | R4-STATE |
| 2 | fifo_set_limit | 10 | 10 | ❌ FAIL | R4-ARG |
| **5** | sco_sock_create | 30 | **0** | **✅ V3 성공 (40초)** | - |
| 6 | tcf_exts_init_ex | 2010 | 2010 | ❌ FAIL | R4-STATE |
| 7 | nf_tables_newrule | 10 | 10 | ❌ FAIL | R4-ARG |
| 9 | xfrm_state_find | 미완료 | 2010 | ❌ FAIL | R4-STATE |
| **11** | llc_ui_sendmsg | 미완료 | **0** | **✅ V3 성공 (50초)** | - |

기존 성공 케이스 포함 전체 성적: **5/11 성공 (45%)** — V2 대비 +2 (case 5, 11 신규).

### V3 실험 문제점 분석

**문제 1: Seed Validator가 유효한 LLM Seed를 Reject (case 6)**

- 증상: LLM이 `basic`, `flower` classifier 기반 seed를 올바르게 생성했지만 validator가 `target_kind_missing`으로 전부 reject
- 원인: `_seed_requirements()`가 `cls_api.c`를 `target_type=filter`로 분류하고, `_infer_tc_kind_from_roadmap()`이 `target_kind=u32`를 추론. LLM seed에는 `basic`/`flower` kind가 있지만 `u32`가 없어서 reject
- 근본 문제: `cls_api.c`는 **모든 TC filter의 공통 코드**인데 특정 kind(u32)를 강제하는 게 잘못됨. `tcf_exts_init_ex`는 어떤 filter kind든 호출하는 범용 함수
- 수정 방향: `cls_api.c` 같은 공통 파일은 `target_kind=None`으로 설정하거나, validator에서 kind 체크를 optional로 변경

**문제 2: R4-ARG Corpus Re-injection이 실제로 작동하지 않음 (case 2, 7)**

- 증상: `[R4-ARG] Close to target, re-injecting closest corpus programs...` 로그만 있고 `Found N closest programs` 로그 없음
- 원인: `extract_closest_programs()`가 `detail_corpus_path`에서 프로그램을 찾지 못함. `_last_detail_corpus` 속성이 `None`이거나 파일 경로가 맞지 않는 것으로 추정
- 수정 방향: `detail_corpus`의 실제 경로를 디버깅하고, detailCorpus.txt가 생성되는 조건 확인

**문제 3: Syzlang Type Injection이 LLM 프롬프트에 반영되었는지 불명 (case 0, 7 등)**

- 증상: type extraction 관련 로그가 전혀 없음. LLM의 reasoning에서도 syzlang type 참조 안 보임
- 원인: `llm_generate_seed_program()`에서 type context 주입이 silent하게 실패(exception catch 후 print만)하거나, 해당 syscall의 `.txt` 파일을 찾지 못한 것으로 추정 (syz_dir 경로 문제)
- 수정 방향: `_get_syzlang_db()` 호출 결과 로깅 추가, `.txt` 파일 존재 여부 확인

**문제 4: 변수명 충돌 버그 (구현 실수, 수정 완료)**

- 증상: case 0~6 전부 `TypeError: expected str, bytes or os.PathLike object, not SyzlangDB`로 즉시 crash
- 원인: `llm_generate_seed_program()`에서 `syz_db`(syz-db 바이너리 경로)를 `syz_db = _get_syzlang_db()`로 덮어씌움
- 수정: 변수명을 `_syzlang_db`로 변경 (수정 후 재시작하여 실험 완료)

### V3 Hotfix 1: 실험 결과 분석 기반 버그 수정 (2026-04-05)

**수정 1: detailCorpus.txt JSON 파서** (`llm_enhance.py`)
- detailCorpus.txt가 `{"Uptime": ..., "Prog": ..., "Dist": ...}` JSON 형식인데 기존 파서는 `sig dist` space-delimited 텍스트로 파싱하고 있었음
- `_parse_detail_corpus()` 헬퍼 추가: `json.JSONDecoder.raw_decode()`로 연속 JSON 파싱
- `extract_closest_program()`: detailCorpus에서 직접 프로그램 텍스트 반환 (unpack 불필요)
- `extract_closest_programs()`: JSON 파싱 + dedup + dist_threshold 필터링
- 영향: case 2 (dist=10), case 7 (dist=10)에서 R4-ARG corpus re-injection 정상 작동 예상

**수정 2: TC 공통 파일 kind 강제 해제** (`llm_enhance.py`)
- `_detect_tc_target_type()`에서 `*_api.c` → `"unknown"` 반환 (기존: `cls_api.c` → `"filter"`)
- case 6 (`cls_api.c`=`tcf_exts_init_ex`)에서 `target_kind=u32` 강제 → LLM의 `basic`/`flower` seed reject 문제 해소
- 영향: `cls_api.c`, `sch_api.c` 등 공통 API 파일 타겟에서 어떤 TC kind든 seed 허용

**수정 3: Syzlang type injection 로깅 강화** (`llm_enhance.py`)
- 추출 성공/실패, syscall 수, 문자 수 명시적 로그 추가 + traceback 출력
- V3 실험에서 type injection이 silent fail한 근본 원인 = 변수명 충돌 크래시 (수정 4에서 이미 수정)로 `llm_generate_seed_program()` 자체가 exception 발생, type injection 코드에 도달하지 못함

**3번 문제 조사 결과: seed는 fuzzer에 정상 주입됨**
- case 0에서 매 라운드 `Seeded corpus: ... -> .../corpus.db` 로그 확인
- seed unpack 결과: prio qdisc → tcindex filter 순서 올바름, RTM_NEWQDISC(0x24)/RTM_NEWTFILTER(0x2c) 구조 정확
- 근데 1189개 corpus 프로그램이 전부 dist=2010 → tcindex 모듈까지 도달했지만 `tcindex_change()` 진입 못 함
- 원인: TCA_OPTIONS 내부 tcindex 속성(TCA_TCINDEX_HASH, TCA_TCINDEX_MASK 등)이 불충분. syzlang type definition이 LLM에 제공되지 않아서 (변수명 충돌로 크래시) LLM이 세부 속성을 모른 채 생성
- 수정: 변수명 충돌 수정 + type injection 로깅 → 다음 실행에서 syzlang type 정보가 LLM에 전달되면 TCA_OPTIONS 정밀도 향상 기대

### 다음 단계

- 위 3개 hotfix 적용 후 실패 케이스 재실행 (case 0, 1, 2, 6, 7, 9)
- type injection이 실제로 프롬프트에 들어가는지 로그 확인
- dist=10 케이스(2, 7)에서 corpus re-injection 후 dist 변화 모니터링

---

## V4 — LLM Code-Gen Seed + dist=10 돌파 (2026-04-06)

### 배경

V3 Hotfix 이후 5/11 성공 (45%). 실패 6개의 근본 원인:
- dist≥2010 (case 0, 1, 6, 9): LLM이 올바른 syscall 구조를 이해하지만 hex byte 계산 틀림 → 커널 validator reject
- dist=10 (case 2, 7): 타겟 바로 앞까지 도달했지만 마지막 분기 조건 미충족

### 핵심 아이디어

**"LLM이 hex 대신 Python 코드를 짜게 한다"**

- 현재: LLM → hex string (틀림) → ANYBLOB
- 개선: LLM → Python struct.pack() 코드 → 실행 → 정확한 hex → ANYBLOB
- LLM은 hex 계산은 못하지만 Python 코드는 잘 짬
- netlink뿐 아니라 ioctl, setsockopt, xfrm 등 모든 서브시스템에 적용 가능

### 구현 내용

**개선 1: LLM Code-Gen Seed Generator (`llm_enhance.py`)**

`llm_generate_seed_via_codegen()` 함수 추가 — 기존 `llm_generate_seed_program()`의 fallback으로 동작.

흐름:
1. 기존과 동일하게 roadmap, source_snippets, syzlang type context 수집
2. LLM에게 Python 스크립트 생성 요청 (struct.pack()으로 binary payload 빌드, stdout으로 syzkaller program 출력)
3. sandbox에서 실행 (timeout 15초)
4. 실패 시 에러 메시지를 LLM에 피드백하여 1회 retry
5. stdout에서 program text 파싱 → syz-db pack

설계 결정:
- 별도 헬퍼 라이브러리(seed_helpers.py) 없음 — 순수 Python stdlib만 사용. LLM이 struct.pack()만으로 충분히 코드를 짤 수 있고, 헬퍼 의존성은 오히려 버그 원인
- 기존 seed 성공 시 codegen 스킵 (순차 실행으로 LLM API 비용 절약)
- 실패 시 에러를 LLM에 피드백하여 1회 retry (syntax error, import error 대응)

**개선 2: agent_loop.py 통합**

`_enhance_for_distance_stall()`에서:
- 1차: 기존 `llm_generate_seed_program()` 실행
- 2차: seed_corpus가 None일 때만 `llm_generate_seed_via_codegen()` fallback
- R4-STATE/R4-ARG 모두에서 codegen 경로 사용

**개선 3: dist<100 timeout 부스트**

- dist < 100이면 `dist_stall_timeout`을 1800초로 증가 (기본 600초의 3배)
- 거의 도달한 프로그램에게 mutation 시간을 더 줌

**개선 4: 근접 거리 프롬프트 힌트**

- dist < 100일 때 codegen 프롬프트에 추가:
  "Distance is only {dist}. Analyze the EXACT branch condition blocking entry."
- LLM이 caller의 if-check, flag validation 등을 집중 분석하도록 유도

### 수정 파일

| 파일 | 변경 | 설명 |
|------|------|------|
| llm_enhance.py | 추가 | `llm_generate_seed_via_codegen()`, `_strip_markdown_fences()`, `_execute_codegen_script()`, `_retry_codegen_script()` |
| agent_loop.py | 수정 | codegen fallback 통합 + dist<100 timeout 부스트 |

### V4 실험 결과 (2026-04-06)

**실험 Run 1 (codegen fallback 조건: seed_db=None일 때만)**

| Case | Target | dist | codegen 트리거 | 결과 |
|------|--------|:----:|:--------------:|------|
| 0 | tcindex_alloc_perfect_hash | 2010 | X | FAIL |
| 1 | qdisc_create | 1010 | X | FAIL |
| 2 | fifo_set_limit | 10 | X | FAIL |
| 6 | tcf_exts_init_ex | 2010 | X | FAIL |
| 7 | nf_tables_newrule | 0 | X (자체 성공) | SUCCESS |
| 9 | xfrm_state_find | 2010 | X (LLM 무응답) | FAIL |

문제: 기존 `llm_generate_seed_program()`이 corpus.db를 만들면 "성공"으로 판정 → codegen 스킵.
수정: 라운드 2+에서 dist 변화 없으면 codegen도 시도하도록 변경 (`dist_not_improving` 조건 추가).

**실험 Run 2 (codegen 조건 수정 후, 6개 병렬)**

| Case | Target | dist | codegen 성공 횟수 | 결과 |
|------|--------|:----:|:-----------------:|------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 2 | FAIL |
| 1 | qdisc_create | 1010 | 2 | FAIL |
| 2 | fifo_set_limit | 10 | 2 | FAIL |
| 6 | tcf_exts_init_ex | 2010 | 2 | FAIL |
| 7 | nf_tables_newrule | **0** | 0 (fuzzer 자체 성공) | **SUCCESS** |
| 9 | xfrm_state_find | 2010 | 0 (LLM 무응답) | FAIL |

**Codegen Seed 품질 분석:**

Case 0 codegen seed를 hex 디코딩한 결과:
- `RTM_NEWTFILTER(0x2c)`, `TCA_KIND="tcindex"` (철자 정확!), NLA 패딩 정확
- `TCA_OPTIONS` 내부에 `TCA_TCINDEX_HASH=16, MASK=0xf, SHIFT=0, FALL_THROUGH=1, CLASSID` 전부 포함
- 이전 LLM의 "tcindux" 오타 문제 완전 해결
- **구조적으로 완벽하지만 dist=2010 유지** — tcindex_change()까지만 도달, tcindex_alloc_perfect_hash() 미진입

Case 2 codegen seed:
- pfifo: `limit=1` (양수 ✓)
- tbf: `limit=0` ← **fifo_set_limit 진입 조건 `qopt->limit > 0` 미충족**

### 근본 원인 발견: 커널 소스 누락 (Critical Bug)

**문제**: `workdir_v3_unified`에 `srcs/` 디렉토리가 아예 없음.

```
[proactive] No kernel source at .../srcs/case_0, skipping semantic pipeline
[R4] No kernel source at .../srcs/case_0, skipping semantic pipeline
```

이 로그가 **V3 실험(04-05)부터 V4 Run 2(04-06)까지 모든 실험의 모든 라운드에서** 출력됨.

**영향 범위**:
1. V2 개선 A (Caller Condition Extraction) — `_extract_caller_conditions()`가 **한번도 실행된 적 없음**. 커널 소스가 없으니 stepping stone 소스 읽기도 불가
2. V4 codegen — `source_snippets` 파라미터가 항상 빈 문자열. LLM이 커널 분기 조건을 모른 채 seed 생성
3. `read_stepping_stone_sources()` — 항상 빈 문자열 반환
4. `reverse_trace_bottleneck()` — 실행 불가
5. semantic_seed pipeline — 완전 스킵

**원인**: `setup_11cases_workdir.py`는 srcs를 case별로 symlink하는데, workdir_v3_unified가 이 스크립트로 만들어졌음에도 srcs 디렉토리 자체가 존재하지 않음. 원본 workdir_v3_ga에는 srcs/case_0~3이 있지만 unified에 parent 디렉토리(srcs/)가 생성되지 않아 symlink도 실패한 것으로 추정.

**기존 성공 케이스(3, 4, 5, 11)는 소스 없이도 성공** — callfile만으로 fuzzer가 도달 가능한 simple한 케이스였음. 실패 케이스(0, 1, 2, 6, 9)는 정확한 payload 값이 필요한데, 커널 소스 없이는 LLM이 그 값을 추론할 수 없음.

**이전에 비슷한 문제가 있었는가?**

V3 문제 4 (변수명 충돌 `syz_db`)가 유사 — 코드는 구현됐지만 런타임에 silent fail하여 기능이 실행되지 않음. 두 문제 모두:
- 구현은 존재하지만 전제 조건(파일 경로, 변수)이 안 맞아서 실행 안 됨
- 에러가 `print`로만 출력되고 진행되어 발견이 늦음
- 실험 결과만 보면 "기능이 효과 없다"로 잘못 해석될 수 있음

### 해결 방안

**1단계: workdir_v3_unified에 srcs symlink 복구**

```bash
mkdir -p /home/ai/work_real/workdir_v3_unified/srcs
# case 0~3: workdir_v3_ga에서
for c in 0 1 2 3; do
    ln -s /home/ai/work_real/workdir_v3_ga/srcs/case_$c \
          /home/ai/work_real/workdir_v3_unified/srcs/case_$c
done
# case 7,9: workdir_cases_7_9_10_11에서
for c in 7 9; do
    ln -s /home/ai/work_real/workdir_cases_7_9_10_11/srcs/case_$c \
          /home/ai/work_real/workdir_v3_unified/srcs/case_$c
done
```

Note: case 4(mremap), 5(bluetooth), 6(cls_api), 11(llc)의 srcs는 각각의 new_cases workdir에서 확인 필요.

**2단계: _make_version_workdir()가 srcs를 symlink하는지 재확인**

이미 SYMLINK_ITEMS에 "srcs" 포함됨. unified에 srcs가 있으면 version workdir에도 자동 전파.

**3단계: 재실험**

srcs 복구 후 6케이스 재실행. 이번에는:
- `read_stepping_stone_sources()` → 커널 소스 snippet이 LLM 프롬프트에 포함
- `_extract_caller_conditions()` → caller의 if-check 조건이 포함
- `reverse_trace_bottleneck()` → bottleneck 함수 역추적 가능
- codegen 프롬프트에 실제 커널 코드가 들어감 → 정확한 필드 값 추론 가능

**기대 효과**: case 2 (dist=10)에서 `tbf_change()`의 `qopt->limit > 0` 조건이 커널 소스로 LLM에 전달되면, codegen이 `limit=1` 이상의 값을 설정할 수 있음.

### V4 Run 3 실험 결과 (srcs 복구 후, 2026-04-06)

| Case | Target | dist | 변화 |
|------|--------|:----:|------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 없음 |
| 1 | qdisc_create | 1010 | 없음 |
| 2 | fifo_set_limit | 10 | 없음 |
| 6 | tcf_exts_init_ex | 2010 | 없음 |
| **7** | **nf_tables_newrule** | **0** | **성공 (fuzzer 자체)** |
| 9 | xfrm_state_find | 2010 | 없음 |

**긍정적 변화:**
- source snippets 주입 작동 확인 (proactive: 4~9개, R4: 1~2개)
- codegen seed 품질 향상: case 2 tbf의 limit=0 → limit=65576 (양수)
- case 0 tcindex seed: 철자 정확, NLA 구조 완벽

**여전히 실패하는 이유 — 2차 근본 원인 발견:**

**문제 A: dist=10 케이스(case 2)에서 stepping stone이 없음**

```
[R4] No stepping stones, will query LLM with CVE context only
```

`sch_fifo.dist` 파일에서 dist < current_dist(10)인 함수가 `fifo_set_limit` 자체(dist=0)뿐.
`extract_distance_roadmap()`은 현재 dist보다 낮은 함수만 stepping stone으로 취급 →
stepping stone 없음 → 소스 안 읽힘 → codegen에 커널 코드 미전달.

즉 **dist가 아주 가까운 케이스(10, 30 등)에서 오히려 소스 정보가 없는 역설**.
proactive 단계에서는 static roadmap(전체 dist 파일)을 읽어서 snippets가 나오지만,
R4 triage 단계에서는 동적 roadmap만 사용하여 stepping stone이 비어버림.

**해결 방안**: dist < 100일 때는 stepping stone 대신 **타겟 함수의 direct caller 소스**를 직접 읽어서 codegen에 주입.
`read_stepping_stone_sources()`가 빈 값을 반환하면, `_extract_caller_conditions(target_func)`로 fallback.

**문제 B: dist≥1010 케이스(case 0, 1, 6, 9)에서 소스가 읽히지만 부족**

case 0: `Read 1 source snippets` — tcindex_change() 소스 1개만 읽힘.
tcindex_alloc_perfect_hash()는 tcindex_change() 내부에서 호출되는데,
호출 조건(hash table이 full일 때만)이 snippet에 없을 수 있음.

**해결 방안**: stepping stone뿐 아니라 **타겟 함수 자체**의 소스도 항상 포함.
현재는 stepping stone 함수만 읽는데, 타겟 함수의 caller가 어떤 조건에서
타겟을 호출하는지가 가장 중요한 정보.

### V4.1 구현: wide roadmap fallback + target source direct read (2026-04-06)

**구현 내용** (`agent_loop.py` `_enhance_for_distance_stall()`):

1. stepping stones가 비어있으면 `current_dist_min=99999`로 wide roadmap 재시도
2. wide roadmap에서도 snippets가 없으면 타겟 함수 소스 + caller conditions 직접 읽기
3. `subprocess` import 추가

### V4 Run 4 실험 결과 (wide roadmap fallback, 2026-04-06~07)

| Case | Target | dist | wide fallback | codegen | 결과 |
|------|--------|:----:|:---:|:---:|------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 0 | 2 | FAIL |
| 1 | qdisc_create | 1010 | 0 | 2 | FAIL |
| 2 | fifo_set_limit | 10 | **2** | **2** | FAIL |
| 6 | tcf_exts_init_ex | 2010 | 0 | 0 | FAIL |
| 7 | nf_tables_newrule | 10 | **1** | 0 | FAIL |
| 9 | xfrm_state_find | 2010 | 0 | 2 | FAIL |

**Wide roadmap fallback 작동 확인:**
- case 2: `No stepping stones at dist<10, retrying with wide threshold... Wide roadmap: 12 stepping stones → Read 8 source snippets`
- case 7: `Wide roadmap: 12 stepping stones → Read 6 source snippets`

**그럼에도 실패하는 3차 근본 원인:**

**Case 2 심층 분석:**
- codegen이 pfifo, bfifo, pfifo_head_drop seed를 생성 — **tbf seed 미생성**
- `fifo_set_limit()`은 직접 호출되지 않음. 실제 커널 경로: `tbf_change()` → `qdisc_change()` → `fifo_set_limit()`
- semantic pipeline은 이 체인을 정확히 찾음 (`tbf_change [direct_call] → fifo_set_limit [target]`)
- 하지만 wide roadmap의 stepping stones에 `tbf_change`가 없음 — 다른 .dist 파일(sch_tbf.dist)에 있기 때문
- source snippets는 stepping stone 함수만 읽으므로 `tbf_change()` 소스가 누락
- LLM은 "fifo_set_limit이 sch_fifo.c에 있으니까 pfifo qdisc를 만들면 된다"고 추론 → 틀림

**핵심 문제: stepping stone 기반 소스 읽기의 한계**

현재 파이프라인:
```
dist 파일 → stepping stones → 해당 함수 소스 읽기 → LLM 프롬프트
```

이 접근의 문제:
1. stepping stones는 **같은 dist 파일에 있는 함수만** 포함. 타겟의 직접 caller가 다른 파일에 있으면 누락
2. `fifo_set_limit`의 caller인 `tbf_change`는 `sch_tbf.dist`에 있지 `sch_fifo.dist`에 없음
3. semantic pipeline의 call chain 분석이 더 정확하지만, 그 결과가 codegen에 전달되지 않음

**진짜 해결해야 할 것:**

LLM에게 "이 함수에 도달하려면 어떤 syscall로 어떤 값을 넣어야 하는가"를 알려주려면,
stepping stones(정적 분석 기반)보다 **call chain(동적 분석 기반)**이 더 적합.

semantic pipeline이 이미 `tbf_change → fifo_set_limit` 체인을 찾고 있으니,
이 정보를 codegen 프롬프트에 활용해야 함.

### V4.2 구현 완료 (2026-04-07)

1. ✅ **semantic pipeline의 call chain을 codegen에 주입**: `last_semantic_plan`에서 call_chain, branch_conditions, prerequisite_sequence를 추출, codegen/seed 프롬프트에 `semantic_context`로 포함
2. ✅ **caller 소스 직접 읽기**: semantic chain의 direct caller 함수(예: `tbf_change`)의 소스를 자동으로 읽어 snippets에 주입
3. ✅ **R4-ARG 오분류 수정**: semantic chain depth >= 3이면 R4-ARG → R4-STATE로 재분류
4. ✅ **codegen 프롬프트에 multi-step 지시 추가**: "MUST generate multi-step programs" 가이드

**V4r5 결과**: LLM이 정확히 `tbf` 시드를 생성하고 2-step(CREATE + REPLACE) 프로그램도 만들었으나, dist 변화 없음.

**V4r5 실패 분석**: 시드 바이너리 분석 결과 구조적으로 올바름 (RTM_NEWQDISC, kind=tbf, TCA_TBF_PARMS 정상).
- 2-step 프로그램: 1차 CREATE(flags=0x0405) → 2차 CREATE|REPLACE(flags=0x0505), 동일 parent=0xffff0000
- 이론적으로 `tbf_change → fifo_set_limit` 경로를 트리거해야 하지만 dist=10 유지

**잔여 문제 가설**:
1. **corpus.db 덮어쓰기**: semantic_seed.db, llm_seed.db, codegen_seed.db가 순서대로 corpus.db를 덮어씀 → 마지막 것만 로드됨. 2-step seed가 덮어써졌을 가능성
2. **syzkaller가 multi-call 프로그램을 올바르게 실행하지 않을 가능성**: 같은 프로그램 내의 두 sendmsg가 순서대로 실행되는지 확인 필요
3. **첫 CREATE가 실패**: tbf qdisc가 실제로 생성되지 않으면 두 번째 REPLACE도 `tbf_change`에 도달 못함
4. **TCA_TBF_RTAB/PTAB 누락**: 커널의 tbf는 rate table이 필요할 수 있음 (attr type 6, 7이 이걸 시도하는 것으로 보이나 크기가 너무 작음 — 실제 rtab은 256*4=1024 바이트)

### V4.3 심층 분석 (2026-04-07)

**Case 2 상세 분석 — 왜 dist=10에서 0으로 안 가는가?**

.dist 파일 분석:
- `tbf_change` BB 48 = dist=10: `if (q->qdisc != &noop_qdisc)` 체크 블록
- `fifo_set_limit` BB 0 = dist=0: 타겟 함수 entry
- 423개 프로그램이 BB 48에 도달하지만, 0개가 fifo_set_limit 진입

즉 **조건 `q->qdisc != &noop_qdisc`가 항상 FALSE**. 이유:
1. 첫 번째 RTM_NEWQDISC(tbf CREATE) → `tbf_init` → `tbf_change` → `qopt->limit > 0` → `fifo_create_dflt` → child fifo 생성
2. 두 번째 RTM_NEWQDISC(tbf CHANGE) → `qdisc_change` → `tbf_change` → `q->qdisc != &noop_qdisc` → `fifo_set_limit`

**문제**: syzkaller의 corpus mutation이 2-step의 첫 번째 CREATE를 깨뜨림.
- corpus에서 mutation 시 첫 번째 sendmsg의 바이트가 변경됨 → tbf CREATE 실패
- 실패하면 child fifo 미생성 → 두 번째 CHANGE에서 조건 FALSE
- 또는: 첫 번째 CREATE 자체의 limit=0으로 mutation → child fifo 생성 안 됨

**corpus.db 덮어쓰기 문제 확인**:
- Round 1: semantic_seed(1개) → corpus:1
- Round 2: llm_seed(tbf 2개) → corpus:2 ✓ (하지만 dist 변화 없음)
- Round 3: semantic_seed(1개)로 다시 덮어쓰기 → corpus:1 (tbf seed 사라짐!)
- Round 3에서 codegen, llm_seed 모두 "No response from LLM" (6 병렬 + 장시간 → timeout)

**rtab 분석**: `linklayer=1`(TC_LINKLAYER_ETHERNET)이면 rtab 불필요. 우리 seed는 linklayer=1 → rtab 문제 아님.

**근본 문제**: syzkaller의 mutation은 multi-step 시드를 보존하지 못함
- 단일 프로그램 안에 2개 sendmsg가 있어도, mutation이 첫 번째를 깨뜨리면 두 번째도 무효
- syzkaller는 개별 syscall 단위로 mutation하지 않고 바이트 단위 mutation → 구조 파괴

### V4.3 구현 + 추가 분석 (2026-04-07)

**V4r6 결과**: corpus merge 구현했으나 LLM timeout으로 tbf seed 미생성. dist 변화 없음.

**V4r5 결정적 증거**: 2-step tbf seed가 `corpus:2 (deleted 0 broken)`으로 정상 로드됨.
하지만 dist=10 유지 → **2-step 프로그램이 실행되지만 fifo_set_limit에 도달 못함.**

바이너리 확인: `fifo_set_limit`은 vmlinux에 별도 함수로 존재 (not inlined).
`__sanitizer_cov_trace_pc`가 entry에서 호출됨 → kcov에 잡혀야 함.

**근본 원인 가설**: 첫 번째 RTM_NEWQDISC(tbf CREATE)가 **sandbox 네트워크 네임스페이스에서 실패**.
- syzkaller sandbox는 새 net namespace 생성
- namespace 내 loopback의 기본 qdisc 상태가 호스트와 다를 수 있음
- 또는: 시드의 nlmsghdr 인코딩이 미묘하게 잘못됨 (padding, alignment)

### V4.4 계획: syzbot Reproducer Mining + VM Iterative Deepening (2026-04-07)

#### 배경

dist≥1000 케이스(case 0, 1, 6, 9)는 중간 함수 진입 조건이 복잡하여 fuzzer mutation만으로 돌파 불가.
두 가지 상호보완적 접근을 구현한다:

1. **syzbot reproducer mining** — 비용 0, 이미 검증된 syscall 시퀀스 확보
2. **VM iterative deepening** — LLM이 seed 실행 → 피드백 → 수정 반복하여 한 홉씩 돌파

#### 접근법 1: syzbot Reproducer Mining

**아이디어**: syzbot은 수천 개의 crash reproducer를 공개. 타겟 함수가 call stack에 있는 reproducer를 찾으면 **이미 해당 함수에 도달하는 검증된 프로그램**을 얻을 수 있다.

**신규 파일: `syzbot_mining.py`**

```python
# 핵심 함수:
def search_syzbot_bugs(target_function: str) -> list[dict]:
    """syzbot에서 타겟 함수가 crash stack에 등장하는 버그 검색.
    
    방법: Google 검색 'site:syzkaller.appspot.com "{target_function}"'
    → bug ID 목록 추출.
    
    Returns: [{"bug_id": str, "title": str, "url": str}, ...]
    """

def fetch_reproducer(bug_id: str) -> dict | None:
    """syzbot bug에서 reproducer 다운로드.
    
    syzbot API: GET https://syzkaller.appspot.com/bug?extid={bug_id}
    → .ReproSyz (syzkaller 프로그램 텍스트) 또는 .ReproC (C 코드) 추출.
    
    Returns: {"type": "syz"|"c", "text": str, "kernel_commit": str}
    """

def convert_c_to_syz(c_code: str, syz_db_path: str) -> str | None:
    """C reproducer → syzkaller 프로그램 변환.
    LLM에게 C 코드를 보여주고 syzkaller 프로그램 형식으로 변환 요청.
    """

def mine_seeds_for_target(target_function: str, syz_db_path: str,
                          output_dir: str, max_bugs: int = 5) -> str | None:
    """타겟 함수에 대한 syzbot reproducer를 수집하여 corpus.db로 패킹.
    
    흐름:
    1. search_syzbot_bugs() → 관련 bug 목록
    2. 각 bug에서 fetch_reproducer() → syz/C reproducer
    3. syz reproducer는 직접 사용, C는 convert_c_to_syz()
    4. pack_programs_to_corpus() → corpus.db
    
    Returns: corpus.db 경로 또는 None
    """
```

**데이터 흐름**:
```
target_function (e.g., "tcindex_alloc_perfect_hash")
  → Google search: site:syzkaller.appspot.com "tcindex_alloc_perfect_hash"
  → bug URLs → bug IDs
  → syzbot API → reproducer (syz program text)
  → pack_programs_to_corpus() → corpus.db
  → agent_loop에서 seed로 주입
```

#### 접근법 2: VM Iterative Deepening

**아이디어**: seed를 실제 VM에서 실행하여 **어디까지 도달했는지** 확인 후, LLM이 다음 홉을 뚫는 seed를 생성. fuzzer의 무작위 mutation 대신 **LLM의 targeted refinement**를 사용.

**신규 파일: `vm_verify.py`**

```python
def verify_seed_in_vm(seed_programs: list[str], layout, ci: int,
                      uptime: int = 30) -> dict:
    """seed 프로그램을 VM에서 실행하고 도달 거리를 측정.
    
    방법: syz-manager를 매우 짧은 uptime(30초)으로 실행하되,
    mutation을 최소화 (procs=1). seed corpus만 실행하고
    detailCorpus.txt에서 각 프로그램의 dist를 수집.
    
    Returns: {
        "best_dist": int,
        "programs": [{"text": str, "dist": int}, ...],
        "reached_functions": [{"function": str, "dist": int}, ...],
    }
    """

def analyze_reached_functions(detail_corpus_path: str, dist_dir: str,
                              target_function: str) -> dict:
    """detailCorpus.txt + .dist 파일에서 도달한 함수 목록 추출.
    
    .dist 파일의 모든 함수를 dist별로 정렬, 
    detailCorpus의 best dist와 비교하여 
    "이 시드로 어디까지 왔고, 다음에 뭘 뚫어야 하는지" 분석.
    
    Returns: {
        "reached": [{"function": "tc_modify_qdisc", "dist": 2010}, ...],
        "next_target": {"function": "qdisc_change", "dist": 1010},
        "blocking_condition": str,  # next_target의 caller에서 추출한 조건
    }
    """

def build_deepening_feedback(reached: dict, src_dir: str,
                             target_function: str) -> str:
    """LLM에게 줄 피드백 텍스트 생성.
    
    '당신의 seed로 tc_modify_qdisc(dist=2010)까지 도달했다.
     다음 함수 qdisc_change에 진입하려면 아래 조건을 만족해야 한다:
     [조건 소스 코드]
     이 조건을 만족하도록 seed를 수정하라.'
    """

def iterative_deepen(target_function: str, target_file: str,
                     layout, ci: int, config: RunnerConfig,
                     max_iterations: int = 5,
                     initial_seed: str | None = None) -> str | None:
    """VM 기반 iterative deepening 메인 루프.
    
    흐름:
    1. initial_seed 또는 codegen으로 초기 seed 생성
    2. verify_seed_in_vm() → 도달 거리 측정
    3. analyze_reached_functions() → 다음 뚫어야 할 함수 식별
    4. build_deepening_feedback() → LLM 피드백 생성
    5. LLM에게 refined seed 생성 요청 (codegen 방식)
    6. 2~5 반복 (dist 개선 없으면 3회 후 포기)
    7. 최종 best seed를 corpus.db로 반환
    
    핵심 차이: fuzzer mutation 없이 LLM이 직접 seed를 정교화.
    한 홉씩 진행하므로 dist≥1000 케이스에서 효과적.
    
    Returns: corpus.db 경로 또는 None
    """
```

**데이터 흐름**:
```
iteration 0: codegen seed → VM 실행 → dist=2010 (tc_modify_qdisc에서 막힘)
  → feedback: "qdisc_change 진입 조건: RTM_NEWQDISC flags에 NLM_F_CREATE 필요"
  → LLM refined seed

iteration 1: refined seed → VM 실행 → dist=1010 (qdisc_change 통과!)
  → feedback: "tbf_change 진입 조건: TCA_OPTIONS에 TCA_TBF_PARMS 존재 필요"
  → LLM refined seed

iteration 2: refined seed → VM 실행 → dist=10 (tbf_change 통과!)
  → feedback: "fifo_set_limit 진입 조건: q->qdisc != &noop_qdisc"
  → LLM refined seed (2-step: CREATE+CHANGE)

iteration 3: refined seed → VM 실행 → dist=0 (성공!)
```

#### agent_loop.py 수정

`_enhance_for_distance_stall()`에 새 분기 추가:

```python
# dist >= 1000: syzbot mining + iterative deepening
if current_dist >= 1000:
    # 1순위: syzbot reproducer 검색
    from syzbot_mining import mine_seeds_for_target
    syzbot_corpus = mine_seeds_for_target(
        target_func, syz_db_path, seed_out_dir,
    )
    if syzbot_corpus:
        self._add_seed_corpus(syzbot_corpus)
    
    # 2순위: VM iterative deepening
    from vm_verify import iterative_deepen
    deepened_corpus = iterative_deepen(
        target_func, target_file, self.layout, ci,
        config=RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds),
        initial_seed=closest_prog,
    )
    if deepened_corpus:
        self._add_seed_corpus(deepened_corpus)
```

#### 구현 순서

1. `syzbot_mining.py` 구현 (독립 모듈, 외부 의존성 없음)
2. `vm_verify.py` 구현 (Fuzz.py의 runFuzzer 재사용)
3. `agent_loop.py` 통합
4. 테스트: case 0 (tcindex_alloc_perfect_hash)으로 검증

#### 기대 효과

- syzbot reproducer가 있는 케이스: **즉시 dist=0 달성** (reproducer가 이미 해당 함수 도달)
- reproducer 없는 케이스: iterative deepening으로 **라운드당 1홉씩 진행**
- 기존 fuzzer 대비: mutation이 seed를 파괴하지 않으므로 multi-step seed 보존

---

## V5 — Cross-file Call Chain 자동 탐지 + Corpus 보존 (2026-04-07)

### 배경

V4.4 구현(syzbot_mining.py, vm_verify.py) 후, 기존 seed를 `verify_seed.py`로 직접 VM에서 검증한 결과 **seed 자체가 타겟에 도달하지 못함**을 확인. syzkaller의 처리 문제가 아니라 **LLM이 올바른 호출 경로를 모른 채 seed를 생성**하는 것이 근본 원인.

### Seed 검증 결과 (verify_seed.py)

| Case | Seed | Best dist | 분석 |
|------|------|:---------:|------|
| 0 | llm_seed (prio+tcindex 2-step) | 2010 | tcindex_change까지 도달, alloc_perfect_hash 미진입 |
| 2 | codegen_seed (pfifo/bfifo) | 10 | **tbf seed가 아예 없음** — 잘못된 호출 경로 사용 |

Case 2 결정적 발견: `fifo_set_limit`은 직접 호출이 아니라 `tbf_change() → qdisc_change() → fifo_set_limit()` 경로로만 도달 가능. codegen은 pfifo를 직접 생성하고 있었음 → 완전히 다른 코드 경로.

### 근본 원인 분석: 모든 실패 케이스의 공통 문제

**`extract_distance_roadmap()`의 두 가지 결함:**

**결함 1: `d < current_dist_min` 비교 (strict less-than)**

```python
# 기존 코드
if 0 < d < current_dist_min and fn != target_function:
    stones.append(...)
```

Case 2에서 `current_dist_min=10`, `tbf_change`의 min_dist=10 → `0 < 10 < 10`은 **false** → stepping stone에서 제외.
이것이 project.md V4.1에서 발견한 "dist가 가까운 케이스에서 오히려 소스 정보가 없는 역설"의 정확한 원인.

**결함 2: 타겟 함수의 실제 caller를 탐지하지 않음**

.dist 파일에서 모든 함수를 수집하지만, 그 중 어느 것이 타겟을 **실제로 호출**하는지 알 수 없음.
dist=10인 함수가 수백 개(ipoib, sunrpc, ath9k 등 무관한 드라이버)인데 `tbf_change`가 그 속에 묻힘.
결과적으로 LLM은 무관한 함수의 소스를 읽고 잘못된 방향으로 seed를 생성.

**실패 케이스별 caller 누락 현황:**

| Case | Target | 실제 Caller | 같은 .dist 파일? | 기존 파이프라인에서 발견? |
|------|--------|------------|:---:|:---:|
| 0 | tcindex_alloc_perfect_hash | tcindex_set_parms | ✓ (같은 파일) | ✗ (.dist에 미포함) |
| 1 | qdisc_create | tc_modify_qdisc | ✓ | ✓ (하지만 우선순위 낮음) |
| 2 | fifo_set_limit | **tbf_change** | **✗ (다른 파일!)** | **✗** |
| 6 | tcf_exts_init_ex | **fl_change** | **✗ (다른 파일!)** | **✗** |
| 7 | nf_tables_newrule | nft_rule_lookup_byid | ✓ | ✗ |
| 9 | xfrm_state_find | **xfrm_tmpl_resolve_one** | **✗ (다른 파일!)** | **✗** |

Case 2, 6, 9는 caller가 다른 .dist 파일에 있어서 기존 파이프라인이 완전히 놓침.

### 구현 내용

**수정 1: Stepping stone 필터 완화 (`llm_enhance.py`)**

```python
# 수정 후: <= 비교 (같은 dist인 함수도 포함)
if 0 < d <= current_dist_min and fn != target_function:
    stones.append(...)
```

**수정 2: 타겟 함수의 실제 caller를 커널 소스에서 자동 탐지 (`llm_enhance.py`)**

`extract_distance_roadmap()`에 `src_dir` 파라미터 추가.
타겟 함수 이름을 커널 소스에서 grep → 호출 위치 발견 → 역방향으로 enclosing function 탐색.

```
grep "fifo_set_limit" srcs/case_2/**/*.c
  → sch_tbf.c:418: err = fifo_set_limit(q->qdisc, qopt->limit);
  → scan backwards from line 418 → find "static int tbf_change("
  → actual_callers = {"tbf_change"}
```

Caller를 stones 최상위에 배치하고 `is_caller=True` 태그 부여.
.dist에 없는 caller(예: `tcindex_set_parms`)도 `actual_callers` 리스트에 포함하여 소스 읽기 대상으로 등록.

**수정 3: Cross-file caller 자동 탐지 (`llm_enhance.py`)**

타겟 함수가 있는 .dist 파일을 식별하고, **다른 .dist 파일**에서 같은 dist 범위의 함수를 cross-file caller 후보로 수집.

**수정 4: Actual caller 소스 자동 주입 (`agent_loop.py`)**

`_enhance_for_distance_stall()`에서 `actual_callers`의 소스를 커널에서 읽어 snippet에 추가:
```
// ACTUAL CALLER OF fifo_set_limit: tbf_change in net/sched/sch_tbf.c:337
static int tbf_change(struct Qdisc *sch, struct nlattr *opt, ...)
{
    ...
    err = fifo_set_limit(q->qdisc, qopt->limit);  // ← 이 호출
    ...
}
```

**수정 5: Corpus 덮어쓰기 방지 (`agent_loop.py`)**

문제: 매 라운드 `llm_seed_{func}.db`, `codegen_seed_{func}.db`가 같은 경로에 덮어써짐.
`_add_seed_corpus`의 `path not in self.seed_corpus_list` 체크로 이전 내용이 사라짐.

수정:
- `_add_seed_corpus()`: 같은 경로가 재등록되면 타임스탬프 붙인 백업 생성 → 이전 라운드 seed 보존
- `_preserve_best_corpus()`: 라운드 종료 후 detailCorpus에서 best 20 프로그램을 `best_corpus_r{N}.db`로 보존 → 다음 라운드 merge에 포함

**수정 6: Seed 검증 스크립트 (`verify_seed.py` 신규)**

seed를 VM에서 직접 실행하여 실제 도달 거리를 측정하는 독립 스크립트.
- `--dry-run`: seed 내용만 표시 (ANYBLOB hex 디코딩 포함)
- VM 실행: procs=1 (최소 mutation), 단기간(90초) 실행 후 detailCorpus 분석
- "seed가 맞는데 syzkaller가 잘못 처리하는 건가, 아니면 seed 자체가 틀린 건가" 진단

### 수정 파일

| 파일 | 변경 | 설명 |
|------|------|------|
| llm_enhance.py | 수정 | `extract_distance_roadmap()`: `<=` 비교, actual caller 탐지, cross-file caller, `src_dir` 파라미터 |
| agent_loop.py | 수정 | actual caller 소스 주입, corpus 덮어쓰기 방지, best corpus 보존 |
| verify_seed.py | 신규 | seed 검증 스크립트 (dry-run + VM 실행) |

### V5 실험 결과

**실행 명령:**
```bash
python3 run_hunt.py fuzz --targets 0 1 2 6 7 9 -j 8 -uptime 2 \
  --agent-rounds 3 --agent-uptime 1 --proactive-seed --hunt-mode hybrid \
  -workdir /home/ai/work_real/workdir_v3_unified
```

**결과 요약:**

실험이 case 0에서 LLM API 타임아웃(opencode 300~600s)으로 인해 병목 발생.
약 3.5시간 동안 case 0만 처리, cases 1/2/6/7/9는 실행되지 않음.

| Case | Target | V4 결과 | V5 결과 | 비고 |
|------|--------|---------|---------|------|
| 0 | tcindex_alloc_perfect_hash | dist=2010 | dist=2010 (3라운드) | LLM 타임아웃으로 개선 불가 |
| 1 | qdisc_create | 미도달 | 미실행 | LLM 병목으로 미도달 |
| 2 | fifo_set_limit | 미도달 | 미실행 | |
| 6 | tcf_exts_init_ex | 미도달 | 미실행 | |
| 7 | nf_tables_newrule | 미도달 | 미실행 | |
| 9 | xfrm_state_find | 미도달 | 미실행 | |

**Case 0 상세:**
- Round 1: dist=2010 고착 (609s stall → 조기 종료)
- Round 2: merged 5 seed DBs (22 programs), dist=2010 고착
- Round 3: iterative deepening iteration 2에서 LLM codegen 타임아웃으로 중단
- V5 신규 기능 확인:
  - ✅ Actual caller 탐지: tcindex_set_parms 발견
  - ✅ Cross-file caller: tc_new_tfilter(1010), attribute_container(2010)
  - ✅ Corpus 보존: best_corpus_r1.db, r2.db 생성
  - ✅ Seed 백업: 타임스탬프 백업 정상 동작
  - ✅ Seed merge: 5 DB → 22 programs
  - ✅ syzbot mining: tcindex 재현기 1개 수집
  - ✅ Iterative deepening: 3회 반복 실행
  - ❌ LLM 호출: 전부 타임아웃 (300~600s)

**근본 원인 분석:**

V5의 코드 개선은 정상 동작하지만, LLM API(opencode/gpt-5.4-mini)가 타임아웃되어 핵심 기능인 semantic seed 개선이 작동하지 않음. dist=2010은 tc_new_tfilter(1010)를 호출하지 못하는 상태로, RTM_NEWTFILTER 메시지를 보내기 전에 qdisc 생성(RTM_NEWQDISC)이 선행되어야 하지만 현재 seed는 이 순서를 갖추지 못함.

**다음 단계 (V5.1):**

1. LLM 타임아웃 문제 해결: 로컬 모델 또는 더 빠른 API 사용
2. LLM 없이도 작동하는 rule-based seed 생성기 구현 (tc subsystem의 경우 qdisc→tfilter 순서를 하드코딩하지 않고 도메인 룰로 추론)
3. 실험 재실행: LLM 의존성 제거 후 6개 실패 케이스 전체 실행

---

## V5.1: LLM 프롬프트 최적화 (2026-04-08)

### 문제점

V5 실험에서 LLM 호출이 전부 타임아웃(300~600s)되어 핵심 기능이 작동하지 않음.
원인 분석 결과, LLM 프롬프트에 **불필요한 raw 데이터**가 대량 포함되어 있었음:

| # | 섹션 | 크기 | LLM 추론 필요? | 판정 |
|---|------|------|----------------|------|
| 1 | 고정 텍스트 (지시사항) | ~800자 | ✅ 필요 | 유지 |
| 2 | semantic_section (iteration feedback) | ~3000자 | 반반 | **Python으로 전처리** |
| 3 | roadmap_section (stepping stones) | ~300자 | ❌ 데이터 | **Python으로 전처리** |
| 4 | snippets_section (**커널 소스 원문**) | ~5000자+ | ❌ 데이터 | **Python으로 전처리** |
| 5 | syzlang type injection (**타입 정의 전체**) | ~3000자+ | ❌ 데이터 | **Python으로 전처리** |
| 6 | resource_section | ~500자 | ❌ 데이터 | **Python으로 전처리** |
| 7 | corpus_section (best program) | ~500자 | ⚠️ 참고용 | 축약 유지 |
| 8 | close_distance_hint | ~200자 | ✅ 필요 | 유지 |

**핵심 통찰**: LLM이 만드는 것은 `struct.pack()`으로 netlink 메시지를 만드는 Python 스크립트.
이를 위해 필요한 정보(nlmsg_type, NLA attr index/타입, 조건 만족 값, syscall 순서)는 전부 Python으로 미리 계산 가능.
커널 소스 원문이나 syzlang 타입 정의 전체를 LLM에 넘길 필요가 없음.

### 해결: seed_planner.py

`seed_planner.py` 모듈을 신규 생성하여, 커널 소스 + .dist 파일 + syzlang에서 **결론만 추출**:

- `extract_branch_conditions()`: 커널 소스에서 `if (expr)` 패턴을 regex로 추출 → 구체적 constraint로 변환
- `extract_nla_policy()`: NLA 속성 정의에서 이름/타입/크기만 추출
- `determine_syscall_sequence()`: target_file의 서브시스템별 필수 syscall 순서 자동 결정
  - `net/sched/cls_*.c` → socket → RTM_NEWQDISC(htb) → RTM_NEWTFILTER(kind)
  - `net/netfilter/*` → socket → NEWTABLE → NEWCHAIN → NEWRULE
  - `net/xfrm/*` → socket → NEWSA → NEWPOLICY
  - `net/bluetooth/*`, `net/sctp/*`, `net/llc/*`, `mm/*` 등 각 서브시스템별 처리
- `build_compact_plan()`: 위 결과를 ~1000자 텍스트로 통합

**변환 예시** (case 0, tcindex_alloc_perfect_hash):
```
기존 프롬프트: ~12000자 (커널 소스 + syzlang + roadmap + feedback 중복)
↓
컴팩트 plan: 971자

TARGET: tcindex_alloc_perfect_hash in net/sched/cls_tcindex.c
CURRENT DISTANCE: 2010
SYSCALL SEQUENCE:
  1. socket$nl_route(0x10, 0x3, 0x0) → r0
  2. sendmsg RTM_NEWQDISC kind="htb" handle=0x10000 parent=0xffffffff
  3. sendmsg RTM_NEWTFILTER kind="tcindex" parent=0x10000
CONDITIONS to satisfy:
  - TCA_TCINDEX_HASH must be set
  - TCA_TCINDEX_MASK must be set
  - cp->shift > 16
  ...
```

### 수정 파일

| 파일 | 변경 | 설명 |
|------|------|------|
| seed_planner.py | 신규 | 커널소스/syzlang → 컴팩트 plan 변환기 |
| llm_enhance.py | 수정 | 3개 함수의 프롬프트를 compact plan으로 교체, 타임아웃 600s→120s |
| semantic_seed.py | 수정 | llm_semantic_analysis()에서 중복 SOURCE SNIPPETS 제거 |

**수정된 함수별 상세:**

| 함수 | 변경 전 | 변경 후 |
|------|---------|---------|
| `llm_generate_seed_via_codegen()` | raw source + syzlang + roadmap, timeout=600s | `build_compact_plan()`, timeout=120s |
| `llm_generate_seed_program()` | raw source + syzlang + subsystem instructions, timeout=600s | `build_compact_plan()`, timeout=120s |
| `llm_enhance_callfile_for_distance()` | raw roadmap + source, timeout=180s | `build_compact_plan()`, timeout=120s |
| `llm_semantic_analysis()` | 정적분석 결과 + SOURCE SNIPPETS (중복), timeout=300s | SOURCE SNIPPETS 제거, timeout=300s |

### V5.1 실험 결과 (2026-04-08)

**변경사항 요약**: opencode→ollama(mistral:7b) 전환, seed_planner.py로 프롬프트 12000자→1000자 축소

| Case | Target | V4 dist | V5.1 dist | 결과 | 비고 |
|------|--------|---------|-----------|------|------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 2010 | ❌ 변화없음 | tcindex deprecated |
| 1 | qdisc_create | 2010 | 0 | ✅ 성공 | V5.1에서 새로 해결 |
| 2 | fifo_set_limit | 10 | 10 | ❌ 변화없음 | tbf 프로그램 0개 |
| 6 | tcf_exts_init_ex | 2010 | 2010 | ❌ 변화없음 | case 0과 동일 패턴 |
| 7 | nf_tables_newrule | 0 | 10 | ⚠️ 퇴보 | V4에서 dist=0이었음 |
| 9 | xfrm_state_find | 3010 | 3010 | ❌ 변화없음 | xfrm sendmsg 3/3261 |

**성과**: Case 1 신규 해결 (dist 2010→0), LLM 타임아웃 문제 해결
**퇴보**: Case 7 (dist 0→10, 비결정적 — V4에서도 dist=0 도달했으므로 재실행으로 복구 가능)

---

### 실패 케이스 근본 원인 분석 및 해결 방안

#### Case 0 (tcindex, dist=2010) & Case 6 (tcf_exts_init_ex, dist=2010)

**근본 원인**: TC 서브시스템은 multi-step stateful sequence 필요 (qdisc 생성 → filter 추가). syzkaller의 byte-level mutation이 이 순서를 파괴함.

**증거**:
- detailCorpus에서 `sendmsg$nl_route_sched` 프로그램은 존재하나 dist가 2010에서 줄지 않음
- tcindex는 Linux 커널에서 deprecated됨 — syzbot reproducer도 최신 커널에서 실패

**해결 방안**:
1. **callfile에 RTM_NEWQDISC step 추가**: `inp_0.json`의 `fifo_set_limit` 항목처럼, `Relate`에 qdisc 생성 syscall을 명시적으로 포함
2. **seed program 고정**: agent_loop.py에서 R1 seed에 정적으로 생성한 multi-step program을 주입 (qdisc→filter 순서 고정)
3. **mutation 보호**: syzkaller의 `mutate` 단계에서 첫 N개 syscall을 보호하는 옵션 (현재 syzkaller에 없음 — 구현 필요)

**검증**: 방안 1은 callfile 수정만으로 가능, 가장 빠름. 단, tcindex가 deprecated이므로 최신 커널에서 근본적으로 동작 불가능할 수 있음. Case 6(cls_api.c)는 tcindex와 독립적이므로 callfile 수정으로 효과 기대 가능.

#### Case 2 (fifo_set_limit, dist=10)

**근본 원인**: **callfile 문제**. `inp_0.json`에서 `fifo_set_limit`의 `Relate`가 `[socket, setsockopt, setsockopt]`로, tbf qdisc 생성 단계가 완전히 누락됨. 경로: `tbf_change() → fifo_set_limit()` 이므로 tbf qdisc를 먼저 생성해야 하지만, 13864개 corpus 프로그램 중 tbf 관련 프로그램이 **0개**.

**증거**:
- `grep -c tbf detailCorpus.txt` = 0
- callfile의 fifo_set_limit Relate에 tbf 관련 syscall 없음
- dist=10은 fifo_set_limit 근처까지는 도달하지만 tbf_change 경로를 타지 못함

**해결 방안**:
1. **callfile 수정 (필수)**: `fifo_set_limit`의 `Relate`에 `sendmsg$nl_route_sched` (RTM_NEWQDISC kind="tbf")를 추가
2. **seed_planner.py에 tbf 경로 추가**: `determine_syscall_sequence()`에서 `sch_tbf.c` → tbf qdisc 생성 시퀀스를 자동 감지하도록 수정

**검증**: 이 방안이 맞는 근거:
- fifo_set_limit은 `net/sched/sch_fifo.c`에 있고 `tbf_change()`에서만 호출됨
- tbf_change는 RTM_NEWQDISC(kind="tbf") 또는 RTM_CHANGEQDISC로만 도달 가능
- 현재 callfile에 이 경로가 없으므로 fuzzer가 절대 tbf 프로그램을 생성할 수 없음
- **callfile 수정이 가장 확실한 해결책**

#### Case 9 (xfrm_state_find, dist=3010)

**근본 원인**: xfrm_state_find는 복잡한 xfrm state/policy 구조체를 필요로 하며, 3261개 corpus 중 xfrm sendmsg 프로그램이 3개뿐. 7b 모델이 xfrm 구조체를 올바르게 생성하지 못함.

**증거**:
- detailCorpus에서 xfrm sendmsg 비율: 3/3261 (0.09%)
- dist=3010 = callgraph 3hop 이상 떨어져 있음 — xfrm_state_find까지의 경로 자체를 못 탐
- callfile에는 xfrm 관련 syscall이 존재하나 fuzzer가 유효한 xfrm 메시지를 구성하지 못함

**해결 방안**:
1. **더 큰 LLM 사용**: mistral:7b → codellama:13b 또는 외부 API (GPT-4 등)로 xfrm 구조체 생성 품질 향상
2. **정적 seed 주입**: syzbot의 기존 xfrm reproducer를 seed corpus에 포함 — xfrm_state_add + xfrm_policy_add 시퀀스를 기반 seed로 사용
3. **callfile 보강**: `xfrm_state_find`의 `Relate`에 XFRM_MSG_NEWSA → XFRM_MSG_NEWPOLICY → traffic trigger 순서를 명시

**검증**: xfrm_state_find는 패킷 처리 중 호출되므로, 단순히 xfrm netlink 메시지 전송만으로는 부족. state와 policy를 생성한 후 실제 트래픽(sendmsg on AF_INET)이 필요. 이 점에서 방안 2(기존 reproducer 기반)가 가장 현실적.

---

### 우선순위 정리

| 순위 | 작업 | 대상 | 난이도 | 기대 효과 |
|------|------|------|--------|-----------|
| 1 | Case 2 callfile 수정 (tbf 추가) | case 2 | 낮음 | 높음 (근본 원인 해결) |
| 2 | Case 0/6 seed에 qdisc→filter 고정 시퀀스 주입 | case 0, 6 | 중간 | 중간 |
| 3 | Case 7 재실행 (V4에서 성공했으므로) | case 7 | 낮음 | 높음 |
| 4 | Case 9 정적 xfrm seed 주입 | case 9 | 중간 | 중간 |
| 5 | 더 큰 LLM 모델 전환 | 전체 | 높음 | 불확실 |

---

## V6 — CallGraph Proximity Filter Fix (code done, rebuild needed, 2026-04-08)

### 근본 원인 (verified)

`syzdirect_function_model/src/lib/CallGraph.cc` 의 LLVM 18 opaque-pointer 대응용 proximity filter (lines 731–793) 가 ops table 디스패처(`tbf_change`, `tcindex_*`, `nf_tables_*`, `xfrm_*` 등 12,009개 비-tracepoint 함수)의 indirect call edges 를 통째로 비워버린다. 결과적으로 forward `Callees[CI]` 가 비어 있어 `kernel_signature_full` 에 sendmsg → … → tbf_change 같은 경로가 전혀 생성되지 않고, 모든 case 0/2/6/9 의 callfile/distance 가 generic stub 로 떨어진다.

**Verified evidence**:
- `interfaces/case_2/log` 에 `no proximity matches, clearing` 25,417건, tracepoint 제외 12,009건.
- 실패 case 의 모든 핵심 함수가 cleared 목록에 존재 (tbf_change, tcindex_bind_class, cls_bpf_change, tc_modify_qdisc, nf_tables_newrule, xfrm_state_find …).
- `interfaces/case_2/kernel_signature_full` 에 sched/qdisc/netlink_route 경로가 0건 (오직 tcp/udp/sctp/dccp/l2tp/ping/raw/mptcp sendmsg 만 존재).
- `CodeFeatures.cc` line 526/534/686/693/828/1037/1207/1529/1678/1770/1826/2041 모두 forward 탐색에 `GlobalCtx.Callees[callInst]` 사용 → FS.clear() 가 직접적으로 signature 추출을 끊는다.
- `CallGraph.cc:794` `Ctx->Callees[CI] = FS;` 가 clear 이후에 실행되므로 forward edge 는 영구적으로 손실.

### proximity filter 의 두 가지 버그

1. **`pos = i + 1` 위치 버그** (line 745–752): `if` 블록 밖에서 매 iteration 마다 `pos` 가 갱신되므로, slashes 가 4 에 도달하지 못하면 `pos` 가 `callerPath.size()` 가 되어 `callerDir` = 전체 경로. 그러면 어떤 callee 도 prefix 매칭에 성공하지 못해 `filtered.empty()` 분기로 빠지고 FS.clear() 발생.
2. **모든 ops dispatcher 를 noise 로 취급**: 진짜 noise (tracepoint __traceiter_*, perf_trace_*, trace_event_raw_event_*) 와 정상 ops table dispatch 를 구분하지 않고 동일하게 잘라낸다.

### 수정 계획

**Step 1 — pos 계산 버그 수정**
```cpp
size_t slashes = 0, pos = 0;
for (size_t i = 0; i < callerPath.size(); ++i) {
    if (callerPath[i] == '/') {
        if (++slashes == 4) { pos = i; break; }
    }
}
if (pos == 0) pos = callerPath.size();   // fallback: 전체 경로
```

**Step 2 — tracepoint 만 안전하게 제거**
indirect call 의 caller 이름이 tracepoint 패턴에 매칭될 때만 FS.clear() 를 허용:
```cpp
auto callerName = F->getName();
bool isTracepointNoise =
    callerName.startswith("__traceiter_") ||
    callerName.startswith("perf_trace_")  ||
    callerName.startswith("trace_event_raw_event_") ||
    callerName.startswith("__bpf_trace_");
```

**Step 3 — 비-tracepoint 는 보존**
proximity filter 는 logging/info 만 남기고 FS.clear() 분기를 제거. 200 초과 hard cap 도 비-tracepoint 에 한해 제거 (또는 1000 까지 완화). 이렇게 해야 ops table dispatch 가 살아남아 `kernel_signature_full` 에 sched/qdisc/netfilter/xfrm 경로가 채워진다.

**Step 4 — 동일 변경을 `syzdirect_kernel_analysis/src/lib/CallGraph.cc` 에도 반영** (target_analyzer 도 같은 LLVM pass 사용).

### 검증 절차

1. function_model + kernel_analysis 재빌드.
2. `interface_generator` 를 case 2 에 대해 재실행.
3. `interfaces/case_2/kernel_signature_full` 에 다음 grep 결과가 ≥1 건이어야 한다:
   - `sendmsg.*tbf_change`
   - `tc_modify_qdisc`
   - `nf_tables_newrule`
4. `interfaces/case_2/log` 의 `no proximity matches, clearing` 건수가 12,009 → 0 (tracepoint 만 남으면 OK).
5. `target_analyzer` 재실행 후 `CompactOutput.json` 에 tbf 관련 BB constraint 존재 확인.
6. `PrepareForFuzzing` → `inp_0.json` 에 tbf 관련 syscall (`sendmsg$nl_route_sched_qdisc_tbf` 등) 가 자동 등장하는지 확인.
7. case 2 단독 fuzzing 30 분 실행 후 distance 감소율이 V5.1 (0%) → 양수로 바뀌는지 확인.

### 적용 상태 (2026-04-09)

- **코드 수정 완료**: `syzdirect_function_model/src/lib/CallGraph.cc`, `syzdirect_kernel_analysis/src/lib/CallGraph.cc` 양쪽 모두 V6 패치 적용됨 (git diff 확인).
  - tracepoint dispatcher (`__traceiter_*`, `perf_trace_*`, `trace_event_raw_event_*`, `__bpf_trace_*`) 만 FS.clear()
  - 비-tracepoint는 1000 soft cap + proximity filter 유지
  - `pos = i + 1` 버그 수정됨
- **빌드 완료**: `interface_generator` 바이너리 V6 패치로 재컴파일됨 (Apr 9 11:16).

### V6 실험 결과 (2026-04-09~10)

**`workdir_v6_full`에서 case_0 interface_generator 실행 완료.**

**interface_generator 결과:**
- `kernel_signature_full`: 20,926줄 생성 (정상 완료)
- proximity filter clearing 로그: **0건** — V6 패치 적용 확인
- sendmsg 항목: 17개 (tcp, udp, sctp, l2tp, dccp, mptcp, raw, ping)
- **`sendmsg$nl_route` 항목: 0건** — netlink route 경로 여전히 누락
- `tcindex`, `tbf_change`, `tc_modify_qdisc` 관련 signature: **0건**

**파이프라인 진행 상태:**
- interface_generator: case_0만 완료 (다른 case는 미실행)
- target_analyzer (`tpa/`): case 7, 9, 10, 11만 존재 (이전 실행 잔여)
- `kwithdist/`: 비어있음 (distance instrumentation 미실행)
- `fuzzres/`: 비어있음 (퍼징 미실행)
- `fuzzinps/`: case 0,1,2,5,6,7,9,10,11에 callfile 존재 (round1~4까지)

**핵심 발견: V6 proximity filter 수정만으로는 부족**

proximity filter가 callee를 clear하는 문제는 해결됐지만, `sendmsg → netlink_sendmsg → rtnetlink_rcv → tc_modify_qdisc → tbf_change` 같은 **netlink dispatch 경로 자체가 kernel_signature_full에 없다.**

이는 proximity filter 이전 단계에서 이미 edge가 누락되는 것을 의미:
1. **netlink 디스패치는 function pointer table을 통한 간접 호출** (`rtnl_msg_handlers[RTM_NEWQDISC]` = `tc_modify_qdisc`). LLVM의 indirect call analysis가 이 매핑을 resolve하지 못할 수 있음
2. V6 이전에 proximity filter가 이 edge를 clear한 것이 아니라, **애초에 CallGraph에 이 edge가 생성되지 않았을 가능성**
3. sendmsg 17개가 전부 직접 프로토콜 핸들러 (tcp_sendmsg 등) — socket type으로 정적 resolve 가능한 것만 포함

**검증 필요 사항:**
- `CallGraph.cc`의 indirect call resolution이 `rtnl_register(RTM_NEWQDISC, tc_modify_qdisc, ...)` 패턴을 resolve하는지 확인
- V6 이전 (workdir_v3_unified)의 `kernel_signature_full`에 `sendmsg$nl_route`가 있었는지 비교 확인

### 전체 실험 결과 종합 (V1~V6, 2026-04-10 기준)

**최신 fuzzing 결과 (workdir_v3_unified + workdir_v3_ga 통합):**

| Case | Target | Best dist | Exec | Workdir | 최종 결과 |
|------|--------|:---------:|-----:|---------|-----------|
| 0 | tcindex_alloc_perfect_hash | 2010 | 599 | v3_unified | ❌ FAIL |
| 1 | qdisc_create | **0** | 78 | v3_unified | ✅ V5.1에서 성공 |
| 2 | fifo_set_limit | 10 | 1685 | v3_unified | ❌ FAIL |
| 3 | tcp_cleanup_congestion_control | **0** | 1701 | v3_ga | ✅ V2에서 성공 |
| 4 | move_page_tables | 1000 | 301 | v3_unified | ⚠️ 이전 V3에서 성공했으나 최근 퇴보 |
| 5 | sco_sock_create | **0** | 154 | v3_unified | ✅ V3에서 성공 |
| 6 | tcf_exts_init_ex | 2010 | 701 | v3_unified | ❌ FAIL |
| 7 | nf_tables_newrule | 10 | 2869 | v3_unified | ⚠️ V4에서 성공, 최근 퇴보 |
| 8 | sctp_sf_do_prm_asoc | **0** | - | (V2 baseline) | ✅ V2에서 성공 |
| 9 | xfrm_state_find | 2010 | 1783 | v3_unified | ❌ FAIL |
| 10 | packet_snd | **0** | 28525 | v3_unified | ✅ V2에서 성공 |
| 11 | llc_ui_sendmsg | **0** | 4166 | v3_unified | ✅ V3에서 성공 |

**성공: 7/12 (58%)** — V2 시점(3/12=25%) 대비 대폭 향상

**완고한 실패 4개의 공통 근본 원인:**
- Case 0, 2, 6: TC 서브시스템 — netlink route dispatch가 kernel_signature에 없어 callfile이 부정확
- Case 9: xfrm 서브시스템 — 동일한 netlink dispatch 누락 문제 + 복잡한 state/policy 선행 조건

**이 4개의 근본 원인은 V6 이후에도 미해결**: proximity filter 수정은 tracepoint clearing만 해결. netlink dispatch table의 indirect call resolution은 CallGraph.cc의 type-based analysis 범위 밖일 수 있음.

### 리스크

- 지나친 callee 보존으로 distance computation 시간/메모리 폭증 가능 → 1000 cap 유지.
- 일부 기존 case (V1–V5 에서 성공한 case) 의 distance 가 변할 수 있어 회귀 테스트 필요 (case 1, 3, 4, 5, 8 모두 재측정).
- Case 4, 7이 이전에 성공했다가 최근 퇴보 — 비결정적 퍼징 특성. 재실행으로 복구 가능.

### 다음 단계 → V7 (Indirect Dispatch Resolver)로 진행

---

## V7 — Indirect Dispatch Resolver (2026-04-10)

### 배경 및 근본 원인

V6에서 proximity filter를 수정했지만, `kernel_signature_full`에 TC/netfilter/xfrm 경로가 여전히 0건.
`kernelCode2syscall.json` (k2s)에도 `tc_modify_qdisc`, `nf_tables_newrule`, `xfrm_state_find` 등이 **아예 없음**.

**근본 원인**: 커널의 주요 서브시스템은 **function pointer registration 패턴**으로 핸들러를 등록하고, 런타임에 indirect call로 디스패치함. LLVM 기반 정적 분석(CallGraph.cc)이 이 패턴을 resolve 못함.

**확인된 주요 패턴 (23개+)**:
- `rtnl_register()` — TC qdisc/filter (case 0, 1, 2, 6)
- `nfnetlink_subsys_register()` — nftables (case 7)
- `xfrm_register_km()` — xfrm (case 9)
- `genl_register_family()` — nl80211, devlink, ethtool
- `sock_register()` — 모든 AF_* 패밀리
- `register_qdisc()`, `register_tcf_proto_ops()`, `tcf_register_action()` — TC 내부
- `nf_register_net_hook()`, `xt_register_match()`, `nft_register_expr()` — netfilter 내부
- `tcp_register_congestion_control()` — TCP CC
- `inet_register_protosw()` — inet protocol-socket binding
- `bt_sock_register()` — Bluetooth
- `crypto_register_alg()`, `af_alg_register_type()` — crypto/AF_ALG
- `security_add_hooks()` — LSM
- `elv_register()` — block I/O scheduler
- `vsock_core_register()` — vsock transport
- 기타: `dev_add_pack()`, `perf_pmu_register()`, `register_key_type()` 등

### 설계

**접근법: 커널 소스 레벨에서 registration 패턴을 grep → handler-to-syscall 매핑 자동 생성 → k2s 보강**

LLVM CallGraph를 고치는 대신, 소스 레벨에서 indirect call edge를 복원:

```
커널 소스에서:
  rtnl_register(PF_UNSPEC, RTM_NEWQDISC, tc_modify_qdisc, ...) 발견
  → tc_modify_qdisc는 sendmsg$nl_route를 통해 도달
  → k2s에 "tc_modify_qdisc" → {"none": ["sendmsg$nl_route_sched"]} 추가
```

**신규 모듈: `indirect_dispatch_resolver.py`**

#### 핵심 설계 원칙

1. **일반화**: 특정 서브시스템 하드코딩이 아니라, registration 패턴을 자동 발견
2. **2단계 분석**:
   - Phase 1: 커널 소스에서 `*_register*()` 호출 grep → `{registration_func → [handler_func]}` 매핑
   - Phase 2: 각 registration 패턴에 대해 syscall entry point 결정 → handler→syscall 매핑
3. **k2s 보강**: 기존 k2s에 누락된 handler→syscall 매핑을 추가
4. **파이프라인 통합**: interface_generator 실행 후, target_analyzer 실행 전에 k2s 보강

#### 구현 계획

**Phase 1: Registration Pattern Scanner**

```python
def scan_registration_patterns(src_dir: str) -> dict[str, list[dict]]:
    """커널 소스에서 *_register*() 호출을 grep하여 handler 함수 추출.
    
    Returns: {
        "rtnl_register": [
            {"args": ["PF_UNSPEC", "RTM_NEWQDISC", "tc_modify_qdisc", "tc_dump_qdisc", "NULL"],
             "file": "net/sched/sch_api.c", "line": 2053},
            ...
        ],
        "genl_register_family": [...],
        ...
    }
    """
```

구현 방법:
- 알려진 registration 함수 이름 리스트 (23개) 순회
- `grep -rn "registration_func(" src_dir/` 실행
- 각 매칭에서 인자를 파싱하여 handler 함수 이름 추출
- 함수 포인터가 아닌 상수(NULL, 0 등)는 필터링

**Phase 2: Handler-to-Syscall Mapper**

```python
# Registration 패턴별 syscall 매핑 규칙
DISPATCH_RULES = {
    "rtnl_register": {
        # rtnl_register(family, msgtype, doit, dumpit, flags)
        "handler_arg_indices": [2, 3],  # doit, dumpit이 handler
        "syscall_template": "sendmsg$nl_route",
        "socket_type": "socket$nl_route",
    },
    "nfnetlink_subsys_register": {
        "handler_arg_indices": None,  # ops struct 내부
        "syscall_template": "sendmsg$nl_netfilter",
        "socket_type": "socket$nl_netfilter",
    },
    "genl_register_family": {
        "handler_arg_indices": None,  # family->ops[].doit
        "syscall_template": "sendmsg$nl_generic",
        "socket_type": "socket$nl_generic",
    },
    "register_qdisc": {
        "handler_arg_indices": None,  # Qdisc_ops struct
        "syscall_template": "sendmsg$nl_route_sched",
        "socket_type": "socket$nl_route",
    },
    # ... 각 패턴별 규칙
}
```

**Phase 3: k2s Augmentation**

```python
def augment_k2s(k2s_path: str, src_dir: str, target_function: str) -> dict:
    """기존 k2s에 indirect dispatch 매핑 추가.
    
    1. scan_registration_patterns()로 모든 등록 패턴 수집
    2. target_function의 caller chain에서 등록된 handler 찾기
    3. handler → syscall 매핑을 k2s에 추가
    4. 보강된 k2s 반환
    """
```

target_function에서 역추적:
```
target: tcindex_alloc_perfect_hash
  ← called by: tcindex_set_parms (same file, grep으로 발견)
  ← called by: tcindex_change (same file)
  ← tcindex_change는 Qdisc_ops.change에 등록됨 (register_qdisc 패턴)
  ← register_qdisc → sendmsg$nl_route_sched
```

**Phase 4: Pipeline Integration**

`pipeline_dataset.py`에서 interface_generator 실행 후:
```python
# After interface_generator generates k2s
from indirect_dispatch_resolver import augment_k2s
augmented = augment_k2s(k2s_path, src_dir, target_function)
# Write augmented k2s back
json.dump(augmented, open(k2s_path, 'w'))
# Then proceed to target_analyzer
```

#### 수정 파일

| 파일 | 변경 | 설명 |
|------|------|------|
| indirect_dispatch_resolver.py | **신규** | registration pattern scanner + handler-syscall mapper + k2s augmenter |
| pipeline_dataset.py | 수정 | interface_generator 후 k2s 보강 호출 추가 |

### V7 구현 완료 (2026-04-10)

**구현된 파일:**
- `indirect_dispatch_resolver.py` (신규, ~960줄): 18개 registration 패턴 + subsystem fallback
- `pipeline_dataset.py` (수정): step3에서 k2s 보강 자동 호출

**핵심 기능:**
1. **Registration Pattern Scanner**: 커널 소스에서 18개 `*_register*()` 패턴 자동 탐지 (rtnl, TC qdisc/classifier/action, netfilter, xfrm, genl, bluetooth, crypto, vsock 등)
2. **Ops Struct Resolver**: `register_qdisc(&tbf_qdisc_ops)` → `sch_tbf.c`의 `Qdisc_ops` struct에서 `tbf_change` 등 함수 포인터 추출
3. **Caller Chain Tracer**: BFS로 target_function → registered handler까지 caller chain 역추적
4. **Subsystem Fallback**: trace 실패 시 파일 경로 기반 서브시스템 규칙 적용 (net/xfrm/ → sendmsg$nl_xfrm 등)
5. **k2s Augmentation**: 발견된 handler→syscall 매핑을 kernelCode2syscall.json에 주입

**검증 결과:**

| Case | Target | Chain | Syscall | Pattern |
|------|--------|-------|---------|---------|
| 0 | tcindex_alloc_perfect_hash | → tcindex_set_parms → tcindex_change | sendmsg$nl_route_sched | register_tcf_proto_ops ✅ |
| 2 | fifo_set_limit | → tbf_change | sendmsg$nl_route_sched | register_qdisc ✅ |
| 6 | tcf_exts_init (실제 타겟) | → u32_change | sendmsg$nl_route_sched | register_tcf_proto_ops ✅ |
| 7 | nf_tables_newrule | → ...→ nf_tables_abort | sendmsg$nl_netfilter | nfnetlink_subsys_register ✅ |
| 9 | xfrm_state_find | (subsystem rule) | sendmsg$nl_xfrm | net/xfrm/ ✅ |

**스캔 통계 (case_0 커널 소스 기준):**
- 18개 패턴 중 11개에서 결과 발견
- 총 registration 인스턴스: ~280개
- 총 핸들러 함수: ~1000개+
- 스캔 시간: ~20초

**미해결 패턴:**
- `nft_register_expr`: nftables expression type 초기화 패턴이 `}};` 대신 `};`로 끝나는 등 파싱 차이
- `genl_register_family`: ops 배열이 별도 static const 배열로 정의됨
- `elv_register`, `inet_protosw`: struct 초기화 패턴 차이

### V7 통합 테스트 결과 (2026-04-10)

k2s augmentation 후 target_analyzer 재실행하여 CompactOutput.json의 target syscall 검증.

| Case | Target | Dispatch Chain | Augmented syscall | TA result | Status |
|------|--------|----------------|-------------------|-----------|--------|
| 0 | tcindex_alloc_perfect_hash | `→ tcindex_change → register_qdisc` | sendmsg$nl_route_sched | rank=0 ✅ | **성공** |
| 9 | xfrm_state_find | subsystem fallback `net/xfrm/` | sendmsg$nl_xfrm | rank=0 ✅ | **성공** |
| 2 | fifo_set_limit | `→ tbf_change → register_qdisc` | sendmsg$nl_route_sched | bitcode 미빌드 | k2s 보강 완료, TA 미실행 |
| 6 | tcf_exts_init_ex | (인프라 없음) | - | - | workdir 미구축 |

**핵심 발견:**
- 18개 registration pattern 스캔 → 392 registrations, 899 handler functions 발견 (case별 커널 소스 기준)
- BFS trace (max_depth=6)로 `tcindex_alloc_perfect_hash → tcindex_change` 1-hop 체인 발견
- `xfrm_state_find`은 packet-processing 경로라 직접 handler trace 불가 → SUBSYSTEM_RULES fallback으로 해결
- case 0: k2s 207→210 entries, case 9: 205→206 entries, case 2: 241→243 entries

**workdir 인프라 현황:**
- workdir_v6_full: case 0, 1만 bitcode 빌드됨 (dataset_build.xlsx에 2개만 포함)
- workdir_cases_7_9_10_11: case 7, 9, 10, 11 빌드됨
- workdir_v3_ga: case 0~3 interfaces 있으나 bitcode 없음
- case 2, 6 TA 실행하려면 해당 커널의 bitcode 빌드 필요

### 다음 단계

1. **Case 2, 6 bitcode 빌드**: pipeline_dataset.py로 bitcode 생성 후 V7 TA 실행
2. **퍼징 실험**: case 0, 9의 보강된 callfile로 실제 퍼징 → dist=0 달성 여부 확인
3. **미해결 패턴 추가**: genl_register_family, nft_register_expr 파싱 개선
4. **Case 4, 7 재실행**: 비결정적 퇴보 복구

### Latest Fuzzing Snapshot Reconciliation (2026-04-11)

`workdir_v3_unified/fuzzres/`의 현재 산출물을 기준으로 round/run0 전체 `detailCorpus.txt`를 다시 집계했다.
이 스냅샷은 문서 앞부분의 일부 중간 메모보다 최신이며, 특히 case 1/7/9/11의 성공 여부가 이전 표와 다르다.

| Case | Target | Latest best dist | First observed at | 현재 판정 |
|------|--------|:----------------:|-------------------|-----------|
| 0 | tcindex_alloc_perfect_hash | 2010 | agent_round_1 | ❌ FAIL |
| 1 | qdisc_create | 0 | agent_round_2 | ✅ SUCCESS |
| 2 | fifo_set_limit | 10 | agent_round_1 | ❌ FAIL |
| 4 | move_page_tables | 1000 | run0 | ⚠️ REGRESSION |
| 5 | sco_sock_create | 0 | agent_round_1 | ✅ SUCCESS |
| 6 | tcf_exts_init_ex | 2010 | agent_round_1 | ❌ FAIL |
| 7 | nf_tables_newrule | 0 | agent_round_1 | ✅ SUCCESS |
| 9 | xfrm_state_find | 0 | agent_round_3 | ✅ SUCCESS |
| 10 | packet_snd | 0 | run0 | ✅ SUCCESS |
| 11 | llc_ui_sendmsg | 0 | agent_round_1 | ✅ SUCCESS |

현재 `workdir_v3_unified` 기준으로 남아 있는 핵심 실패는 **case 0, 2, 6**이다.

### Failure Analysis From Latest Runs

#### Case 2 — `fifo_set_limit` (best dist = 10, all three agent rounds stuck)

최신 실행에서도 round 1~3 모두 `dist_min=10`에서 더 내려가지 않았다.
metrics 기준:
- round 1: exec 45K, dist 10 고정
- round 2: exec 141K, dist 10 고정
- round 3: exec 152K, dist 10 고정

즉 탐색량 부족 문제가 아니라, **타겟 직전 상태까지는 가지만 마지막 조건을 못 넘는 상태**다.

이번 재확인에서 드러난 점:

1. **R4-ARG corpus re-injection 자체는 고장나지 않았다**
   - `detailCorpus.txt`는 실제 존재한다.
   - `extract_closest_programs()`는 현재 코드에서 정상 동작하며 dist=10 프로그램들을 반환한다.
   - `corpus_reinject.db`도 실제 생성되어 있다.
   - 따라서 이전 중간 메모의 "re-injection이 동작하지 않음"은 현재 코드 기준으로는 더 이상 핵심 원인이 아니다.

2. **하지만 re-injection 품질이 낮다**
   - `corpus_reinject.db`를 unpack해 보면 target과 무관한 `openat$proc_capi20`, `IPSET`, `USBIP`, tunnel ioctl류 프로그램이 섞여 있다.
   - 현재 기준은 "dist <= current_dist * 2" 뿐이라서, `fifo_set_limit`과 직접 관련 없는 dist=10 프로그램도 함께 재주입된다.
   - 결과적으로 seed 강화가 아니라 **노이즈 보강**에 가깝다.

3. **dist=10 프로그램이 존재해도, 그것이 곧 올바른 TBF 2-step이라는 뜻은 아니다**
   - round 1 `detailCorpus.txt`에는 dist=10 엔트리가 280개나 있다.
   - 그러나 대표 예시는:
     ```syz
     r0 = socket$nl_route(0x10, 0x3, 0x0)
     sendmsg$nl_route_sched(r0, ... @newtclass={0x24, 0x10, 0x3} ...)
     ```
   - 즉 `fifo_set_limit`에 필요한 `tbf create -> tbf change`의 명시적 2-step이 아니라,
     매우 generic한 `sendmsg$nl_route_sched` 한 방만으로도 dist=10 근처 블록까지는 갈 수 있다.
   - 이 때문에 "dist=10 근접 corpus"를 그대로 다시 넣어도 target-specific mutation pressure가 약하다.

4. **기본 callfile이 여전히 너무 generic하다**
   - 최신 `fuzzinps/case_2/inp_0.json`은:
     - `Target = sendmsg$nl_route_sched`
     - `Relate = [socket$nl_route, sendmsg$nl_route, bind, close]`
   - 여기에 `tbf` create/change 시퀀스 정보는 없다.
   - semantic seed가 TBF 특화 seed를 보강하고는 있지만, base callfile 자체가 generic해서 전체 퍼징 분포가 너무 넓다.

5. **현재 병목은 "tbf 경로 부재"가 아니라 "tbf 직전 조건 미충족"이다**
   - 과거 메모에는 "corpus에 tbf가 0개"라는 상태가 있었지만, 그건 최신 스냅샷을 설명하지 못한다.
   - 지금은 `dist=10`이 수백 개이고, reinjection corpus도 생성된다.
   - 따라서 최신 실패 원인은:
     - TBF 경로가 전혀 없어서가 아니라,
     - **마지막 분기/속성 조합이 맞지 않거나**
     - **재주입된 corpus가 target-specific하지 않아서**
     - `fifo_set_limit()` 진입으로 이어지지 않는 것이다.

정리:
- **옛 진단**: "tbf 프로그램이 아예 없다"
- **최신 진단**: "tbf 근처까지는 가는데, 마지막 payload/state precision이 부족하다"

우선순위 높은 수정 방향:
1. re-injection 대상을 `sendmsg$nl_route_sched` + `tbf`/`RTM_NEWQDISC` shape로 한 번 더 필터링
2. case 2 callfile 자체에 `tbf create -> change` 힌트를 직접 넣기
3. ANYBLOB 기반 netlink seed를 줄이고, syzkaller가 필드 단위 mutation 가능한 표현으로 전환

#### Case 6 — `tcf_exts_init_ex` (best dist = 2010, no progress across rounds)

최신 실행에서도 round 1~3 모두 `dist_min=2010`에서 고정됐다.
metrics 기준:
- round 1: exec 87K, dist 2010 고정
- round 2: exec 50K, dist 2010 고정
- round 3: exec 43K, dist 2010 고정

즉 case 2와 달리, case 6은 **타겟 근처까지도 못 가고 2-hop 바깥에서 멈춘다.**

이번 재확인에서 드러난 점:

1. **seed는 아예 없는 상태가 아니다**
   - `merged_seed.db`를 unpack하면 32개 seed가 들어 있다.
   - `sendmsg$nl_route_sched` 기반 seed도 다수 존재한다.
   - 따라서 "seed 생성 실패"는 현재 핵심 원인이 아니다.

2. **그러나 seed가 target kind를 제대로 집중하지 못한다**
   - unpack 결과에 `u32`, `matchall`, `sfq` 등 여러 kind가 섞여 있고,
     `flower`를 직접 나타내는 seed는 거의 보이지 않는다.
   - target이 `cls_api.c` 공통 경로라서 generic classifier fallback을 쓰는 것은 맞지만,
     그 결과 실제 target dispatch에 필요한 kind로 mutation pressure가 집중되지 않는다.

3. **best dist=2010은 "올바른 syscall family는 잡았지만, handler dispatch에 못 들어간다"는 신호다**
   - 최신 corpus에는 `sendmsg$nl_route_sched`가 많이 보이지만,
     target 진입 직전인 dist=10/30 수준 엔트리는 없다.
   - 이는 `tcf_exts_init_ex`가 호출되는 classifier change 경로 자체로 못 들어가고 있다는 뜻이다.
   - 즉 문제는 단순한 argument fine-tuning보다 더 앞 단계인 **dispatch/state selection 실패**에 가깝다.

4. **generic classifier fallback은 coverage는 늘리지만 precision은 낮다**
   - `cls_api.c`가 공통 코드라서 `basic`, `flower`, `u32`, `matchall`을 다 seed로 생성하는 방향은 seed 0개 문제를 해결했다.
   - 하지만 최신 결과를 보면 이 방식은 "뭔가 보내는 것"까지는 해결했어도,
     "어떤 classifier path로 `tcf_exts_init_ex`까지 갈 것인가"를 충분히 좁혀 주지 못한다.

5. **ANYBLOB/raw netlink encoding 한계가 case 6에서 특히 치명적이다**
   - TC filter payload는 nested attribute 구조가 복잡하고 kind-specific validation이 많다.
   - 현재 seed의 상당수는 raw blob/거친 구조로 들어가 있어, syzkaller가 `TCA_KIND`, `TCA_OPTIONS`, nested attr를 의미 있게 mutation하기 어렵다.
   - case 6은 case 2보다도 payload precision 의존도가 높아서, 이 표현 한계의 영향을 더 크게 받는다.

정리:
- **현재 case 6의 실패 원인**은 validator reject가 아니라,
  **generic한 TC filter seed는 생성되지만 실제 target classifier dispatch와 nested attribute validation을 통과하지 못하는 것**이다.
- 즉 "seed 생성 여부"보다 **seed precision과 kind targeting 부족**이 핵심이다.

우선순위 높은 수정 방향:
1. `cls_api.c` 공통 타겟일 때도 kind 후보를 무차별 확장하지 말고, semantic chain/roadmap에서 나온 실제 caller(kind) 쪽으로 가중치 주기
2. `u32/basic/matchall/flower`별로 seed를 만들더라도, `tcf_exts_init_ex`로 이어진 실제 change handler 기준으로 rank를 매기기
3. TC filter netlink를 ANYBLOB이 아닌 구조화된 syzlang 형태로 생성해서 nested attr mutation 가능하게 만들기

#### Case 0 — `tcindex_alloc_perfect_hash` (best dist = 2010, fully stalled)

최신 실행에서도 round 1~3 모두 `dist_min=2010`에서 고정됐다.
exec은 55K~175K까지 늘었지만 거리 변화가 전혀 없다.

재확인 결과:
- `merged_seed.db`에는 seed가 33개 존재한다.
- `sendmsg$nl_route_sched` 기반 프로그램도 다수 있다.
- 하지만 `detailCorpus.txt`의 dist=2010 엔트리 669개 중 대표 예시가 `creat("./file0")` 같은 완전 비관련 프로그램이다.

즉 case 0은 case 6보다도 더 심하게, **퍼저가 넓은 generic coverage로 흩어지고 target subsystem으로 수렴하지 못하고 있다.**
`tcindex` 관련 문자열이 round 1 corpus에 아주 소수만 보이는 것도 같은 신호다.

최신 기준 해석:
- registration/dispatch 추론으로 `sendmsg$nl_route_sched`까지는 복구했지만,
- 실제 `tcindex_change -> tcindex_set_parms -> tcindex_alloc_perfect_hash` 경로를 타게 하는
  classifier-specific payload precision은 여전히 부족하다.

### Updated Conclusion

최신 `workdir_v3_unified` 기준으로 남은 실패 3개(case 0/2/6)는 성격이 다르다.

- **case 2**: 타겟 직전(`dist=10`)까지는 감. 문제는 close corpus filtering과 마지막 state/payload precision.
- **case 6**: 올바른 syscall family는 쓰지만 classifier dispatch와 nested attr validation을 못 넘음.
- **case 0**: subsystem 수렴 자체가 약해 generic coverage에 퍼짐.

공통 병목은 결국 **TC/netlink structured payload precision**이다.
callfile repair, reinjection, indirect-dispatch 복구는 모두 도움이 되었지만,
남은 3개는 raw ANYBLOB 기반 seed로는 한계가 분명하다.
