# R4 Seed Selection / Metadata Fix Notes (2026-03-31)

## Goal
- Stop R4 from selecting qdisc-only seeds for filter targets.
- Stop stale target metadata from silently turning filter targets into qdisc targets.
- Make validator/generator/scorer use the same target-type basis.
- Reduce R4 callfile broadening when the problem is payload/state shape, not syscall family.

## Observed Problems
- `target_file` can become stale (`sch_teql.c`) even when the effective target function is `tcindex_alloc_perfect_hash`.
- Seed scorer then computes `target_type=qdisc`, so qdisc-only seeds get selected.
- `_validate_seed_programs()` still uses only `target_file`, so stale metadata also weakens validation.
- `_generate_tc_seed_programs()` also uses only `target_file`, so deterministic generation can still produce wrong qdisc seeds.
- `multi_stage` scoring is too broad: any 3-message program gets bonus, even if the extra step is the wrong path.
- `repeated_target_kind` is too broad: repeated `tcindex` in qdisc messages can score, even when no filter-update path exists.
- R4 may still widen the callfile with broad base syscalls like `sendmsg$nl_route`, which is usually not the real bottleneck here.

## Planned Fixes
1. Persist corrected target metadata to `tpa/case_X/target_functions_info.txt` during agent-loop sync.
2. Log effective `target_function` and `target_file` at proactive and R4 seed generation time.
3. Make seed requirements snippet-aware and use snippet-derived target type when metadata is stale.
4. Make `_validate_seed_programs()` snippet-aware so validation matches scoring.
5. Make `_generate_tc_seed_programs()` snippet-aware so deterministic generation matches scoring.
6. Narrow `multi_stage` scoring to same-path state transitions:
   - filter/action: repeated `RTM_NEWTFILTER`
   - qdisc: repeated qdisc ops only
7. Narrow `repeated_target_kind` scoring to the target path type, not just repeated kind strings anywhere.
8. Tighten R4 target expansion so broad base-syscall widening is rejected when a more specific current variant already exists.

## Expected Outcome
- Filter targets should be scored as `target_type=filter` consistently.
- Qdisc-only candidates should be rejected for classifier targets.
- Raw logs should explain candidate structure and reject reasons clearly.
- R4 should focus more on seed/state/path quality and less on broadening syscall space.

## Next Generic Refactor (2026-03-31, later)

### Why the previous fixes were not enough
- Metadata sync improved scoring, but stale `target_file` still leaked into downstream prompts and semantic analysis.
- The semantic pipeline existed, but it was still too shallow: call chains often stopped at depth 1 and prerequisite extraction returned nothing useful.
- R4 diagnosis improved, but the recovery path still behaved mostly like "distance stall => ask LLM again" instead of routing through generic prerequisite/shape recovery.
- Seed validation improved at the shape level, but it still did not validate enough of the *execution structure* implied by the extracted plan.

### Generic changes to implement now
1. **Stale metadata hard-stop**
   - Treat `target function ↔ target file` mismatch as invalid metadata, not a soft hint.
   - Always overwrite `target_functions_info.txt` with the resolved effective target during agent-loop sync.
   - Normalize target metadata again before semantic analysis and before LLM seed generation.

2. **Turn semantic pipeline into a real analyzer**
   - Normalize target metadata from source before call-chain extraction.
   - Improve caller extraction to handle multi-line kernel function definitions.
   - Extract validation/error paths from callers and target-adjacent functions, not only the final file.
   - Extract prerequisite/dependency edges from lookup/create/parse/error patterns.
   - Extract branch predicates from the actual caller path that gates the target call.

3. **Route R4 through R2/R3 recovery**
   - Treat R4 as a symptom.
   - If secondary signals include R2 or R3, prioritize prerequisite/state/seed recovery before syscall broadening.
   - Only widen the callfile for R4 when there is explicit evidence for an R1-style syscall-space problem.

4. **Validate seeds as execution structures**
   - Derive execution requirements from the semantic plan.
   - Validate message ordering, prerequisite creation, required options, and multi-stage updates against the plan.
   - Reject seeds that match the target textually but violate the extracted plan structure.

### Concrete code targets
- `agent_loop.py`
  - hard metadata overwrite during sync
  - R4 secondary-signal coupling
  - stricter control of callfile broadening
- `semantic_seed.py`
  - target metadata normalization
  - better function-range / caller extraction
  - deeper prerequisite and predicate extraction
  - plan-derived structural validation
- `agent_triage.py`
  - expose weaker R2 evidence as secondary signals during R4
- `llm_enhance.py`
  - keep using snippet-aware scoring, but defer more authority to semantic plan and target normalization

---

## 핵심 버그 발견 및 수정 (2026-03-31 22:30)

### 근본 원인: `rg` (ripgrep) 바이너리를 Python subprocess가 못 찾음

Shell에서 `rg`는 Claude Code가 등록한 **shell function**으로 동작한다.
그런데 Python `subprocess.run(["rg", ...])` 는 shell function을 resolve하지 못하고,
시스템 PATH에 실제 `rg` 바이너리가 없기 때문에 **`FileNotFoundError`가 발생**한다.

모든 소스 분석 함수가 `except (subprocess.TimeoutExpired, OSError)` 로 이 에러를 조용히 삼키고 있어서,
**에러 로그 없이 빈 결과만 반환**했다.

영향받은 함수들:
- `semantic_seed.py`: `_find_function_definition()`, `normalize_target_metadata()`, `extract_call_chain()` 내부의 caller 탐색, `extract_branch_predicates()` 내부의 함수 위치 탐색
- `pipeline_new_cve.py`: `_guess_function_path_from_source()`, `function_exists_in_file()`

**결과**: 모든 kernel source 분석이 무음 실패 → target file이 `sch_teql.c`(stale)로 남음 → call chain depth 1 / 0 predicates / 0 dependencies → seed가 의미 없는 구조로 생성

### 증상 (수정 전)

```
[semantic] Target metadata: function=tcindex_alloc_perfect_hash file=net/sched/sch_teql.c
[semantic]   Chain depth: 1
    → tcindex_alloc_perfect_hash [target]
[semantic]   0 error conditions, 0 dependencies
[semantic]   0 branch predicates near target
```

### 수정 후

```
[semantic] Target metadata: function=tcindex_alloc_perfect_hash file=net/sched/cls_tcindex.c
[semantic]   Chain depth: 3
    → tcindex_change [direct_call]
    → tcindex_set_parms [direct_call]
    → tcindex_alloc_perfect_hash [target]
[semantic]   7 error conditions, 7 dependencies
[semantic]   17 branch predicates near target
    · if (tb[TCA_TCINDEX_HASH])
    · if (tb[TCA_TCINDEX_MASK])
    · if ((cp->mask >> cp->shift) < PERFECT_HASH_THRESHOLD)
    · if (!cp->perfect && !cp->h)
    · if (handle >= cp->alloc_hash)
    ...
```

### 수정 내용

| 파일 | 변경 | 이유 |
|---|---|---|
| `semantic_seed.py` | `_rg_bin()` 추가, `["rg", ...]` → `[_rg_bin(), ...]` | 실제 rg 바이너리 경로 resolve |
| `pipeline_new_cve.py` | 동일 | 동일 |
| `semantic_seed.py` | `generate_seeds()`에서 `plan["solved_values"]` → encoder에 variant 추가 | LLM이 뽑은 condition solution이 저장만 되고 encoder에 전달 안 되던 버그 |
| `semantic_seed.py` | `_validate_tc_seed()`에 parameter value 검증 추가 | hash > (mask >> shift) 같은 값 관계를 validation 단계에서 체크 |
| `semantic_seed.py` | `_extract_options_attrs()` 추가 | TCA_OPTIONS 안의 실제 attribute 값을 파싱하는 헬퍼 |

### 범용적 의미

이 `rg` 문제는 tcindex에 국한된 게 아니다.
**모든 target case의 semantic pipeline이 동일하게 실패**하고 있었다.
수정 후에는 어떤 target이든 kernel source 분석이 실제로 동작한다.

---

## 2차 수정 (2026-04-01 00:40)

### 5라운드 전체 로그 분석 후 발견한 추가 문제점

rg 바이너리 수정 후에도 dist=2010에 계속 갇힘. 5라운드 로그 분석 결과 5개 추가 문제 발견.

### 문제 1: `extract_nla_policy()` regex 실패 — attr_specs 빈 dict

**증거**: 모든 라운드에서 `Phase 3.5` 후 attribute 출력 없음
**원인**: 두 가지 regex 버그
  - `\[\s*\]`가 `[TCA_TCINDEX_MAX + 1]`를 못 매칭 (빈 대괄호만 매칭)
  - `[^}]+`가 nested brace `{ .type = NLA_U32 }`의 첫 `}`에서 끊김
  - enum 정의가 `include/uapi/linux/pkt_cls.h` 헤더에 있는데 target 파일만 검색

**수정**:
  - regex를 `\[[^\]]*\]`로 변경
  - body 추출을 brace-depth 매칭으로 변경
  - UAPI 헤더 디렉토리까지 enum 검색 확장

**수정 후**: 5개 attribute 정확 추출 (HASH=1, MASK=2, SHIFT=3, FALL_THROUGH=4, CLASSID=5)

### 문제 2: Qdisc handle=0 → filter parent 불일치 가능

**원인**: prio qdisc를 `handle=0`으로 생성 → 커널 auto-assign → filter가 `parent=0x00010000`으로 attach
**수정**: qdisc 생성 시 `handle=0x00010000` 명시

### 문제 3: LLM kind name 오타 → 라운드 낭비

**증거**: Round 3에서 `tcindux` (오타) → score=11 seed 2개 전부 reject
**영향**: 해당 라운드에서 TCA_OPTIONS 없는 score=7 seed만 사용 → target path 탐색 불가능
**수정**: `llm_enhance.py`에 edit distance ≤ 2 fuzzy matching 추가. `tcindux` → `tcindex`로 자동 교정

### 문제 4: LLM seed prompt에 kernel source snippet 미포함

**원인**: `llm_generate_seed_program()`이 `source_snippets` 인자를 받지만 prompt에 안 넣음
**영향**: LLM이 target function의 실제 branch 조건을 모르고 seed 생성
**수정**: prompt에 `KERNEL SOURCE` 섹션 추가

### 문제 5: 매 라운드 동일한 seed 반복 (피드백 없음)

**증거**: Round 1~5 모두 같은 semantic seed 2개 + 유사한 LLM seed
**원인**: 이전 라운드 결과(coverage, corpus)가 다음 라운드 seed 생성에 반영 안 됨
**상태**: 미수정 (아키텍처 변경 필요, 다음 단계에서 처리)

### 수정 요약

| 파일 | 변경 | 효과 |
|---|---|---|
| `semantic_seed.py` | nla_policy regex → brace-depth + 헤더 검색 | 5개 attribute index/type 정확 추출 |
| `semantic_seed.py` | qdisc handle=0x00010000 명시 | filter parent 매칭 보장 |
| `llm_enhance.py` | kind name fuzzy matching | LLM 오타(tcindux) 자동 교정 |
| `llm_enhance.py` | source snippets → LLM prompt 포함 | LLM이 실제 branch 조건 보고 seed 생성 |

---

## 3차 수정 (2026-04-01 04:50)

### 근본 원인: prio qdisc에 TCA_OPTIONS 누락 → 모든 filter seed 무효

**증거**: seed hex 디코딩 결과, prio qdisc 메시지에 TCA_OPTIONS가 없음.
커널의 `prio_init()` → `prio_tune()`은 `opt`가 NULL이면 `-EINVAL` 반환.

**결과**:
1. prio qdisc 생성 → **커널이 EINVAL로 거부**
2. tcindex filter 생성 → parent qdisc가 없으니 **실패**
3. tcindex 코드 경로에 **한번도 진입 못함**
4. dist = 2010에 영원히 갇힘

이건 tcindex 전용 문제가 아니라, prio를 parent로 쓰는 **모든 filter target**에 해당.

### 수정 내용

| 파일 | 변경 | 범용성 |
|---|---|---|
| `semantic_seed.py` `_filter_programs()` | prio qdisc에 `tc_prio_qopt` (bands=3 + priomap) TCA_OPTIONS 추가 | 범용 — 모든 filter target |
| `semantic_seed.py` `_update_programs()` | 동일 | 범용 |
| `llm_enhance.py` `_build_netlink_tc_seed()` | kind=="prio" && msg_type==0x24일 때 자동으로 prio options 추가 | 범용 — 모든 deterministic seed |
| `llm_enhance.py` `_generate_tc_seed_programs()` | prio handle=0x00010000 명시 | 범용 |

### 범용성에 대한 메모

`_generate_tcindex_seed_programs()`는 원래부터 tcindex 전용 하드코딩 함수(기존 코드).
범용 경로는 `semantic_seed.py`의 `TCNetlinkEncoder`이며, 이번 수정들은 그 범용 경로에 적용됨.

---

## 4차 수정 (2026-04-01 13:00)

### 근본 원인: ANYBLOB seed가 syzkaller deserializer에서 잘못 파싱됨

**발견 과정**:
1. 3차 수정 (prio TCA_OPTIONS) 후에도 dist=2010에 갇힘
2. distance 파일 분석: `tcindex_set_parms`가 distance 파일에 없음 → LLVM이 `tcindex_change`에 inline
3. dist=2010은 **tcindex 코드가 아닌** `tcf_classify`, `crypto_user_rcv_msg` 등 무관한 함수에서 온 값
4. Round 1 corpus 분석: `corpus: 2 (deleted 0 broken)` — seed 2개가 로드됨
5. **corpus에서 prio+tcindex 조합 프로그램이 0개** — 원래 multi-message seed가 분해됨
6. corpus의 tcindex 항목 분석: syzkaller가 ANYBLOB을 자체 type으로 deserialize하면서 **attribute 구조를 잘못 파싱**
   - 우리 seed: TCA_KIND="tcindex", TCA_OPTIONS={HASH=16, MASK=15, SHIFT=0, ...}
   - syzkaller 변환 결과: `@f_tcindex={{0xc}, {0x4}}` — **hash/mask/shift 전부 사라짐!**
   - TCA_OPTIONS가 빈 payload(nla_len=4)로 축소

**결과**:
1. seed가 corpus에 로드됐지만 tcindex attribute가 전부 사라진 상태
2. fuzzer가 tcindex_change에 진입해도 set_parms 내부 조건 불만족
3. dist=2010에서 개선 불가

**근본 해결**: ANYBLOB 대신 syzkaller의 **native typed format**으로 seed 생성

### syzkaller typed format이란

syzkaller는 자체 type system으로 syscall 인자를 표현:
```
@newqdisc={len, type, flags, seq, pid, tcmsg{}, [attrs]}
@newtfilter={len, type, flags, seq, pid, tcmsg{}, [attrs]}
```

ANYBLOB은 raw hex bytes를 넣는 방식 — syzkaller가 이걸 자체 type으로 재해석할 때 구조가 깨질 수 있음.
Typed format은 syzkaller가 구조를 완전히 이해하므로:
1. **Deserialize 시 attribute가 보존됨**
2. **Mutation이 구조-aware** (hash 값만 변경, kind는 유지 등)
3. **Minimizer가 핵심 attribute를 보존**

### 검증

1. typed seed를 `syz-prog2c`로 파싱 → C 코드 생성 성공
2. C 코드에서 TCA_TCINDEX_HASH=0x10, MASK=0xf, SHIFT=0 모두 정확
3. `syz-db pack` → `syz-db unpack` → **seed 구조 완전 보존** (ANYBLOB 때와 달리)
4. 12/12 seed 전부 syzkaller 파싱 성공

### 수정 내용

| 파일 | 변경 | 범용성 |
|---|---|---|
| `semantic_seed.py` | `_typed_qdisc_msg()` 추가 — prio/ingress qdisc를 typed format으로 생성 | 범용 — `_QDISC_KIND_MAP`으로 확장 가능 |
| `semantic_seed.py` | `_typed_filter_msg()` 추가 — tcindex 등 filter를 typed format으로 생성 | 범용 — `_FILTER_KIND_MAP`으로 확장 가능 |
| `semantic_seed.py` | `_typed_tcindex_attrs()` 추가 — tcindex policy attrs를 typed format으로 인코딩 | tcindex 전용이지만, 다른 filter도 같은 패턴으로 추가 가능 |
| `semantic_seed.py` | `_make_sendmsg_typed()` 추가 — typed message를 sendmsg로 감싸기 | 범용 |
| `semantic_seed.py` | `_filter_programs()` 수정 — typed format 우선, ANYBLOB fallback | 범용 |
| `semantic_seed.py` | `_update_programs()` 수정 — 동일 | 범용 |
| `semantic_seed.py` | `_validate_tc_seed()` 수정 — typed format seed도 validation 지원 | 범용 |

### 범용성

- `_QDISC_KIND_MAP`, `_FILTER_KIND_MAP` dict에 kind 이름 추가만으로 다른 qdisc/filter 지원
- typed format generator는 syzkaller의 type description을 기반으로 하므로, 어떤 TC kind든 동일 패턴
- 알 수 없는 kind는 자동으로 ANYBLOB fallback
- `llm_enhance.py`의 LLM seed는 아직 ANYBLOB — 향후 typed format으로 전환 필요
prio options 자동 추가는 `_build_netlink_tc_seed()`에 넣었으므로 어떤 filter target이든 자동 적용.
