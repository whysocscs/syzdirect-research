# Agent Loop Improvement Plan (IMPLEMENTED)

## 현재 문제
1. **Proactive seed**: TC만 잘 됨 → 나머지 서브시스템은 LLM이 syzkaller 문법 모름
2. **R4 callfile 확장**: syscall 이름만 제안 → fuzzer가 이미 아는 것과 겹침
3. **1시간 라운드**: 피드백 느림 → stall 판단 후 LLM 개입까지 낭비
4. **corpus 무시**: fuzzer가 찾은 "가장 가까운 프로그램"을 분석 안 함
5. **실패 원인 미분류**: stuck 이유를 구분 안 하고 전부 같은 R4 처리

---

## Phase 1 (병렬 가능, 독립)

### #3 라운드 30분으로 축소
- **변경 파일**: `run_v123_comparison.py`, `Config.py`
- `V123Config.agent_uptime` 기본값: `1.0` → `0.5`
- `Config.FuzzUptime` 관련 기본값 확인 및 조정

### #1 Corpus 분석 — 가장 가까운 프로그램 추출 → LLM 피드
- **새 함수**: `llm_enhance.py`에 `extract_closest_program(workdir, syz_db_path, dist_dir, target_function)`
  - `syz-db unpack <workdir>/corpus.db <tmpdir>` 으로 프로그램 추출
  - `detailCorpus.txt` 파싱하여 per-program distance 확인
  - dist_min을 달성한 프로그램 텍스트 반환
- **수정**: `agent_loop.py` `_enhance_for_distance_stall()`
  - `extract_closest_program()` 호출하여 closest program 확보
  - `llm_enhance_callfile_for_distance()`와 `llm_generate_seed_program()`에 전달
- **수정**: `llm_enhance.py` 두 LLM 함수
  - `closest_program=""` 파라미터 추가
  - 프롬프트에 "CLOSEST PROGRAM IN CORPUS (achieved dist=X):" 섹션 추가

### #2 Stepping stone → syscall 역추적
- **새 함수**: `llm_enhance.py`에 `reverse_trace_bottleneck(src_dir, bottleneck_func)`
  - 커널 소스에서 bottleneck 함수 정의 찾기
  - 이 함수를 호출하는 caller 함수 grep (2단계까지)
  - caller → syscall entry point 매핑
  - 결과: "bottleneck_func ← caller_func ← syscall X" 텍스트
- **수정**: `llm_enhance_callfile_for_distance()` 프롬프트에 reverse trace 결과 포함
- **수정**: `_enhance_for_distance_stall()`에서 roadmap stones[0]에 대해 reverse trace 호출

---

## Phase 2 (#1, #2 완료 후)

### #4 Argument-level seed 생성
- **수정**: `llm_enhance_callfile_for_distance()` 프롬프트
  - syscalls 외에 `"seed_programs"` 필드도 요청 → 한 번의 LLM 호출로 callfile + seed 동시 생성
- **새 함수**: `_generate_generic_seed_programs(roadmap, target_function, target_file, source_snippets)`
  - 비-TC 타겟용 프로그래밍 기반 fallback
  - 서브시스템 휴리스틱: `net/ipv4/*` → socket+setsockopt, `mm/*` → mmap+mremap, `net/bluetooth/*` → socket$bt+connect 등
  - 구체적 argument 값 포함한 syzkaller 프로그램 생성
- **수정**: `llm_generate_seed_program()` line ~1134
  - `deterministic`이 비어있을 때 → `_generate_generic_seed_programs()` 호출 (TC 아닌 경우)

---

## Phase 3 (#1, #2, #4 완료 후)

### #6 실패 원인 분류
- **새 함수**: `agent_triage.py`에 `classify_r4_cause(health, roadmap, dist_history, current_callfile)`
  - **R4-WRONG** (잘못된 syscall family): stepping stones 전부 멀고 (dist > 5000), k2s 매핑에 현재 callfile 없음
  - **R4-STATE** (prerequisite 누락): 이전 라운드에선 dist 줄었으나 지금 stuck, stepping stone에 alloc/init 패턴
  - **R4-ARG** (argument 부족): dist < 1000, 올바른 서브시스템에 있으나 특정 check 통과 못함
- **수정**: `agent_loop.py` `_enhance_for_distance_stall()`
  - R4-WRONG → `llm_enhance_callfile_for_distance()` 우선 (새 syscall 필요)
  - R4-STATE → `llm_generate_seed_program()` 우선 + "setup prerequisite" 프롬프트 강조
  - R4-ARG → seed 생성 + bottleneck 소스 분석(#2) + corpus 분석(#1) 프롬프트 결합

---

## 핵심 파일 목록
| 파일 | 관련 개선 |
|------|----------|
| `llm_enhance.py` | #1, #2, #4 (함수 추가 + 프롬프트 수정) |
| `agent_loop.py` | #1, #4, #6 (데이터 흐름 변경) |
| `agent_triage.py` | #6 (R4 세분화) |
| `run_v123_comparison.py` | #3 (기본값) |
| `Config.py` | #3 (기본값) |

## 구현 순서
```
Phase 1: #3 + #1 + #2 (병렬)
Phase 2: #4 (Phase 1 의존)
Phase 3: #6 (Phase 1+2 의존)
```
