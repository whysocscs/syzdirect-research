# SyzDirect 코드 수정 설명서

## 전체 개요

SyzDirect는 Linux 커널 directed fuzzer다. 커널 내부의 특정 함수(target)에 도달하는 입력을 자동 생성하는 것이 목표.

**동작 흐름**:
1. 정적 분석으로 target 함수까지의 call chain 추출 (어떤 syscall → 어떤 경로로 target에 도달하는지)
2. distance 정보가 심어진 커널(kwithdist) 빌드
3. `semantic_seed.py`가 call chain을 분석하여 syzkaller용 초기 seed 프로그램 생성
4. `run_hunt.py`가 syzkaller fuzzer를 실행, seed 기반으로 mutation하며 target 도달 시도
5. 도달 실패 시 `llm_enhance.py`가 dist roadmap 분석 + LLM으로 seed 개선 → 재퍼징

**핵심 메트릭**: `dist = callgraph_hops × 1000 + cfg_distance`
- dist=0 → target 함수 도달 성공
- dist=10 → target 함수와 같은 caller 안에 있지만 아직 target 호출 조건 미충족
- dist=2010 → target에서 2 hop 떨어진 함수까지만 도달

**현재 상태**: 12개 벤치마크 중 9개 성공(dist=0), 3개 실패(case 0, 2, 6)

---

## 수정 파일 1: `semantic_seed.py`

### 이 파일이 하는 일

커널 소스코드의 정적 분석 결과(call chain, branch 조건, nla_policy 등)를 읽어서, syzkaller가 이해하는 syzlang 형식의 seed 프로그램을 자동 생성한다. TC(Traffic Control) netlink 서브시스템에 특화된 `TCNetlinkEncoder`가 핵심 클래스.

예를 들어 target이 `flower` 필터의 함수라면:
```
r0 = socket$nl_route(0x10, 0x3, 0x0)           ← netlink 소켓 열기
sendmsg$nl_route_sched(r0, &(...)=ANY=[...])     ← RTM_NEWQDISC (qdisc 생성)
sendmsg$nl_route_sched(r0, &(...)=ANY=[...])     ← RTM_NEWTFILTER (flower 필터 추가)
```
이런 프로그램을 자동 생성해서 syzkaller의 초기 corpus에 넣어준다.

### 수정 1: `_infer_kind()` 메서드 (line 810~831)

**역할**: target 함수 이름에서 TC kind(tcindex, flower, tbf 등)를 추론한다.

**수정 전 문제**: 함수명 prefix만으로 매칭. `fl_change`는 "flower"로 시작하지 않아서 kind=None.

**수정 내용**: 3단계 fallback 도입.

```python
def _infer_kind(self, target_func, call_chain):
    candidates = [target_func] + [c["function"] for c in call_chain]
    # Pass 1: 기존 방식 — _KIND_MAP에서 prefix 매칭
    #   "tbf_change" → "tbf" 찾음 ✓
    #   "fl_change" → 못 찾음 ✗
    for fn in candidates:
        for prefix, kind in self._KIND_MAP.items():
            if fn.startswith(prefix): return kind

    # Pass 2: TC 소스코드 컨벤션 별칭 매핑
    #   "fl_" → "flower", "mall_" → "matchall" 등
    #   "fl_change" → "fl_" 매칭 → "flower" ✓
    for fn in candidates:
        for prefix, kind in self._PREFIX_ALIASES.items():
            if fn.startswith(prefix): return kind

    # Pass 3: call chain의 소스 파일명에서 추론
    #   cls_flower.c → "flower", sch_tbf.c → "tbf"
    for c in call_chain:
        basename = os.path.basename(c.get("file", ""))
        m = re.match(r'cls_(\w+)\.c', basename)
        if m and m.group(1) not in ("api", "route"):
            return self._KIND_MAP.get(m.group(1), m.group(1))
    return None
```

**해결한 문제**: Case 6 — `fl_change` → `flower` 매핑 성공 → seed가 0개에서 2개로 증가.

---

### 수정 2: `_is_generic_classifier()` + kind=None fallback (line 841~853)

**역할**: target이 특정 classifier에 속하지 않는 공통 함수(cls_api.c 등)일 때 처리.

**수정 전 문제**: kind를 추론 못하면(`_infer_kind` → None) 바로 `return []` → seed 0개.

**수정 내용**: `cls_api.c`, `act_api.c` 같은 generic dispatcher 파일이면, 주요 classifier 4종(flower, u32, basic, matchall)으로 각각 seed를 생성.

```python
@staticmethod
def _is_generic_classifier(target_file):
    basename = os.path.basename(target_file or "")
    return basename in ("cls_api.c", "act_api.c")

# generate_seeds() 내부:
if not kind:
    if self._is_generic_classifier(target_file):
        all_programs = []
        for k in ("flower", "u32", "basic", "matchall"):
            all_programs.extend(
                self._build_programs(k, "filter", attr_specs, {},
                                     prefer_update=False))
        return all_programs
    return []
```

**해결한 문제**: `tcf_exts_init_ex`처럼 어떤 classifier에서든 호출 가능한 함수에 대해서도 seed를 생성할 수 있게 됨.

---

### 수정 3: `_qdisc_programs()` — 다단계 create→change (line 1015~1042)

**역할**: qdisc(큐잉 스케줄러)를 생성하는 netlink 프로그램을 만든다.

**수정 전 문제**: RTM_NEWQDISC 메시지 1개만 생성. 하지만 `fifo_set_limit`에 도달하려면:
- 1단계: TBF qdisc create → `tbf_change` 호출 → child qdisc(bfifo) 생성
- 2단계: 같은 TBF qdisc change → `q->qdisc != &noop_qdisc` 조건 충족 → `fifo_set_limit` 호출

1단계만으로는 child qdisc가 아직 noop 상태라 `fifo_set_limit`에 절대 도달 못함.

**수정 내용**: `prefer_update=True`일 때 2-step 프로그램 추가.

```python
def _qdisc_programs(self, kind, tca_options, idx, prefer_update=False):
    # 기존: 단일 create
    programs = [{ "name": f"sem_{kind}_qdisc_{idx}",
                  "text": socket + sendmsg(create) }]

    if prefer_update:
        # 추가: create → change 2단계
        #   create: handle=기본값 → child qdisc 생성
        #   change: handle=0x00100000 → 기존 qdisc에 대한 change → set_limit 경로
        programs.append({
            "name": f"sem_{kind}_qdisc_update_{idx}",
            "text": socket + sendmsg(create) + sendmsg(change)
        })
    return programs
```

**해결한 문제**: Case 2 — TBF qdisc의 2단계 호출 시퀀스를 seed로 제공.

---

### 수정 4: `_build_programs()` — prefer_update 파라미터 전달 (line 882~792)

**역할**: kind와 type에 따라 filter/qdisc 프로그램 생성을 분기하는 메인 빌더.

**수정 전 문제**: plan에서 `prefer_update_shape=True`를 읽어도 `_qdisc_programs()`에 전달하지 않았음.

**수정 내용**: 시그니처에 `prefer_update` 파라미터 추가, `generate_seeds()`에서 plan의 execution_requirements를 읽어서 전달.

```python
# generate_seeds() 내:
exec_req = plan.get("execution_requirements", {})
prefer_update = exec_req.get("prefer_update_shape", False)
return self._build_programs(kind, target_type, attr_specs, attr_values,
                            prefer_update=prefer_update)

# _build_programs() 내:
def _build_programs(self, kind, target_type, attr_specs, attr_values,
                    prefer_update=False):
    ...
    programs.extend(self._qdisc_programs(kind, tca_options, vi,
                                         prefer_update=prefer_update))
```

**해결한 문제**: 수정 3의 multi-step 기능이 실제로 활성화되도록 연결.

---

### 수정 5: `_derive_execution_requirements()` — 감지 조건 확장 (line 688~693)

**역할**: call chain을 분석해서 "이 target은 create-then-change 패턴이 필요한가?"를 판단.

**수정 전 문제**: `change`, `alloc` 같은 토큰만 감지. `set_limit`, `set_parms` 등 미감지.

**수정 내용**:

```python
# 토큰 확장: set_limit, set_parms 추가
if any(any(tok in fn for tok in ("change", "update", "replace", "modify", "alloc",
                                 "set_limit", "set_parms")) for fn in call_chain):
    req["prefer_update_shape"] = True

# child qdisc 파일은 무조건 2-step 필요 (부모 qdisc가 먼저 child를 생성해야 함)
if basename in ("sch_fifo.c", "sch_pfifo.c", "sch_pfifo_fast.c"):
    req["prefer_update_shape"] = True
```

**해결한 문제**: Case 2 — call chain에 `fifo_set_limit`가 있으면 자동으로 `prefer_update_shape=True` 설정.

---

## 수정 파일 2: `llm_enhance.py`

### 이 파일이 하는 일

퍼징 중 dist가 줄어들지 않을 때, LLM을 활용해서 seed를 개선하는 모듈. `extract_distance_roadmap()`은 현재 dist에서 target까지 남은 경로를 분석하고, 각 stepping stone 함수에 도달 가능한 syscall 목록을 `k2s` (kernel function → syscalls) 매핑에서 가져온다.

### 수정: k2s dict 구조 처리 버그 (line 435, line 625)

**수정 전 문제**: `k2s.json`의 값이 `{"bb_0": ["sendmsg$nl_route"], "bb_1": ["write$..."]}` 형태의 dict인데, 코드가 이것을 list로 가정하고 `[:5]` 슬라이싱 → `KeyError: slice(None, 5, None)` 크래시.

```python
# 수정 전 (크래시):
syscalls = k2s.get(stone["function"], [])
stone["reachable_via"] = syscalls[:5]  # ← dict에 [:5] 슬라이싱 시도 → 크래시

# 수정 후:
raw = k2s.get(stone["function"], [])
if isinstance(raw, dict):
    # dict의 모든 value(각 basic block의 syscall 리스트)를 합쳐서 중복 제거
    syscalls = list({s for bb_syscalls in raw.values() for s in bb_syscalls})
else:
    syscalls = list(raw)
stone["reachable_via"] = syscalls[:5] if syscalls else []
```

동일한 패턴이 2곳에 있어서 둘 다 수정:
- `extract_distance_roadmap()` (line 435): dist roadmap에서 각 함수의 도달 가능 syscall 표시
- `reverse_trace_bottleneck()` (line 625): 병목 함수의 caller chain 추적 시 syscall 매핑

**해결한 문제**: agent loop에서 LLM seed 개선 단계 진입 시 크래시 방지.

---

---

## 수정 파일 3: `semantic_seed.py` — TBF seed 추가 수정 (Case 2 완성)

### 수정 6: `_build_tbf_options()` — 올바른 TCA_TBF_PARMS 생성

**문제**: `_build_programs()`는 tcindex용 hash/mask 속성을 생성하는데, TBF에 이걸 넣으면 `tbf_change`에서 `nla_parse_nested_deprecated`가 TCA_TBF_PARMS의 길이를 검증하다 실패. 즉 seed를 보내도 tbf_change가 바로 EINVAL로 리턴.

**수정**: `_build_tbf_options()` 함수 추가. `struct tc_tbf_qopt` (36 bytes)를 올바르게 직렬화:

```python
def _build_tbf_options(limit=0x10000, rate_bps=0x00100000, burst=0x4000):
    # rate: 1MB/s, linklayer=1(ethernet)
    rate_spec = struct.pack('<BBHhHI', 0, 1, 0, 0, 0, rate_bps)
    peak_spec = struct.pack('<BBHhHI', 0, 0, 0, 0, 0, 0)
    tbf_qopt  = rate_spec + peak_spec + struct.pack('<III', limit, burst, 0)
    tca_parms = _nlattr_bytes(1, tbf_qopt)   # TCA_TBF_PARMS=1
    tca_burst = _nlattr_u32(6, burst)        # TCA_TBF_BURST=6 → max_size 직접 지정
    return _nlattr_bytes(2, tca_parms + tca_burst)  # TCA_OPTIONS=2
```

TCA_TBF_BURST(6)를 포함해서 max_size를 16KB로 직접 지정. 이렇게 하면 `psched_ns_t2l` 계산 없이도 `max_size > 0` 보장.

`_qdisc_programs()` 안에서 `kind == "tbf"`일 때 이 함수 사용:
```python
if kind == "tbf":
    tca_options = _build_tbf_options()
```

### 수정 7: `_build_netlink_msg()` flags 파라미터 + `_qdisc_programs()` change 메시지 수정

**문제**: 2-step seed의 두 번째 메시지(change)가 `flags=NLM_F_CREATE(0x0405)`로 전송됨. `tc_modify_qdisc` 커널 코드:

```c
if (q && !(n->nlmsg_flags & NLM_F_REPLACE)) {
    return -EEXIST;  // ← NLM_F_REPLACE 없으면 기존 qdisc 있을 때 FAIL
}
```

두 번째 메시지의 handle(0x00100000)이 커널이 자동 할당한 handle과 다르기 때문에 EEXIST 반환. tbf_change 두 번째 호출이 아예 일어나지 않음.

**수정**:
1. `_build_netlink_msg()`에 `flags` 파라미터 추가
2. change 메시지: `handle=0`, `flags=0x0005`(NLM_F_REQUEST|NLM_F_ACK, no NLM_F_CREATE)

```python
# handle=0 + no NLM_F_CREATE → tc_modify_qdisc 흐름:
# clid=TC_H_ROOT → q=dev->qdisc(기존 TBF), !tcm_handle=True
# → else branch → !q=False → magic test(NLM_F_CREATE 없음) → 통과
# → "Change qdisc parameters" 섹션 → qdisc_change() → tbf_change 호출!
# → q->qdisc != &noop_qdisc → fifo_set_limit 도달 ✓
```

**검증**: 생성된 두 번째 메시지 bytes 확인:
- type=RTM_NEWQDISC(0x24) ✓
- flags=0x0005 (NLM_F_CREATE 없음) ✓
- handle=0x00000000 ✓
- parent=0xffff0000=TC_H_ROOT ✓

---

## 현재 한계와 남은 문제

### 세 케이스 모두 dist가 줄어들지 않은 이유

seed 생성 자체는 성공했지만, **생성된 seed가 syzkaller의 mutation에 효과적이지 않다**.

원인은 `_build_netlink_msg()`가 netlink 메시지를 **raw hex bytes**로 인코딩하기 때문:

```
sendmsg$nl_route_sched(r0, &(...)=ANY=[@ANYBLOB="580000002400050401..."])
```

이 `ANYBLOB`은 syzkaller 입장에서 불투명한 바이트 덩어리. syzkaller는 "TCA_KIND 필드를 flower로 바꿔보자" 같은 구조적 mutation을 할 수 없고, 랜덤 바이트 flip만 가능. 그래서:

- **Case 0** (dist=2010): tcindex 필터 생성 seed는 있지만, mutation으로 tcindex_change 진입 조건을 만족시키지 못함
- **Case 2** (dist=10): 2-step TBF seed는 있지만, 두 번째 메시지의 handle/옵션이 정확하지 않아 change로 인식 안 됨
- **Case 6** (dist=2010): flower 필터 seed는 있지만, dispatch 조건(tcm_parent, tcm_info)이 맞지 않아 fl_change 진입 실패

### 근본적 해결 방향

ANYBLOB 대신 syzkaller의 네이티브 타입으로 프로그램을 생성해야 한다. syzkaller가 필드 단위로 mutation할 수 있으면 훨씬 빠르게 target에 도달할 수 있음.

---

## 실행 방법

```bash
cd /home/ai/work/SyzDirect/source/syzdirect/Runner

# 1. seed 생성만 테스트 (퍼징 없이)
#    주의: 반환값 순서는 (plan, seeds)
python3 -B -c "
from semantic_seed import run_semantic_pipeline
plan, seeds = run_semantic_pipeline(
    '/home/ai/work_real/workdir_v3_unified/srcs/case_6',
    'tcf_exts_init_ex', 'net/sched/cls_api.c')
print(f'{len(seeds)} seeds generated')
for s in seeds:
    print(f'  {s[\"name\"]}')
    print(f'  {s[\"text\"][:120]}...')
"

# 2. 실제 퍼징
python3 -B run_hunt.py fuzz \
  -workdir /home/ai/work_real/workdir_v3_unified \
  --targets 0 2 6 \
  --agent-rounds 1 --proactive-seed -uptime 2 -j 8

# 3. 결과 확인
for case in 0 2 6; do
  echo "=== Case $case ==="
  tail -3 /home/ai/work_real/workdir_v3_unified/fuzzres/case_${case}/xidx_0/agent_round_1/logs_x0/manager.log
done
```

## 주의사항

- `run_semantic_pipeline()` 반환값: `(plan, seeds)` 순서. `(seeds, plan)` 아님
- `.pyc` 캐시: 반드시 `python3 -B` 사용하거나 `rm -rf __pycache__` 실행
- workdir 경로: `/home/ai/work_real/workdir_v3_unified`
