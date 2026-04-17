# 실험 환경 구성 가이드 (이호준용)

SyzAgent 3-way 비교 실험 (baseline vs agent vs agent+proactive-seed)

---

## 요구 사항

- Ubuntu 22.04 / Debian 11 이상 (WSL2 포함)
- RAM: 48GB 이상 권장 (최소 32GB)
- 디스크: 100GB 이상 여유 공간
- CPU: 8코어 이상
- QEMU + KVM (없으면 TCG로 자동 폴백)

---

## 1. 레포 클론

```bash
git clone -b experiment/3way https://github.com/whysocscs/syzdirect-research.git
cd syzdirect-research/source/syzdirect/Runner
```

---

## 2. 도구 빌드

```bash
# LLVM 18 + SyzDirect tools 빌드 (30~60분 소요)
# 상위 폴더(source/syzdirect/) 에서 실행
cd ../..
make all    # 또는 scripts/setup.sh 있으면 bash scripts/setup.sh
cd Runner
```

빌드 완료 후 확인:
```bash
ls ../../llvm-project-new/build/bin/clang           # LLVM 18
ls ../../syzdirect_fuzzer/bin/syz-manager           # syzkaller
ls ../../syzdirect_function_model/build/lib/interface_generator
ls ../../syzdirect_kernel_analysis/build/lib/target_analyzer
```

---

## 3. 실험 데이터셋

`generated_datasets/syzdirect_100/` 에 SyzDirect CCS'23 논문 기준 케이스들이 있다.
각 케이스는 xlsx 파일 1개 (커널 커밋, 타겟 함수/파일, recommend syscall 포함).

**분담:**
- 이상호: cases 1–50  (`rolling_cases_1_50.csv`)
- 이호준: cases 51–100 (`rolling_cases_51_100.csv`)

---

## 4. CSV 생성

```bash
# 본인 환경 경로에 맞게 CSV 생성
python3 make_cases_csv.py \
  --workdir-base /your/workdir/root \
  --output my_rolling_cases.csv \
  --cases 51-100 \
  --linux-template /optional/linux/src   # 있으면 빌드 재사용 가능
```

CSV 포맷:
```
case_id, dataset_xlsx, workdir_agent, workdir_baseline, workdir_proactive, build_j, fuzz_j [, linux_template]
```

- `workdir_agent`: 조건 2 (agent loop 포함)
- `workdir_baseline`: 조건 1 (순수 SyzDirect)
- `workdir_proactive`: 조건 3 (agent + proactive seed)
- `build_j`: 빌드 병렬 수 (RAM 여유에 따라, 권장 4)
- `fuzz_j`: 퍼징 VM 수 (기본 2)
- `linux_template`: 같은 커밋의 커널 소스가 있으면 재사용 (선택사항)

---

## 5. 실험 실행

```bash
mkdir -p bg_logs/rolling_pipeline

# 3-way 비교 실험 시작
python3 -u run_rolling_pipeline.py \
  --cases-csv my_rolling_cases.csv \
  --fuzz-hours 6 \
  --fuzz-slots 3 \
  2>&1 | tee bg_logs/rolling_pipeline/main.log &
```

- `--fuzz-hours 6`: 케이스당 6시간 퍼징
- `--fuzz-slots 3`: 동시에 최대 3개 케이스 (각 케이스 3개 tmux 세션)
- 빌드는 순차, 퍼징은 최대 3×3 = 9개 tmux 세션 병렬

세 조건이 동시에 실행됨:
1. `rolling_baseline_case_N` — 순수 SyzDirect
2. `rolling_agent_case_N`    — agent loop 포함
3. `rolling_proactive_case_N` — agent loop + proactive seed

---

## 6. 모니터링

```bash
# 전체 진행 로그
tail -f bg_logs/rolling_pipeline/main.log

# 특정 케이스 빌드 로그
tail -f bg_logs/rolling_pipeline/build_case_53.log

# 퍼징 세션 목록
tmux list-sessions | grep rolling

# 특정 세션 연결
tmux attach -t rolling_agent_case_53
```

---

## 7. 결과 확인

결과 JSON: `bg_logs/rolling_results/case_N.json`

```bash
cat bg_logs/rolling_results/case_53.json
```

---

## 8. 환경 변수

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # LLM 에이전트 필요 (agent/proactive 조건)
export SYZDIRECT_RUNTIME=/path/to/img  # QEMU 이미지 경로 (기본: /home/ai/syzdirect-runtime/cve)
```

---

## 9. 단일 케이스 테스트

전체 실험 전에 케이스 1개로 환경 검증:

```bash
python3 run_hunt.py dataset \
  -dataset generated_datasets/syzdirect_100/case_51.xlsx \
  -workdir /tmp/test_workdir \
  -j 4 \
  -actions prepare_for_manual_instrument compile_kernel_bitcode analyze_kernel_syscall extract_syscall_entry instrument_kernel_with_distance \
  2>&1 | tail -30
```

성공하면 `/tmp/test_workdir/kwithdist/case_51/bzImage_0` 생성.
