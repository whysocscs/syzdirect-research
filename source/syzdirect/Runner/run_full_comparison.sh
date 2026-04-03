#!/usr/bin/env bash
# run_full_comparison.sh
#
# V2 vs V3 전체 비교 실험 (기존 3케이스 + 새 3케이스)
#
# 케이스 목록:
#   [중]  case 1 — qdisc_create         (workdir_v3_ga)
#   [중]  case 2 — fifo_set_limit        (workdir_v3_ga)
#   [하]  case 3 — tcp_cleanup_cc        (workdir_v3_ga)
#   [하]  bug45  — move_page_tables      (workdir_new_cases/case_bug45_mremap)
#   [중상] bug74  — sco_sock_create       (workdir_new_cases/case_bug74_bluetooth)
#   [상]  bug78  — tcf_exts_init_ex      (workdir_new_cases/case_bug78_cls_api)
#
# Usage:
#   bash run_full_comparison.sh
#   bash run_full_comparison.sh --uptime 2 --agent-rounds 3 --agent-uptime 1

set -euo pipefail

RUNNER_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_REAL="/home/ai/work_real"
LOG_DIR="$WORK_REAL/comparison_logs"
PYTHON="$(which python3)"
SCRIPT="$RUNNER_DIR/run_v123_comparison.py"

mkdir -p "$LOG_DIR"

# 기본값
UPTIME=2
AGENT_ROUNDS=3
AGENT_UPTIME=1

for arg in "$@"; do
    case "$arg" in
        --uptime=*)       UPTIME="${arg#--uptime=}" ;;
        --agent-rounds=*) AGENT_ROUNDS="${arg#--agent-rounds=}" ;;
        --agent-uptime=*) AGENT_UPTIME="${arg#--agent-uptime=}" ;;
    esac
done

echo "=============================="
echo " Full V2 vs V3 Comparison"
echo " Started   : $(date)"
echo " uptime    : ${UPTIME}h per version"
echo " V3 rounds : ${AGENT_ROUNDS} x ${AGENT_UPTIME}h"
echo " Logs      : $LOG_DIR"
echo "=============================="

run_exp() {
    local LABEL="$1"
    local WORKDIR="$2"
    local CASES="$3"
    local LOG="$LOG_DIR/${LABEL}.log"

    echo ""
    echo "──────────────────────────────────────────"
    echo " [$LABEL] started: $(date)"
    echo " workdir: $WORKDIR"
    echo " cases  : $CASES"
    echo "──────────────────────────────────────────"

    $PYTHON "$SCRIPT" \
        --prebuilt-workdir "$WORKDIR" \
        --cases $CASES \
        --versions v2 v3 \
        --uptime "$UPTIME" \
        --agent-rounds "$AGENT_ROUNDS" \
        --agent-uptime "$AGENT_UPTIME" \
        2>&1 | tee "$LOG"

    echo " [$LABEL] done: $(date)"
}

# ── 병렬 실행 3개씩 ──────────────────────────────────────
# 그룹 1: existing_cases_123 + bug45 + bug74 (동시)
run_exp "existing_cases_123" \
    "$WORK_REAL/workdir_v3_ga" \
    "1 2 3" &
PID1=$!

run_exp "bug45_mremap_하" \
    "$WORK_REAL/workdir_new_cases/case_bug45_mremap" \
    "0" &
PID2=$!

run_exp "bug74_bluetooth_중상" \
    "$WORK_REAL/workdir_new_cases/case_bug74_bluetooth" \
    "0" &
PID3=$!

echo "[parallel] group1 started: PID1=$PID1 PID2=$PID2 PID3=$PID3"
wait $PID1; echo "[done] existing_cases_123"
wait $PID2; echo "[done] bug45_mremap"
wait $PID3; echo "[done] bug74_bluetooth"

# 그룹 2: bug78 단독 (나머지)
run_exp "bug78_cls_api_상" \
    "$WORK_REAL/workdir_new_cases/case_bug78_cls_api" \
    "0"
echo "[done] bug78_cls_api"

echo ""
echo "=============================="
echo " 전체 완료: $(date)"
echo " 로그 위치: $LOG_DIR"
echo "=============================="
