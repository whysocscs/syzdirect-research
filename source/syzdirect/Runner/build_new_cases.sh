#!/usr/bin/env bash
# build_new_cases.sh
#
# Builds 3 new fuzzing targets from scratch using run_hunt.py new mode.
# Runs sequentially to avoid OOM. Each case logs to its own file.
#
# Cases:
#   case_bug45 : mm/mremap.c       — move_page_tables      [하]
#   case_bug74 : bluetooth/sco.c   — sco_sock_create       [중상]
#   case_bug78 : cls_api.c         — tcf_exts_init_ex      [상]
#
# Usage:
#   bash build_new_cases.sh            # full build + fuzz (1h per case)
#   bash build_new_cases.sh --build-only  # build only, no fuzzing
#   bash build_new_cases.sh --uptime 6    # 6h fuzzing per case

set -euo pipefail

RUNNER_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_REAL="/home/ai/work_real"
LOG_DIR="$WORK_REAL/new_cases_logs"
WORKDIR_BASE="$WORK_REAL/workdir_new_cases"

mkdir -p "$LOG_DIR"

# Parse args
BUILD_ONLY=0
UPTIME=1
for arg in "$@"; do
    case "$arg" in
        --build-only) BUILD_ONLY=1 ;;
        --uptime) shift; UPTIME="$1" ;;
        --uptime=*) UPTIME="${arg#--uptime=}" ;;
    esac
done

if [ "$BUILD_ONLY" = "1" ]; then
    FUZZ_FLAG=""
    echo "[INFO] Build-only mode (no fuzzing)"
else
    FUZZ_FLAG="--agent-rounds 0"
    echo "[INFO] Build + fuzz mode (uptime=${UPTIME}h per case)"
fi

PYTHON="$(which python3)"
HUNT="$RUNNER_DIR/run_hunt.py"

# ─────────────────────────────────────────────────────────
# Helper: run one case
# ─────────────────────────────────────────────────────────
run_case() {
    local NAME="$1"
    local CVE_DUMMY="$2"
    local COMMIT="$3"
    local FUNCTION="$4"
    local FILE="$5"
    local WORKDIR="$WORKDIR_BASE/$NAME"
    local LOG="$LOG_DIR/${NAME}.log"

    echo ""
    echo "============================================================"
    echo " Building: $NAME"
    echo "   cve     : $CVE_DUMMY (dummy)"
    echo "   commit  : $COMMIT"
    echo "   function: $FUNCTION"
    echo "   file    : $FILE"
    echo "   workdir : $WORKDIR"
    echo "   log     : $LOG"
    echo "   started : $(date)"
    echo "============================================================"

    CMD=(
        "$PYTHON" "$HUNT" new
        --cve "$CVE_DUMMY"
        --commit "$COMMIT"
        --function "$FUNCTION"
        --file "$FILE"
        -workdir "$WORKDIR"
        -j 8
        -uptime "$UPTIME"
    )

    if [ "$BUILD_ONLY" = "0" ]; then
        CMD+=(--agent-rounds 0)
    fi

    # Run and tee output to log
    "${CMD[@]}" 2>&1 | tee "$LOG"
    local RC="${PIPESTATUS[0]}"

    if [ "$RC" = "0" ]; then
        echo "[OK] $NAME finished at $(date)"
    else
        echo "[WARN] $NAME exited with RC=$RC at $(date) — check $LOG"
        echo "       Continuing with next case..."
    fi
}

echo "=============================="
echo " New Cases Build Script"
echo " Started: $(date)"
echo " Logs: $LOG_DIR"
echo "=============================="

# ─────────────────────────────────────────────────────────
# Case A: Bug 45 — mm/mremap.c (하, simple)
#   target: move_page_tables
#   commit: 56e337f2cf1326323844927a04e9dbce9a244835
#   kernel: 5.16.0-rc2
# ─────────────────────────────────────────────────────────
run_case \
    "case_bug45_mremap" \
    "BUG-45-mremap" \
    "56e337f2cf1326323844927a04e9dbce9a244835" \
    "move_page_tables" \
    "mm/mremap.c"

# ─────────────────────────────────────────────────────────
# Case B: Bug 74 — net/bluetooth/sco.c (중상)
#   target: sco_sock_create
#   commit: fdaf9a5840acaab18694a19e0eb0aa51162eeeed
#   kernel: 5.14.0-rc1
# ─────────────────────────────────────────────────────────
run_case \
    "case_bug74_bluetooth" \
    "BUG-74-bluetooth-sco" \
    "fdaf9a5840acaab18694a19e0eb0aa51162eeeed" \
    "sco_sock_create" \
    "net/bluetooth/sco.c"

# ─────────────────────────────────────────────────────────
# Case C: Bug 78 — net/sched/cls_api.c (상)
#   target: tcf_exts_init_ex
#   commit: 1ec35eadc3b448c91a6b763371a7073444e95f9d
#   kernel: 6.2.0
# ─────────────────────────────────────────────────────────
run_case \
    "case_bug78_cls_api" \
    "BUG-78-cls-api" \
    "1ec35eadc3b448c91a6b763371a7073444e95f9d" \
    "tcf_exts_init_ex" \
    "net/sched/cls_api.c"

echo ""
echo "=============================="
echo " All cases done: $(date)"
echo " Results:"
for NAME in case_bug45_mremap case_bug74_bluetooth case_bug78_cls_api; do
    LOG="$LOG_DIR/${NAME}.log"
    if grep -q "ERROR\|FAIL\|assert" "$LOG" 2>/dev/null; then
        echo "  [WARN] $NAME — see $LOG"
    else
        echo "  [OK]   $NAME"
    fi
done
echo "=============================="
