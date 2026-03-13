#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Run a SyzDirect dataset case with repo-local defaults.

Usage:
  bash scripts/run_case.sh CASE_ID [extra run_dataset_case.py args]

Environment:
  DATASET_KIND=known-bugs|patches
  MODE=agent-loop|syzdirect|baseline
  BUDGET_HOURS=1
  REPETITIONS=1
  SYZDIRECT_ROOT=<repo>/deps/SyzDirect
  OUTPUT_ROOT=<repo>/.runtime
  VM_CPU=1
  KERNEL_CMDLINE_EXTRA='maxcpus=1 net.ifnames=0 biosdevname=0'
  SUDO_PASSWORD=<optional sudo password for image build / KVM setup>
EOF
}

if [ $# -eq 0 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

CASE_ID="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export VM_CPU="${VM_CPU:-1}"
export KERNEL_CMDLINE_EXTRA="${KERNEL_CMDLINE_EXTRA:-maxcpus=1 net.ifnames=0 biosdevname=0}"

exec python3 "$REPO_ROOT/scripts/run_dataset_case.py" \
    --case-id "$CASE_ID" \
    --dataset-kind "${DATASET_KIND:-known-bugs}" \
    --mode "${MODE:-agent-loop}" \
    --budget-hours "${BUDGET_HOURS:-1}" \
    --repetitions "${REPETITIONS:-1}" \
    --syzdirect-root "${SYZDIRECT_ROOT:-$REPO_ROOT/deps/SyzDirect}" \
    --output-root "${OUTPUT_ROOT:-$REPO_ROOT/.runtime}" \
    "$@"
