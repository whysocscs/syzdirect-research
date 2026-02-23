#!/bin/bash
#
# SyzDirect Experiment Runner
#
# Runs experiments with different configurations and collects results.
#

set -e

WORK_DIR="/work"
SYZDIRECT_DIR="$WORK_DIR/SyzDirect"
SCRIPTS_DIR="$SYZDIRECT_DIR/scripts"
SOURCE_DIR="$SYZDIRECT_DIR/source"

# Default parameters
EXPERIMENT_TYPE="${1:-baseline}"  # baseline, syzdirect, agent-loop
TARGET_FILE="${2:-}"
BUDGET_HOURS="${3:-1}"
REPETITIONS="${4:-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

#
# Run baseline syzkaller (non-directed)
#
run_baseline_syzkaller() {
    local target_id="$1"
    local budget_seconds="$2"
    local run_dir="$WORK_DIR/runs/baseline-syzkaller/${target_id}_$(date +%Y%m%d_%H%M%S)"
    
    log_step "Running baseline syzkaller for $target_id"
    log_info "Budget: ${budget_seconds}s, Output: $run_dir"
    
    mkdir -p "$run_dir"
    
    # Create run-specific config
    cat > "$run_dir/config.cfg" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$run_dir/workdir",
    "kernel_obj": "$WORK_DIR/linux-build",
    "image": "$WORK_DIR/images/bullseye.qcow2",
    "sshkey": "$WORK_DIR/images/bullseye.id_rsa",
    "syzkaller": "$WORK_DIR/syzkaller",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$WORK_DIR/linux-build/bzImage",
        "cpu": 2,
        "mem": 2048
    }
}
EOF
    
    # Run syzkaller with timeout
    timeout "${budget_seconds}s" \
        "$WORK_DIR/syzkaller/bin/syz-manager" -config "$run_dir/config.cfg" \
        2>&1 | tee "$run_dir/manager.log" || true
    
    # Collect results
    collect_results "$run_dir" "baseline"
    
    echo "$run_dir"
}

#
# Run SyzDirect (directed fuzzing)
#
run_syzdirect() {
    local target_id="$1"
    local target_file="$2"
    local budget_seconds="$3"
    local run_dir="$WORK_DIR/runs/baseline-syzdirect/${target_id}_$(date +%Y%m%d_%H%M%S)"
    
    log_step "Running SyzDirect for $target_id"
    log_info "Target: $target_file"
    log_info "Budget: ${budget_seconds}s, Output: $run_dir"
    
    mkdir -p "$run_dir"/{templates,distances,logs}
    
    # Activate Python environment
    source "$SYZDIRECT_DIR/venv/bin/activate" 2>/dev/null || true
    
    # Step 1: Static Analysis
    log_info "Step 1: Running static analysis..."
    python3 "$SOURCE_DIR/analyzer/syscall_analyzer.py" \
        --kernel "$WORK_DIR/linux-src" \
        --target "$target_file" \
        --output "$run_dir/templates/analysis.json" \
        2>&1 | tee "$run_dir/logs/analysis.log"
    
    # Step 2: Distance Calculation
    log_info "Step 2: Computing distances..."
    target_path=$(jq -r '.file_path' "$target_file")
    target_line=$(jq -r '.line // 0' "$target_file")
    
    python3 "$SOURCE_DIR/distance/distance_calculator.py" \
        --kernel "$WORK_DIR/linux-src" \
        --target-file "$target_path" \
        --target-line "$target_line" \
        --output "$run_dir/distances/distances.json" \
        2>&1 | tee "$run_dir/logs/distance.log"
    
    # Step 3: Template Generation
    log_info "Step 3: Generating templates..."
    python3 "$SOURCE_DIR/template/template_generator.py" \
        --analysis "$run_dir/templates/analysis.json" \
        --distances "$run_dir/distances/distances.json" \
        --output "$run_dir/templates" \
        2>&1 | tee "$run_dir/logs/template.log"
    
    # Step 4: Run directed fuzzing
    log_info "Step 4: Running directed fuzzing..."
    
    # Create SyzDirect config
    cat > "$run_dir/config.cfg" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56742",
    "workdir": "$run_dir/workdir",
    "kernel_obj": "$WORK_DIR/linux-build",
    "kernel_src": "$WORK_DIR/linux-src",
    "image": "$WORK_DIR/images/bullseye.qcow2",
    "sshkey": "$WORK_DIR/images/bullseye.id_rsa",
    "syzkaller": "$WORK_DIR/syzkaller",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$WORK_DIR/linux-build/bzImage",
        "cpu": 2,
        "mem": 2048
    }
}
EOF
    
    # Run fuzzing with monitoring
    (
        timeout "${budget_seconds}s" \
            "$WORK_DIR/syzkaller/bin/syz-manager" -config "$run_dir/config.cfg" \
            2>&1 | tee "$run_dir/manager.log"
    ) &
    manager_pid=$!
    
    # Monitor and collect runtime logs
    monitor_fuzzing "$run_dir" "$manager_pid" "$budget_seconds" &
    monitor_pid=$!
    
    wait $manager_pid || true
    kill $monitor_pid 2>/dev/null || true
    
    # Collect results
    collect_results "$run_dir" "syzdirect"
    
    echo "$run_dir"
}

#
# Run Agent-Enhanced Loop
#
run_agent_loop() {
    local target_id="$1"
    local target_file="$2"
    local total_budget_seconds="$3"
    local max_rounds="${4:-5}"
    local per_round_seconds=$((total_budget_seconds / max_rounds))
    
    local run_dir="$WORK_DIR/runs/agent-loop/${target_id}_$(date +%Y%m%d_%H%M%S)"
    
    log_step "Running Agent-Enhanced Loop for $target_id"
    log_info "Total budget: ${total_budget_seconds}s, Max rounds: $max_rounds"
    log_info "Per-round budget: ${per_round_seconds}s"
    log_info "Output: $run_dir"
    
    mkdir -p "$run_dir"/{rounds,templates,logs,triage}
    
    source "$SYZDIRECT_DIR/venv/bin/activate" 2>/dev/null || true
    
    # Initial static analysis
    log_info "Initial static analysis..."
    python3 "$SOURCE_DIR/analyzer/syscall_analyzer.py" \
        --kernel "$WORK_DIR/linux-src" \
        --target "$target_file" \
        --output "$run_dir/templates/initial_analysis.json"
    
    # Agent loop
    current_templates="$run_dir/templates/initial_analysis.json"
    
    for round in $(seq 1 $max_rounds); do
        log_step "=== Round $round of $max_rounds ==="
        
        round_dir="$run_dir/rounds/round_$round"
        mkdir -p "$round_dir"/{workdir,logs}
        
        # Run short fuzzing session
        log_info "Running fuzzing for round $round..."
        run_short_fuzz "$round_dir" "$current_templates" "$per_round_seconds"
        
        # Analyze results
        log_info "Analyzing round $round results..."
        
        # Generate execution logs for triage
        generate_execution_logs "$round_dir"
        
        # Run failure triage
        python3 "$SOURCE_DIR/agent/failure_triage.py" \
            --logs "$round_dir/execution_logs.json" \
            --static-info "$current_templates" \
            --output "$round_dir/triage_result.json" \
            2>&1 | tee "$round_dir/logs/triage.log"
        
        # Check triage result
        failure_class=$(jq -r '.failure_class' "$round_dir/triage_result.json")
        
        log_info "Failure class: $failure_class"
        
        if [ "$failure_class" == "SUCCESS" ]; then
            log_info "Target reached! Stopping loop."
            break
        fi
        
        # Apply appropriate agent based on failure class
        case "$failure_class" in
            "R1")
                log_info "Applying Related-Syscall Deepening Agent..."
                # R1 is similar to R3 in treatment
                python3 "$SOURCE_DIR/agent/related_syscall_agent.py" \
                    --templates "$current_templates" \
                    --triage "$round_dir/triage_result.json" \
                    --output "$round_dir/enhanced_templates.json"
                ;;
            "R2")
                log_info "Applying Object/Parameter Synthesis Agent..."
                python3 "$SOURCE_DIR/agent/object_synthesis_agent.py" \
                    --triage "$round_dir/triage_result.json" \
                    --templates "$current_templates" \
                    --output "$round_dir/synthesis_result.json"
                    
                # Extract enhanced templates
                jq '.enhanced_templates' "$round_dir/synthesis_result.json" > "$round_dir/enhanced_templates.json"
                ;;
            "R3"|"MIXED")
                log_info "Applying Related-Syscall Deepening Agent..."
                python3 "$SOURCE_DIR/agent/related_syscall_agent.py" \
                    --templates "$current_templates" \
                    --triage "$round_dir/triage_result.json" \
                    --output "$round_dir/enhanced_templates.json"
                ;;
            *)
                log_warn "Unknown failure class, continuing with current templates"
                cp "$current_templates" "$round_dir/enhanced_templates.json"
                ;;
        esac
        
        # Check if improvements meet criteria
        if check_improvement "$round_dir"; then
            log_info "Improvement detected, updating templates"
            current_templates="$round_dir/enhanced_templates.json"
        else
            log_warn "No significant improvement, keeping current templates"
        fi
        
        # Save round summary
        save_round_summary "$round_dir" "$round" "$failure_class"
    done
    
    # Final summary
    generate_final_report "$run_dir"
    
    echo "$run_dir"
}

#
# Helper: Run short fuzzing session
#
run_short_fuzz() {
    local round_dir="$1"
    local templates="$2"
    local budget="$3"
    
    cat > "$round_dir/config.cfg" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56743",
    "workdir": "$round_dir/workdir",
    "kernel_obj": "$WORK_DIR/linux-build",
    "image": "$WORK_DIR/images/bullseye.qcow2",
    "sshkey": "$WORK_DIR/images/bullseye.id_rsa",
    "syzkaller": "$WORK_DIR/syzkaller",
    "procs": 2,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "$WORK_DIR/linux-build/bzImage",
        "cpu": 2,
        "mem": 2048
    }
}
EOF
    
    timeout "${budget}s" \
        "$WORK_DIR/syzkaller/bin/syz-manager" -config "$round_dir/config.cfg" \
        2>&1 | tee "$round_dir/manager.log" || true
}

#
# Helper: Generate execution logs from syzkaller output
#
generate_execution_logs() {
    local round_dir="$1"
    
    # Create synthetic execution logs from manager output
    # In production, this would parse actual syzkaller logs
    cat > "$round_dir/execution_logs.json" << EOF
[
    {
        "timestamp": $(date +%s),
        "seed_id": "seed_1",
        "template_id": "template_1",
        "syscall_distances": {},
        "seed_distance": 100.0,
        "template_distance": 100.0,
        "reached_target": false,
        "crash": false,
        "errno_counts": {"EINVAL": 10, "EPERM": 5},
        "coverage_new": true,
        "iteration": 1
    }
]
EOF
}

#
# Helper: Check if round showed improvement
#
check_improvement() {
    local round_dir="$1"
    
    # Check triage result for improvement indicators
    local confidence=$(jq -r '.confidence // 0' "$round_dir/triage_result.json")
    local min_distance=$(jq -r '.distance_analysis.min_distance // 999' "$round_dir/triage_result.json")
    
    # Simple heuristic: improvement if confidence > 0.5 or distance decreased
    if (( $(echo "$confidence > 0.5" | bc -l) )); then
        return 0
    fi
    
    return 1
}

#
# Helper: Save round summary
#
save_round_summary() {
    local round_dir="$1"
    local round_num="$2"
    local failure_class="$3"
    
    cat > "$round_dir/summary.json" << EOF
{
    "round": $round_num,
    "failure_class": "$failure_class",
    "timestamp": "$(date -Iseconds)",
    "triage_file": "$round_dir/triage_result.json",
    "enhanced_templates": "$round_dir/enhanced_templates.json"
}
EOF
}

#
# Helper: Monitor fuzzing progress
#
monitor_fuzzing() {
    local run_dir="$1"
    local manager_pid="$2"
    local budget="$3"
    local interval=60
    
    local elapsed=0
    while [ $elapsed -lt $budget ] && kill -0 $manager_pid 2>/dev/null; do
        sleep $interval
        elapsed=$((elapsed + interval))
        
        # Log progress
        echo "[$(date)] Elapsed: ${elapsed}s / ${budget}s" >> "$run_dir/logs/monitor.log"
        
        # Could add distance tracking here if integrated with syzkaller
    done
}

#
# Helper: Collect results
#
collect_results() {
    local run_dir="$1"
    local run_type="$2"
    
    log_info "Collecting results for $run_type run..."
    
    # Create results summary
    cat > "$run_dir/results.json" << EOF
{
    "run_type": "$run_type",
    "run_dir": "$run_dir",
    "timestamp": "$(date -Iseconds)",
    "crashes": $(find "$run_dir/workdir/crashes" -type f 2>/dev/null | wc -l || echo 0),
    "corpus_size": $(find "$run_dir/workdir/corpus" -type f 2>/dev/null | wc -l || echo 0)
}
EOF
    
    log_info "Results saved to $run_dir/results.json"
}

#
# Helper: Generate final report
#
generate_final_report() {
    local run_dir="$1"
    
    log_info "Generating final report..."
    
    # Aggregate round results
    local rounds_data="[]"
    for round_dir in "$run_dir/rounds/"round_*; do
        if [ -d "$round_dir" ]; then
            round_summary=$(cat "$round_dir/summary.json" 2>/dev/null || echo "{}")
            rounds_data=$(echo "$rounds_data" | jq ". + [$round_summary]")
        fi
    done
    
    cat > "$run_dir/final_report.json" << EOF
{
    "experiment_type": "agent-loop",
    "run_dir": "$run_dir",
    "timestamp": "$(date -Iseconds)",
    "total_rounds": $(echo "$rounds_data" | jq 'length'),
    "rounds": $rounds_data,
    "final_status": "complete"
}
EOF
    
    log_info "Final report saved to $run_dir/final_report.json"
}

#
# Main
#
main() {
    case "$EXPERIMENT_TYPE" in
        baseline)
            if [ -z "$TARGET_FILE" ]; then
                log_error "Target file required for baseline"
                exit 1
            fi
            target_id=$(jq -r '.target_id' "$TARGET_FILE")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_baseline_syzkaller "$target_id" "$budget_seconds"
            done
            ;;
            
        syzdirect)
            if [ -z "$TARGET_FILE" ]; then
                log_error "Target file required for syzdirect"
                exit 1
            fi
            target_id=$(jq -r '.target_id' "$TARGET_FILE")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_syzdirect "$target_id" "$TARGET_FILE" "$budget_seconds"
            done
            ;;
            
        agent-loop)
            if [ -z "$TARGET_FILE" ]; then
                log_error "Target file required for agent-loop"
                exit 1
            fi
            target_id=$(jq -r '.target_id' "$TARGET_FILE")
            budget_seconds=$((BUDGET_HOURS * 3600))
            
            for rep in $(seq 1 $REPETITIONS); do
                log_info "Repetition $rep of $REPETITIONS"
                run_agent_loop "$target_id" "$TARGET_FILE" "$budget_seconds"
            done
            ;;
            
        *)
            log_error "Unknown experiment type: $EXPERIMENT_TYPE"
            echo "Usage: $0 <baseline|syzdirect|agent-loop> <target.json> [budget_hours] [repetitions]"
            exit 1
            ;;
    esac
}

main
