# SyzDirect Experiment Environment

LLM/Agent-enhanced directed greybox fuzzing for Linux kernel.

## Quick Start

```bash
# 1. Setup (full - includes kernel build, ~1-2 hours)
./scripts/setup_environment.sh

# 2. Or skip kernel/image for development
./scripts/setup_environment.sh --skip-kernel --skip-image

# 3. Run experiments
./scripts/run_experiment.sh baseline /work/targets/example_target.json 1
./scripts/run_experiment.sh syzdirect /work/targets/example_target.json 1
./scripts/run_experiment.sh agent-loop /work/targets/example_target.json 1

# 4. Analyze results
python3 scripts/analyze_results.py --runs-dir /work/runs
```

## Directory Structure

```
/work/
├── syzkaller/          # Google syzkaller (built)
├── SyzDirect/          # This project
│   ├── source/
│   │   ├── analyzer/   # Static analysis
│   │   ├── distance/   # Distance calculation
│   │   ├── template/   # Template generation
│   │   └── agent/      # LLM/Agent modules (R1/R2/R3)
│   └── scripts/        # Setup & run scripts
├── linux-src/          # Kernel source
├── linux-build/        # Kernel build
├── images/             # VM images
├── targets/            # Target specifications
└── runs/               # Experiment outputs
```

## Failure Classification

| Class | Issue | Detection | Response Agent |
|-------|-------|-----------|----------------|
| R1 | Missing dependencies | Distance plateau | Related-syscall Agent |
| R2 | Object/param issues | High EINVAL, near target | Object Synthesis Agent |
| R3 | Context depth | High error rate | Related-syscall Agent |

## Target Format

```json
{
    "target_id": "bug_001",
    "kernel_commit": "v6.1",
    "file_path": "net/core/sock.c",
    "function": "sock_setsockopt",
    "line": 1234,
    "target_type": "bug_repro"
}
```

## Components

- `syscall_analyzer.py` - Entry/related syscall identification
- `distance_calculator.py` - BB-level distance computation
- `template_generator.py` - Fuzzing template creation
- `failure_triage.py` - R1/R2/R3 classification
- `related_syscall_agent.py` - Context deepening (R3)
- `object_synthesis_agent.py` - Object synthesis (R2)

## Metrics

- TTE (Time-to-Exposure)
- Hitting-round
- Success rate
- Failure class improvement rate
- Distance plateau break rate
