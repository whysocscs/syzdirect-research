#!/usr/bin/env python3
"""
V1/V2/V3 Comparison Runner for SyzDirect Dataset Cases.

This script runs the same known-bugs dataset cases across three versions:
  - V1: Baseline fuzzing (no agent loop, no proactive seed)
  - V2: Agent loop OFF, no proactive seed  (same as V1 but explicit)
  - V3: Agent loop ON  + proactive seed

All three versions use a PRE-BUILT workdir (default: workdir_v3_ga) that
already contains the distance-instrumented kernel and callfiles.
No kernel build step is performed — only fuzzing.

Usage:
  # Run case 0 with all versions using pre-built workdir:
  python3 run_v123_comparison.py --cases 0

  # Run only V2 and V3:
  python3 run_v123_comparison.py --cases 0 1 --versions v2 v3

  # Custom pre-built workdir:
  python3 run_v123_comparison.py --cases 0 --prebuilt-workdir /path/to/workdir

  # Dry run:
  python3 run_v123_comparison.py --cases 0 --dry-run

  # Custom agent loop settings for V3:
  python3 run_v123_comparison.py --cases 0 --agent-rounds 5 --agent-uptime 1
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Paths
SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_DIR = SCRIPT_DIR
RUN_HUNT = RUNNER_DIR / "run_hunt.py"

# Default pre-built workdir (already has kernels + distance files + callfiles)
DEFAULT_PREBUILT_WORKDIR = Path("/home/ai/work_real/workdir_v3_ga")

# Cases available in the pre-built workdir (0-indexed)
DEFAULT_CASES = [0, 1, 2, 3]


@dataclass
class V123Config:
    """Configuration for V1/V2/V3 comparison run."""
    cases: List[int] = field(default_factory=lambda: DEFAULT_CASES.copy())
    versions: List[str] = field(default_factory=lambda: ["v1", "v2", "v3"])
    prebuilt_workdir: Path = field(default_factory=lambda: DEFAULT_PREBUILT_WORKDIR)
    cpus: int = 8
    uptime: float = 1.0   # hours per fuzz session
    agent_rounds: int = 3  # V3 agent loop rounds
    agent_uptime: float = 0.5  # hours per agent round (30 min)
    hunt_mode: str = "hybrid"
    stall_timeout: int = 1800
    dist_stall_timeout: int = 600
    dry_run: bool = False
    parallel: bool = False


def log(msg: str) -> None:
    print(f"[V123] {msg}", flush=True)


def run_cmd(cmd: List[str], dry_run: bool = False, cwd: Optional[Path] = None,
            background: bool = False, logfile: Optional[Path] = None):
    """Run a command, or print it if dry_run. If background=True, return Popen."""
    cmd_str = " ".join(str(c) for c in cmd)
    if dry_run:
        log(f"[DRY-RUN] {cmd_str}")
        return 0
    log(f"Running: {cmd_str}")
    if background and logfile:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        with open(logfile, "w") as f:
            proc = subprocess.Popen(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
        log(f"  Started background PID={proc.pid}, log={logfile}")
        return proc
    result = subprocess.run(cmd, cwd=cwd)
    return result.returncode


def _make_version_workdir(case_id: int, version: str, config: V123Config) -> Path:
    """
    버전별 독립 workdir 생성.
    무거운 read-only 항목(kwithdist, tpa, srcs 등)은 symlink,
    쓰기 가능한 항목(fuzzinps)은 복사, fuzzres는 빈 디렉토리로 생성.
    → V2와 V3가 callfile·fuzzres를 완전히 독립적으로 소유.
    """
    src = config.prebuilt_workdir
    dst = src.parent / f"{src.name}_{version}_case{case_id}"

    if config.dry_run:
        log(f"[DRY-RUN] make version workdir: {dst}")
        return dst

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)

    # read-only 항목 → symlink
    SYMLINK_ITEMS = [
        "consts", "emit-llvm.sh", "interfaces", "kwithdist",
        "multi-pts", "srcs", "syzkaller_signature.txt",
        "target2relate2.json", "tpa",
    ]
    for item in SYMLINK_ITEMS:
        s = src / item
        if s.exists():
            (dst / item).symlink_to(s)

    # fuzzinps → 복사 (callfile은 버전마다 독립적으로 수정 가능)
    src_fuzzinps = src / "fuzzinps"
    if src_fuzzinps.exists():
        shutil.copytree(src_fuzzinps, dst / "fuzzinps")

    # fuzzres → 빈 디렉토리 (결과는 여기에만 쌓임)
    (dst / "fuzzres").mkdir()

    log(f"  Version workdir ready: {dst}")
    return dst


def _fuzz_cmd(case_id: int, version_workdir: Path, config: V123Config,
              agent_rounds: int, proactive_seed: bool) -> List[str]:
    """Build the run_hunt.py fuzz command for a given case and version settings."""
    cmd = [
        sys.executable, str(RUN_HUNT),
        "fuzz",
        "-workdir", str(version_workdir),
        "--targets", str(case_id),
        "-j", str(config.cpus),
        "-uptime", str(int(config.uptime)),
        "--agent-rounds", str(agent_rounds),
        "--hunt-mode", config.hunt_mode,
        "--stall-timeout", str(config.stall_timeout),
        "--dist-stall-timeout", str(config.dist_stall_timeout),
    ]
    if config.agent_uptime:
        cmd += ["--agent-uptime", str(int(config.agent_uptime))]
    if proactive_seed:
        cmd.append("--proactive-seed")
    return cmd


def run_v1(case_id: int, config: V123Config) -> int:
    """Run V1 (baseline, no agent loop, no proactive seed) in isolated workdir."""
    log(f"=== V1: Baseline (case {case_id}) ===")
    vdir = _make_version_workdir(case_id, "v1", config)
    cmd = _fuzz_cmd(case_id, vdir, config, agent_rounds=0, proactive_seed=False)
    return run_cmd(cmd, config.dry_run, cwd=RUNNER_DIR)


def run_v2(case_id: int, config: V123Config) -> int:
    """Run V2 (no agent loop, no proactive seed) in isolated workdir."""
    log(f"=== V2: No Agent Loop (case {case_id}) ===")
    vdir = _make_version_workdir(case_id, "v2", config)
    cmd = _fuzz_cmd(case_id, vdir, config, agent_rounds=0, proactive_seed=False)
    return run_cmd(cmd, config.dry_run, cwd=RUNNER_DIR)


def run_v3(case_id: int, config: V123Config) -> int:
    """Run V3 (agent loop ON + proactive seed) in isolated workdir."""
    log(f"=== V3: Agent Loop + Proactive Seed (case {case_id}) ===")
    vdir = _make_version_workdir(case_id, "v3", config)
    cmd = _fuzz_cmd(case_id, vdir, config, agent_rounds=config.agent_rounds, proactive_seed=True)
    return run_cmd(cmd, config.dry_run, cwd=RUNNER_DIR)


def run_v1_background(case_id: int, config: V123Config) -> Optional[subprocess.Popen]:
    log(f"=== V1: Baseline (case {case_id}) [BACKGROUND] ===")
    vdir = _make_version_workdir(case_id, "v1", config)
    cmd = _fuzz_cmd(case_id, vdir, config, agent_rounds=0, proactive_seed=False)
    logfile = vdir / "run.log"
    if config.dry_run:
        log(f"[DRY-RUN] {' '.join(str(c) for c in cmd)}")
        return None
    return run_cmd(cmd, False, cwd=RUNNER_DIR, background=True, logfile=logfile)


def run_v2_background(case_id: int, config: V123Config) -> Optional[subprocess.Popen]:
    log(f"=== V2: No Agent Loop (case {case_id}) [BACKGROUND] ===")
    vdir = _make_version_workdir(case_id, "v2", config)
    cmd = _fuzz_cmd(case_id, vdir, config, agent_rounds=0, proactive_seed=False)
    logfile = vdir / "run.log"
    if config.dry_run:
        log(f"[DRY-RUN] {' '.join(str(c) for c in cmd)}")
        return None
    return run_cmd(cmd, False, cwd=RUNNER_DIR, background=True, logfile=logfile)


def run_v3_background(case_id: int, config: V123Config) -> Optional[subprocess.Popen]:
    log(f"=== V3: Agent Loop + Proactive Seed (case {case_id}) [BACKGROUND] ===")
    cmd = _fuzz_cmd(case_id, config, agent_rounds=config.agent_rounds, proactive_seed=True)
    logfile = config.prebuilt_workdir / f"v3_case_{case_id}" / "run.log"
    if config.dry_run:
        log(f"[DRY-RUN] {' '.join(str(c) for c in cmd)}")
        return None
    return run_cmd(cmd, False, cwd=RUNNER_DIR, background=True, logfile=logfile)


def run_comparison(config: V123Config) -> None:
    """Run V1/V2/V3 comparison for all configured cases."""
    log(f"Starting V1/V2/V3 comparison")
    log(f"  Cases: {config.cases}")
    log(f"  Versions: {config.versions}")
    log(f"  Pre-built workdir: {config.prebuilt_workdir}")
    log(f"  CPUs: {config.cpus}, Uptime: {config.uptime}h")
    log(f"  Parallel: {config.parallel}")
    if "v3" in config.versions:
        log(f"  Agent rounds: {config.agent_rounds}, Agent uptime: {config.agent_uptime}h")

    if not config.dry_run and not config.prebuilt_workdir.exists():
        log(f"ERROR: Pre-built workdir not found: {config.prebuilt_workdir}")
        log("  Pass --prebuilt-workdir to specify a valid pre-built workdir.")
        sys.exit(1)

    results = {}

    for case_id in config.cases:
        log(f"\n{'='*60}")
        log(f"Processing case {case_id}")
        log(f"{'='*60}")

        results[case_id] = {}

        if config.parallel:
            log("WARNING: --parallel runs all versions simultaneously.")
            log("  fuzzres/case_N will be overwritten by whichever version finishes last.")
            log("  Use sequential mode (no --parallel) for proper result separation.")
            procs = {}

            if "v1" in config.versions:
                proc = run_v1_background(case_id, config)
                if proc:
                    procs["v1"] = proc

            if "v2" in config.versions:
                proc = run_v2_background(case_id, config)
                if proc:
                    procs["v2"] = proc

            if "v3" in config.versions:
                proc = run_v3_background(case_id, config)
                if proc:
                    procs["v3"] = proc

            if config.dry_run:
                for v in config.versions:
                    results[case_id][v] = "ok (dry-run)"
            else:
                log(f"Waiting for {len(procs)} parallel processes...")
                for version, proc in procs.items():
                    rc = proc.wait()
                    results[case_id][version] = "ok" if rc == 0 else f"error({rc})"
                    log(f"  {version}: {'ok' if rc == 0 else f'error({rc})'}")
        else:
            if "v1" in config.versions:
                rc = run_v1(case_id, config)
                results[case_id]["v1"] = "ok" if rc == 0 else f"error({rc})"

            if "v2" in config.versions:
                rc = run_v2(case_id, config)
                results[case_id]["v2"] = "ok" if rc == 0 else f"error({rc})"

            if "v3" in config.versions:
                rc = run_v3(case_id, config)
                results[case_id]["v3"] = "ok" if rc == 0 else f"error({rc})"

    # Summary
    log(f"\n{'='*60}")
    log("SUMMARY")
    log(f"{'='*60}")
    for case_id, res in results.items():
        log(f"  Case {case_id}: {res}")

    results_path = config.prebuilt_workdir / "v123_results.json"
    if not config.dry_run:
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        log(f"Results saved to {results_path}")


def main():
    parser = argparse.ArgumentParser(
        description="V1/V2/V3 Comparison Runner for SyzDirect Dataset Cases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run case 0 with all three versions:
  python3 run_v123_comparison.py --cases 0

  # Run cases 0 and 1, only V2 and V3:
  python3 run_v123_comparison.py --cases 0 1 --versions v2 v3

  # Parallel execution (V1/V2/V3 run simultaneously):
  python3 run_v123_comparison.py --cases 0 --parallel --uptime 2

  # Dry run to see commands:
  python3 run_v123_comparison.py --cases 0 --dry-run

  # Custom pre-built workdir:
  python3 run_v123_comparison.py --cases 0 --prebuilt-workdir /path/to/workdir

  # Custom agent loop settings:
  python3 run_v123_comparison.py --cases 0 --agent-rounds 5 --agent-uptime 2
""",
    )

    parser.add_argument("--cases", type=int, nargs="+", default=DEFAULT_CASES,
                        help=f"Case IDs to run (default: {DEFAULT_CASES})")
    parser.add_argument("--versions", nargs="+", default=["v1", "v2", "v3"],
                        choices=["v1", "v2", "v3"],
                        help="Versions to run (default: v1 v2 v3)")
    parser.add_argument("--prebuilt-workdir", type=Path, default=DEFAULT_PREBUILT_WORKDIR,
                        dest="prebuilt_workdir",
                        help=f"Pre-built workdir with kernels+distance files (default: {DEFAULT_PREBUILT_WORKDIR})")
    parser.add_argument("-j", type=int, default=8, dest="cpus",
                        help="CPU cores (default: 8)")
    parser.add_argument("--uptime", type=float, default=1.0,
                        help="Fuzzing hours per session (default: 1.0)")
    parser.add_argument("--agent-rounds", type=int, default=3, dest="agent_rounds",
                        help="V3 agent loop rounds (default: 3)")
    parser.add_argument("--agent-uptime", type=float, default=0.5, dest="agent_uptime",
                        help="V3 hours per agent round (default: 0.5 = 30min)")
    parser.add_argument("--hunt-mode", default="hybrid",
                        choices=["repro", "harvest", "hybrid"],
                        dest="hunt_mode",
                        help="Hunt mode for V3 (default: hybrid)")
    parser.add_argument("--stall-timeout", type=int, default=1800, dest="stall_timeout",
                        help="Coverage stall timeout in seconds (default: 1800)")
    parser.add_argument("--dist-stall-timeout", type=int, default=600,
                        dest="dist_stall_timeout",
                        help="Distance stall timeout in seconds (default: 600)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without executing")
    parser.add_argument("--parallel", action="store_true",
                        help="Run V1/V2/V3 in parallel")

    args = parser.parse_args()

    config = V123Config(
        cases=args.cases,
        versions=args.versions,
        prebuilt_workdir=args.prebuilt_workdir,
        cpus=args.cpus,
        uptime=args.uptime,
        agent_rounds=args.agent_rounds,
        agent_uptime=args.agent_uptime,
        hunt_mode=args.hunt_mode,
        stall_timeout=args.stall_timeout,
        dist_stall_timeout=args.dist_stall_timeout,
        dry_run=args.dry_run,
        parallel=args.parallel,
    )

    run_comparison(config)


if __name__ == "__main__":
    main()
