#!/usr/bin/env python3
"""
Run a SyzDirect known-bugs dataset case with the user's V1/V2/V3 definitions.

Definitions:
  V1: original SyzDirect checkout
  V2: LLVM 18 SyzDirect (run_hunt.py, agent loop off)
  V3: LLVM 18 SyzDirect + run_hunt.py + agent loop

This script intentionally separates:
  1. metadata/bootstrap for a known-bugs dataset case
  2. V1 execution through the original experiment wrapper
  3. V2/V3 execution through Runner/run_hunt.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from semantic_seed import _collect_function_ranges


RUNNER_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUNNER_DIR.parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
RUN_DATASET_CASE = SCRIPTS_DIR / "run_dataset_case.py"
RUN_HUNT = RUNNER_DIR / "run_hunt.py"


def shlex_join(parts: list[str]) -> str:
    import shlex

    return " ".join(shlex.quote(part) for part in parts)


def run(cmd: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> None:
    print(f"$ {shlex_join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, env=env, cwd=str(cwd) if cwd else None)


def spawn(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    log_path: Path | None = None,
) -> subprocess.Popen:
    print(f"$ {shlex_join(cmd)}", flush=True)
    stdout = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stdout = open(log_path, "w", encoding="utf-8")
    return subprocess.Popen(
        cmd,
        env=env,
        cwd=str(cwd) if cwd else None,
        stdout=stdout or subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        text=True,
    )


def infer_function_from_source(src_root: Path, file_path: str, line: int | None) -> str:
    if not line:
        raise SystemExit("target.json does not include a line number; cannot infer function for V2/V3")

    abs_path = src_root / file_path
    if not abs_path.exists():
        raise SystemExit(f"prepared kernel source missing target file: {abs_path}")

    _, ranges = _collect_function_ranges(str(abs_path))
    if not ranges:
        raise SystemExit(f"failed to infer function from {abs_path}: no function ranges found")

    for item in ranges:
        if item["start"] <= line <= item["end"]:
            return item["name"]

    raise SystemExit(
        f"failed to infer function from {abs_path}:{line}: "
        f"no containing function range matched"
    )


def load_target(output_root: Path, case_id: int) -> tuple[dict, Path]:
    case_root = output_root / "known-bugs" / f"case_{case_id}"
    target_path = case_root / "target.json"
    if not target_path.exists():
        raise SystemExit(f"missing target.json: {target_path}")

    payload = json.loads(target_path.read_text(encoding="utf-8"))
    kernel_src = case_root / "kernel-src"
    if not kernel_src.exists():
        raise SystemExit(f"missing prepared kernel source tree: {kernel_src}")
    return payload, kernel_src


def prepare_case(args: argparse.Namespace) -> None:
    cmd = [
        sys.executable,
        str(RUN_DATASET_CASE),
        "--case-id",
        str(args.case_id),
        "--dataset-kind",
        "known-bugs",
        "--mode",
        "syzdirect",
        "--budget-hours",
        str(args.budget_hours),
        "--repetitions",
        "1",
        "--syzdirect-root",
        str(args.upstream_root),
        "--output-root",
        str(args.output_root),
        "--prepare-only",
    ]
    run(cmd, env=os.environ.copy())


def build_v1_cmd(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        str(RUN_DATASET_CASE),
        "--case-id",
        str(args.case_id),
        "--dataset-kind",
        "known-bugs",
        "--mode",
        "syzdirect",
        "--budget-hours",
        str(args.budget_hours),
        "--repetitions",
        "1",
        "--syzdirect-root",
        str(args.upstream_root),
        "--output-root",
        str(args.output_root),
    ]


def build_v2_v3_cmd(
    args: argparse.Namespace,
    *,
    target: dict,
    inferred_function: str,
    agent_rounds: int,
) -> list[str]:
    workdir = args.output_root / f"v{'3' if agent_rounds > 0 else '2'}_case_{args.case_id}"
    cmd = [
        sys.executable,
        str(RUN_HUNT),
        "-j",
        str(args.jobs),
        "-uptime",
        str(args.budget_hours),
        "-workdir",
        str(workdir),
        "new",
        "--cve",
        f"SYZDIRECT-KNOWN-BUG-{args.case_id}",
        "--commit",
        target["kernel_commit"],
        "--function",
        inferred_function,
        "--file",
        target["file_path"],
        "--hunt-mode",
        args.hunt_mode,
    ]
    if agent_rounds > 0:
        cmd += [
            "--agent-rounds",
            str(agent_rounds),
            "--agent-uptime",
            str(args.agent_uptime),
            "--stall-timeout",
            str(args.stall_timeout),
            "--dist-stall-timeout",
            str(args.dist_stall_timeout),
        ]
        if args.proactive_seed:
            cmd.append("--proactive-seed")
    return cmd


def main() -> None:
    parser = argparse.ArgumentParser(description="Run known-bugs case with V1/V2/V3 layout")
    parser.add_argument("--case-id", type=int, required=True)
    parser.add_argument("--budget-hours", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--upstream-root",
        default="/home/ai/work/SyzDirect-upstream",
        help="Original SyzDirect checkout for V1",
    )
    parser.add_argument(
        "--output-root",
        default="/tmp/syzdirect_v123_runs",
        help="Shared output root for metadata/bootstrap and run outputs",
    )
    parser.add_argument("--hunt-mode", default="hybrid", choices=("repro", "harvest", "hybrid"))
    parser.add_argument("--agent-rounds", type=int, default=5)
    parser.add_argument("--agent-uptime", type=int, default=1)
    parser.add_argument("--stall-timeout", type=int, default=1800)
    parser.add_argument("--dist-stall-timeout", type=int, default=900)
    parser.add_argument("--proactive-seed", action="store_true", default=False)
    parser.add_argument(
        "--versions",
        nargs="+",
        default=["v1", "v2", "v3"],
        choices=("v1", "v2", "v3"),
        help="Subset of versions to run",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print commands without executing them",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run selected versions in parallel after shared prepare step",
    )
    args = parser.parse_args()

    args.upstream_root = Path(args.upstream_root).resolve()
    args.output_root = Path(args.output_root).resolve()

    prepare_case(args)
    target, kernel_src = load_target(args.output_root, args.case_id)
    inferred_function = infer_function_from_source(
        kernel_src, target["file_path"], target.get("line")
    )

    commands: list[tuple[str, list[str]]] = []
    if "v1" in args.versions:
        commands.append(("V1", build_v1_cmd(args)))
    if "v2" in args.versions:
        commands.append(
            (
                "V2",
                build_v2_v3_cmd(args, target=target, inferred_function=inferred_function, agent_rounds=0),
            )
        )
    if "v3" in args.versions:
        commands.append(
            (
                "V3",
                build_v2_v3_cmd(
                    args,
                    target=target,
                    inferred_function=inferred_function,
                    agent_rounds=args.agent_rounds,
                ),
            )
        )

    print(f"[target] case={args.case_id} commit={target['kernel_commit']} file={target['file_path']} function={inferred_function}")
    for label, cmd in commands:
        print(f"\n[{label}] {shlex_join(cmd)}")

    if args.print_only:
        return

    if args.parallel:
        procs: list[tuple[str, subprocess.Popen, Path]] = []
        logs_dir = args.output_root / "parallel_logs" / f"case_{args.case_id}"
        for label, cmd in commands:
            log_path = logs_dir / f"{label.lower()}.log"
            print(f"\n=== Starting {label} in parallel ===", flush=True)
            proc = spawn(cmd, env=os.environ.copy(), log_path=log_path)
            procs.append((label, proc, log_path))
            print(f"[{label}] pid={proc.pid} log={log_path}", flush=True)

        failed = False
        while procs:
            for label, proc, log_path in list(procs):
                rc = proc.poll()
                if rc is None:
                    continue
                procs.remove((label, proc, log_path))
                print(f"[{label}] exit={rc} log={log_path}", flush=True)
                if rc != 0:
                    failed = True
            if procs:
                time.sleep(2)
        if failed:
            raise SystemExit(1)
        return

    for label, cmd in commands:
        print(f"\n=== Running {label} ===", flush=True)
        run(cmd, env=os.environ.copy())


if __name__ == "__main__":
    main()
