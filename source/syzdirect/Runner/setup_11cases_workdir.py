#!/usr/bin/env python3
"""
11개 케이스 통합 workdir 세팅 스크립트.

기존 6개 케이스의 pre-built artifact를 올바른 case index로 symlink하고,
신규 5개 케이스(idx 7~11)는 빈 디렉토리만 생성해 pipeline이 빌드하도록 준비.

실행:
  python3 setup_11cases_workdir.py [--workdir ./workdir_11cases] [--dry-run]
"""

import argparse
import os
import shutil
import sys

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))

# ── 기존 pre-built 케이스 매핑 ─────────────────────────────────────────────
# (new_idx, source_workdir, source_case_idx)
PREBUILT_CASES = [
    (0, "/home/ai/work_real/workdir_v3_ga", 0),   # tcindex_alloc_perfect_hash
    (1, "/home/ai/work_real/workdir_v3_ga", 1),   # qdisc_create
    (2, "/home/ai/work_real/workdir_v3_ga", 2),   # fifo_set_limit
    (3, "/home/ai/work_real/workdir_v3_ga", 3),   # tcp_cleanup_congestion_control
    (4, "/home/ai/work_real/workdir_new_cases/case_bug45_mremap", 0),   # move_page_tables
    (5, "/home/ai/work_real/workdir_new_cases/case_bug74_bluetooth", 0),  # sco_sock_create
    (6, "/home/ai/work_real/workdir_new_cases/case_bug78_cls_api", 0),    # tcf_exts_init_ex
]

# read-only → symlink
SYMLINK_SUBDIRS = [
    "srcs",
    "bcs",
    "interfaces",
    "kwithdist",
    "tpa",
    "consts",
    "multi-pts",   # will be populated by pipeline for new cases
]

# writable → copy (pipeline이 수정할 수 있어야 함)
COPY_SUBDIRS = [
    "fuzzinps",
]

# workdir root 레벨 파일 (symlink)
SYMLINK_ROOT_FILES = [
    "emit-llvm.sh",
    "syzkaller_signature.txt",
    "target2relate2.json",
]


def _src_case_dir(src_workdir, src_ci, subdir):
    """Return path to case-level subdir in source workdir."""
    if subdir in ("multi-pts",):
        return os.path.join(src_workdir, subdir, f"case_{src_ci}.txt")
    return os.path.join(src_workdir, subdir, f"case_{src_ci}")


def _dst_case_dir(dst_workdir, dst_ci, subdir):
    if subdir in ("multi-pts",):
        return os.path.join(dst_workdir, subdir, f"case_{dst_ci}.txt")
    return os.path.join(dst_workdir, subdir, f"case_{dst_ci}")


def setup(workdir, dry_run=False):
    def log(msg):
        print(msg)

    def run(fn, *args, **kwargs):
        if dry_run:
            log(f"[DRY] {fn.__name__}({args}, {kwargs})")
        else:
            fn(*args, **kwargs)

    log(f"Setting up workdir: {workdir}")
    log(f"  Pre-built cases: {[c[0] for c in PREBUILT_CASES]}")
    log(f"  New cases (build needed): 7, 8, 9, 10, 11")
    log("")

    if not dry_run:
        os.makedirs(workdir, exist_ok=True)

    # ── 1. workdir root 레벨 파일 (첫 번째 pre-built에서 가져옴) ──────────
    ref_workdir = PREBUILT_CASES[0][1]
    for fname in SYMLINK_ROOT_FILES:
        src = os.path.join(ref_workdir, fname)
        dst = os.path.join(workdir, fname)
        if os.path.exists(src) and not os.path.exists(dst):
            if dry_run:
                log(f"[DRY] symlink {dst} -> {src}")
            else:
                os.symlink(src, dst)
                log(f"  symlink root: {fname}")

    # ── 2. Pre-built 6개: subdir symlink / copy ───────────────────────────
    for dst_ci, src_workdir, src_ci in PREBUILT_CASES:
        log(f"\n[case {dst_ci}] pre-built from {os.path.basename(src_workdir)}/case_{src_ci}")

        for subdir in SYMLINK_SUBDIRS:
            src = _src_case_dir(src_workdir, src_ci, subdir)
            dst = _dst_case_dir(workdir, dst_ci, subdir)
            if not os.path.exists(src):
                log(f"  skip (not found): {subdir}/case_{src_ci}")
                continue
            dst_parent = os.path.dirname(dst)
            if not dry_run:
                os.makedirs(dst_parent, exist_ok=True)
            if not os.path.exists(dst):
                if dry_run:
                    log(f"  [DRY] symlink {subdir}/case_{dst_ci} -> {src}")
                else:
                    os.symlink(src, dst)
                    log(f"  symlink: {subdir}/case_{dst_ci}")

        for subdir in COPY_SUBDIRS:
            src = _src_case_dir(src_workdir, src_ci, subdir)
            dst = _dst_case_dir(workdir, dst_ci, subdir)
            if not os.path.exists(src):
                log(f"  skip (not found): {subdir}/case_{src_ci}")
                continue
            dst_parent = os.path.dirname(dst)
            if not dry_run:
                os.makedirs(dst_parent, exist_ok=True)
            if not os.path.exists(dst):
                if dry_run:
                    log(f"  [DRY] copytree {subdir}/case_{dst_ci} <- {src}")
                else:
                    shutil.copytree(src, dst)
                    log(f"  copytree: {subdir}/case_{dst_ci}")

        # fuzzres: 빈 디렉토리 (새 실험 결과용)
        fuzzres_dst = os.path.join(workdir, "fuzzres", f"case_{dst_ci}")
        if not os.path.exists(fuzzres_dst):
            if dry_run:
                log(f"  [DRY] mkdir fuzzres/case_{dst_ci}")
            else:
                os.makedirs(fuzzres_dst, exist_ok=True)
                log(f"  mkdir: fuzzres/case_{dst_ci}")

    # ── 3. 신규 5개: 빈 디렉토리만 생성 (pipeline이 채움) ─────────────────
    for dst_ci in range(7, 12):
        log(f"\n[case {dst_ci}] new case — creating empty dirs for pipeline")
        for subdir in ["srcs", "bcs", "interfaces", "kwithdist", "tpa",
                       "consts", "fuzzinps", "fuzzres"]:
            d = os.path.join(workdir, subdir, f"case_{dst_ci}")
            if not dry_run:
                os.makedirs(d, exist_ok=True)
            else:
                log(f"  [DRY] mkdir {subdir}/case_{dst_ci}")

        # multi-pts 디렉토리 (파일은 pipeline이 function 컬럼으로 채움)
        mp_dir = os.path.join(workdir, "multi-pts")
        if not dry_run:
            os.makedirs(mp_dir, exist_ok=True)

    log("\n✓ workdir setup complete.")
    log(f"  Run pipeline with:")
    log(f"    cd {RUNNER_DIR}")
    log(f"    python3 run_hunt.py dataset \\")
    log(f"      -dataset dataset_11cases.xlsx \\")
    log(f"      -workdir {workdir} \\")
    log(f"      -linux-repo-template /home/ai/work_real/workdir_v1/srcs/case_0 \\")
    log(f"      -j 8 \\")
    log(f"      prepare_for_manual_instrument \\")
    log(f"      compile_kernel_bitcode \\")
    log(f"      analyze_kernel_syscall \\")
    log(f"      extract_syscall_entry \\")
    log(f"      instrument_kernel_with_distance")


def main():
    parser = argparse.ArgumentParser(description="Setup 11-case unified workdir")
    parser.add_argument("--workdir", default="./workdir_11cases",
                        help="Target workdir path (default: ./workdir_11cases)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without executing")
    args = parser.parse_args()

    workdir = os.path.abspath(args.workdir)
    setup(workdir, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
