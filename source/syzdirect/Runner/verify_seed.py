#!/usr/bin/env python3
"""
Verify whether a seed corpus actually reaches the target function in a VM.

This answers the critical question: is the seed correct but syzkaller
mishandles it, or is the seed itself wrong?

Usage:
  # Verify a specific seed DB against a case
  python3 verify_seed.py --case 0 --seed path/to/corpus.db

  # Verify all existing seeds for a case
  python3 verify_seed.py --case 0

  # Verify with longer VM runtime
  python3 verify_seed.py --case 0 --vm-uptime 120

  # Just unpack and display seed contents (no VM)
  python3 verify_seed.py --case 0 --dry-run
"""

import argparse
import copy
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

# Add Runner to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paths import WorkdirLayout, PREBUILT_TARGETS
from runner_config import RunnerConfig
from Fuzz import _alloc_free_tcp_port, runFuzzer
from llm_enhance import _parse_detail_corpus
import Config


# ── Constants ──────────────────────────────────────────────────────────

WORKDIR = "/home/ai/work_real/workdir_v3_unified"
SYZ_DB = None  # resolved at runtime

def _update_workdir(path):
    global WORKDIR
    if path:
        WORKDIR = path


CASE_TARGETS = {
    0: "tcindex_alloc_perfect_hash",
    1: "qdisc_create",
    2: "fifo_set_limit",
    3: "tcp_cleanup_congestion_control",
    4: "move_page_tables",
    5: "sco_sock_create",
    6: "tcf_exts_init_ex",
    7: "nf_tables_newrule",
    8: "sctp_sf_do_prm_asoc",
    9: "xfrm_state_find",
    11: "llc_ui_sendmsg",
}


def resolve_syz_db():
    global SYZ_DB
    SYZ_DB = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "syzdirect_fuzzer", "bin", "syz-db",
    )
    if not os.path.exists(SYZ_DB):
        # Try parent
        SYZ_DB = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "syzdirect_fuzzer", "bin", "syz-db",
        )
    assert os.path.exists(SYZ_DB), f"syz-db not found at {SYZ_DB}"
    return SYZ_DB


def unpack_seed(seed_db_path):
    """Unpack a corpus.db and return list of program texts."""
    tmpdir = tempfile.mkdtemp(prefix="seed_unpack_")
    try:
        subprocess.run(
            [SYZ_DB, "unpack", seed_db_path, tmpdir],
            capture_output=True, timeout=30,
        )
        programs = []
        for fname in sorted(os.listdir(tmpdir)):
            fpath = os.path.join(tmpdir, fname)
            if os.path.isfile(fpath):
                with open(fpath) as f:
                    programs.append(f.read().strip())
        return programs
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def decode_anyblob(hex_str):
    """Decode ANYBLOB hex to human-readable netlink structure."""
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        return f"  (invalid hex: {hex_str[:40]}...)"

    if len(b) < 16:
        return f"  (too short: {len(b)} bytes)"

    lines = []
    nllen, nltype, nlflags = struct.unpack_from('<IHH', b, 0)
    type_names = {0x24: "RTM_NEWQDISC", 0x25: "RTM_DELQDISC",
                  0x2c: "RTM_NEWTFILTER", 0x10: "RTM_NEWLINK"}
    type_str = type_names.get(nltype, f"0x{nltype:x}")
    lines.append(f"  nlmsg: len={nllen} type={type_str} flags=0x{nlflags:x}")

    if len(b) >= 36:
        family = b[16]
        ifindex = struct.unpack_from('<i', b, 20)[0]
        handle = struct.unpack_from('<I', b, 24)[0]
        parent = struct.unpack_from('<I', b, 28)[0]
        lines.append(f"  tcmsg: family={family} ifindex={ifindex} "
                      f"handle=0x{handle:x} parent=0x{parent:x}")

        # Parse NLAs
        off = 36
        while off + 4 <= len(b):
            nla_len, nla_type = struct.unpack_from('<HH', b, off)
            if nla_len < 4:
                break
            payload = b[off + 4:off + nla_len]
            if nla_type == 1:  # TCA_KIND
                kind = payload.rstrip(b'\x00').decode('ascii', errors='replace')
                lines.append(f"  TCA_KIND: \"{kind}\"")
            elif nla_type == 2:  # TCA_OPTIONS
                lines.append(f"  TCA_OPTIONS: {payload.hex()} ({len(payload)} bytes)")
            else:
                lines.append(f"  NLA type={nla_type}: {payload.hex()}")
            off += (nla_len + 3) & ~3

    return "\n".join(lines)


def display_seed(program_text):
    """Pretty-print a syzkaller program with decoded ANYBLOBs."""
    import re
    print(program_text)
    # Find and decode ANYBLOBs
    for match in re.finditer(r'@ANYBLOB="([0-9a-fA-F]+)"', program_text):
        hex_str = match.group(1)
        decoded = decode_anyblob(hex_str)
        print(f"  ↳ DECODED:")
        print(decoded)
    print()


def find_seeds_for_case(case_idx):
    """Find all seed DB files for a given case."""
    seeds = []
    # Search in various workdir patterns
    patterns = [
        f"/home/ai/work_real/workdir_v3_unified/fuzzres/case_{case_idx}/xidx_0",
        f"/home/ai/work_real/workdir_v3_unified_v3_case{case_idx}/fuzzres/case_{case_idx}/xidx_0",
    ]
    for d in patterns:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if fname.endswith(".db") and ("seed" in fname or "corpus" in fname):
                fpath = os.path.join(d, fname)
                size = os.path.getsize(fpath)
                if size > 16:  # skip empty DBs
                    seeds.append(fpath)
    return seeds


def run_in_vm(seed_db_path, case_idx, vm_uptime=60):
    """Run seed in VM and measure distance achieved.

    Returns dict with best_dist, program details, etc.
    """
    layout = WorkdirLayout(WORKDIR)

    # Initialize Config
    Config.WorkdirPrefix = WORKDIR
    Config.FuzzUptime = 1
    Config.FuzzRounds = 1
    Config.CPUNum = 2
    Config.PreparePathVariables()

    # Check prerequisites
    kernel_img = layout.bzimage(case_idx)
    callfile = layout.callfile(case_idx)
    assert os.path.exists(kernel_img), f"No kernel image: {kernel_img}"
    assert os.path.exists(callfile), f"No callfile: {callfile}"

    template_config = {
        "target": "linux/amd64",
        "sshkey": Config.KeyPath,
        "procs": 1,  # Minimize mutation
        "type": "qemu",
        "vm": {"count": 1, "cpu": 2, "mem": 4096},
        "reproduce": False,
    }

    syzdirect_path = Config.FuzzerDir
    fuzzer_file = os.path.join(syzdirect_path, "bin", "syz-manager")

    # Get hitindex
    tfmap = Config.ParseTargetFunctionsInfoFile(case_idx)
    if tfmap:
        xidx = list(tfmap.keys())[0]
    else:
        xidx = 0

    verify_dir = tempfile.mkdtemp(prefix="verify_seed_")
    try:
        config = copy.deepcopy(template_config)
        config["image"] = Config.CleanImageTemplatePath
        sub_workdir = os.path.join(verify_dir, "workdir")
        config["workdir"] = sub_workdir
        config["http"] = f"0.0.0.0:{_alloc_free_tcp_port()}"
        config["vm"]["kernel"] = kernel_img
        config["syzkaller"] = syzdirect_path
        config["hitindex"] = int(xidx)

        config_path = os.path.join(verify_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent="\t")

        log_dir = os.path.join(verify_dir, "logs")

        # Set very short uptime
        original_uptime = Config.FuzzUptime
        Config.FuzzUptime = 1  # 1 hour max (will be cut short by stall timeout)

        try:
            print(f"\n{'='*60}")
            print(f"  RUNNING SEED IN VM")
            print(f"  Seed: {seed_db_path}")
            print(f"  Case: {case_idx} (target: {CASE_TARGETS.get(case_idx, '?')})")
            print(f"  VM uptime: {vm_uptime}s, procs: 1 (minimal mutation)")
            print(f"{'='*60}\n")

            manager_log, metrics_jsonl = runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
                stall_timeout=vm_uptime,
                dist_stall_timeout=vm_uptime,
                seed_corpus=seed_db_path,
            )
        finally:
            Config.FuzzUptime = original_uptime

        # Parse results
        detail_corpus = os.path.join(sub_workdir, "detailCorpus.txt")
        programs = _parse_detail_corpus(detail_corpus)
        programs.sort(key=lambda x: x[1])

        best_dist = programs[0][1] if programs else None

        # Parse last metrics
        last_metrics = None
        if metrics_jsonl and os.path.exists(metrics_jsonl):
            try:
                with open(metrics_jsonl) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            last_metrics = json.loads(line)
            except (OSError, json.JSONDecodeError):
                pass

        # Print results
        print(f"\n{'='*60}")
        print(f"  VERIFICATION RESULTS")
        print(f"{'='*60}")
        print(f"  Target: {CASE_TARGETS.get(case_idx, '?')}")
        print(f"  Best distance: {best_dist}")
        print(f"  Programs with distance: {len(programs)}")

        if programs:
            print(f"\n  Top 10 programs by distance:")
            for i, (prog, dist) in enumerate(programs[:10]):
                print(f"    [{i}] dist={dist}  {prog[:80]}...")

        if last_metrics:
            print(f"\n  Final metrics:")
            print(f"    executed: {last_metrics.get('executed', '?')}")
            print(f"    cover: {last_metrics.get('cover', '?')}")
            print(f"    dist: {last_metrics.get('dist_min', '?')}/{last_metrics.get('dist_count', '?')}")

        if best_dist == 0:
            print(f"\n  ✅ TARGET REACHED! The seed is correct.")
        elif best_dist is not None:
            print(f"\n  ❌ Target NOT reached (best_dist={best_dist}).")
            print(f"     The seed itself may be insufficient.")
        else:
            print(f"\n  ⚠  No distance data. VM may have failed to boot or load seed.")

        # Copy logs for inspection
        log_copy = os.path.join(
            os.path.dirname(seed_db_path),
            f"verify_log_case{case_idx}.txt",
        )
        if manager_log and os.path.exists(manager_log):
            shutil.copy2(manager_log, log_copy)
            print(f"\n  Log saved: {log_copy}")

        return {
            "best_dist": best_dist,
            "programs": programs,
            "metrics": last_metrics,
        }
    finally:
        shutil.rmtree(verify_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Verify seed corpus in VM")
    parser.add_argument("--case", "-c", type=int, required=True,
                        help="Case index (0-11)")
    parser.add_argument("--seed", "-s", default=None,
                        help="Path to seed corpus.db (auto-detected if omitted)")
    parser.add_argument("--vm-uptime", type=int, default=90,
                        help="VM runtime in seconds (default: 90)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Just display seed contents, don't run VM")
    parser.add_argument("--workdir", default=None,
                        help="Workdir path (default: workdir_v3_unified)")
    args = parser.parse_args()

    _update_workdir(args.workdir)

    resolve_syz_db()

    # Find or use specified seed
    if args.seed:
        seeds = [args.seed]
    else:
        seeds = find_seeds_for_case(args.case)
        if not seeds:
            print(f"No seed files found for case {args.case}")
            sys.exit(1)
        print(f"Found {len(seeds)} seed files for case {args.case}:")
        for s in seeds:
            size = os.path.getsize(s)
            print(f"  {os.path.basename(s)} ({size} bytes)")

    # Display seed contents
    for seed_path in seeds:
        print(f"\n{'='*60}")
        print(f"  SEED: {os.path.basename(seed_path)}")
        print(f"{'='*60}")
        programs = unpack_seed(seed_path)
        if not programs:
            print("  (empty — 0 programs)")
            continue
        print(f"  {len(programs)} programs:\n")
        for i, prog in enumerate(programs):
            print(f"  --- Program {i} ---")
            display_seed(prog)

    if args.dry_run:
        return

    # Run each non-empty seed in VM
    for seed_path in seeds:
        programs = unpack_seed(seed_path)
        if not programs:
            continue
        try:
            result = run_in_vm(seed_path, args.case, vm_uptime=args.vm_uptime)
        except Exception as e:
            print(f"\n  ERROR running VM: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
