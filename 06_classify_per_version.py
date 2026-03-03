#!/usr/bin/env python3
"""
per-version static analysis 결과 → R1/R2/R3 분류
논문 기준:
  R1: target 못 찾거나 syscall path 없음
  R2: syscall 찾았지만 constraints 없거나 엉뚱한 서브시스템
  R3: syscall + constraints 찾았고 올바른 서브시스템
"""
import json, os, re
from pathlib import Path

RESULT_BASE = Path("/home/ai/static_analysis_per_version")
BUG_COMMITS  = Path("/home/ai/bug_kernel_commits.json")
CLASSIFY_OUT = Path("/home/ai/per_version_classifications.json")

with open(BUG_COMMITS) as f:
    commits = json.load(f)

def target_subsystem(filepath):
    """파일 경로에서 서브시스템 추출 (net, fs, drivers, mm, kernel, sound, crypto, ...)"""
    parts = filepath.split("/")
    return parts[0] if parts else ""

def syscall_subsystem(syscall_name):
    """syscall 이름에서 서브시스템 힌트 추출"""
    name = syscall_name.lower()
    # 네트워크
    if any(k in name for k in ["socket", "sendmsg", "recvmsg", "bind", "connect",
                                 "setsockopt", "ioctl$sock", "sendto", "netlink",
                                 "sched", "tc", "qdisc", "packet", "sctp", "rxrpc",
                                 "smc", "ipvlan", "vxlan", "xfrm", "nftables", "nf_"]):
        return "net"
    if any(k in name for k in ["open$", "read", "write", "ioctl$", "mount",
                                 "mmap", "splice", "sendfile", "fsconfig",
                                 "ext4", "gfs2", "hfs", "ntfs", "erofs", "btrfs",
                                 "fuse", "squashfs", "reiserfs", "aio", "io_uring",
                                 "fscache", "iomap", "namei"]):
        return "fs"
    if any(k in name for k in ["madvise", "mremap", "mprotect", "brk", "mmap"]):
        return "mm"
    if any(k in name for k in ["ioctl$vmci", "vmci"]):
        return "drivers"
    if any(k in name for k in ["snd_", "pcm", "seq", "mixer", "oss"]):
        return "sound"
    if any(k in name for k in ["bpf$", "perf_event"]):
        return "kernel"
    if any(k in name for k in ["infiniband", "rdma", "ib_"]):
        return "drivers"
    return "unknown"

def classify_bug(bug_id, info):
    bid = f"B{int(bug_id):03d}"
    out_dir = RESULT_BASE / bid
    filepath = info.get("filepath", "")
    target_sub = target_subsystem(filepath)

    analysis_log = out_dir / "analysis.log"
    compact_json = out_dir / "CompactOutput.json"

    # 파일 없으면 R1
    if not compact_json.exists():
        return "R1", "CompactOutput.json 없음"

    content = compact_json.read_text().strip()

    # target point 발견 여부
    tp_found = False
    if analysis_log.exists():
        log = analysis_log.read_text(errors='replace')
        tp_found = "[TargetPoint] Found" in log

    # CompactOutput이 빈 배열
    if content == "[]":
        if tp_found:
            return "R1", "target 발견했지만 syscall path 없음"
        else:
            return "R1", "target point 미발견"

    try:
        data = json.loads(content)
    except:
        return "R1", "JSON 파싱 실패"

    if not data:
        return "R1", "syscall 없음"

    # syscall 목록 수집
    syscalls = []
    has_constraints = False
    for item in data:
        for sc_info in item.get("target syscall infos", []):
            sc_name = sc_info.get("target syscall", "")
            if sc_name:
                syscalls.append(sc_name)
            # constraints 확인
            constraints = sc_info.get("constraints", [])
            if constraints and len(constraints) > 0:
                has_constraints = True

    if not syscalls:
        return "R1", "syscall 이름 없음"

    # 서브시스템 매칭 확인
    matched = any(syscall_subsystem(sc) == target_sub or target_sub == "unknown"
                  for sc in syscalls)

    # R2: syscall 있지만 서브시스템 불일치 또는 constraints 없음
    if not matched:
        return "R2", f"syscall({syscalls[:2]}) 서브시스템 불일치 (target={target_sub})"
    if not has_constraints:
        return "R2", f"syscall 있지만 constraints 없음"

    # R3: syscall + constraints + 올바른 서브시스템
    return "R3", f"syscall {syscalls[:2]}, constraints 있음"


results = {}
r_counts = {"R1": 0, "R2": 0, "R3": 0, "MISSING": 0}

for bug_id, info in sorted(commits.items(), key=lambda x: int(x[0])):
    bid = f"B{int(bug_id):03d}"
    out_dir = RESULT_BASE / bid

    if not out_dir.exists():
        r_counts["MISSING"] += 1
        results[bid] = {"classification": "MISSING", "reason": "디렉토리 없음",
                        "filepath": info.get("filepath", ""), "kernel_version": info.get("kernel_version", "")}
        continue

    cls, reason = classify_bug(bug_id, info)
    r_counts[cls] = r_counts.get(cls, 0) + 1
    results[bid] = {
        "classification": cls,
        "reason": reason,
        "filepath": info.get("filepath", ""),
        "kernel_version": info.get("kernel_version", ""),
    }

with open(CLASSIFY_OUT, "w") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("=" * 50)
print(" Per-version 분류 결과")
print("=" * 50)
print(f"  R1: {r_counts['R1']:2d}개  (논문 목표: 19)")
print(f"  R2: {r_counts['R2']:2d}개  (논문 목표: 19)")
print(f"  R3: {r_counts['R3']:2d}개  (논문 목표: 20)")
if r_counts.get("MISSING"):
    print(f"  MISSING: {r_counts['MISSING']}개")
print(f"\n  저장: {CLASSIFY_OUT}")
print()

print("버그별 결과:")
for bid, v in sorted(results.items()):
    print(f"  {bid} [{v['classification']}] ({v['kernel_version']}) {v['filepath']} — {v['reason']}")
