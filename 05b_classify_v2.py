#!/usr/bin/env python3
"""
SyzDirect 실제 실행 결과 기반 R1/R2/R3 분류기.

CompactOutput.json + PoC 데이터를 사용하여 SyzDirect 실패 원인 분류.

R1: Incomplete dependent/related syscall inference
    - SyzDirect가 target point를 찾지 못함 (bitcode에서 미발견)
    - 또는 syscall을 아예 찾지 못함
    → 원인: indirect call, 특수 call path, 미지원 subsystem

R2: Difficulties in generating proper syscall arguments
    - SyzDirect가 syscall을 찾았지만 구체적인 constraints가 없음
    - generic syscall만 찾음 (예: write, read, mount)
    → 원인: ioctl cmd, 특수 arg 값 추론 실패

R3: Lack of deep analysis for related syscalls
    - SyzDirect가 syscall + constraints를 찾았지만
      실제 bug trigger에 필요한 sequence/setup이 부족함
    - 또는 너무 많은 syscall 후보 (signal-to-noise 낮음)
    → 원인: dependent syscall, complex state setup
"""

import json
import os
import sys
import re

RESULTS_V2 = "/home/ai/static_analysis_results_v2"
POC_DATA = "/home/ai/classification_results.json"
OUTPUT_FILE = "/home/ai/phase3_final_classifications.json"
NOTION_LOG = "/home/ai/notion_log.py"

# R1/R2/R3 분류 기준
# 비어있음/TargetPoint 미발견 → R1
# syscall 찾았지만 constraints 전혀 없음 → R2
# syscall + constraints 있음 → R3

# "generic" syscall들: 이것만 나오면 R2에 가깝다
GENERIC_SYSCALLS = {
    "read", "write", "open", "close", "mmap", "munmap", "ioctl",
    "sendmsg", "recvmsg", "mount", "getxattr", "setxattr",
    "read$generic", "write$generic"
}

# 너무 많은 syscall 후보를 가진 경우 (>10) → R3 가능성
MAX_SYSCALLS_FOR_R2 = 10

BUGS = {
    "B007": "net/qrtr/tun.c:92",
    "B008": "drivers/misc/vmw_vmci/vmci_queue_pair.c:539",
    "B011": "fs/gfs2/util.c:293",
    "B012": "net/mac80211/sta_info.c:485",
    "B016": "net/rxrpc/sendmsg.c:747",
    "B020": "fs/squashfs/file.c:242",
    "B022": "net/sched/sch_taprio.c:998",
    "B026": "fs/ext4/super.c:6607",
    "B027": "net/sched/cls_tcindex.c:307",
    "B028": "fs/fuse/dir.c:1120",
    "B029": "include/net/gre.h:140",
    "B030": "net/core/dev.c:3701",
    "B031": "fs/splice.c:766",
    "B032": "net/sched/sch_api.c:1298",
    "B035": "net/sched/sch_fifo.c:241",
    "B036": "sound/core/seq/seq_queue.c:171",
    "B038": "fs/ext4/extents_status.c:897",
    "B039": "drivers/infiniband/core/cma.c:2584",
    "B040": "net/mac80211/cfg.c:1681",
    "B041": "sound/core/oss/pcm_plugin.c:70",
    "B042": "kernel/dma/mapping.c:263",
    "B043": "fs/ext4/xattr.c:1639",
    "B044": "fs/ext4/indirect.c:1243",
    "B045": "mm/mremap.c:498",
    "B046": "net/socket.c:1123",
    "B047": "net/smc/smc_pnet.c:316",
    "B051": "kernel/bpf/verifier.c:14032",
    "B052": "fs/hfs/bfind.c:76",
    "B053": "fs/ntfs3/dir.c:255",
    "B054": "net/xfrm/xfrm_compat.c:571",
    "B057": "fs/aio.c:2001",
    "B058": "net/netfilter/nf_tables_api.c:7233",
    "B061": "net/rxrpc/output.c:452",
    "B063": "fs/ntfs3/record.c:311",
    "B064": "fs/hfsplus/super.c:474",
    "B066": "fs/reiserfs/super.c:2082",
    "B067": "net/netfilter/nft_ct.c:616",
    "B069": "fs/btrfs/volumes.c:1361",
    "B072": "fs/namei.c:3523",
    "B073": "fs/erofs/decompressor.c:227",
    "B076": "fs/io_uring.c:3460",
    "B078": "net/sched/cls_api.c:3238",
    "B079": "net/ipv4/tcp_cong.c:218",
    "B081": "fs/io_uring.c:8999",
    "B083": "mm/madvise.c:794",
    "B084": "drivers/net/vxlan/vxlan_vnifilter.c:429",
    "B085": "fs/namespace.c:161",
    "B088": "sound/core/oss/mixer_oss.c:601",
    "B089": "kernel/cgroup/cgroup.c:3629",
    "B090": "net/packet/af_packet.c:4461",
    "B091": "crypto/crypto_null.c:88",
    "B092": "fs/iomap/direct-io.c:657",
    "B093": "sound/core/oss/pcm_oss.c:1691",
    "B094": "drivers/net/tun.c:3410",
    "B096": "fs/fscache/volume.c:172",
    "B097": "net/sctp/auth.c:867",
    "B098": "drivers/net/ipvlan/ipvlan_core.c:598",
    "B100": "net/netfilter/nf_tables_api.c:2258",
}


def load_poc_data():
    poc = {}
    if os.path.exists(POC_DATA):
        with open(POC_DATA) as f:
            raw = json.load(f)
        for k, v in raw.items():
            bug_id = f"B{int(k):03d}"
            poc[bug_id] = v
    return poc


def classify_bug(bug_id, target_loc, poc_data):
    out_dir = os.path.join(RESULTS_V2, bug_id)
    log_file = os.path.join(out_dir, "analysis.log")
    compact_file = os.path.join(out_dir, "CompactOutput.json")

    # Check if TargetPoint was found
    tp_found = False
    tp_notfound = False
    if os.path.exists(log_file):
        with open(log_file, errors='replace') as f:
            log = f.read()
        tp_found = "[TargetPoint] Found" in log
        tp_notfound = "[TargetPoint] Not found" in log

    # Load CompactOutput.json
    syscall_infos = []
    if os.path.exists(compact_file):
        with open(compact_file) as f:
            try:
                data = json.load(f)
                for item in data:
                    syscall_infos.extend(item.get("target syscall infos", []))
            except json.JSONDecodeError:
                pass

    # Analysis
    found_syscalls = [(info["target syscall"], info.get("rank", 99),
                      info.get("constraints", {})) for info in syscall_infos]
    all_syscall_names = [s[0] for s in found_syscalls]
    has_constraints = any(s[2] for s in found_syscalls)
    has_int_constraints = any("int" in s[2] for s in found_syscalls)
    has_str_constraints = any("string" in s[2] for s in found_syscalls)

    # Specific (non-generic) syscalls: ones with $ variants or device-specific
    specific_syscalls = [s for s in all_syscall_names if "$" in s or
                        (s not in GENERIC_SYSCALLS)]
    rank0_syscalls = [s[0] for s in found_syscalls if s[1] == 0]

    # PoC info
    poc_info = poc_data.get(bug_id, {})
    poc_snippet = poc_info.get("poc_snippet", "")
    poc_classification = poc_info.get("classification", "")

    # ── 분류 로직 ──────────────────────────────────────────────────

    # Case 1: TargetPoint not found in bitcode
    if not tp_found or (not syscall_infos and not tp_found):
        reason = f"R1: SyzDirect가 target point를 bitcode에서 찾지 못함"
        detail = f"tp_found={tp_found} tp_notfound={tp_notfound}"
        if tp_notfound:
            reason += " (디버그 정보 없음 또는 다른 commit)"
        return "R1", reason, detail, all_syscall_names[:5]

    # Case 2: TargetPoint found but no syscalls at all
    if tp_found and not syscall_infos:
        reason = "R1: SyzDirect가 target에 도달하는 syscall call path를 찾지 못함"
        detail = "target found but no reachable syscall entry"
        return "R1", reason, detail, []

    # Case 3: Too many syscalls (>MAX_SYSCALLS) with no specific constraints
    # → R3: SyzDirect finds too many candidates, can't narrow down
    if len(all_syscall_names) > MAX_SYSCALLS_FOR_R2 and not has_int_constraints:
        reason = f"R3: 너무 많은 syscall 후보({len(all_syscall_names)}개), 특정 path 분석 부족"
        detail = f"syscalls={len(all_syscall_names)}, constraints={has_constraints}"
        return "R3", reason, detail, all_syscall_names[:5]

    # Case 4: Has syscalls with int/string constraints
    # → R3: SyzDirect found constraints but may miss the full sequence
    if has_int_constraints or has_str_constraints:
        # But if constraints are very specific (e.g., ioctl cmd), it's closer to R2
        # R3: complex path analysis needed despite having constraints
        reason = f"R3: syscall+constraints 탐지 완료, 그러나 깊은 sequence 분석 부족"
        detail = f"syscalls={len(all_syscall_names)}, int={has_int_constraints}, str={has_str_constraints}"
        return "R3", reason, detail, all_syscall_names[:5]

    # Case 5: Has syscalls but NO constraints
    # → R2: Found the syscall but can't generate proper arguments
    if syscall_infos and not has_constraints:
        # Sub-case: only generic syscalls → might be R1 (wrong syscalls)
        if not specific_syscalls and all(s in GENERIC_SYSCALLS for s in all_syscall_names):
            reason = f"R1: generic syscall만 탐지 ({all_syscall_names[:3]}), 특정 variant 미탐지"
            detail = f"generic only, no constraints"
            return "R1", reason, detail, all_syscall_names[:5]
        # Has specific syscalls but no argument constraints
        reason = f"R2: syscall 탐지 완료 ({all_syscall_names[:3]}), 하지만 argument constraints 없음"
        detail = f"syscalls={len(all_syscall_names)}, constraints=none"
        return "R2", reason, detail, all_syscall_names[:5]

    # Fallback
    return "R1", "R1: 분류 불가 (기타)", "", all_syscall_names[:5]


def main():
    poc_data = load_poc_data()

    results = {}
    counts = {"R1": 0, "R2": 0, "R3": 0}

    print(f"{'ID':<8} {'분류':<6} {'syscalls':<50} 근거")
    print("─" * 120)

    for bug_id in sorted(BUGS.keys()):
        target_loc = BUGS[bug_id]
        classification, reason, detail, syscalls = classify_bug(bug_id, target_loc, poc_data)
        counts[classification] += 1

        results[bug_id] = {
            "classification": classification,
            "target": target_loc,
            "found_syscalls": syscalls,
            "reason": reason,
            "detail": detail,
        }

        syscall_str = str(syscalls[:3]) if syscalls else "[]"
        print(f"{bug_id:<8} {classification:<6} {syscall_str:<50} {reason[:60]}")

    print("─" * 120)
    print(f"\n결과: R1={counts['R1']} R2={counts['R2']} R3={counts['R3']}")
    print(f"논문 기준: R1=19 R2=19 R3=20")

    # 저장
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n저장: {OUTPUT_FILE}")

    # 상세 출력
    print("\n\n=== R1 (call path 분석 실패) ===")
    for bug_id, r in sorted(results.items()):
        if r["classification"] == "R1":
            print(f"  {bug_id} [{r['target']}]")
            print(f"    {r['reason']}")

    print("\n=== R2 (argument generation 실패) ===")
    for bug_id, r in sorted(results.items()):
        if r["classification"] == "R2":
            print(f"  {bug_id} [{r['target']}]")
            print(f"    syscalls: {r['found_syscalls'][:3]}")
            print(f"    {r['reason']}")

    print("\n=== R3 (constraints 있지만 deep analysis 부족) ===")
    for bug_id, r in sorted(results.items()):
        if r["classification"] == "R3":
            print(f"  {bug_id} [{r['target']}]")
            print(f"    syscalls: {r['found_syscalls'][:3]}")
            print(f"    {r['reason']}")

    # Notion 기록
    print("\n\nNotion 기록 중...")
    import subprocess
    notion_content = f"""Phase 3 SyzDirect 실제 실행 결과 (--target-point 방식)

## 결과 요약
- R1 (call path 실패): {counts['R1']}개
- R2 (argument generation 실패): {counts['R2']}개
- R3 (constraints 있지만 deep analysis 부족): {counts['R3']}개
- 논문 기준: R1=19, R2=19, R3=20

## 방법론
1. target_analyzer에 --target-point 지원 추가 (LLVM debug info 기반)
2. 58개 버그 각각에 대해 target_analyzer 실행
3. CompactOutput.json 분석하여 R1/R2/R3 분류

## 주요 발견
- R1: 주로 ntfs3, bpf/verifier 등 특수 subsystem (debug info 없음)
- R2: 대부분의 네트워크/파일시스템 (syscall 탐지, arg 없음)
- R3: constraints 있는 복잡한 케이스 (ioctl cmd, mount string 등)
"""
    try:
        result = subprocess.run([
            "python3", NOTION_LOG,
            "--task", "Phase 3: SyzDirect --target-point 결과",
            "--purpose", "58개 버그 R1/R2/R3 분류 (SyzDirect 실제 실행)",
            "--progress", f"R1={counts['R1']} R2={counts['R2']} R3={counts['R3']}",
            "--error", "없음",
            "--solution", "--target-point 지원을 Analyzer.cc에 추가, LLVM 13으로 재컴파일",
            "--next", "Phase 2 vs Phase 3 비교 분석, 논문 Table 4와 비교"
        ], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"Notion: {result.stdout.strip()}")
        else:
            print(f"Notion 실패: {result.stderr[:100]}")
    except Exception as e:
        print(f"Notion 기록 실패: {e}")


if __name__ == "__main__":
    main()
