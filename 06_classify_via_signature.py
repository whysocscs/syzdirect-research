#!/usr/bin/env python3
"""
SyzDirect 시그니처 기반 R1/R2/R3 분류기.
kernel_signature_full + kernel 소스 분석으로 target_analyzer 없이 분류.

R1: SyzDirect가 어떤 syscall도 식별하지 못함 (call path 없음)
R2: syscall 식별했지만 constraints(인자) 추출 실패
R3: syscall + constraints 모두 성공적으로 추출
"""

import json
import re
import os
import sys

LINUX_SRC = "/work/linux"
KERNEL_SIG = "/home/ai/kernel_interface/kernel_signature_full"
KERNEL_CODE2SYSCALL = "/home/ai/kernel_interface/kernelCode2syscall.json"
POC_DATA = "/home/ai/classification_results.json"

# 58개 버그 (ID → file:line)
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


def find_function_at_line(filepath, target_line):
    """커널 소스에서 target_line을 포함하는 C 함수 이름을 찾기."""
    full_path = os.path.join(LINUX_SRC, filepath)
    if not os.path.exists(full_path):
        return None

    with open(full_path, 'r', errors='replace') as f:
        lines = f.readlines()

    if target_line > len(lines):
        return None

    # C 함수 시작 패턴 (맨 앞에서 시작하는 식별자)
    # 함수 정의는 보통 이렇게 생김:
    # static TYPE func_name(args...) {  또는
    # TYPE func_name(args...) {
    func_pattern = re.compile(
        r'^(?:static\s+)?(?:(?:inline|notrace|__always_inline|__cold|noinline|asmlinkage)\s+)*'
        r'(?:(?:const\s+)?(?:struct\s+)?\w+(?:\s*\*+)?)\s+'
        r'(\w+)\s*\(',
        re.MULTILINE
    )

    # target_line 이전에서 가장 최근 함수 정의 찾기
    last_func = None
    last_func_line = 0

    for i, line in enumerate(lines[:target_line], 1):
        m = func_pattern.match(line)
        if m:
            func_name = m.group(1)
            # 키워드 필터링
            keywords = {'if', 'while', 'for', 'switch', 'return', 'else', 'do',
                       'typedef', 'struct', 'union', 'enum', 'define', 'include',
                       'sizeof', 'typeof', 'int', 'long', 'char', 'void', 'unsigned',
                       'signed', 'bool', 'u8', 'u16', 'u32', 'u64', 's8', 's16',
                       's32', 's64', '__u8', '__u16', '__u32', '__u64'}
            if func_name not in keywords and not func_name.startswith('__'):
                last_func = func_name
                last_func_line = i
            elif func_name.startswith('__') and not func_name.startswith('__ATTR'):
                # __se_sys_, __do_sys_ 등 허용
                last_func = func_name
                last_func_line = i

    return last_func


def find_function_at_line_v2(filepath, target_line):
    """더 정확한 함수 찾기: 중괄호 depth 분석."""
    full_path = os.path.join(LINUX_SRC, filepath)
    if not os.path.exists(full_path):
        # include/ 폴더 처리
        return None

    with open(full_path, 'r', errors='replace') as f:
        lines = f.readlines()

    if target_line > len(lines):
        return None

    # 각 라인의 { } 를 추적해서 함수 범위 파악
    # 함수 정의 패턴: 라인이 depth=0에서 시작하고, { 를 포함
    func_pattern = re.compile(
        r'^(\w[\w\s\*]+?)\s+(\w+)\s*\([^;]*\)\s*(?:__.*?)?\s*\{?\s*$'
    )

    # Simple approach: find the last "function-opening" line before target
    # A function opens when we see ') {' or similar at depth 0
    candidate_funcs = []
    depth = 0
    in_comment = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip preprocessor
        if stripped.startswith('#'):
            continue

        # Track multiline comments
        if '/*' in line and '*/' not in line[line.index('/*'):]:
            in_comment = True
        if '*/' in line:
            in_comment = False

        if in_comment:
            continue

        # Count braces
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1

        if i >= target_line:
            break

    # Use simpler grep-based approach for finding the enclosing function
    return None


def grep_function_at_line(filepath, target_line):
    """grep으로 대략적인 함수 이름 찾기."""
    full_path = os.path.join(LINUX_SRC, filepath)
    if not os.path.exists(full_path):
        return []

    with open(full_path, 'r', errors='replace') as f:
        lines = f.readlines()

    if target_line > len(lines):
        return []

    # 가능한 함수 이름들을 수집
    candidates = []

    # target_line 이전에서 뒤로 스캔하면서 함수 정의처럼 보이는 것 찾기
    # 중괄호 depth를 역으로 추적
    for i in range(target_line - 1, max(0, target_line - 200), -1):
        line = lines[i]
        # 함수 정의의 특징: 들여쓰기 없이 시작 (depth 0)
        if line and not line[0].isspace() and not line[0] in ('#', '/', '*', '}', '\n'):
            # 함수 이름 찾기
            m = re.match(r'^(?:(?:static|extern|inline|notrace|__always_inline|noinline|asmlinkage|__cold)\s+)*'
                        r'(?:(?:const\s+)?(?:struct\s+|enum\s+|union\s+)?\w[\w\s\*]*?)\s*'
                        r'\**\s*(\w+)\s*\(', line)
            if m:
                fname = m.group(1)
                skip = {'if', 'while', 'for', 'switch', 'return', 'else', 'do',
                       'typedef', 'extern', 'unsigned', 'signed', 'static', 'const',
                       'struct', 'union', 'enum', 'int', 'long', 'char', 'void',
                       'bool', 'size_t', 'ssize_t', 'loff_t', 'u8', 'u16', 'u32', 'u64',
                       '__u32', '__u64', 'module_init', 'module_exit', 'EXPORT_SYMBOL'}
                if fname not in skip:
                    candidates.append(fname)
                    if len(candidates) >= 3:
                        break

    return candidates


def load_kernel_signature():
    """kernel_signature_full 파싱: handler_func → {syscall: constraints}"""
    handler_to_syscalls = {}  # handler_func -> list of (syscall, has_constraint)

    with open(KERNEL_SIG, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(' ')
            # 마지막 요소가 entry_function
            entry_func = parts[-1]

            # sig_str 파싱 (첫 번째 필드, |로 구분)
            sig_str = parts[0]
            sig_parts = sig_str.split('|')
            syscall_name = sig_parts[0]  # 예: "write", "ioctl$xyz"

            # constraint 확인 (C[...] 에 값이 있으면 constraint 있음)
            has_constraint = False
            for part in sig_parts[1:]:
                if part.startswith('C[') and part != 'C[]':
                    has_constraint = True
                elif part.startswith('D[') and part != 'D[]':
                    has_constraint = True  # device constraint도 constraint
                elif part.startswith('S[') and part != 'S[]':
                    has_constraint = True

            # target block funcs 파싱
            # 형식: sig bb_num func1 idx1 func2 idx2 ... entry_func
            try:
                # bb_num 찾기 (첫 번째 숫자)
                bb_num_idx = -1
                for i, item in enumerate(parts):
                    if item.isdigit() and i > 0 and parts[i-1].endswith(']'):
                        bb_num_idx = i
                        break

                if bb_num_idx == -1:
                    continue

                bb_num = int(parts[bb_num_idx])
                # target funcs: parts[bb_num_idx+1], parts[bb_num_idx+3], ...
                for j in range(bb_num):
                    t_func = parts[bb_num_idx + 1 + 2*j]
                    if t_func not in handler_to_syscalls:
                        handler_to_syscalls[t_func] = []
                    handler_to_syscalls[t_func].append((syscall_name, has_constraint))

                # entry_func 자체도 추가
                if entry_func not in handler_to_syscalls:
                    handler_to_syscalls[entry_func] = []
                handler_to_syscalls[entry_func].append((syscall_name, has_constraint))

            except (IndexError, ValueError):
                continue

    return handler_to_syscalls


def classify_bug(bug_id, target_loc, handler_to_syscalls, poc_data):
    """버그를 R1/R2/R3로 분류."""
    filepath, lineno_str = target_loc.rsplit(':', 1)
    lineno = int(lineno_str)

    # 후보 함수 이름 찾기
    candidate_funcs = grep_function_at_line(filepath, lineno)

    # 매핑 찾기
    found_syscalls = set()
    has_constraint = False

    for func in candidate_funcs:
        if func in handler_to_syscalls:
            for syscall, constraint in handler_to_syscalls[func]:
                found_syscalls.add(syscall)
                if constraint:
                    has_constraint = True

    # PoC에서 사용된 syscall 확인
    poc_syscalls = set()
    if poc_data and bug_id in poc_data:
        bug_info = poc_data[bug_id]
        if 'poc_syscalls' in bug_info:
            poc_syscalls = set(bug_info['poc_syscalls'])

    # 분류
    if not found_syscalls:
        reason = f"R1: 함수 {candidate_funcs} → kernel_signature에서 찾을 수 없음"
        return "R1", reason, candidate_funcs, list(found_syscalls)
    elif not has_constraint:
        reason = f"R2: 함수 {candidate_funcs} → {list(found_syscalls)[:3]} 찾았지만 constraints 없음"
        return "R2", reason, candidate_funcs, list(found_syscalls)
    else:
        reason = f"R3: 함수 {candidate_funcs} → {list(found_syscalls)[:3]} + constraints 있음"
        return "R3", reason, candidate_funcs, list(found_syscalls)


def main():
    print("kernel_signature_full 로딩 중...")
    handler_to_syscalls = load_kernel_signature()
    print(f"  {len(handler_to_syscalls)} 개 handler 함수 로드됨")

    # PoC 데이터 로드
    poc_data = {}
    if os.path.exists(POC_DATA):
        with open(POC_DATA) as f:
            poc_data = json.load(f)

    results = {}
    counts = {"R1": 0, "R2": 0, "R3": 0}

    print(f"\n{'ID':<8} {'분류':<8} {'함수':<35} {'발견된 syscall'}")
    print("─" * 100)

    for bug_id, target_loc in sorted(BUGS.items()):
        classification, reason, funcs, syscalls = classify_bug(
            bug_id, target_loc, handler_to_syscalls, poc_data
        )
        counts[classification] += 1
        results[bug_id] = {
            "classification": classification,
            "target": target_loc,
            "candidate_functions": funcs,
            "found_syscalls": syscalls[:5],
            "reason": reason,
        }

        func_str = str(funcs[:2]) if funcs else "[]"
        syscall_str = str(syscalls[:3]) if syscalls else "[]"
        print(f"{bug_id:<8} {classification:<8} {func_str:<35} {syscall_str}")

    print("─" * 100)
    print(f"R1={counts['R1']} R2={counts['R2']} R3={counts['R3']}")
    print(f"논문 목표: R1=19 R2=19 R3=20")

    # 저장
    output_path = "/home/ai/phase3_sig_classifications.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n저장: {output_path}")

    # R1 버그 상세 분석 출력
    print("\n\n=== R1 버그 (kernel_signature에서 찾지 못함) ===")
    for bug_id, r in results.items():
        if r['classification'] == 'R1':
            print(f"  {bug_id}: {r['target']} | 후보함수: {r['candidate_functions']}")

    print("\n=== R2 버그 (syscall 찾았지만 constraints 없음) ===")
    for bug_id, r in results.items():
        if r['classification'] == 'R2':
            print(f"  {bug_id}: {r['target']} | 함수: {r['candidate_functions']} | syscall: {r['found_syscalls'][:3]}")

    print("\n=== R3 버그 (syscall + constraints 있음) ===")
    for bug_id, r in results.items():
        if r['classification'] == 'R3':
            print(f"  {bug_id}: {r['target']} | 함수: {r['candidate_functions']} | syscall: {r['found_syscalls'][:3]}")


if __name__ == "__main__":
    main()
