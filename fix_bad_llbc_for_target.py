#!/usr/bin/env python3
"""
특정 target에 대해 target_analyzer를 반복 실행하면서
segfault를 유발하는 .llbc 파일을 찾아 빈 모듈로 교체.

사용법: python3 fix_bad_llbc_for_target.py <target_point>
예시:   python3 fix_bad_llbc_for_target.py net/ipv4/devinet.c:100
"""
import subprocess, os, sys, tempfile, re
from pathlib import Path

BC_DIR = Path("/work/linux_bc")
ANALYZER = "/work/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
LLVM_AS = "/work/SyzDirect/source/llvm-project-new/build/bin/llvm-as"
INTERFACE = "/home/ai/kernel_interface/kernelCode2syscall.json"
MAX_ITERS = 40

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_point>")
    print(f"Example: {sys.argv[0]} net/ipv4/devinet.c:100")
    sys.exit(1)

TARGET = sys.argv[1]

EMPTY_BC = None

def make_empty_bc():
    global EMPTY_BC
    if EMPTY_BC:
        return EMPTY_BC
    ir = ('; ModuleID = "empty"\n'
          'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"\n'
          'target triple = "x86_64-pc-linux-gnu"\n')
    with tempfile.NamedTemporaryFile(suffix='.ll', mode='w', delete=False) as f:
        f.write(ir)
        tmp_ll = f.name
    tmp_bc = tmp_ll.replace('.ll', '.bc')
    result = subprocess.run([LLVM_AS, tmp_ll, '-o', tmp_bc], capture_output=True)
    if result.returncode != 0:
        os.unlink(tmp_ll)
        raise RuntimeError(f"llvm-as failed: {result.stderr.decode()}")
    EMPTY_BC = open(tmp_bc, 'rb').read()
    os.unlink(tmp_ll)
    os.unlink(tmp_bc)
    return EMPTY_BC

def test_analysis(timeout=300):
    """분석 실행 → (crashed, last_llbc_relpath, output)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [ANALYZER,
             "--verbose-level=1",
             f"--target-point={TARGET}",
             f"--kernel-interface-file={INTERFACE}",
             str(BC_DIR)],
            capture_output=True, text=True, timeout=timeout,
            cwd=tmpdir, errors='replace'
        )
        combined = result.stdout + result.stderr
        crashed = result.returncode not in (0, 1)

        last_llbc = None
        for line in reversed(combined.splitlines()):
            if '.llbc' in line and 'linux_bc' in line:
                m = re.search(r'/work/linux_bc/([^\]\s]+\.llbc)', line)
                if m:
                    last_llbc = m.group(1)
                    break
        return crashed, last_llbc, combined

def blank_file(rel_path):
    full = BC_DIR / rel_path
    if not full.exists():
        print(f"  ⚠️  파일 없음: {rel_path}")
        return
    backup = Path(str(full) + '.bak')
    if not backup.exists():
        import shutil
        shutil.copy2(str(full), str(backup))
    full.write_bytes(make_empty_bc())
    print(f"  ⬜ 제거: {rel_path}")

print(f"[fix_bad_llbc] target: {TARGET}")
print(f"[fix_bad_llbc] BC_DIR: {BC_DIR}")

make_empty_bc()

for i in range(MAX_ITERS):
    print(f"\n[시도 {i+1}/{MAX_ITERS}] 분석 실행 중...", flush=True)
    try:
        crashed, last_llbc, output = test_analysis(timeout=360)
    except subprocess.TimeoutExpired:
        print("  ⏱️  timeout → 크래시 없는 것으로 간주, 완료")
        sys.exit(0)

    if not crashed:
        print("  ✅ 크래시 없음! 완료")
        sys.exit(0)

    if last_llbc:
        print(f"  ❌ 크래시: {last_llbc}")
        blank_file(last_llbc)
    else:
        print("  ❌ 크래시, .llbc 파일 특정 불가. 마지막 로그:")
        for line in output.splitlines()[-10:]:
            print(f"    {line}")
        sys.exit(1)

print(f"\n⚠️  최대 반복({MAX_ITERS}) 도달")
blanked = list(BC_DIR.rglob("*.llbc.bak"))
print(f"교체된 파일 수: {len(blanked)}")
for f in blanked:
    print(f"  {f.relative_to(BC_DIR)}")
sys.exit(1)
