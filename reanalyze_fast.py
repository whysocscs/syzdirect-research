#!/usr/bin/env python3
"""
현재 BC_DIR의 빌드로 모든 버그를 올바른 target-point 포맷으로 재분석.
빌드 없이 분석만 수행 (~50분 예상).
"""
import json, subprocess, os, sys
from pathlib import Path

BC_DIR = "/work/linux_bc"
ANALYZER = "/work/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
INTERFACE = "/home/ai/kernel_interface/kernelCode2syscall.json"
RESULT_BASE = "/home/ai/static_analysis_exact_commit"
BUG_COMMITS = "/home/ai/bug_kernel_commits.json"
OUT_JSON = "/home/ai/exact_commit_classifications.json"

bugs = json.load(open(BUG_COMMITS))
print(f"총 {len(bugs)}개 버그 재분석 시작")
print(f"BC_DIR: {BC_DIR} ({len(list(Path(BC_DIR).rglob('*.llbc')))} llbc files)")

results = {}
r1=r2=r3=0

for i, (bug_id, info) in enumerate(sorted(bugs.items(), key=lambda x: int(x[0]))):
    target = info.get("filepath", "")
    out_dir = Path(RESULT_BASE) / f"B{int(bug_id):03d}"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "analysis_rerun.log"

    print(f"[{i+1:2d}/58] B{int(bug_id):03d} {target} ...", end=" ", flush=True)

    try:
        result = subprocess.run(
            [ANALYZER,
             "--verbose-level=1",
             f"--target-point={target}",
             f"--kernel-interface-file={INTERFACE}",
             BC_DIR],
            capture_output=True, text=True, timeout=180,
            cwd=str(out_dir), errors='replace'
        )
        log_file.write_text(result.stdout + result.stderr)

        compact = out_dir / "CompactOutput.json"
        if compact.exists():
            content = compact.read_text().strip()
            if content == "[]":
                # target 발견했는지 확인
                if "[TargetPoint] Found" in (result.stdout + result.stderr):
                    cat = "R2"
                    r2 += 1
                    print(f"⚠️  R2 (target 발견, syscall path 없음)")
                else:
                    cat = "R1"
                    r1 += 1
                    print(f"❌ R1 (target 미발견)")
            else:
                data = json.loads(content)
                cat = "R3"
                r3 += 1
                print(f"✅ R3 (syscall {len(data)}개)")
        else:
            cat = "R1"
            r1 += 1
            print(f"❌ R1 (CompactOutput 없음, exit={result.returncode})")

    except subprocess.TimeoutExpired:
        cat = "R1"
        r1 += 1
        print(f"⏱️  timeout → R1")
    except Exception as e:
        cat = "R1"
        r1 += 1
        print(f"💥 error: {e} → R1")

    results[bug_id] = {
        "classification": cat,
        "filepath": target,
        "commit": info.get("commit", ""),
        "kernel_version": info.get("kernel_version", ""),
    }

print(f"\n=== 결과 ===")
print(f"R1 (target 미발견): {r1}")
print(f"R2 (target 발견, path 없음): {r2}")
print(f"R3 (syscall path 있음): {r3}")
print(f"논문 목표: R1=19, R2=19, R3=20")

json.dump(results, open(OUT_JSON, "w"), indent=2)
print(f"\n저장: {OUT_JSON}")
