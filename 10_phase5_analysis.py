#!/usr/bin/env python3
"""
Phase 5: exact_commit_classifications.json 분석 + 논문 목표 달성도 평가
  - R1/R2/R3 vs 논문 목표 (19/19/20) 비교
  - R1 세부 원인 분류
  - 빌드 실패 / target 미발견 / PoC 불일치 케이스 분리
  - 개선 포인트 제안

실행: python3 /home/ai/syzdirect_setup/10_phase5_analysis.py
"""
import json, sys
from pathlib import Path
from collections import defaultdict

CLASSIFY_OUT  = Path("/home/ai/exact_commit_classifications.json")
BUG_COMMITS   = Path("/home/ai/bug_kernel_commits.json")
POC_FILE      = Path("/home/ai/phase1_pocs.json")
RESULT_BASE   = Path("/home/ai/static_analysis_exact_commit")
PAPER_TARGETS = {"R1": 19, "R2": 19, "R3": 20}  # 논문 Table 4

# ── 파일 로드 ──────────────────────────────────────────────────
if not CLASSIFY_OUT.exists():
    print(f"[ERROR] {CLASSIFY_OUT} 없음 — 08_exact_commit_analyze.sh 완료 후 실행하세요")
    sys.exit(1)

with open(CLASSIFY_OUT) as f:
    results = json.load(f)

with open(BUG_COMMITS) as f:
    commits = json.load(f)

with open(POC_FILE) as f:
    pocs = json.load(f)

# ── 집계 ──────────────────────────────────────────────────────
counts = defaultdict(int)
r1_reasons = defaultdict(list)  # reason → bug list
r2_bugs, r3_bugs, missing_bugs = [], [], []

for bid, v in sorted(results.items()):
    cls = v["classification"]
    counts[cls] += 1
    if cls == "R1":
        # reason 카테고리화
        reason = v.get("reason", "")
        if "CompactOutput.json 없음" in reason:
            r1_reasons["빌드/분석 실패"].append(bid)
        elif "target point 미발견" in reason:
            r1_reasons["target point 미발견"].append(bid)
        elif "target 발견했지만 syscall path 없음" in reason:
            r1_reasons["target 발견 but no path"].append(bid)
        elif "PoC syscall" in reason and "불일치" in reason:
            r1_reasons["PoC syscall 불일치 (엉뚱한 syscall)"].append(bid)
        elif "target syscall 이름 없음" in reason or "비어있음" in reason:
            r1_reasons["빈 결과"].append(bid)
        else:
            r1_reasons["기타"].append(bid)
    elif cls == "R2":
        r2_bugs.append(bid)
    elif cls == "R3":
        r3_bugs.append(bid)
    elif cls == "MISSING":
        missing_bugs.append(bid)

total_classified = counts["R1"] + counts["R2"] + counts["R3"]

# ── 헤더 출력 ─────────────────────────────────────────────────
print("=" * 60)
print("  Phase 5: Exact Commit 분류 결과 vs 논문 Table 4")
print("=" * 60)
print()

# ── 메인 결과 ─────────────────────────────────────────────────
print("[ 분류 결과 ]")
print(f"{'':4}{'우리':>6}  {'논문':>6}  {'차이':>6}")
print(f"  {'─'*30}")
for cat in ["R1", "R2", "R3"]:
    ours  = counts[cat]
    paper = PAPER_TARGETS[cat]
    diff  = ours - paper
    arrow = f"{'▲' if diff > 0 else '▼' if diff < 0 else '='}{abs(diff):d}" if diff != 0 else "  ✓"
    print(f"  {cat}:  {ours:>4}개   {paper:>4}개   {arrow}")
print(f"  {'─'*30}")
print(f"  합계: {total_classified}개 / 58개")
if missing_bugs:
    print(f"  ⚠️  MISSING (분석 미완료): {len(missing_bugs)}개 — {missing_bugs[:5]}...")
print()

# ── R1 세부 원인 ──────────────────────────────────────────────
print("[ R1 세부 원인 분석 ]")
for reason, bids in sorted(r1_reasons.items(), key=lambda x: -len(x[1])):
    print(f"  [{len(bids):2d}개] {reason}")
    for bid in bids:
        v = results[bid]
        fp = v.get("filepath", "")
        print(f"         {bid}  {fp}")
print()

# ── R2/R3 목록 ────────────────────────────────────────────────
print("[ R2 버그 목록 ]")
for bid in r2_bugs:
    v = results[bid]
    print(f"  {bid}  {v.get('filepath','')}  — {v.get('reason','')[:70]}")
print()

print("[ R3 버그 목록 ]")
for bid in r3_bugs:
    v = results[bid]
    print(f"  {bid}  {v.get('filepath','')}  — {v.get('reason','')[:70]}")
print()

# ── 빌드 실패 목록 ────────────────────────────────────────────
build_logs = list(RESULT_BASE.glob("build_*.log"))
failed_builds = []
for log in sorted(build_logs):
    text = log.read_text(errors='replace')
    # make error 체크
    if "error:" in text.lower() and ".llbc" not in text:
        failed_builds.append(log.name)

if failed_builds:
    print("[ 빌드 오류 의심 로그 ]")
    for name in failed_builds[:10]:
        print(f"  {name}")
    print()

# ── PoC 불일치 케이스 상세 ────────────────────────────────────
mismatch_bugs = r1_reasons.get("PoC syscall 불일치 (엉뚱한 syscall)", [])
if mismatch_bugs:
    print("[ PoC 불일치 상세 — 개선 후보 ]")
    for bid in mismatch_bugs:
        v = results[bid]
        bid_num = bid[1:]  # "B054" → "054"
        bug_id_str = str(int(bid_num))

        # CompactOutput에서 찾은 syscall 읽기
        compact = RESULT_BASE / bid / "CompactOutput.json"
        found_syscalls = []
        if compact.exists():
            try:
                data = json.loads(compact.read_text())
                for item in data:
                    for sc in item.get("target syscall infos", []):
                        name = sc.get("target syscall", "")
                        if name:
                            found_syscalls.append(name)
            except: pass

        # PoC syscall
        poc_entry = pocs.get(bug_id_str) or pocs.get(bid_num)
        poc_syscalls = set()
        if poc_entry:
            import re
            for line in poc_entry.get("poc_text", "").split('\n'):
                m = re.match(r'(?:\w+\s*=\s*)?([\w\$]+)\s*\(', line.strip())
                if m:
                    poc_syscalls.add(m.group(1))

        fp = v.get("filepath", "")
        print(f"  {bid}  {fp}")
        print(f"    PoC syscall:   {sorted(poc_syscalls)[:5]}")
        print(f"    Found syscall: {found_syscalls[:5]}")
        print()

# ── 요약 및 다음 단계 ─────────────────────────────────────────
print("=" * 60)
print("[ 다음 단계 제안 ]")
r1_diff = counts["R1"] - PAPER_TARGETS["R1"]
r2_diff = counts["R2"] - PAPER_TARGETS["R2"]
r3_diff = counts["R3"] - PAPER_TARGETS["R3"]

if abs(r1_diff) <= 3 and abs(r2_diff) <= 3 and abs(r3_diff) <= 3:
    print("  ✅ 논문 목표 달성 범위 내 (±3 이내)")
else:
    if r1_diff > 3:
        print(f"  ❌ R1 과다 ({counts['R1']}개): PoC 불일치 {len(mismatch_bugs)}개 재검토 필요")
        print(f"     → syscall base name 매칭 로직 개선 고려")
    if r2_diff < -3:
        print(f"  ❌ R2 과소 ({counts['R2']}개): R1(불일치)→R2 재분류 후보 검토")
    if r3_diff < -3:
        print(f"  ❌ R3 과소 ({counts['R3']}개): constraints 탐지 범위 확인")
    if r3_diff > 3:
        print(f"  ❌ R3 과다 ({counts['R3']}개): constraints 기준 너무 관대함")
    print()
    print("  힌트:")
    print("  1. PoC 불일치 케이스에서 found syscall이 PoC와 partial match인지 확인")
    print("  2. 빌드 실패 커밋 재빌드 시도")
    print("  3. target point 미발견 케이스의 filepath/line 정확도 확인")

print("=" * 60)
print(f"\n결과 파일: {CLASSIFY_OUT}")
