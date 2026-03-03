#!/usr/bin/env python3
"""
PoC 기반 R1/R2/R3 분류 스크립트

phase1_pocs.json의 실제 PoC syscall과
CompactOutput.json의 분석 결과를 비교하여 분류.

논문 기준:
  R1: SyzDirect가 올바른 syscall call path를 찾지 못함
  R2: syscall은 찾았지만 argument constraints 추론 실패
  R3: syscall + constraints 찾았지만 related syscall sequence 부족

실행: python3 09_classify_poc_based.py
"""
import json, re, sys
from pathlib import Path

RESULT_BASE   = Path("/home/ai/static_analysis_exact_commit")
BUG_COMMITS   = Path("/home/ai/bug_kernel_commits.json")
POC_FILE      = Path("/home/ai/phase1_pocs.json")
CLASSIFY_OUT  = Path("/home/ai/exact_commit_classifications.json")

# ── 데이터 로드 ────────────────────────────────────────────────
with open(BUG_COMMITS) as f:
    commits = json.load(f)

with open(POC_FILE) as f:
    pocs = json.load(f)

# ── syscall 유틸 ───────────────────────────────────────────────
def extract_poc_syscalls(poc_text: str) -> set:
    """PoC 텍스트에서 syscall base name 집합 추출.
    형식: [r0 = ]syscall$spec(...) 또는 syscall(...)
    """
    syscalls = set()
    for line in poc_text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        m = re.match(r'(?:\w+\s*=\s*)?([\w\$]+)\s*\(', line)
        if m:
            syscalls.add(m.group(1))
    return syscalls

def base_name(sc: str) -> str:
    """sendmsg$sock → sendmsg, openat$qrtrtun → openat"""
    return sc.split('$')[0].lower().strip()

def find_overlap(poc_syscalls: set, found_syscalls: list) -> set:
    """PoC syscall과 분석 결과 syscall의 base name 교집합 반환."""
    poc_bases = {base_name(s) for s in poc_syscalls}
    found_bases = {base_name(s) for s in found_syscalls}
    return poc_bases & found_bases


# ── 분류 함수 ──────────────────────────────────────────────────
def classify_bug(bug_id: str, info: dict) -> tuple:
    """(classification, reason) 반환. classification = R1/R2/R3."""
    bid = f"B{int(bug_id):03d}"
    out_dir = RESULT_BASE / bid
    compact_json = out_dir / "CompactOutput.json"
    analysis_log = out_dir / "analysis.log"

    # CompactOutput 없음 → R1
    if not compact_json.exists():
        return "R1", "CompactOutput.json 없음"

    content = compact_json.read_text(errors='replace').strip()

    # target point 발견 여부 (R1 세부 이유 구분용)
    tp_found = False
    if analysis_log.exists():
        log_text = analysis_log.read_text(errors='replace')
        tp_found = "[TargetPoint] Found" in log_text

    if content == "[]":
        if tp_found:
            return "R1", "target 발견했지만 syscall path 없음"
        else:
            return "R1", "target point 미발견"

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return "R1", f"JSON 파싱 실패: {e}"

    if not data:
        return "R1", "CompactOutput 비어있음"

    # 분석에서 찾은 syscall 목록 + constraints 정보
    found_syscalls = []
    all_has_constraints = False

    for item in data:
        for sc_info in item.get("target syscall infos", []):
            sc_name = sc_info.get("target syscall", "")
            if sc_name:
                found_syscalls.append(sc_name)
            if sc_info.get("constraints", []):
                all_has_constraints = True

    if not found_syscalls:
        return "R1", "target syscall 이름 없음"

    # PoC syscall 추출
    poc_entry = pocs.get(bug_id) or pocs.get(str(int(bug_id)))
    poc_syscalls = set()
    if poc_entry:
        poc_text = poc_entry.get("poc_text", "")
        poc_syscalls = extract_poc_syscalls(poc_text)

    if not poc_syscalls:
        # PoC 없을 때 fallback: constraints 유무만으로 판단
        if all_has_constraints:
            return "R3", f"constraints 있음 (PoC 없음 fallback, found={found_syscalls[:2]})"
        else:
            return "R2", f"constraints 없음 (PoC 없음 fallback, found={found_syscalls[:2]})"

    # PoC 매칭 확인
    overlap = find_overlap(poc_syscalls, found_syscalls)

    if not overlap:
        # 분석이 엉뚱한 syscall만 찾음 → R1
        poc_sample = sorted(poc_syscalls)[:3]
        found_sample = found_syscalls[:3]
        return "R1", (f"PoC syscall {poc_sample}과 불일치 "
                      f"(found={found_sample})")

    # 올바른 syscall 찾음 → constraints 확인
    # 매칭된 syscall에 constraints가 있는지 확인
    matched_has_constraints = False
    for item in data:
        for sc_info in item.get("target syscall infos", []):
            sc_name = sc_info.get("target syscall", "")
            if base_name(sc_name) in overlap:
                if sc_info.get("constraints", []):
                    matched_has_constraints = True

    if not matched_has_constraints:
        return "R2", (f"올바른 syscall {sorted(overlap)[:2]} 찾았지만 "
                      f"constraints 없음")
    else:
        return "R3", (f"올바른 syscall {sorted(overlap)[:2]} + "
                      f"constraints 있음")


# ── 메인 분류 루프 ────────────────────────────────────────────
results = {}
r_counts = {"R1": 0, "R2": 0, "R3": 0, "MISSING": 0}

for bug_id, info in sorted(commits.items(), key=lambda x: int(x[0])):
    bid = f"B{int(bug_id):03d}"
    out_dir = RESULT_BASE / bid

    if not out_dir.exists():
        r_counts["MISSING"] += 1
        results[bid] = {
            "classification": "MISSING",
            "reason": "결과 디렉토리 없음",
            "filepath": info.get("filepath", ""),
            "commit": info.get("commit", ""),
            "kernel_version": info.get("kernel_version", ""),
        }
        continue

    cls, reason = classify_bug(bug_id, info)
    r_counts[cls] = r_counts.get(cls, 0) + 1
    results[bid] = {
        "classification": cls,
        "reason": reason,
        "filepath": info.get("filepath", ""),
        "commit": info.get("commit", ""),
        "kernel_version": info.get("kernel_version", ""),
    }

# ── 저장 ──────────────────────────────────────────────────────
with open(CLASSIFY_OUT, "w") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# ── 결과 출력 ─────────────────────────────────────────────────
print("=" * 55)
print(" Exact Commit 분류 결과 (PoC 기반)")
print("=" * 55)
print(f"  R1: {r_counts['R1']:2d}개  (논문 목표: 19)")
print(f"  R2: {r_counts['R2']:2d}개  (논문 목표: 19)")
print(f"  R3: {r_counts['R3']:2d}개  (논문 목표: 20)")
total = r_counts['R1'] + r_counts['R2'] + r_counts['R3']
print(f"  합계: {total}개 / 58개")
if r_counts.get("MISSING"):
    print(f"  MISSING: {r_counts['MISSING']}개  ← 분석 미완료")
print(f"\n  저장: {CLASSIFY_OUT}")
print()

print("버그별 결과:")
for bid, v in sorted(results.items()):
    marker = {"R1": "❌", "R2": "⚠️ ", "R3": "✅", "MISSING": "🔲"}.get(v["classification"], "  ")
    print(f"  {bid} {marker} [{v['classification']}] {v['filepath']} — {v['reason']}")

# ── PoC 없는 버그 경고 ────────────────────────────────────────
missing_poc = []
for bug_id in commits:
    if not (pocs.get(bug_id) or pocs.get(str(int(bug_id)))):
        missing_poc.append(bug_id)
if missing_poc:
    print(f"\n⚠️  PoC 없는 버그 (fallback 사용): {missing_poc}")
