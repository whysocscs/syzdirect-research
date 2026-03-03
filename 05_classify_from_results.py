#!/usr/bin/env python3
"""
Step 5: target_analyzer 출력(CompactOutput.json) + PoC 비교로 R1/R2/R3 분류

CompactOutput.json 실제 구조:
[
  {
    "case index": "0",
    "target syscall infos": [
      {
        "target syscall": "sendmsg$rds",
        "rank": 1,
        "constraints": {
          "int": [{"name": "MSG_TYPE", "value": "1"}],
          "string": "rds"
        }
      }
    ]
  }
]
"""
import json, os, re, urllib.request
from datetime import datetime, timezone, timedelta

RESULT_DIR  = "/home/ai/static_analysis_results"
POC_FILE    = "/home/ai/phase1_pocs.json"
OUTPUT_FILE = "/home/ai/phase3_classifications.json"
NOTION_TOKEN = os.environ.get("NOTION_TOKEN", "")  # set via environment variable
DATABASE_ID  = "31583330f49080e4abd5de689ebda63e"

def load_compact_output(bug_id):
    path = os.path.join(RESULT_DIR, f"B{bug_id:03d}", "CompactOutput.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def extract_poc_syscalls(poc_text):
    """PoC 텍스트에서 syscall 이름 추출"""
    syscalls = []
    for line in (poc_text or "").split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            m = re.match(r'(?:r\d+\s*=\s*)?(\w[\w$]*)[\s(]', line)
            if m:
                syscalls.append(m.group(1))
    return syscalls

def parse_compact_output(compact):
    """
    CompactOutput.json → (entry_syscalls, has_constraints)

    Returns:
        entry_syscalls: set of syscall names found
        has_constraints: True if any syscall has non-empty constraints
    """
    entry_syscalls = set()
    has_constraints = False

    if not compact or not isinstance(compact, list):
        return entry_syscalls, has_constraints

    for item in compact:
        infos = item.get("target syscall infos", [])
        for info in infos:
            tcall = info.get("target syscall", "")
            if tcall:
                # "$variant" 접두어 제거하여 기본 syscall 이름도 추가
                base = tcall.split("$")[0] if "$" in tcall else tcall
                entry_syscalls.add(tcall)
                entry_syscalls.add(base)
            csts = info.get("constraints", {})
            if csts.get("int") or csts.get("string"):
                has_constraints = True

    return entry_syscalls, has_constraints

def classify(bug_id, filepath, poc_text, compact):
    """
    R1: SyzDirect가 PoC에 있는 syscall을 못 찾음
        → entry_syscalls ∩ PoC_syscalls = ∅  (또는 CompactOutput.json 없음)

    R2: Syscall은 찾았지만 argument 조건이 없음
        → entry_syscalls 있음, constraints 없음

    R3: Syscall + 조건도 있지만 dependent/related syscall 분석 부족
        → entry_syscalls 있음, constraints 있음
        → 이 경우 상세 판단은 추가 TRMap 분석 필요
    """
    reasons = []

    # static analysis 결과 없음 → 도달 불가 or 분석 실패
    if compact is None:
        reasons.append("static analysis 결과 없음 (CompactOutput.json 미생성)")
        return "R1", reasons

    entry_syscalls, has_constraints = parse_compact_output(compact)

    # 아무 syscall도 못 찾은 경우 → R1
    if not entry_syscalls:
        reasons.append("R1: SyzDirect가 어떤 syscall도 찾지 못함 (call path 분석 실패)")
        return "R1", reasons

    poc_syscalls = set(extract_poc_syscalls(poc_text))

    # PoC syscall과 매칭 확인
    matched = poc_syscalls & entry_syscalls
    unmatched = poc_syscalls - entry_syscalls

    if unmatched and not matched:
        # PoC의 syscall 전혀 못 찾음 → R1
        reasons.append(f"R1: PoC syscall {sorted(unmatched)[:3]}을 SyzDirect가 못 찾음 (암묵적 의존)")
        return "R1", reasons

    if unmatched and matched:
        # 일부만 찾음 → R1 (불완전한 dependent syscall)
        reasons.append(f"R1: PoC syscall 일부({sorted(unmatched)[:3]}) 누락 — 암묵적 의존 미탐지")
        return "R1", reasons

    # 모든 PoC syscall 찾았지만 constraints 없음 → R2
    if not has_constraints:
        reasons.append(f"R2: 찾은 syscall({sorted(entry_syscalls)[:3]})의 argument 조건 추출 실패")
        return "R2", reasons

    # Syscall + constraints 모두 있음 → R3 (related syscall 심층 분석 부족)
    reasons.append(f"R3: syscall 탐지+조건 OK, but related syscall 심층 분석 부족 (filepath={filepath})")
    return "R3", reasons


def notion_log(results):
    kst = timezone(timedelta(hours=9))
    ts  = datetime.now(kst).strftime("%Y-%m-%d %H:%M KST")

    counts = {"R1": 0, "R2": 0, "R3": 0, "UNKNOWN": 0}
    for v in results.values():
        c = v["classification"]
        counts[c] = counts.get(c, 0) + 1

    detail = ""
    for k in sorted(results.keys(), key=int):
        v = results[k]
        reason = v["reasons"][0] if v["reasons"] else ""
        detail += f"B{v['bug_id']:03d} [{v['classification']}] {v['filepath']}\n  → {reason}\n"

    def block(t, btype="paragraph"):
        return {"object": "block", "type": btype, btype:
                {"rich_text": [{"type": "text", "text": {"content": t[:2000]}}]}}

    children = [
        {"object": "block", "type": "callout", "callout": {
            "rich_text": [{"type": "text", "text": {"content": f"Phase 3 완료 — {ts}"}}],
            "icon": {"type": "emoji", "emoji": "✅"}, "color": "green_background"}},
        {"object": "block", "type": "divider", "divider": {}},
        block(f"총 {len(results)}개 분류\n"
              f"R1={counts['R1']} R2={counts['R2']} R3={counts['R3']} UNKNOWN={counts['UNKNOWN']}\n"
              f"논문: R1=19 R2=19 R3=20", "heading_2"),
        {"object": "block", "type": "divider", "divider": {}},
        block(detail),
    ]

    payload = json.dumps({
        "parent": {"database_id": DATABASE_ID},
        "properties": {"이름": {"title": [{"text": {"content":
            f"[{ts}] Phase 3: SyzDirect 기반 R1/R2/R3 분류"}}]}},
        "children": children
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.notion.com/v1/pages", data=payload,
        headers={"Authorization": f"Bearer {NOTION_TOKEN}",
                 "Notion-Version": "2022-06-28",
                 "Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode()).get("url", "")


def main():
    with open(POC_FILE) as f:
        pocs = json.load(f)

    results = {}
    counts = {"R1": 0, "R2": 0, "R3": 0, "UNKNOWN": 0}

    print(f"{'ID':<6} {'분류':<8} {'근거'}")
    print("─" * 72)

    for k in sorted(pocs.keys(), key=int):
        v = pocs[k]
        compact = load_compact_output(v["bug_id"])
        cls, reasons = classify(v["bug_id"], v["filepath"], v["poc_text"], compact)

        results[k] = {
            "bug_id": v["bug_id"],
            "filepath": v["filepath"],
            "classification": cls,
            "reasons": reasons,
            "has_static_result": compact is not None,
        }
        counts[cls] = counts.get(cls, 0) + 1
        reason_short = reasons[0][:58] if reasons else ""
        print(f"B{v['bug_id']:03d}   {cls:<8} {reason_short}")

    print("\n" + "─" * 72)
    print(f"R1={counts['R1']} R2={counts['R2']} R3={counts['R3']} UNKNOWN={counts['UNKNOWN']}")
    print(f"논문 목표: R1=19 R2=19 R3=20")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n저장: {OUTPUT_FILE}")

    print("Notion 기록 중...")
    try:
        url = notion_log(results)
        print(f"Notion: {url}")
    except Exception as e:
        print(f"Notion 실패: {e}")


if __name__ == "__main__":
    main()
