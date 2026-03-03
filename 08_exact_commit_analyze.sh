#!/bin/bash
# ================================================================
# 08_exact_commit_analyze.sh
# 각 버그의 정확한 syzbot crash commit에서 bitcode 빌드 + 분석
#
# 실행 방법:
#   bash /home/ai/syzdirect_setup/08_exact_commit_analyze.sh
#
# 예상 시간: 8~12시간 (58개 버그, ~50개 unique commit)
# 재개: 이미 CompactOutput.json 있는 버그는 자동 스킵
# ================================================================
set -euo pipefail

# ── 경로 설정 ───────────────────────────────────────────────────
WORK_DIR="/work"
LINUX_SRC="$WORK_DIR/linux"
BC_DIR="$WORK_DIR/linux_bc"
EMIT_SCRIPT="$WORK_DIR/emit-llvm.sh"
TARGET_ANALYZER="$WORK_DIR/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
INTERFACE_FILE="/home/ai/kernel_interface/kernelCode2syscall.json"
BIGCONFIG="$WORK_DIR/SyzDirect/source/syzdirect/bigconfig"
RESULT_BASE="/home/ai/static_analysis_exact_commit"
BUG_COMMITS="/home/ai/bug_kernel_commits.json"
FIX_LLBC_SCRIPT="/home/ai/syzdirect_setup/fix_bad_llbc_for_target.py"
JOBS=$(nproc)

mkdir -p "$RESULT_BASE"
LOG_FILE="$RESULT_BASE/main.log"
GROUPS_FILE="$RESULT_BASE/commit_groups.txt"

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠️  $*" | tee -a "$LOG_FILE"; }

# ── objtool GCC-13 호환 패치 ───────────────────────────────────
patch_objtool() {
    local SUBCMD="$LINUX_SRC/tools/lib/subcmd/subcmd-util.h"
    if [ -f "$SUBCMD" ] && grep -q 'ret = realloc(ptr, size);' "$SUBCMD" 2>/dev/null; then
        python3 - <<'PY'
import pathlib
p = pathlib.Path("/work/linux/tools/lib/subcmd/subcmd-util.h")
src = p.read_text()
old = ('static inline void *xrealloc(void *ptr, size_t size)\n'
       '{\n'
       '\tvoid *ret = realloc(ptr, size);\n'
       '\tif (!ret && !size)\n'
       '\t\tret = realloc(ptr, 1);\n'
       '\tif (!ret) {\n'
       '\t\tret = realloc(ptr, size);\n'
       '\t\tif (!ret && !size)\n'
       '\t\t\tret = realloc(ptr, 1);\n'
       '\t\tif (!ret)\n'
       '\t\t\tdie("Out of memory, realloc failed");\n'
       '\t}\n'
       '\treturn ret;\n'
       '}')
new = ('static inline void *xrealloc(void *ptr, size_t size)\n'
       '{\n'
       '\tvoid *ret = realloc(ptr, size ? size : 1);\n'
       '\tif (!ret)\n'
       '\t\tdie("Out of memory, realloc failed");\n'
       '\treturn ret;\n'
       '}')
if old in src:
    p.write_text(src.replace(old, new))
    print("  objtool 패치 적용")
else:
    print("  objtool 이미 패치됨")
PY
    fi
}

# ── 커밋 빌드 ──────────────────────────────────────────────────
build_commit() {
    local COMMIT="$1"
    local STABLE_VER="$2"
    local COMMIT_DATE="$3"   # YYYY/MM/DD
    local START_TIME
    START_TIME=$(date +%s)

    log "====== 빌드: ${COMMIT:0:12} ($STABLE_VER, $COMMIT_DATE) ======"

    cd "$LINUX_SRC"

    # 1. 이미 이 커밋이 체크아웃되어 있는지 확인
    local CURRENT
    CURRENT=$(git rev-parse HEAD 2>/dev/null || echo "none")
    if [ "$CURRENT" = "$COMMIT" ]; then
        local BC_COUNT
        BC_COUNT=$(find "$BC_DIR" -name '*.llbc' 2>/dev/null | wc -l)
        if [ "$BC_COUNT" -gt 1000 ]; then
            log "  이미 이 커밋 빌드됨 (${BC_COUNT}개 .llbc), 빌드 스킵"
            return 0
        fi
    fi

    # 2. 커밋 fetch (TAG: 접두사면 stable 태그 사용)
    if [[ "$COMMIT" == TAG:* ]]; then
        local TAG="${COMMIT#TAG:}"
        log "  [1/5] stable 태그 사용: $TAG"
        git checkout -- . 2>/dev/null || true
        git fetch --depth=1 origin "+refs/tags/${TAG}:refs/tags/${TAG}" 2>&1 | tail -3 || true
        git -c advice.detachedHead=false checkout "tags/${TAG}"
    else
        # 커밋이 로컬에 있는지 확인
        if ! git cat-file -e "${COMMIT}^{commit}" 2>/dev/null; then
            log "  [1/5] commit fetch: ${COMMIT:0:12}"

            # GitHub torvalds mirror에서 직접 hash fetch 시도
            git remote add github https://github.com/torvalds/linux.git 2>/dev/null || true

            local FETCHED=false
            if git fetch --depth=1 github "$COMMIT" 2>&1 | tail -2; then
                FETCHED=true
            else
                # shallow-since 방식 (commit date 기준 ±2주)
                warn "  직접 fetch 실패, shallow-since 재시도..."
                local DATE_ISO
                DATE_ISO=$(echo "$COMMIT_DATE" | tr '/' '-')
                local DATE_FROM
                DATE_FROM=$(date -d "$DATE_ISO - 14 days" +%Y-%m-%d 2>/dev/null || echo "$DATE_ISO")
                if git fetch --shallow-since="$DATE_FROM" github master 2>&1 | tail -3; then
                    if git cat-file -e "${COMMIT}^{commit}" 2>/dev/null; then
                        FETCHED=true
                    fi
                fi
            fi

            if [ "$FETCHED" = "false" ]; then
                # 최종 fallback: nearest stable tag
                warn "  커밋 fetch 실패 → stable tag fallback: $STABLE_VER"
                git fetch --depth=1 origin "+refs/tags/${STABLE_VER}:refs/tags/${STABLE_VER}" 2>&1 | tail -2 || true
                git checkout -- . 2>/dev/null || true
                git -c advice.detachedHead=false checkout "tags/${STABLE_VER}"
                echo "FALLBACK_TAG" > "$RESULT_BASE/.fallback_${COMMIT:0:12}"
                patch_objtool
                goto_build=true
            fi
        fi

        if [ "${goto_build:-false}" != "true" ]; then
            log "  [2/5] checkout: ${COMMIT:0:12}"
            git checkout -- . 2>/dev/null || true
            git -c advice.detachedHead=false checkout "$COMMIT"
        fi
        unset goto_build
    fi

    patch_objtool

    # 3. BC_DIR 클린
    log "  [3/5] BC_DIR 클린..."
    if [ -d "$BC_DIR" ]; then
        make mrproper -C "$LINUX_SRC" O="$BC_DIR" 2>&1 | tail -2 || true
    fi
    mkdir -p "$BC_DIR"

    # 4. config 준비
    log "  [4/5] config 준비..."
    cp "$BIGCONFIG" "$BC_DIR/.config"
    printf 'CONFIG_KASAN=n\nCONFIG_KCSAN=n\nCONFIG_UBSAN=n\nCONFIG_KCOV=y\n' >> "$BC_DIR/.config"
    yes "" | make CC="$EMIT_SCRIPT" -C "$LINUX_SRC" O="$BC_DIR" oldconfig 2>&1 | tail -2 || true

    # 5. 빌드
    log "  [5/5] 빌드 중 (jobs=$JOBS)..."
    local BUILD_LOG="$RESULT_BASE/build_${COMMIT:0:12}.log"
    make CC="$EMIT_SCRIPT" -C "$LINUX_SRC" O="$BC_DIR" -j"$JOBS" 2>&1 \
        | tee "$BUILD_LOG" | tail -5 || {
        warn "  빌드 오류 (계속 진행)"
    }

    local BC_COUNT
    BC_COUNT=$(find "$BC_DIR" -name '*.llbc' 2>/dev/null | wc -l)
    local END_TIME
    END_TIME=$(date +%s)
    log "  .llbc: ${BC_COUNT}개 | 소요: $(( (END_TIME - START_TIME) / 60 ))분"
}

# ── bad llbc 제거 ─────────────────────────────────────────────
fix_bad_llbc() {
    local TEST_TARGET="$1"
    log "  [fix_bad_llbc] 테스트: $TEST_TARGET"
    python3 "$FIX_LLBC_SCRIPT" "$TEST_TARGET" 2>&1 | tee -a "$LOG_FILE" || {
        warn "  fix_bad_llbc 실패 (계속 진행)"
    }
}

# ── 단일 버그 분석 ─────────────────────────────────────────────
run_analysis() {
    local BUG_ID="$1"
    local TARGET="$2"
    local OUT_DIR="$RESULT_BASE/B$(printf '%03d' "$BUG_ID")"

    mkdir -p "$OUT_DIR"
    cd "$OUT_DIR"   # 반드시 OUT_DIR로 cd (CompactOutput.json이 CWD에 생성됨)

    set +e
    "$TARGET_ANALYZER" \
        --verbose-level=1 \
        --target-point="$TARGET" \
        --kernel-interface-file="$INTERFACE_FILE" \
        "$BC_DIR" > "$OUT_DIR/analysis.log" 2>&1
    local EXIT_CODE=$?
    set -e

    if [ -f "$OUT_DIR/CompactOutput.json" ]; then
        local CONTENT
        CONTENT=$(cat "$OUT_DIR/CompactOutput.json")
        if [ "$CONTENT" = "[]" ]; then
            if grep -q '\[TargetPoint\] Found' "$OUT_DIR/analysis.log" 2>/dev/null; then
                log "    B$(printf '%03d' "$BUG_ID"): ⚠️  target 발견, syscall path 없음"
            else
                log "    B$(printf '%03d' "$BUG_ID"): ❌ target point 미발견"
            fi
        else
            local N
            N=$(python3 -c "
import json, sys
try:
    d = json.load(open('$OUT_DIR/CompactOutput.json'))
    print(len(d))
except:
    print('?')
" 2>/dev/null)
            log "    B$(printf '%03d' "$BUG_ID"): ✅ syscall ${N}개"
        fi
    else
        if [ "$EXIT_CODE" -ne 0 ]; then
            warn "    B$(printf '%03d' "$BUG_ID"): analyzer 크래시 (exit=$EXIT_CODE) → CompactOutput 없음"
        else
            warn "    B$(printf '%03d' "$BUG_ID"): CompactOutput.json 없음 (exit=$EXIT_CODE)"
        fi
    fi
}

# ================================================================
# 메인 로직
# ================================================================
log "================================================================"
log " Exact Commit Static Analysis"
log " BUG_COMMITS : $BUG_COMMITS"
log " RESULT_BASE : $RESULT_BASE"
log " JOBS        : $JOBS"
log "================================================================"

TOTAL_START=$(date +%s)

# ── 1. commit 그룹 파일 생성 ──────────────────────────────────
log "커밋 그룹 생성 중..."
python3 - <<'PY' > "$GROUPS_FILE"
import json, sys

with open("/home/ai/bug_kernel_commits.json") as f:
    bugs = json.load(f)

groups = {}  # commit_key -> info
for bug_id, info in bugs.items():
    commit = info.get("commit", "").strip()
    if not commit or commit in ("unknown", ""):
        commit = "TAG:" + info.get("kernel_version", "v5.15")

    if commit not in groups:
        groups[commit] = {
            "commit": commit,
            "stable_ver": info.get("kernel_version", "v5.15"),
            "commit_date": info.get("commit_date", "2022/01/01"),
            "bugs": []
        }
    groups[commit]["bugs"].append({
        "bug_id": bug_id,
        "filepath": info.get("filepath", "")
    })

# 날짜 기준 정렬 (오래된 것부터 빌드)
sorted_groups = sorted(groups.values(), key=lambda g: g["commit_date"])

for g in sorted_groups:
    bugs_str = ",".join(f"{b['bug_id']}:{b['filepath']}" for b in g["bugs"])
    print(f"{g['commit']}\t{g['stable_ver']}\t{g['commit_date']}\t{bugs_str}")

import sys
print(f"[Python] 총 {len(sorted_groups)}개 unique commit 그룹", file=sys.stderr)
PY

NGROUPS=$(wc -l < "$GROUPS_FILE")
log "커밋 그룹: ${NGROUPS}개"

# ── 2. 각 커밋 처리 ───────────────────────────────────────────
while IFS=$'\t' read -r COMMIT STABLE_VER COMMIT_DATE BUGS_STR; do
    [ -z "$COMMIT" ] && continue

    # 모든 버그가 완료됐는지 확인
    ALL_DONE=true
    IFS=',' read -ra BUG_LIST <<< "$BUGS_STR"
    for BUG_ENTRY in "${BUG_LIST[@]}"; do
        BUG_ID="${BUG_ENTRY%%:*}"
        OUT_DIR="$RESULT_BASE/B$(printf '%03d' "$BUG_ID")"
        if [ ! -f "$OUT_DIR/CompactOutput.json" ]; then
            ALL_DONE=false
            break
        fi
    done

    if [ "$ALL_DONE" = "true" ]; then
        log "[${COMMIT:0:12}] 이미 완료, 스킵"
        continue
    fi

    # 빌드
    build_commit "$COMMIT" "$STABLE_VER" "$COMMIT_DATE"

    # 첫 번째 버그 target으로 bad llbc 검사
    FIRST_ENTRY="${BUG_LIST[0]}"
    FIRST_TARGET="${FIRST_ENTRY##*:}"
    if [ -n "$FIRST_TARGET" ]; then
        fix_bad_llbc "$FIRST_TARGET"
    fi

    # 분석
    log "  분석 시작: ${COMMIT:0:12}"
    for BUG_ENTRY in "${BUG_LIST[@]}"; do
        BUG_ID="${BUG_ENTRY%%:*}"
        TARGET="${BUG_ENTRY##*:}"
        OUT_DIR="$RESULT_BASE/B$(printf '%03d' "$BUG_ID")"

        if [ -f "$OUT_DIR/CompactOutput.json" ]; then
            log "    B$(printf '%03d' "$BUG_ID"): 이미 완료"
            continue
        fi

        run_analysis "$BUG_ID" "$TARGET"
    done

    log "  ✅ ${COMMIT:0:12} 완료"
done < "$GROUPS_FILE"

TOTAL_END=$(date +%s)
TOTAL_MIN=$(( (TOTAL_END - TOTAL_START) / 60 ))

log "================================================================"
log "✅ 빌드+분석 완료 | 총 소요: ${TOTAL_MIN}분"
log "결과: $RESULT_BASE"
log "================================================================"

# ── 3. 분류 실행 ─────────────────────────────────────────────
log "PoC 기반 분류 시작..."
python3 /home/ai/syzdirect_setup/09_classify_poc_based.py

log "모든 작업 완료!"
