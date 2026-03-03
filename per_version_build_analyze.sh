#!/bin/bash
# ================================================================
# per_version_build_analyze.sh
# 각 kernel stable 버전별로 bitcode 빌드 + target_analyzer 실행
# 논문 방식: 각 버그를 crash 날짜 기준 가장 가까운 stable 버전으로 분석
# ================================================================
set -e

WORK_DIR="/work"
LINUX_SRC="$WORK_DIR/linux"
BC_DIR="$WORK_DIR/linux_bc"
EMIT_SCRIPT="$WORK_DIR/emit-llvm.sh"
LLVM_DIR="$WORK_DIR/SyzDirect/source/llvm-project-new/build"
CLANG="$LLVM_DIR/bin/clang"
TARGET_ANALYZER="$WORK_DIR/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
INTERFACE_FILE="/home/ai/kernel_interface/kernelCode2syscall.json"
BIGCONFIG="$WORK_DIR/SyzDirect/source/syzdirect/bigconfig"
RESULT_BASE="/home/ai/static_analysis_per_version"
JOBS=$(nproc)

mkdir -p "$RESULT_BASE"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ────────────────────────────────────────────────────────────────
# 버전별 버그 목록 (bug_id|file:line)
# ────────────────────────────────────────────────────────────────
declare -A VERSION_BUGS

VERSION_BUGS["v5.10"]="8|drivers/misc/vmw_vmci/vmci_queue_pair.c:539
11|fs/gfs2/util.c:293
43|fs/ext4/xattr.c:1639
54|net/xfrm/xfrm_compat.c:571
66|fs/reiserfs/super.c:2082"

VERSION_BUGS["v5.11"]="7|net/qrtr/tun.c:92
40|net/mac80211/cfg.c:1681"

VERSION_BUGS["v5.12"]="12|net/mac80211/sta_info.c:485
20|fs/squashfs/file.c:242
22|net/sched/sch_taprio.c:998
46|net/socket.c:1123"

VERSION_BUGS["v5.13"]="27|net/sched/cls_tcindex.c:307
29|include/net/gre.h:140
31|fs/splice.c:766
36|sound/core/seq/seq_queue.c:171
72|fs/namei.c:3523"

VERSION_BUGS["v5.14"]="26|fs/ext4/super.c:6607
28|fs/fuse/dir.c:1120
30|net/core/dev.c:3701
32|net/sched/sch_api.c:1298
35|net/sched/sch_fifo.c:241
67|net/netfilter/nft_ct.c:616
76|fs/io_uring.c:3460"

VERSION_BUGS["v5.15"]="73|fs/erofs/decompressor.c:227
88|sound/core/oss/mixer_oss.c:601"

VERSION_BUGS["v5.16"]="39|drivers/infiniband/core/cma.c:2584
57|fs/aio.c:2001
58|net/netfilter/nf_tables_api.c:7233
89|kernel/cgroup/cgroup.c:3629
90|net/packet/af_packet.c:4461"

VERSION_BUGS["v5.17"]="41|sound/core/oss/pcm_plugin.c:70
44|fs/ext4/indirect.c:1243
45|mm/mremap.c:498
47|net/smc/smc_pnet.c:316
69|fs/btrfs/volumes.c:1361
81|fs/io_uring.c:8999
84|drivers/net/vxlan/vxlan_vnifilter.c:429
91|crypto/crypto_null.c:88
93|sound/core/oss/pcm_oss.c:1691"

VERSION_BUGS["v5.18"]="61|net/rxrpc/output.c:452
92|fs/iomap/direct-io.c:657
94|drivers/net/tun.c:3410"

VERSION_BUGS["v5.19"]="16|net/rxrpc/sendmsg.c:747
38|fs/ext4/extents_status.c:897
42|kernel/dma/mapping.c:263
96|fs/fscache/volume.c:172
97|net/sctp/auth.c:867
98|drivers/net/ipvlan/ipvlan_core.c:598"

VERSION_BUGS["v6.0"]="53|fs/ntfs3/dir.c:255
79|net/ipv4/tcp_cong.c:218
100|net/netfilter/nf_tables_api.c:2258"

VERSION_BUGS["v6.1"]="51|kernel/bpf/verifier.c:14032
52|fs/hfs/bfind.c:76
63|fs/ntfs3/record.c:311
64|fs/hfsplus/super.c:474
83|mm/madvise.c:794"

VERSION_BUGS["v6.2"]="78|net/sched/cls_api.c:3238"

VERSION_BUGS["v6.3"]="85|fs/namespace.c:161"

VERSIONS=("v5.10" "v5.11" "v5.12" "v5.13" "v5.14" "v5.15" "v5.16" "v5.17" "v5.18" "v5.19" "v6.0" "v6.1" "v6.2" "v6.3")

# ────────────────────────────────────────────────────────────────
# objtool GCC-13 호환 패치
# ────────────────────────────────────────────────────────────────
patch_objtool() {
    local SUBCMD="$LINUX_SRC/tools/lib/subcmd/subcmd-util.h"
    if [ -f "$SUBCMD" ] && grep -q "ret = realloc(ptr, size);" "$SUBCMD" 2>/dev/null; then
        python3 - <<'PY'
import pathlib
p = pathlib.Path("/work/linux/tools/lib/subcmd/subcmd-util.h")
src = p.read_text()
old = '''static inline void *xrealloc(void *ptr, size_t size)
{
\tvoid *ret = realloc(ptr, size);
\tif (!ret && !size)
\t\tret = realloc(ptr, 1);
\tif (!ret) {
\t\tret = realloc(ptr, size);
\t\tif (!ret && !size)
\t\t\tret = realloc(ptr, 1);
\t\tif (!ret)
\t\t\tdie("Out of memory, realloc failed");
\t}
\treturn ret;
}'''
new = '''static inline void *xrealloc(void *ptr, size_t size)
{
\tvoid *ret = realloc(ptr, size ? size : 1);
\tif (!ret)
\t\tdie("Out of memory, realloc failed");
\treturn ret;
}'''
if old in src:
    p.write_text(src.replace(old, new))
    print("  objtool 패치 적용")
else:
    print("  objtool 이미 패치됨")
PY
    fi
}

# ────────────────────────────────────────────────────────────────
# 버전 체크아웃 + 빌드
# ────────────────────────────────────────────────────────────────
build_version() {
    local VER="$1"
    local START_TIME=$(date +%s)
    
    log "====== 빌드 시작: $VER ======"
    
    # 1. 소스 fetch + checkout
    log "[1/5] git fetch: $VER"
    cd "$LINUX_SRC"
    git fetch --depth=1 origin "+refs/tags/${VER}:refs/tags/${VER}" 2>&1 | tail -3 || {
        log "  stable repo에서 실패, torvalds 시도..."
        git remote add torvalds https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git 2>/dev/null || true
        git fetch --depth=1 torvalds "+refs/tags/${VER}:refs/tags/${VER}" 2>&1 | tail -3
    }
    
    log "[2/5] git checkout: $VER"
    git checkout -- . 2>/dev/null || true   # 로컬 변경사항 초기화
    git -c advice.detachedHead=false checkout "tags/${VER}"
    patch_objtool
    
    # 2. BC_DIR 클린
    log "[3/5] BC_DIR 클린 (mrproper)..."
    if [ -d "$BC_DIR" ]; then
        # mrproper로 클린
        make mrproper -C "$LINUX_SRC" O="$BC_DIR" 2>&1 | tail -2 || true
    fi
    mkdir -p "$BC_DIR"
    
    # 3. config 준비
    log "[4/5] config 준비..."
    cp "$BIGCONFIG" "$BC_DIR/.config"
    printf 'CONFIG_KASAN=n\nCONFIG_KCSAN=n\nCONFIG_UBSAN=n\nCONFIG_KCOV=y\n' >> "$BC_DIR/.config"
    yes "" | make CC="$EMIT_SCRIPT" -C "$LINUX_SRC" O="$BC_DIR" oldconfig 2>&1 | tail -2
    
    # 4. 빌드
    log "[5/5] 빌드 중 (jobs=$JOBS)..."
    local BUILD_LOG="$RESULT_BASE/build_${VER}.log"
    make CC="$EMIT_SCRIPT" -C "$LINUX_SRC" O="$BC_DIR" -j"$JOBS" 2>&1 | tee "$BUILD_LOG" | tail -5 || {
        log "  ⚠️  빌드 오류 (계속 진행)"
    }
    
    local BC_COUNT
    BC_COUNT=$(find "$BC_DIR" -name '*.llbc' 2>/dev/null | wc -l)
    local END_TIME=$(date +%s)
    log "  .llbc: ${BC_COUNT}개 | 소요: $(( (END_TIME - START_TIME) / 60 ))분"
}

# ────────────────────────────────────────────────────────────────
# 단일 버그 분석
# ────────────────────────────────────────────────────────────────
run_analysis() {
    local BUG_ID="$1"
    local TARGET="$2"
    local OUT_DIR="$RESULT_BASE/B$(printf '%03d' $BUG_ID)"
    
    mkdir -p "$OUT_DIR"
    cd "$OUT_DIR"

    set +e
    "$TARGET_ANALYZER" \
        --verbose-level=1 \
        --target-point="$TARGET" \
        --kernel-interface-file="$INTERFACE_FILE" \
        "$BC_DIR" > "$OUT_DIR/analysis.log" 2>&1
    set -e
    
    if [ -f "$OUT_DIR/CompactOutput.json" ]; then
        local CONTENT
        CONTENT=$(cat "$OUT_DIR/CompactOutput.json")
        if [ "$CONTENT" = "[]" ]; then
            if grep -q "\[TargetPoint\] Found" "$OUT_DIR/analysis.log" 2>/dev/null; then
                echo "    B$(printf '%03d' $BUG_ID): ⚠️  target 발견, syscall 없음 (R1)"
            else
                echo "    B$(printf '%03d' $BUG_ID): ❌ target 미발견"
                grep "\[TargetPoint\]" "$OUT_DIR/analysis.log" 2>/dev/null | head -2 | sed 's/^/      /' || true
            fi
        else
            local N
            N=$(python3 -c "import json; d=json.load(open('$OUT_DIR/CompactOutput.json')); print(len(d))" 2>/dev/null || echo "?")
            echo "    B$(printf '%03d' $BUG_ID): ✅ ${N}개 syscall"
        fi
    else
        echo "    B$(printf '%03d' $BUG_ID): ⚠️  출력 없음"
    fi
}

# ────────────────────────────────────────────────────────────────
# 메인 루프
# ────────────────────────────────────────────────────────────────
log "======================================================"
log " Per-version Static Analysis (논문 방식)"
log " 버전: ${#VERSIONS[@]}개 | 코어: $JOBS"
log "======================================================"

TOTAL_START=$(date +%s)

for VER in "${VERSIONS[@]}"; do
    BUGS="${VERSION_BUGS[$VER]:-}"
    if [ -z "$BUGS" ]; then
        log "[$VER] 버그 없음, 스킵"
        continue
    fi
    
    # 이미 모든 버그 분석됐는지 확인
    ALL_DONE=true
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        BUG_ID="${line%%|*}"
        OUT_DIR="$RESULT_BASE/B$(printf '%03d' $BUG_ID)"
        if [ ! -f "$OUT_DIR/CompactOutput.json" ]; then
            ALL_DONE=false
            break
        fi
    done <<< "$BUGS"
    
    if [ "$ALL_DONE" = "true" ]; then
        log "[$VER] 이미 모두 분석됨, 스킵"
        continue
    fi
    
    # 빌드
    build_version "$VER"
    
    # 분석
    log "  분석 시작: $VER"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        BUG_ID="${line%%|*}"
        TARGET="${line##*|}"
        OUT_DIR="$RESULT_BASE/B$(printf '%03d' $BUG_ID)"
        
        if [ -f "$OUT_DIR/CompactOutput.json" ]; then
            echo "    B$(printf '%03d' $BUG_ID): 이미 완료"
            continue
        fi
        
        run_analysis "$BUG_ID" "$TARGET"
    done <<< "$BUGS"
    
    log "  ✅ $VER 분석 완료"
done

TOTAL_END=$(date +%s)
TOTAL_MIN=$(( (TOTAL_END - TOTAL_START) / 60 ))

log "======================================================"
log "✅ 전체 완료 | 총 소요: ${TOTAL_MIN}분"
log "결과: $RESULT_BASE"
log "======================================================"

