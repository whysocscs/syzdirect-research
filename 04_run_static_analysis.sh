#!/bin/bash
# Step 4: SyzDirect 분석 도구로 58개 버그 static analysis
# 실제 바이너리 직접 호출 방식
set -e

WORK_DIR="/work"
SYZDIRECT="$WORK_DIR/SyzDirect/source/syzdirect"
LLVM_DIR="$WORK_DIR/SyzDirect/source/llvm-project-new/build"
BC_DIR="$WORK_DIR/linux_bc"          # 커널 bitcode 출력 디렉토리
RESULT_DIR="/home/ai/static_analysis_results"
INTERFACE_DIR="/home/ai/kernel_interface"   # 한 번만 생성

# 바이너리 경로
INTERFACE_GEN="$SYZDIRECT/syzdirect_function_model/src/build/lib/interface_generator"
TARGET_ANALYZER="$SYZDIRECT/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
SYZ_FEATURES="$SYZDIRECT/syzdirect_fuzzer/bin/syz-features"

mkdir -p "$RESULT_DIR" "$INTERFACE_DIR"

echo "======================================"
echo " Step 4: Static Analysis (58개 버그)"
echo "======================================"

# ── 사전 확인 ─────────────────────────────────
echo ""
echo "[사전확인] 빌드 결과 확인..."

if [ ! -f "$INTERFACE_GEN" ]; then
    echo "❌ interface_generator 없음: $INTERFACE_GEN"
    exit 1
fi
if [ ! -f "$TARGET_ANALYZER" ]; then
    echo "❌ target_analyzer 없음: $TARGET_ANALYZER"
    exit 1
fi
if [ ! -f "$SYZ_FEATURES" ]; then
    echo "❌ syz-features 없음: $SYZ_FEATURES"
    exit 1
fi
if [ ! -d "$BC_DIR" ] || [ -z "$(find $BC_DIR -name '*.llbc' 2>/dev/null | head -1)" ]; then
    echo "❌ 커널 bitcode 없음: $BC_DIR (먼저 03_build_kernel.sh 실행)"
    exit 1
fi
echo "  ✅ 모든 바이너리 및 bitcode 존재"

# ── [A] kernel_signature_full 생성 (한 번만) ─────
echo ""
echo "[A/C] interface_generator 실행 중..."
KERNEL_SIG="$INTERFACE_DIR/kernel_signature_full"

if [ ! -f "$KERNEL_SIG" ]; then
    cd "$INTERFACE_DIR"
    "$INTERFACE_GEN" --verbose-level=4 "$BC_DIR" 2>&1 | tee "$INTERFACE_DIR/ig_log.txt"
    if [ -f "$KERNEL_SIG" ]; then
        echo "  ✅ kernel_signature_full 생성 완료"
    else
        echo "  ❌ kernel_signature_full 생성 실패 — 로그: $INTERFACE_DIR/ig_log.txt"
        exit 1
    fi
else
    echo "  이미 존재함, 스킵"
fi

# ── [B] syz-features 시그니처 생성 (한 번만) ─────
echo ""
echo "[B/C] syzkaller 시그니처 생성 중..."
SYZ_SIG="$INTERFACE_DIR/syzkaller_signature.txt"

if [ ! -f "$SYZ_SIG" ]; then
    "$SYZ_FEATURES" > "$SYZ_SIG"
    if [ -s "$SYZ_SIG" ]; then
        echo "  ✅ syzkaller_signature.txt 생성 완료 ($(wc -l < $SYZ_SIG) 항목)"
    else
        echo "  ❌ syzkaller_signature.txt 생성 실패"
        exit 1
    fi
else
    echo "  이미 존재함, 스킵"
fi

# ── [C] kernelCode2syscall.json 생성 (한 번만) ───
echo ""
echo "[C/C] kernel interface 매칭 중..."
INTERFACE_FILE="$INTERFACE_DIR/kernelCode2syscall.json"

if [ ! -f "$INTERFACE_FILE" ]; then
    python3 - <<PYEOF
import sys
sys.path.insert(0, '/work/SyzDirect/source/syzdirect/Runner')
sys.path.insert(0, '/work/SyzDirect/source/syzdirect/Runner/SyscallAnalyze')
import InterfaceGenerate
import json

print("  매칭 중 (수분 소요)...")
result = InterfaceGenerate.MatchSig(
    "$SYZ_SIG",
    "$KERNEL_SIG"
)
# set을 list로 변환
def convert(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(type(obj))

with open("$INTERFACE_FILE", "w") as f:
    json.dump(result, f, default=convert, indent=2)
print(f"  저장 완료: {len(result)} 핸들러")
PYEOF
    echo "  ✅ kernelCode2syscall.json 생성 완료"
else
    echo "  이미 존재함, 스킵"
fi

# ── 58개 버그 분석 ────────────────────────────
echo ""
echo "버그 별 target_analyzer 실행..."

BUGS=(
    "7|net/qrtr/tun.c:92"
    "8|drivers/misc/vmw_vmci/vmci_queue_pair.c:539"
    "11|fs/gfs2/util.c:293"
    "12|net/mac80211/sta_info.c:485"
    "16|net/rxrpc/sendmsg.c:747"
    "20|fs/squashfs/file.c:242"
    "22|net/sched/sch_taprio.c:998"
    "26|fs/ext4/super.c:6607"
    "27|net/sched/cls_tcindex.c:307"
    "28|fs/fuse/dir.c:1120"
    "29|include/net/gre.h:140"
    "30|net/core/dev.c:3701"
    "31|fs/splice.c:766"
    "32|net/sched/sch_api.c:1298"
    "35|net/sched/sch_fifo.c:241"
    "36|sound/core/seq/seq_queue.c:171"
    "38|fs/ext4/extents_status.c:897"
    "39|drivers/infiniband/core/cma.c:2584"
    "40|net/mac80211/cfg.c:1681"
    "41|sound/core/oss/pcm_plugin.c:70"
    "42|kernel/dma/mapping.c:263"
    "43|fs/ext4/xattr.c:1639"
    "44|fs/ext4/indirect.c:1243"
    "45|mm/mremap.c:498"
    "46|net/socket.c:1123"
    "47|net/smc/smc_pnet.c:316"
    "51|kernel/bpf/verifier.c:14032"
    "52|fs/hfs/bfind.c:76"
    "53|fs/ntfs3/dir.c:255"
    "54|net/xfrm/xfrm_compat.c:571"
    "57|fs/aio.c:2001"
    "58|net/netfilter/nf_tables_api.c:7233"
    "61|net/rxrpc/output.c:452"
    "63|fs/ntfs3/record.c:311"
    "64|fs/hfsplus/super.c:474"
    "66|fs/reiserfs/super.c:2082"
    "67|net/netfilter/nft_ct.c:616"
    "69|fs/btrfs/volumes.c:1361"
    "72|fs/namei.c:3523"
    "73|fs/erofs/decompressor.c:227"
    "76|fs/io_uring.c:3460"
    "78|net/sched/cls_api.c:3238"
    "79|net/ipv4/tcp_cong.c:218"
    "81|fs/io_uring.c:8999"
    "83|mm/madvise.c:794"
    "84|drivers/net/vxlan/vxlan_vnifilter.c:429"
    "85|fs/namespace.c:161"
    "88|sound/core/oss/mixer_oss.c:601"
    "89|kernel/cgroup/cgroup.c:3629"
    "90|net/packet/af_packet.c:4461"
    "91|crypto/crypto_null.c:88"
    "92|fs/iomap/direct-io.c:657"
    "93|sound/core/oss/pcm_oss.c:1691"
    "94|drivers/net/tun.c:3410"
    "96|fs/fscache/volume.c:172"
    "97|net/sctp/auth.c:867"
    "98|drivers/net/ipvlan/ipvlan_core.c:598"
    "100|net/netfilter/nf_tables_api.c:2258"
)

TOTAL=${#BUGS[@]}
DONE=0

for entry in "${BUGS[@]}"; do
    BUG_ID="${entry%%|*}"
    TARGET="${entry##*|}"
    OUT_DIR="$RESULT_DIR/B$(printf '%03d' $BUG_ID)"

    echo ""
    echo "[$((++DONE))/$TOTAL] B$(printf '%03d' $BUG_ID): $TARGET"

    if [ -f "$OUT_DIR/CompactOutput.json" ]; then
        echo "  ✅ 이미 완료, 스킵"
        continue
    fi

    mkdir -p "$OUT_DIR"

    # target_analyzer 직접 호출
    # --target-point: "file:line" 형식
    # --kernel-interface-file: kernelCode2syscall.json
    # 마지막 인자: 커널 bitcode 디렉토리
    set +e
    cd "$OUT_DIR"
    "$TARGET_ANALYZER" \
        --verbose-level=4 \
        --target-point="$TARGET" \
        --kernel-interface-file="$INTERFACE_FILE" \
        "$BC_DIR" \
        > "$OUT_DIR/analysis.log" 2>&1
    set -e

    if [ -f "$OUT_DIR/CompactOutput.json" ]; then
        echo "  ✅ 완료"
    else
        echo "  ⚠️  CompactOutput.json 없음 — 로그: $OUT_DIR/analysis.log"
        # 로그 마지막 5줄 출력
        tail -5 "$OUT_DIR/analysis.log" 2>/dev/null || true
    fi
done

echo ""
echo "======================================"
echo "✅ Static Analysis 완료"
echo "결과: $RESULT_DIR"
echo "다음: python3 /home/ai/syzdirect_setup/05_classify_from_results.py"
echo "======================================"
