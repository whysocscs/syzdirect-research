#!/bin/bash
# target_analyzer를 --target-point로 재실행 (kcov_mark_block 없이)
set -e

TARGET_ANALYZER="/work/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer"
INTERFACE_FILE="/home/ai/kernel_interface/kernelCode2syscall.json"
BC_DIR="/work/linux_bc"
RESULT_DIR="/home/ai/static_analysis_results_v2"

mkdir -p "$RESULT_DIR"

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

echo "======================================"
echo " target_analyzer (--target-point 방식)"
echo "======================================"

for entry in "${BUGS[@]}"; do
    BUG_ID="${entry%%|*}"
    TARGET="${entry##*|}"
    OUT_DIR="$RESULT_DIR/B$(printf '%03d' $BUG_ID)"
    DONE=$((DONE + 1))

    echo ""
    echo "[$DONE/$TOTAL] B$(printf '%03d' $BUG_ID): $TARGET"

    if [ -f "$OUT_DIR/CompactOutput.json" ] && [ -s "$OUT_DIR/CompactOutput.json" ]; then
        CONTENT=$(cat "$OUT_DIR/CompactOutput.json")
        if [ "$CONTENT" != "[]" ]; then
            echo "  ✅ 이미 완료 (비어있지 않음), 스킵"
            continue
        fi
    fi

    mkdir -p "$OUT_DIR"
    cd "$OUT_DIR"

    set +e
    "$TARGET_ANALYZER" \
        --verbose-level=1 \
        --target-point="$TARGET" \
        --kernel-interface-file="$INTERFACE_FILE" \
        "$BC_DIR" > "$OUT_DIR/analysis.log" 2>&1
    EXIT_CODE=$?
    set -e

    if [ -f "$OUT_DIR/CompactOutput.json" ]; then
        CONTENT=$(cat "$OUT_DIR/CompactOutput.json")
        if [ "$CONTENT" = "[]" ]; then
            # Check if TargetPoint was found
            if grep -q "\[TargetPoint\] Found" "$OUT_DIR/analysis.log" 2>/dev/null; then
                echo "  ⚠️  타겟 찾았지만 syscall 없음 (R1)"
            else
                echo "  ❌ 타겟 미발견"
                grep "\[TargetPoint\]" "$OUT_DIR/analysis.log" 2>/dev/null || true
            fi
        else
            SYSCALL=$(python3 -c "import json; d=json.load(open('$OUT_DIR/CompactOutput.json')); print([x['target syscall'] for item in d for x in item['target syscall infos']][:3])" 2>/dev/null || echo "?")
            echo "  ✅ 완료: $SYSCALL"
        fi
    else
        echo "  ⚠️  CompactOutput.json 없음 (exit=$EXIT_CODE)"
    fi
done

echo ""
echo "======================================"
echo "✅ 완료"
echo "결과: $RESULT_DIR"
echo "다음: python3 /home/ai/syzdirect_setup/05b_classify_v2.py"
echo "======================================"
