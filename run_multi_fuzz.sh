#!/bin/bash
# 3개 버그 (B029, B040, B054) 에 대해 SyzDirect 전체 파이프라인 실행
# 순서: 거리분석 → 커널빌드 → 퍼징(4시간)
set -euo pipefail

LINUX_REPO=/work/linux
BC_DIR=/work/linux_bc
ANALYZER=/work/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src/build/lib/target_analyzer
INTERFACE=/home/ai/kernel_interface/kernelCode2syscall.json
CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang
BIGCONFIG=/work/SyzDirect/source/syzdirect/bigconfig
KCOV_PATCH=/work/SyzDirect/source/syzdirect/kcov.diff
FUZZER=/work/SyzDirect/source/syzdirect/syzdirect_fuzzer/bin/syz-manager
BC_CURRENT_COMMIT=da8e7da11e4ba758caf4c149cc8d8cd555aefe5f
FUZZ_HOURS=4

declare -A BUG_TARGET=(
    [29]="include/net/gre.h:140"
    [40]="net/mac80211/cfg.c:1681"
    [54]="net/xfrm/xfrm_compat.c:571"
)
declare -A BUG_FUNC=(
    [29]="gre_build_header"
    [40]="sta_apply_parameters"
    [54]="xfrm_user_rcv_msg_compat"
)
declare -A BUG_COMMIT=(
    [29]="3dbdb38e2869"
    [40]="e0756cfc7d7c"
    [54]="3cea11cd5e3b"
)
declare -A BUG_SYSCALL=(
    [29]="sendmsg"
    [40]="sendmsg"
    [54]="sendmsg"
)
declare -A BUG_PORT=(
    [29]=56742
    [40]=56743
    [54]=56744
)

log() { echo "[$(date '+%H:%M:%S')] $*"; }

run_bug() {
    local BID=$1
    local TARGET="${BUG_TARGET[$BID]}"
    local FUNC="${BUG_FUNC[$BID]}"
    local PORT="${BUG_PORT[$BID]}"
    local BASE="/home/ai/fuzz_bug${BID}"
    local DIST_DIR="$BASE/distance_xidx0"
    local KERNEL_SRC="$BASE/linux_src"
    local BUILD_DIR="$BASE/kernel_build"
    local OUT_DIR="$BASE/instrumented_kernel"
    local RESULT_DIR="$BASE/analysis_result"
    local LOG="$BASE/pipeline.log"

    exec > >(tee -a "$LOG") 2>&1
    log "===== Bug ${BID} 파이프라인 시작 ====="
    log "타겟: $TARGET ($FUNC)"

    # 1. 거리 분석
    log "[1/4] 거리 분석 실행..."
    mkdir -p "$DIST_DIR" "$RESULT_DIR"
    cd "$RESULT_DIR"
    $ANALYZER \
        --verbose-level=1 \
        --target-point="$TARGET" \
        --kernel-interface-file="$INTERFACE" \
        --distance-output="$DIST_DIR" \
        $BC_DIR > "$RESULT_DIR/analysis.log" 2>&1
    NDIST=$(find "$DIST_DIR" -type f 2>/dev/null | wc -l)
    log "거리 파일 ${NDIST}개 생성"

    # 2. callfile 생성
    log "[2/4] callfile 생성..."
    python3 - << PYEOF > "$BASE/callfile_xidx0.json"
import json
data = json.load(open("$RESULT_DIR/CompactOutput.json"))
syscall = "${BUG_SYSCALL[$BID]}"
# CompactOutput에서 구체적인 syscall variant 찾기
target_sc = None
for item in data:
    for sc_info in item.get("target syscall infos", []):
        sc = sc_info.get("target syscall","")
        if syscall in sc:
            target_sc = sc
            break
    if target_sc:
        break
if not target_sc:
    target_sc = syscall
print(json.dumps([{"Target": target_sc, "Relate": []}], indent=2))
PYEOF
    log "callfile: $(cat $BASE/callfile_xidx0.json)"

    # 3. 커널 빌드 (BC_CURRENT_COMMIT 기준 worktree)
    log "[3/4] 커널 빌드 시작..."
    rm -rf "$KERNEL_SRC" 2>/dev/null || true
    cd $LINUX_REPO
    git worktree add "$KERNEL_SRC" $BC_CURRENT_COMMIT 2>&1
    cd "$KERNEL_SRC"

    # kcov 패치 적용 - v6.3용 패치 (vm_flags_set API 사용)
    git checkout -- scripts/Makefile.kcov 2>/dev/null || true
    cp /work/linux/kernel/kcov.c kernel/kcov.c
    python3 /home/ai/syzdirect_setup/patch_kcov_v63.py kernel/kcov.c
    log "kcov.c v6.3 패치 완료"

    # Makefile.kcov 설정
    cat > scripts/Makefile.kcov << KCOV
# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-\$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=$KERNEL_SRC -fsanitize-coverage-distance-dir=$DIST_DIR -fsanitize-coverage-target-function=$FUNC
kcov-flags-\$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
export CFLAGS_KCOV := \$(kcov-flags-y)
KCOV

    mkdir -p "$BUILD_DIR"
    cp $BIGCONFIG "$BUILD_DIR/.config"
    printf 'CONFIG_UBSAN=n\nCONFIG_KCOV=y\nCONFIG_KASAN=n\nCONFIG_KCSAN=n\n' >> "$BUILD_DIR/.config"
    make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig 2>&1 | tail -3
    make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j$(nproc) 2>&1

    if [ -f "$BUILD_DIR/arch/x86/boot/bzImage" ]; then
        mkdir -p "$OUT_DIR"
        cp "$BUILD_DIR/arch/x86/boot/bzImage" "$OUT_DIR/bzImage_xidx0"
        cp "$BUILD_DIR/vmlinux" "$OUT_DIR/vmlinux_0"
        log "커널 빌드 성공!"
    else
        log "❌ 커널 빌드 실패"
        exit 1
    fi

    # 4. fuzz config 생성 및 실행
    log "[4/4] 퍼징 시작 (${FUZZ_HOURS}시간)..."
    cat > "$BASE/fuzz_config.json" << CONF
{
    "target": "linux/amd64",
    "sshkey": "/home/ai/fuzz_bug7/images/bullseye.id_rsa",
    "procs": 4,
    "type": "qemu",
    "vm": {
        "count": 1,
        "cpu": 1,
        "mem": 4096,
        "kernel": "$OUT_DIR/bzImage_xidx0"
    },
    "image": "/home/ai/fuzz_bug7/images/bullseye.img",
    "workdir": "$BASE/fuzz_run",
    "syzkaller": "/work/SyzDirect/source/syzdirect/syzdirect_fuzzer",
    "http": "0.0.0.0:${PORT}",
    "hitindex": 0,
    "reproduce": false
}
CONF
    rm -rf "$BASE/fuzz_run" && mkdir -p "$BASE/fuzz_run"
    $FUZZER -config="$BASE/fuzz_config.json" \
            -callfile="$BASE/callfile_xidx0.json" \
            -uptime=$FUZZ_HOURS \
            2>&1 | tee "$BASE/fuzzer_run.log"
    log "===== Bug ${BID} 퍼징 완료 ====="
}

# 순차 실행 (커널빌드 3개 직렬 → 퍼징은 병렬)
# B029 먼저
log "===== 전체 시작: B029, B040, B054 ====="
run_bug 29 &
PID29=$!
log "B029 PID: $PID29"

# 20분 후 B040 시작 (빌드 겹침 방지)
sleep 1200
run_bug 40 &
PID40=$!
log "B040 PID: $PID40"

# 20분 후 B054 시작
sleep 1200
run_bug 54 &
PID54=$!
log "B054 PID: $PID54"

wait $PID29 $PID40 $PID54
log "모든 작업 완료!"
