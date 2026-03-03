#!/bin/bash
# Step 3: Linux 커널 bitcode 컴파일 (SyzDirect emit-llvm 방식)
# ⚠️  약 1~2시간 소요
set -e

WORK_DIR="/work"
KERNEL_VERSION="v5.15"
JOBS=$(nproc)
LLVM_DIR="$WORK_DIR/SyzDirect/source/llvm-project-new/build"
CLANG="$LLVM_DIR/bin/clang"
KERNEL_DIR="$WORK_DIR/linux"
BC_DIR="$WORK_DIR/linux_bc"   # 빌드 아웃풋 (bitcode 포함)
EMIT_SCRIPT="$WORK_DIR/emit-llvm.sh"

echo "======================================"
echo " Step 3: Linux 커널 빌드 (bitcode)"
echo " 버전: $KERNEL_VERSION | 코어: $JOBS"
echo "======================================"

# ── 1. 커널 소스 ──────────────────────────────────────
echo ""
echo "[1/4] 커널 소스 확인..."
if [ ! -d "$KERNEL_DIR" ]; then
    cd $WORK_DIR
    git clone --depth=1 --branch $KERNEL_VERSION \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
else
    echo "  이미 존재함, 스킵"
fi

# ── 2. objtool GCC-13 호환 패치 ───────────────────────
echo ""
echo "[2/4] objtool 패치 (GCC-13 호환)..."
SUBCMD_UTIL="$KERNEL_DIR/tools/lib/subcmd/subcmd-util.h"
if grep -q "ret = realloc(ptr, size);" "$SUBCMD_UTIL" 2>/dev/null; then
    # xrealloc 함수를 GCC-13 호환 버전으로 교체
    python3 - <<'PY'
import re, pathlib
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
    print("  패치 적용 완료")
else:
    print("  이미 패치되었거나 버전 다름, 스킵")
PY
else
    echo "  이미 패치됨, 스킵"
fi

# ── 3. emit-llvm 래퍼 스크립트 생성 ──────────────────
echo ""
echo "[3/4] emit-llvm 래퍼 스크립트 생성..."
cat > "$EMIT_SCRIPT" << EMIT_EOF
#!/bin/sh
CLANG=$CLANG
if [ ! -e \$CLANG ]; then exit; fi
OFILE=\`echo \$* | sed -e 's/^.* \(.*\.o\) .*$/\1/'\`
if [ "x\$OFILE" != x -a "\$OFILE" != "\$*" ]; then
    \$CLANG -emit-llvm -g "\$@" >/dev/null 2>&1
    if [ -f "\$OFILE" ]; then
        BCFILE=\`echo \$OFILE | sed -e 's/o\$/llbc/'\`
        if [ \`file \$OFILE | grep -c "LLVM IR bitcode"\` -eq 1 ]; then
            mv \$OFILE \$BCFILE
        else
            touch \$BCFILE
        fi
    fi
fi
exec \$CLANG "\$@"
EMIT_EOF
chmod +x "$EMIT_SCRIPT"
echo "  emit-llvm.sh 생성 완료"

# ── 4. 커널 빌드 ──────────────────────────────────────
echo ""
echo "[4/4] 커널 bitcode 컴파일 중... (1~2시간 예상)"

mkdir -p "$BC_DIR"

# .config 복사
if [ ! -f "$BC_DIR/.config" ]; then
    cp "$WORK_DIR/SyzDirect/source/syzdirect/bigconfig" "$BC_DIR/.config"
    # KASAN/KCSAN 비활성화 (SyzDirect 방식)
    echo "CONFIG_KASAN=n" >> "$BC_DIR/.config"
    echo "CONFIG_KCSAN=n" >> "$BC_DIR/.config"
    echo "CONFIG_UBSAN=n" >> "$BC_DIR/.config"
    echo "CONFIG_HAVE_DEBUG_KMEMLEAK=n" >> "$BC_DIR/.config"
    echo "CONFIG_KCOV=y" >> "$BC_DIR/.config"
fi

cd "$KERNEL_DIR"

# 소스 트리 클린업 (이전 in-tree 빌드 잔여물 제거)
echo "  소스 트리 정리 (mrproper)..."
make mrproper 2>&1 | tail -3

# git checkout -- scripts/Makefile.kcov (SyzDirect 방식)
git checkout -- scripts/Makefile.kcov 2>/dev/null || true

# oldconfig (질문이 있으면 yes로 자동 답변)
yes | make CC="$EMIT_SCRIPT" O="$BC_DIR" oldconfig 2>&1 | tail -3

# 빌드
make CC="$EMIT_SCRIPT" O="$BC_DIR" -j$JOBS 2>&1 | tail -10

# 완료 확인
if [ -f "$BC_DIR/arch/x86/boot/bzImage" ]; then
    echo ""
    echo "✅ Step 3 완료 — bzImage 생성됨"
    echo "   bitcode 위치: $BC_DIR (*.llbc 파일들)"
    echo "   다음: bash 04_run_static_analysis.sh"
else
    echo ""
    echo "⚠️  bzImage 없음 — 빌드 실패 가능성 있음"
    echo "   llbc 파일 수: $(find $BC_DIR -name '*.llbc' 2>/dev/null | wc -l)"
fi
