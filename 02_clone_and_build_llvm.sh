#!/bin/bash
# Step 2: SyzDirect 클론 + 커스텀 LLVM 빌드
# ⚠️  약 2~3시간 소요
set -e

WORK_DIR="/work"
JOBS=$(nproc)

echo "======================================"
echo " Step 2: SyzDirect 클론 + LLVM 빌드"
echo " 코어: $JOBS | 작업 디렉토리: $WORK_DIR"
echo "======================================"

# 작업 디렉토리 생성
sudo mkdir -p $WORK_DIR
sudo chown $USER:$USER $WORK_DIR
cd $WORK_DIR

# SyzDirect 클론
echo ""
echo "[1/3] SyzDirect 클론 중..."
if [ ! -d "$WORK_DIR/SyzDirect" ]; then
    git clone https://github.com/seclab-fudan/SyzDirect.git
else
    echo "  이미 존재함, 스킵"
fi

cd $WORK_DIR/SyzDirect/source

# LLVM 빌드
echo ""
echo "[2/3] 커스텀 LLVM 빌드 중... (2~3시간 예상)"
if [ ! -f "$WORK_DIR/SyzDirect/source/llvm-project-new/build/bin/clang" ]; then
    cd llvm-project-new
    mkdir -p build && cd build
    cmake -G Ninja \
        -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_ENABLE_ASSERTIONS=ON \
        ../llvm
    ninja -j$JOBS
    cd $WORK_DIR/SyzDirect/source
else
    echo "  LLVM 이미 빌드됨, 스킵"
fi

# SyzDirect 분석 도구 빌드
echo ""
echo "[3/3] SyzDirect 분석 도구 빌드 중..."
LLVM_DIR="$WORK_DIR/SyzDirect/source/llvm-project-new/build"
CLANG="$LLVM_DIR/bin/clang"
CLANGPP="$LLVM_DIR/bin/clang++"

# syzdirect_function_model
cd $WORK_DIR/SyzDirect/source/syzdirect/syzdirect_function_model/src
rm -rf build && mkdir -p build && cd build
cmake -G Ninja \
    -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANGPP" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_CXX_FLAGS="-fno-rtti" \
    ..
ninja -j$JOBS
echo "  ✅ syzdirect_function_model 빌드 완료"

# syzdirect_kernel_analysis
cd $WORK_DIR/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/src
rm -rf build && mkdir -p build && cd build
cmake -G Ninja \
    -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" \
    -DCMAKE_C_COMPILER="$CLANG" \
    -DCMAKE_CXX_COMPILER="$CLANGPP" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_CXX_FLAGS="-fno-rtti" \
    ..
ninja -j$JOBS
echo "  ✅ syzdirect_kernel_analysis 빌드 완료"

echo ""
echo "✅ Step 2 완료"
echo "   다음: bash 03_build_kernel.sh"
