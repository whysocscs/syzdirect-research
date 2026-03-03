#!/bin/bash
# SyzDirect 환경 설치 전 의존성 확인
echo "======================================"
echo " SyzDirect 의존성 체크"
echo "======================================"

check() {
    if command -v "$1" &>/dev/null; then
        echo "  ✅ $1: $(command -v $1) $(${1} --version 2>&1 | head -1)"
    else
        echo "  ❌ $1: 없음"
    fi
}

echo ""
echo "[ 기본 빌드 도구 ]"
check cmake
check ninja
check make
check git
check python3
check pip3

echo ""
echo "[ 컴파일러 ]"
check clang
check clang++
check gcc
check g++

echo ""
echo "[ Go (syzkaller용) ]"
check go

echo ""
echo "[ 기타 ]"
check wget
check curl
check bc
check flex
check bison

echo ""
echo "[ 시스템 자원 ]"
echo "  CPU 코어: $(nproc)"
echo "  메모리:   $(free -h | awk '/^메모리|^Mem/{print $2}')"
echo "  디스크:   $(df -h / | awk 'NR==2{print $4}') 여유"

echo ""
echo "[ Python 패키지 ]"
python3 -c "import networkx; print('  ✅ networkx')" 2>/dev/null || echo "  ❌ networkx"
python3 -c "import openpyxl; print('  ✅ openpyxl')" 2>/dev/null || echo "  ❌ openpyxl"
python3 -c "import paramiko; print('  ✅ paramiko')" 2>/dev/null || echo "  ❌ paramiko"
