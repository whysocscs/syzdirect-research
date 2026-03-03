#!/bin/bash
# Step 1: 필요한 패키지 설치
set -e
echo "======================================"
echo " Step 1: 의존성 패키지 설치"
echo "======================================"

sudo apt-get update -y
sudo apt-get install -y \
    build-essential cmake ninja-build \
    clang lld \
    git wget curl bc \
    flex bison libelf-dev libssl-dev \
    python3 python3-pip \
    libncurses-dev dwarves \
    qemu-system-x86 debootstrap \
    golang-go

pip3 install --break-system-packages networkx openpyxl paramiko

echo ""
echo "✅ 패키지 설치 완료"
