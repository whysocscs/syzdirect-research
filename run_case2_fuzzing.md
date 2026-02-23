# Case 2 (NBD) 퍼징 실행 가이드

## 📊 현재 상태 확인

```bash
# Step 1-4 완료 상태
cd /work/syzdirect_workdir/tpa/case_2
cat CompactOutput.json  # sendmsg 1개 매핑됨
ls distance_xidx0/      # 3,692개 distance 파일
cat target_functions_info.txt
```

**target_functions_info.txt 내용:**
```
xidx=0 target_function=nbd_genl_connect
```

---

## 🚀 Step 5: InstrumentDistance (거리 기반 커널 빌드)

### 준비사항
1. ✅ CompactOutput.json (syscall 매핑)
2. ✅ distance_xidx0/ (거리 정보)
3. ⚠️ Config.py 설정 필요

### 실행 방법

#### Option A: Runner 스크립트 사용 (권장)

```bash
# 1. dataset 파일 생성 (case_2만 포함)
cd /work/SyzDirect/source/syzdirect/Runner

# dataset_case2.xlsx가 이미 있는지 확인
ls -lh dataset_case2.xlsx

# 2. Main.py 실행 (Step 5만)
python3 Main.py --step instrument --idx 2
```

#### Option B: 수동 실행

```bash
# 1. 소스 디렉토리 확인
SRC_DIR=/work/syzdirect_workdir/srcs/case_2
DIST_DIR=/work/syzdirect_workdir/tpa/case_2/distance_xidx0
TARGET_FUNC=nbd_genl_connect

# 2. Makefile.kcov 수정
cat > $SRC_DIR/scripts/Makefile.kcov << 'EOF'
# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=/work/syzdirect_workdir/srcs/case_2 -fsanitize-coverage-distance-dir=/work/syzdirect_workdir/tpa/case_2/distance_xidx0 -fsanitize-coverage-target-function=nbd_genl_connect
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := $(kcov-flags-y)
EOF

# 3. 빌드 디렉토리 준비
BUILD_DIR=/work/syzdirect_workdir/instrumented/case_2/temp_build
mkdir -p $BUILD_DIR

# 4. .config 복사 및 수정
cp /work/syzdirect_workdir/bcs/case_2/.config $BUILD_DIR/
echo "CONFIG_UBSAN=n" >> $BUILD_DIR/.config
echo "CONFIG_KCOV=y" >> $BUILD_DIR/.config

# 5. 커널 빌드 (거리 instrumentation 포함)
cd $SRC_DIR
make clean
make mrproper

CLANG=/work/SyzDirect/source/llvm-project-new/build/bin/clang
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR olddefconfig
make ARCH=x86_64 CC=$CLANG O=$BUILD_DIR -j2

# 6. 결과 확인
ls -lh $BUILD_DIR/arch/x86/boot/bzImage
ls -lh $BUILD_DIR/vmlinux

# 7. 결과물 복사
mkdir -p /work/syzdirect_workdir/instrumented/case_2
cp $BUILD_DIR/arch/x86/boot/bzImage /work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0
cp $BUILD_DIR/vmlinux /work/syzdirect_workdir/instrumented/case_2/vmlinux_0
```

**예상 시간:** 30분 ~ 1시간 (커널 풀 빌드)

---

## 🎯 Step 6: Fuzz (실제 퍼징 실행)

### 준비사항

1. ✅ Instrumented kernel (bzImage_xidx0)
2. ✅ CompactOutput.json (syscall 매핑)
3. ⚠️ VM 이미지 필요
4. ⚠️ Syzkaller 빌드 필요

### 사전 준비

#### 1. VM 이미지 생성

```bash
# Debian Bullseye 이미지 생성
cd /work/SyzDirect
sudo ./create_vm.sh

# 결과 확인
ls -lh /work/images/bullseye.img
ls -lh /work/images/bullseye.id_rsa
```

#### 2. Syzkaller 빌드

```bash
cd /work/SyzDirect/source/syzdirect/syzdirect_fuzzer
make -j$(nproc)

# 바이너리 확인
ls -lh bin/syz-manager
ls -lh bin/syz-fuzzer
```

#### 3. Fuzz Input 파일 생성

```bash
# CompactOutput.json을 callfile 형태로 변환
FUZZ_INP_DIR=/work/syzdirect_workdir/fuzz_inp/case_2
mkdir -p $FUZZ_INP_DIR

# callfile 생성 (예시)
cat > $FUZZ_INP_DIR/callfile_xidx0 << 'EOF'
sendmsg
NBD_ATTR_SIZE_BYTES=2
NBD_ATTR_SOCKETS=7
EOF
```

### 실행 방법

#### Option A: Runner 스크립트 사용 (권장)

```bash
cd /work/SyzDirect/source/syzdirect/Runner

# Config.py 확인/수정 필요
# - CleanImageTemplatePath
# - KeyPath
# - FuzzUptime (기본 24시간)

python3 Main.py --step fuzz --idx 2
```

#### Option B: 수동 실행

```bash
# 1. Config 파일 생성
cat > /work/case2_fuzz_config.json << 'EOF'
{
    "target": "linux/amd64",
    "http": "0.0.0.0:56741",
    "workdir": "/work/syzdirect_workdir/fuzz_result/case_2/xidx0/run0",
    "kernel_obj": "/work/syzdirect_workdir/instrumented/case_2",
    "image": "/work/images/bullseye.img",
    "sshkey": "/work/images/bullseye.id_rsa",
    "syzkaller": "/work/SyzDirect/source/syzdirect/syzdirect_fuzzer",
    "procs": 2,
    "type": "qemu",
    "hitindex": 0,
    "vm": {
        "count": 2,
        "kernel": "/work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0",
        "cpu": 2,
        "mem": 2048
    }
}
EOF

# 2. syz-manager 실행
cd /work/SyzDirect/source/syzdirect/syzdirect_fuzzer

bin/syz-manager \
  -config=/work/case2_fuzz_config.json \
  -callfile=/work/syzdirect_workdir/fuzz_inp/case_2/callfile_xidx0 \
  -uptime=3600  # 1시간 실행

# 3. 웹 UI로 진행 상황 모니터링
# 브라우저: http://localhost:56741
```

**퍼징 시간:** 기본 24시간 (테스트용으로 1-2시간도 가능)

---

## 📊 R3 실패 패턴 수집

### 퍼징 로그 확인

```bash
WORKDIR=/work/syzdirect_workdir/fuzz_result/case_2/xidx0/run0

# Manager 로그
tail -f $WORKDIR/manager.log

# Crash 로그
ls $WORKDIR/crashes/

# Coverage 정보
cat $WORKDIR/corpus.db | grep -i coverage

# 타겟 도달 여부 확인
grep -i "nbd_genl_connect" $WORKDIR/*.log
grep -i "target hit" $WORKDIR/*.log
```

### R3 실패 분석 포인트

**예상 R3 실패 시나리오:**

1. **Netlink 소켓 설정 실패**
   - sendmsg는 호출되지만 AF_NETLINK가 아닌 다른 family 사용
   - NETLINK_GENERIC 프로토콜 미설정

2. **NBD family 등록 미발견**
   - Generic netlink에서 NBD family를 찾지 못함
   - nlmsg_type이 잘못됨

3. **속성(attribute) 파싱 실패**
   - NBD_ATTR_SIZE_BYTES, NBD_ATTR_SOCKETS가 누락
   - netlink 메시지 구조가 잘못됨

4. **Permission 문제**
   - CAP_NET_ADMIN 권한 필요할 수 있음
   - /dev/nbd* 디바이스 접근 권한

### 로그에서 확인할 항목

```bash
# 1. Syscall 호출 통계
grep "sendmsg" $WORKDIR/manager.log | wc -l

# 2. 에러 메시지
grep -i "error\|fail\|EINVAL\|EPERM" $WORKDIR/executor.*.log

# 3. 커버리지 증가 여부
# - 타겟 근처까지 도달했는지 확인
# - distance가 줄어드는지 확인
```

---

## 🔧 트러블슈팅

### 문제 1: VM 이미지 없음
```bash
sudo apt-get install -y debootstrap qemu-system-x86
cd /work/SyzDirect
sudo ./create_vm.sh
```

### 문제 2: 빌드 실패
```bash
# 디스크 공간 확인
df -h /work

# 메모리 확인 (최소 8GB 권장)
free -h
```

### 문제 3: QEMU 부팅 실패
```bash
# 커널 이미지 유효성 확인
file /work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0

# QEMU 테스트
qemu-system-x86_64 \
  -kernel /work/syzdirect_workdir/instrumented/case_2/bzImage_xidx0 \
  -append "console=ttyS0" \
  -nographic
```

---

## 📝 체크리스트

**Step 5 (InstrumentDistance) 전:**
- [ ] CompactOutput.json 존재
- [ ] distance_xidx0/ 디렉토리 존재 (3,692개 파일)
- [ ] target_functions_info.txt 존재
- [ ] 소스 코드 정상 (case_2/)
- [ ] LLVM clang 빌드 완료

**Step 6 (Fuzz) 전:**
- [ ] Instrumented bzImage 존재
- [ ] VM 이미지 생성 완료 (/work/images/bullseye.img)
- [ ] SSH 키 존재 (/work/images/bullseye.id_rsa)
- [ ] syzkaller 빌드 완료 (bin/syz-manager)
- [ ] callfile 생성 완료
- [ ] Config 파일 수정 완료

---

## 📚 참고

- **Step 5 소요 시간:** 30분 ~ 1시간
- **Step 6 소요 시간:** 1시간 ~ 24시간 (설정에 따라)
- **디스크 필요량:** 최소 20GB (instrumented kernel + workdir)
- **메모리 필요량:** 최소 8GB (VM 2개 × 2GB + host overhead)

---

## 🎯 최소 테스트 (빠른 검증용)

Step 5-6를 짧게 테스트하려면:

```bash
# Step 5: 이미 완료되어 있다면 skip

# Step 6: 1시간만 퍼징
cd /work/SyzDirect/source/syzdirect/syzdirect_fuzzer
bin/syz-manager \
  -config=/work/case2_fuzz_config.json \
  -callfile=/work/syzdirect_workdir/fuzz_inp/case_2/callfile_xidx0 \
  -uptime=3600  # 1시간

# 로그 확인
tail -100 /work/syzdirect_workdir/fuzz_result/case_2/xidx0/run0/manager.log
```

이렇게 하면 **1-2시간 내에 R3 실패 패턴을 확인**할 수 있습니다!
