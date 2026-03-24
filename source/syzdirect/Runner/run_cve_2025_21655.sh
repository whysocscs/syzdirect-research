#!/bin/bash
set -e
cd /home/ai/work/SyzDirect/source/syzdirect/Runner

python3 -c "
from pipeline_new_cve import NewCVEPipeline
import argparse

args = argparse.Namespace(
    cve='CVE-2025-21655',
    commit='c9a40292a44e78f71258b8522655bffaf5753bdb',
    function='io_eventfd_do_signal',
    file='io_uring/eventfd.c',
    config='/home/ai/work/SyzDirect/source/syzdirect/bigconfig',
    workdir='fresh_runs/cve_2025_21655',
    mode='new', hunt_mode='hybrid',
    j=32, uptime=12, fuzz_rounds=1,
    from_stage='bitcode', boot_profile='default',
    agent_rounds=0, agent_window=300, agent_uptime=None,
    stall_timeout=1800, syscalls=None, linux_template=None,
)
p = NewCVEPipeline(args)
p.step2_compile_bitcode()   # bitcode with second flag
p.step3_analyze_kernel()    # interface analysis
p.step4_analyze_target_point()  # target analyzer + dist files
p.step5_instrument_distance()   # kernel with real distances
"

echo ""
echo "========================================="
echo "Pipeline complete! Now start the fuzzer:"
echo "========================================="
echo ""
echo "mkdir -p fresh_runs/cve_2025_21655/fuzzres/case_0/xidx_0/run0"
echo ""
echo "cat > fresh_runs/cve_2025_21655/fuzzres/case_0/xidx_0/config0 << 'EOF'"
echo '{'
echo '    "target": "linux/amd64",'
echo '    "sshkey": "/home/ai/syzdirect-runtime/cve/cve_cve_2025_68205/image-work/bullseye.id_rsa",'
echo '    "procs": 8,'
echo '    "type": "qemu",'
echo '    "vm": {"count": 1, "cpu": 2, "mem": 4096,'
echo '        "kernel": "/home/ai/work/SyzDirect/source/syzdirect/Runner/fresh_runs/cve_2025_21655/kwithdist/case_0/bzImage_0"},'
echo '    "reproduce": false,'
echo '    "image": "/home/ai/syzdirect-runtime/cve/cve_cve_2025_68205/image-work/bullseye.img",'
echo '    "workdir": "/home/ai/work/SyzDirect/source/syzdirect/Runner/fresh_runs/cve_2025_21655/fuzzres/case_0/xidx_0/run0",'
echo '    "http": "0.0.0.0:33069",'
echo '    "syzkaller": "/home/ai/work/SyzDirect/source/syzdirect/syzdirect_fuzzer",'
echo '    "hitindex": 0'
echo '}'
echo "EOF"
echo ""
echo "./syzdirect_fuzzer/bin/syz-manager \\"
echo "  -config=fresh_runs/cve_2025_21655/fuzzres/case_0/xidx_0/config0 \\"
echo "  -callfile=fresh_runs/cve_2025_21655/fuzzinps/case_0/inp_0.json \\"
echo "  -uptime=12"
