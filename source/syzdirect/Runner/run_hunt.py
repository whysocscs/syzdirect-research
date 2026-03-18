#!/usr/bin/env python3
"""
General-purpose SyzDirect CVE hunt runner.

Usage:
  # Dataset mode — run original SyzDirect pipeline from dataset.xlsx:
  python3 run_hunt.py dataset -dataset dataset.xlsx -j 8 \\
      prepare_for_manual_instrument compile_kernel_bitcode \\
      analyze_kernel_syscall extract_syscall_entry \\
      instrument_kernel_with_distance fuzz

  # New CVE — CVE number only (auto-resolves commit/function/file):
  python3 run_hunt.py new --cve CVE-2025-XXXXX

  # New CVE — with manual overrides:
  python3 run_hunt.py new --cve CVE-2025-XXXXX --commit abc123 \\
      --function vuln_func --file net/core/sock.c -j 8

  # Pre-built targets — fuzz only:
  python3 run_hunt.py fuzz [--targets 0 3 5]
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys


# ──────────────────────────────────────────────────────────────────────────
# Paths (derived from project layout)
# ──────────────────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_ROOT = os.path.dirname(SCRIPT_DIR)

LLVM_ROOT = os.path.join(RESOURCE_ROOT, "..", "llvm-project-new")
LLVM_BUILD = os.path.join(LLVM_ROOT, "build")
CLANG_PATH = os.path.join(LLVM_BUILD, "bin", "clang")
FUZZER_DIR = os.path.join(RESOURCE_ROOT, "syzdirect_fuzzer")
FUZZER_BIN = os.path.join(FUZZER_DIR, "bin")
INTERFACE_GENERATOR = os.path.join(RESOURCE_ROOT, "syzdirect_function_model", "build", "lib", "interface_generator")
TARGET_ANALYZER = os.path.join(RESOURCE_ROOT, "syzdirect_kernel_analysis", "build", "lib", "target_analyzer")
FUNCTION_MODEL_DIR = os.path.join(RESOURCE_ROOT, "syzdirect_function_model")
KERNEL_ANALYSIS_DIR = os.path.join(RESOURCE_ROOT, "syzdirect_kernel_analysis")

KCOV_PATCH = os.path.join(RESOURCE_ROOT, "kcov.diff")
BIGCONFIG = os.path.join(RESOURCE_ROOT, "bigconfig")
TEMPLATE_CONFIG = os.path.join(RESOURCE_ROOT, "template_config")

RUNTIME_BASE = os.environ.get("SYZDIRECT_RUNTIME", "/home/ai/syzdirect-runtime/cve")
VM_IMAGE = os.environ.get(
    "SYZDIRECT_VM_IMAGE",
    os.path.join(RUNTIME_BASE, "cve_cve_2025_68205/image-work/bullseye.img"),
)
SSH_KEY = os.environ.get(
    "SYZDIRECT_SSH_KEY",
    os.path.join(RUNTIME_BASE, "cve_cve_2025_68205/image-work/bullseye.id_rsa"),
)

# Syscall names MUST match syzkaller sys/linux/gen/amd64.go
PREBUILT_TARGETS = [
    {"idx": 0, "name": "teql_uaf",       "function": "teql_destroy",
     "func_path": "net/sched/sch_teql.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 1, "name": "cec_adap",       "function": "__cec_s_phys_addr",
     "func_path": "drivers/media/cec/core/cec-adap.c",
     "syscalls": [{"Target": "ioctl",
                   "Relate": ["openat", "close", "read", "write"]}]},
    {"idx": 2, "name": "hfsc_netem",     "function": "hfsc_change_class",
     "func_path": "net/sched/sch_hfsc.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 3, "name": "packet_fanout",  "function": "fanout_add",
     "func_path": "net/packet/af_packet.c",
     "syscalls": [{"Target": "setsockopt$packet_fanout",
                   "Relate": ["socket$packet", "bind", "close", "unshare"]}]},
    {"idx": 4, "name": "vsock_race",     "function": "virtio_transport_close",
     "func_path": "net/vmw_vsock/virtio_transport_common.c",
     "syscalls": [{"Target": "connect$vsock_stream",
                   "Relate": ["socket$vsock_stream", "bind", "listen",
                              "shutdown", "close", "accept4"]}]},
    {"idx": 5, "name": "bpf_verifier",   "function": "do_check",
     "func_path": "kernel/bpf/verifier.c",
     "syscalls": [{"Target": "bpf$PROG_LOAD",
                   "Relate": ["bpf", "close"]}]},
]


# ──────────────────────────────────────────────────────────────────────────
# WorkdirLayout — single source of truth for all workdir paths
# ──────────────────────────────────────────────────────────────────────────

class WorkdirLayout:
    """All path conventions for a SyzDirect workdir, in one place."""

    def __init__(self, root):
        self.root = os.path.abspath(root)

    # per-case directories
    def src(self, ci):          return os.path.join(self.root, "srcs", f"case_{ci}")
    def bc(self, ci):           return os.path.join(self.root, "bcs", f"case_{ci}")
    def interface(self, ci):    return os.path.join(self.root, "interfaces", f"case_{ci}")
    def tpa(self, ci):          return os.path.join(self.root, "tpa", f"case_{ci}")
    def kwithdist(self, ci):    return os.path.join(self.root, "kwithdist", f"case_{ci}")
    def fuzzinps(self, ci):     return os.path.join(self.root, "fuzzinps", f"case_{ci}")
    def fuzzres(self, ci):      return os.path.join(self.root, "fuzzres", f"case_{ci}")
    def consts(self, ci):       return os.path.join(self.root, "consts", f"case_{ci}")

    # per-case files
    def bzimage(self, ci, xi=0):    return os.path.join(self.kwithdist(ci), f"bzImage_{xi}")
    def vmlinux(self, ci, xi=0):    return os.path.join(self.kwithdist(ci), f"vmlinux_{xi}")
    def tfinfo(self, ci):           return os.path.join(self.tpa(ci), "target_functions_info.txt")
    def compact(self, ci):          return os.path.join(self.tpa(ci), "CompactOutput.json")
    def dist_dir(self, ci, xi=0):   return os.path.join(self.tpa(ci), f"distance_xidx{xi}")
    def callfile(self, ci, xi=0):   return os.path.join(self.fuzzinps(ci), f"inp_{xi}.json")
    def multi_pts(self, ci):        return os.path.join(self.root, "multi-pts", f"case_{ci}.txt")
    def k2s(self, ci):              return os.path.join(self.interface(ci), "kernelCode2syscall.json")
    def kernel_sig(self, ci):       return os.path.join(self.interface(ci), "kernel_signature_full")
    def fuzzres_xidx(self, ci, xi=0):  return os.path.join(self.fuzzres(ci), f"xidx_{xi}")
    def const_xidx(self, ci, xi=0):    return os.path.join(self.consts(ci), f"xidx_{xi}.json")
    def custom_syz(self, ci, xi=0):    return os.path.join(self.fuzzres_xidx(ci, xi), "syzkaller")
    def dup_report(self, ci):       return os.path.join(self.tpa(ci), "duplicate_points.txt")

    # global files
    def syz_sig(self):      return os.path.join(self.root, "syzkaller_signature.txt")
    def tr_map(self):        return os.path.join(self.root, "target2relate2.json")
    def emit_script(self):   return os.path.join(self.root, "emit-llvm.sh")

    def apply_to_config(self, Config):
        """Bind all path lambdas onto the Config module."""
        w = self
        Config.WorkdirPrefix = self.root
        Config.getSrcDirByCase                          = w.src
        Config.getBitcodeDirByCase                      = w.bc
        Config.getInterfaceDirByCase                    = w.interface
        Config.getTargetPointAnalysisResultDirByCase    = w.tpa
        Config.getTargetPointAnalysisMidResult          = w.compact
        Config.getTargetPointAnalysisDuplicateReport    = w.dup_report
        Config.getTargetFunctionInfoFile                = w.tfinfo
        Config.getDistanceResultDir                     = w.dist_dir
        Config.getMultiPointsSpecificFile               = w.multi_pts
        Config.getConstOutDirPathByCase                 = w.consts
        Config.getConstOutFilePathByCaseAndXidx         = w.const_xidx
        Config.getFuzzInpDirPathByCase                  = w.fuzzinps
        Config.getFuzzInpDirPathByCaseAndXidx           = w.callfile
        Config.getFuzzResultDirByCase                   = w.fuzzres
        Config.getFuzzResultDirByCaseAndXidx            = w.fuzzres_xidx
        Config.getCustomizedSyzByCaseAndXidx            = w.custom_syz
        Config.getInstrumentedKernelDirByCase           = w.kwithdist
        Config.getInstrumentedKernelImageByCaseAndXidx  = w.bzimage
        Config.getKernelSignatureByCase                 = w.kernel_sig
        Config.getFinalInterfaceParingResultByCase      = w.k2s
        Config.SrcDirRoot                               = os.path.join(self.root, "srcs")


# ──────────────────────────────────────────────────────────────────────────
# Shared utilities
# ──────────────────────────────────────────────────────────────────────────

def Q(path):
    return shlex.quote(str(path))


def sh(cmd, check=True, capture=False, big=False):
    """Run a shell command.  big=True for long-running builds (no capture)."""
    tag = "[BIG] " if big else ""
    print(f"  {tag}$ {cmd}")
    if capture:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and r.returncode != 0:
            print(f"  STDERR: {r.stderr[:500]}")
            raise RuntimeError(f"Command failed: {cmd}")
        return r.stdout.strip()
    subprocess.run(cmd, shell=True, check=check)


def write_makefile_kcov(src_dir, dist_dir, target_func):
    """Write scripts/Makefile.kcov for distance-guided instrumentation."""
    path = os.path.join(src_dir, "scripts", "Makefile.kcov")
    with open(path, "w") as f:
        f.write(
            "# SPDX-License-Identifier: GPL-2.0-only\n"
            f"kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += "
            f"-fsanitize-coverage=trace-pc,second "
            f"-fsanitize-coverage-kernel-src-dir={src_dir} "
            f"-fsanitize-coverage-distance-dir={dist_dir} "
            f"-fsanitize-coverage-target-function={target_func}\n"
            "kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)\t+= -fsanitize-coverage=trace-cmp\n"
            "kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)\t\t+= "
            "-fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so\n"
            "\nexport CFLAGS_KCOV := $(kcov-flags-y)\n"
        )


def append_build_config(config_path):
    """Disable sanitizers/debug-info and enable KCOV in a kernel .config."""
    disabled = [
        "CONFIG_KASAN", "CONFIG_KCSAN", "CONFIG_UBSAN",
        "CONFIG_HAVE_DEBUG_KMEMLEAK", "CONFIG_DEBUG_INFO",
        "CONFIG_DEBUG_INFO_REDUCED", "CONFIG_DEBUG_INFO_COMPRESSED",
        "CONFIG_DEBUG_INFO_SPLIT", "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT",
        "CONFIG_DEBUG_INFO_DWARF4", "CONFIG_DEBUG_INFO_DWARF5",
        "CONFIG_GDB_SCRIPTS",
    ]
    with open(config_path, "a") as f:
        for c in disabled:
            f.write(f"{c}=n\n")
        f.write("\nCONFIG_DEBUG_INFO_NONE=y\nCONFIG_KCOV=y\n")


# ──────────────────────────────────────────────────────────────────────────
# Build compatibility fixes (ported from Compilation.py)
# ──────────────────────────────────────────────────────────────────────────

def _get_clang_version():
    """Return (major, minor, patch) tuple of the configured clang, or None."""
    try:
        proc = subprocess.run([CLANG_PATH, "--version"],
                              check=False, capture_output=True, text=True)
    except OSError:
        return None
    m = re.search(r"clang version (\d+)\.(\d+)\.(\d+)", proc.stdout)
    return tuple(int(x) for x in m.groups()) if m else None


def _patch_file(path, replacements, label=""):
    """Apply text replacements to a file. Returns True if changed."""
    if not os.path.exists(path):
        return False
    with open(path) as f:
        txt = f.read()
    updated = txt
    for old, new in replacements.items():
        updated = updated.replace(old, new)
    if updated != txt:
        with open(path, "w") as f:
            f.write(updated)
        if label:
            print(f"  [compat] {label}: {path}")
        return True
    return False


def relax_kernel_build(src_dir):
    """Apply all clang/kernel build compatibility relaxations to a source tree."""
    ver = _get_clang_version()
    if ver is None or ver >= (15, 0, 0):
        return

    # 1) min-tool-version.sh: lower required clang from 15 to 13
    _patch_file(
        os.path.join(src_dir, "scripts", "min-tool-version.sh"),
        {"echo 15.0.0": "echo 13.0.0"},
        "Relaxed min clang version",
    )

    # 2) arch/x86/Makefile: wrap clang-only flags in cc-option
    _patch_file(
        os.path.join(src_dir, "arch", "x86", "Makefile"),
        {
            "KBUILD_CFLAGS += -mno-fp-ret-in-387":
                "KBUILD_CFLAGS += $(call cc-option,-mno-fp-ret-in-387)",
            "KBUILD_CFLAGS += -mskip-rax-setup":
                "KBUILD_CFLAGS += $(call cc-option,-mskip-rax-setup)",
            "KBUILD_CFLAGS += -mstack-protector-guard-reg=$(percpu_seg)":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-reg=$(percpu_seg))",
            "KBUILD_CFLAGS += -mstack-protector-guard-symbol=__ref_stack_chk_guard":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-symbol=__ref_stack_chk_guard)",
            "KBUILD_CFLAGS += -mstack-protector-guard=global":
                "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard=global)",
        },
        "Relaxed x86 clang flags",
    )

    # 3) scripts/Makefile.warn: wrap clang warning flags
    _patch_file(
        os.path.join(src_dir, "scripts", "Makefile.warn"),
        {
            "KBUILD_CFLAGS += -Wno-pointer-to-enum-cast":
                "KBUILD_CFLAGS += $(call cc-disable-warning,pointer-to-enum-cast)",
            "KBUILD_CFLAGS += -Wno-tautological-constant-out-of-range-compare":
                "KBUILD_CFLAGS += $(call cc-disable-warning,tautological-constant-out-of-range-compare)",
            "KBUILD_CFLAGS += -Wno-unaligned-access":
                "KBUILD_CFLAGS += $(call cc-disable-warning,unaligned-access)",
            "KBUILD_CFLAGS += -Wno-enum-compare-conditional":
                "KBUILD_CFLAGS += $(call cc-disable-warning,enum-compare-conditional)",
        },
        "Relaxed warning flags",
    )


def ensure_kcov_support(src_dir):
    """Patch kcov.h and kcov.c for SyzDirect distance-tracking support."""
    header_path = os.path.join(src_dir, "include", "linux", "kcov.h")
    source_path = os.path.join(src_dir, "kernel", "kcov.c")

    if os.path.exists(header_path):
        with open(header_path) as f:
            txt = f.read()
        updated = txt
        if "void notrace kcov_mark_block(u32 i);" not in updated:
            updated = updated.replace(
                "void kcov_remote_stop(void);\n",
                "void kcov_remote_stop(void);\nvoid notrace kcov_mark_block(u32 i);\n")
        if "static inline void kcov_mark_block(u32 i) {}" not in updated:
            updated = updated.replace(
                "static inline void kcov_remote_stop_softirq(void) {}\n",
                "static inline void kcov_remote_stop_softirq(void) {}\n"
                "static inline void kcov_mark_block(u32 i) {}\n")
        if updated != txt:
            with open(header_path, "w") as f:
                f.write(updated)
            print(f"  [kcov] Patched {header_path}")

    if os.path.exists(source_path):
        with open(source_path) as f:
            txt = f.read()
        updated = txt

        if "#define DISTBLOCKSIZE 300" not in updated:
            updated = updated.replace(
                "#define KCOV_WORDS_PER_CMP 4\n",
                "#define KCOV_WORDS_PER_CMP 4\n\n#define DISTBLOCKSIZE 300\n")

        if "void notrace kcov_mark_block(u32 i)" not in updated:
            updated, count = re.subn(
                r"void notrace __sanitizer_cov_trace_pc\(void\)\n\{.*?\n\}\nEXPORT_SYMBOL\(__sanitizer_cov_trace_pc\);\n",
                """void notrace __sanitizer_cov_trace_pc(void)
{
\tstruct task_struct *t;
\tunsigned long *area;
\tu32 *dt_area;
\tunsigned long ip = canonicalize_ip(_RET_IP_);
\tunsigned long pos;

\tt = current;
\tif (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
\t\treturn;

\tdt_area = (u32 *)t->kcov_area;
\tarea = (unsigned long *)(dt_area + DISTBLOCKSIZE);
\t/* The first 64-bit word is the number of subsequent PCs. */
\tpos = READ_ONCE(area[0]) + 1;
\tif (likely(pos < t->kcov_size - DISTBLOCKSIZE / 2)) {
\t\tWRITE_ONCE(area[0], pos);
\t\tbarrier();
\t\tarea[pos] = ip;
\t}
}
EXPORT_SYMBOL(__sanitizer_cov_trace_pc);

void notrace kcov_mark_block(u32 i)
{
\tstruct task_struct *t;
\tu32 *dt_area;

\tt = current;
\tif (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
\t\treturn;

\tif (unlikely(i + 1 >= DISTBLOCKSIZE))
\t\treturn;

\tdt_area = (u32 *)t->kcov_area;
\tif (i < READ_ONCE(dt_area[0]))
\t\tWRITE_ONCE(dt_area[0], i);
\tWRITE_ONCE(dt_area[i + 1], READ_ONCE(dt_area[i + 1]) + 1);
}
EXPORT_SYMBOL(kcov_mark_block);
""",
                updated, count=1, flags=re.S)

        # kcov size checks
        updated = updated.replace(
            "if (size < 2 || size > INT_MAX / sizeof(unsigned long))",
            "if (size < DISTBLOCKSIZE / 2 + 2 || size > INT_MAX / sizeof(unsigned long))")

        updated = updated.replace(
            "\t\tif ((unsigned long)remote_arg->area_size >\n"
            "\t\t    LONG_MAX / sizeof(unsigned long))\n"
            "\t\t\treturn -EINVAL;\n",
            "\t\tif ((unsigned long)remote_arg->area_size >\n"
            "\t\t    LONG_MAX / sizeof(unsigned long) ||\n"
            "\t\t    remote_arg->area_size < DISTBLOCKSIZE / 2)\n"
            "\t\t\treturn -EINVAL;\n")

        # kcov reset area
        updated = updated.replace(
            "\t/* Reset coverage size. */\n\t*(u64 *)area = 0;\n",
            "\t/* Reset coverage size. */\n"
            "\tif (mode == KCOV_MODE_TRACE_PC) {\n"
            "\t\tu32 *dt_area = area;\n\n"
            "\t\tdt_area[0] = 0xffffffff;\n"
            "\t\tfor (int i = 1; i < DISTBLOCKSIZE + 2; i++)\n"
            "\t\t\tdt_area[i] = 0;\n"
            "\t} else {\n"
            "\t\t*(u64 *)area = 0;\n"
            "\t}\n")

        # kcov merge entries
        if "u32 *dst_dt_entries, *src_dt_entries;" not in updated:
            updated = updated.replace(
                "\tvoid *dst_entries, *src_entries;\n",
                "\tvoid *dst_entries, *src_entries;\n"
                "\tu32 *dst_dt_entries, *src_dt_entries;\n")

        updated = updated.replace(
            "\tcase KCOV_MODE_TRACE_PC:\n"
            "\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n"
            "\t\tsrc_len = *(unsigned long *)src_area;\n"
            "\t\tcount_size = sizeof(unsigned long);\n"
            "\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n"
            "\t\tbreak;\n",
            "\tcase KCOV_MODE_TRACE_PC:\n"
            "\t\tdst_dt_entries = dst_area;\n"
            "\t\tsrc_dt_entries = src_area;\n"
            "\t\tdst_area_size -= DISTBLOCKSIZE / 2;\n"
            "\t\tdst_area = dst_dt_entries + DISTBLOCKSIZE;\n"
            "\t\tsrc_area = src_dt_entries + DISTBLOCKSIZE;\n"
            "\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n"
            "\t\tsrc_len = *(unsigned long *)src_area;\n"
            "\t\tcount_size = sizeof(unsigned long);\n"
            "\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n"
            "\t\tbreak;\n")

        if "dst_dt_entries[0] =" not in updated:
            updated = updated.replace(
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
                "\tif (mode == KCOV_MODE_TRACE_PC) {\n"
                "\t\tif (src_dt_entries[0] < dst_dt_entries[0])\n"
                "\t\t\tdst_dt_entries[0] = src_dt_entries[0];\n"
                "\t\tfor (int i = 1; i < DISTBLOCKSIZE; i++)\n"
                "\t\t\tWRITE_ONCE(dst_dt_entries[i], "
                "READ_ONCE(dst_dt_entries[i]) + READ_ONCE(src_dt_entries[i]));\n"
                "\t}\n\t\n"
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n")

        if updated != txt:
            with open(source_path, "w") as f:
                f.write(updated)
            print(f"  [kcov] Patched {source_path}")


# ──────────────────────────────────────────────────────────────────────────
# Configure runner (shared)
# ──────────────────────────────────────────────────────────────────────────

def configure_runner(layout, cpus, uptime, fuzz_rounds):
    """Set all Config module globals needed by the pipeline and Fuzz.MultirunFuzzer."""
    import Config
    layout.apply_to_config(Config)
    Config.CPUNum = cpus
    Config.FuzzRounds = fuzz_rounds
    Config.FuzzUptime = uptime
    Config.FuzzerDir = FUZZER_DIR
    Config.FuzzerBinDir = FUZZER_BIN
    Config.SyzManagerPath = os.path.join(FUZZER_BIN, "syz-manager")
    Config.SyzTRMapPath = os.path.join(FUZZER_BIN, "direct")
    Config.SyzFeaturePath = os.path.join(FUZZER_BIN, "syz-features")
    Config.TRMapPath = layout.tr_map()
    Config.SyzkallerSignaturePath = layout.syz_sig()
    Config.EmitScriptPath = layout.emit_script()
    Config.TemplateConfigPath = TEMPLATE_CONFIG
    Config.CleanImageTemplatePath = VM_IMAGE
    Config.KeyPath = SSH_KEY
    Config.ClangPath = CLANG_PATH
    Config.LLVMRootDir = LLVM_ROOT
    Config.LLVMBuildDir = LLVM_BUILD
    Config.KcovPatchPath = KCOV_PATCH
    Config.BigConfigPath = BIGCONFIG
    Config.FunctionModelDirRoot = FUNCTION_MODEL_DIR
    Config.FunctionModelBinary = INTERFACE_GENERATOR
    Config.TargetPointAnalysisDirRoot = KERNEL_ANALYSIS_DIR
    Config.TargetPointAnalysisBinary = TARGET_ANALYZER
    Config.Q = Q
    return Config


# ──────────────────────────────────────────────────────────────────────────
# Syscall helpers
# ──────────────────────────────────────────────────────────────────────────

def guess_syscalls(file_path):
    """Heuristic syscall mapping based on kernel source file path.
    Names match syzkaller sys/linux/gen/amd64.go."""
    p = file_path.lower()
    patterns = [
        ("net/sched",     {"Target": "sendmsg$nl_route_sched",
                           "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}),
        ("net/packet",    {"Target": "setsockopt$packet_fanout",
                           "Relate": ["socket$packet", "bind", "close"]}),
        ("net/vmw_vsock", {"Target": "connect$vsock_stream",
                           "Relate": ["socket$vsock_stream", "bind", "listen", "shutdown", "close"]}),
        ("net/",          {"Target": "sendmsg",
                           "Relate": ["socket", "bind", "connect", "close"]}),
        ("drivers/media", {"Target": "ioctl",
                           "Relate": ["openat", "close", "read", "write"]}),
        ("kernel/bpf",    {"Target": "bpf$PROG_LOAD",
                           "Relate": ["bpf", "close"]}),
        ("fs/",           {"Target": "openat",
                           "Relate": ["read", "write", "close", "ioctl"]}),
    ]
    for prefix, entry in patterns:
        if prefix in p:
            return [entry]
    return [{"Target": "ioctl", "Relate": ["openat", "close", "read", "write", "mmap"]}]


def llm_analyze_cve(cve_id, kernel_commit, target_function, file_path):
    """Ask Claude for syzkaller syscall suggestions. Returns dict or None."""
    prompt = (
        "You are a Linux kernel security researcher.\n"
        f"CVE: {cve_id}\nKernel commit: {kernel_commit}\n"
        f"Target function: {target_function}\nFile: {file_path}\n\n"
        "Suggest the most relevant syzkaller syscalls to reach this function.\n"
        "Return ONLY valid JSON:\n"
        '{"syscalls": [{"Target": "name$variant", "Relate": ["setup1", "setup2"]}]}\n'
        "Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, "
        "bpf$PROG_LOAD, connect$vsock_stream). 1-3 Target entries, 3-6 Relate each."
    )
    try:
        r = subprocess.run(
            ["claude", "--print", "--model", "haiku", prompt],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            print(f"  [LLM] claude failed: {r.stderr[:200]}")
            return None
        text = r.stdout.strip()
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [LLM] Error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# emit-llvm.sh generator
# ──────────────────────────────────────────────────────────────────────────

def write_emit_script(path):
    with open(path, "w") as f:
        f.write(f"""#!/bin/sh
CLANG={CLANG_PATH}
[ ! -e $CLANG ] && exit
OFILE=`echo $* | sed -e 's/^.* \\(.*\\.o\\) .*$/\\1/'`
if [ "x$OFILE" != x -a "$OFILE" != "$*" ] ; then
    $CLANG -emit-llvm -g "$@" >/dev/null 2>&1
    if [ -f "$OFILE" ] ; then
        BCFILE=`echo $OFILE | sed -e 's/o$/llbc/'`
        [ `file $OFILE | grep -c "LLVM IR bitcode"` -eq 1 ] && mv $OFILE $BCFILE || touch $BCFILE
    fi
fi
exec $CLANG "$@"
""")
    os.chmod(path, 0o775)


# ──────────────────────────────────────────────────────────────────────────
# Dataset mode — run original SyzDirect pipeline from dataset.xlsx
# ──────────────────────────────────────────────────────────────────────────

class DatasetPipeline:
    """Run the original SyzDirect pipeline on all datapoints in a dataset.xlsx file."""

    ACTIONS = {
        "prepare_for_manual_instrument":     "step1_prepare_source",
        "compile_kernel_bitcode":            "step2_compile_bitcode",
        "analyze_kernel_syscall":            "step3_analyze_kernel",
        "extract_syscall_entry":             "step4_analyze_target_point",
        "instrument_kernel_with_distance":   "step5_instrument_distance",
        "fuzz":                              "step6_fuzz",
    }

    def __init__(self, args):
        self.dataset_file = args.dataset
        self.linux_template = args.linux_template
        self.cpus = args.j
        self.uptime = args.uptime
        self.fuzz_rounds = args.fuzz_rounds
        self.layout = WorkdirLayout(args.workdir)
        self.actions = args.actions

        # load dataset
        import pandas as pd
        assert os.path.exists(self.dataset_file), f"Dataset not found: {self.dataset_file}"
        df = pd.read_excel(self.dataset_file)
        self.datapoints = [dict(zip(df.columns, row)) for row in df.values]
        print(f"Loaded {len(self.datapoints)} datapoints from {self.dataset_file}")

        # normalize datapoints
        for dp in self.datapoints:
            if pd.isna(dp.get('config path', float('nan'))):
                dp['config path'] = BIGCONFIG
            if pd.isna(dp.get('recommend syscall', float('nan'))):
                dp['recommend syscall'] = []
            else:
                dp['recommend syscall'] = str(dp['recommend syscall']).split(',')
            assert os.path.exists(dp['config path']), \
                f"Config path not found for case {dp['idx']}: {dp['config path']}"

        # validate linux template
        if self.linux_template and os.path.exists(self.linux_template):
            r = subprocess.run(f"cd {Q(self.linux_template)} && git remote -v",
                               shell=True, capture_output=True, text=True)
            if "linux.git" not in r.stdout:
                print(f"  WARNING: {self.linux_template} does not seem to be a linux repo")
        else:
            self.linux_template = None

    def run(self):
        Config = configure_runner(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Config.datapoints = self.datapoints
        Config.LinuxSrcTemplate = self.linux_template

        # ensure directories
        os.makedirs(self.layout.root, exist_ok=True)
        os.makedirs(os.path.join(self.layout.root, "srcs"), exist_ok=True)

        print(f"\n{'='*60}")
        print(f"SyzDirect Dataset Pipeline")
        print(f"  {len(self.datapoints)} cases, actions: {self.actions}")
        print(f"  workdir={self.layout.root}")
        print(f"{'='*60}\n")

        self._build_tools()

        for action in self.actions:
            if action not in self.ACTIONS:
                sys.exit(f"ERROR: Unknown action '{action}'. Choose from: {list(self.ACTIONS.keys())}")
            print(f"\n{'─'*40}")
            print(f"ACTION: {action}")
            print(f"{'─'*40}")
            getattr(self, self.ACTIONS[action])()

    def _build_tools(self):
        """Build LLVM, interface_generator, kernel_analysis, and fuzzer if needed."""
        # LLVM
        if not os.path.exists(CLANG_PATH):
            print("[build] Building customized LLVM...")
            sh(f"cd {Q(LLVM_ROOT)} && "
               f"cmake -S llvm -B build -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release && "
               f"cmake --build build -j {self.cpus}", big=True)
        assert os.path.exists(CLANG_PATH), "Failed to build customized LLVM (clang)"

        # interface_generator
        print("[build] Building interface_generator...")
        sh(f"cd {Q(FUNCTION_MODEL_DIR)} && make clean && make LLVM_BUILD={Q(LLVM_BUILD)}", big=True)
        assert os.path.exists(INTERFACE_GENERATOR), "Failed to build interface_generator"

        # kernel_analysis
        print("[build] Building target_analyzer...")
        sh(f"cd {Q(KERNEL_ANALYSIS_DIR)} && make clean && make LLVM_BUILD={Q(LLVM_BUILD)}", big=True)
        assert os.path.exists(TARGET_ANALYZER), "Failed to build target_analyzer"

        # fuzzer
        print("[build] Building fuzzer...")
        sh(f"cd {Q(FUZZER_DIR)} && make", big=True)
        assert os.path.exists(FUZZER_BIN), "Failed to build fuzzer"

    # ── stages ───────────────────────────────────────────────────────────

    def step1_prepare_source(self):
        print("\n[1/6] PREPARE_SRC")
        for dp in self.datapoints:
            ci = dp['idx']
            commit = dp['kernel commit']
            src = self.layout.src(ci)

            if os.path.exists(src) and not os.path.exists(os.path.join(src, ".git")):
                shutil.rmtree(src, ignore_errors=True)

            if not os.path.exists(src):
                if self.linux_template:
                    template_git = os.path.join(self.linux_template, ".git")
                    if os.path.exists(template_git):
                        sh(f"git clone --local --no-checkout {Q(self.linux_template)} {Q(src)}")
                        if not os.path.exists(src):
                            shutil.copytree(self.linux_template, src)
                    else:
                        shutil.copytree(self.linux_template, src)
                else:
                    src_root = os.path.join(self.layout.root, "srcs")
                    sh(f"cd {Q(src_root)} && git clone https://github.com/torvalds/linux.git case_{ci}")

            assert os.path.exists(src), f"[case {ci}] Source dir not created"
            sh(f"cd {Q(src)} && git checkout -f {commit}")

            # build compatibility fixes
            relax_kernel_build(src)

            # kcov patch
            result = sh(f"cd {Q(src)} && git apply {Q(KCOV_PATCH)} 2>&1",
                        check=False, capture=True)
            if "patch failed" in (result or ""):
                print(f"  [case {ci}] WARNING: kcov patch failed, applying fallback")
            ensure_kcov_support(src)

            print(f"  [case {ci}] Source prepared (commit {commit})")

    def step2_compile_bitcode(self):
        print("\n[2/6] COMPILE_BITCODE")
        emit = self.layout.emit_script()
        write_emit_script(emit)

        for dp in self.datapoints:
            ci = dp['idx']
            config_path = dp['config path']
            bc = self.layout.bc(ci)

            if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
                print(f"  [case {ci}] Already compiled, skipping")
                continue

            if os.path.exists(bc):
                shutil.rmtree(bc, ignore_errors=True)

            os.makedirs(bc, exist_ok=True)
            shutil.copyfile(config_path, os.path.join(bc, ".config"))
            append_build_config(os.path.join(bc, ".config"))

            src = self.layout.src(ci)
            sh(f"cd {Q(src)} && git checkout -- scripts/Makefile.kcov 2>/dev/null; "
               f"make clean && make mrproper && "
               f"make CC={Q(emit)} O={Q(bc)} olddefconfig && "
               f"make CC={Q(emit)} O={Q(bc)} -j{self.cpus}", big=True)

            if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
                print(f"  [case {ci}] Bitcode compiled successfully")
            else:
                print(f"  [case {ci}] ERROR: Bitcode compilation failed!")

    def step3_analyze_kernel(self):
        print("\n[3/6] ANALYZE_KERNEL")

        # generate syzkaller signature once
        syz_sig = self.layout.syz_sig()
        if not os.path.exists(syz_sig) or os.stat(syz_sig).st_size == 0:
            sh(f"{Q(os.path.join(FUZZER_BIN, 'syz-features'))} > {Q(syz_sig)}")
        assert os.path.exists(syz_sig) and os.stat(syz_sig).st_size != 0, \
            "Failed to generate syzkaller signature"

        for dp in self.datapoints:
            ci = dp['idx']
            iface_dir = self.layout.interface(ci)
            os.makedirs(iface_dir, exist_ok=True)
            bc = self.layout.bc(ci)
            sig = self.layout.kernel_sig(ci)

            if not os.path.exists(sig):
                sh(f"cd {Q(iface_dir)} && "
                   f"{Q(INTERFACE_GENERATOR)} --verbose-level=4 {Q(bc)} 2>&1 | tee log",
                   big=True)
                if not os.path.exists(sig):
                    print(f"  [case {ci}] ERROR: interface_generator failed!")
                    continue

            k2s = self.layout.k2s(ci)
            if not os.path.exists(k2s):
                sys.path.insert(0, SCRIPT_DIR)
                from SyscallAnalyze.InterfaceGenerate import MatchSig
                result = MatchSig(syz_sig, sig)
                with open(k2s, "w") as f:
                    json.dump(result, f, indent="\t")

            print(f"  [case {ci}] Kernel interface analyzed")

    def step4_analyze_target_point(self):
        print("\n[4/6] ANALYZE_TARGET_POINT")

        # generate syscall pair map
        tr_map = self.layout.tr_map()
        if not os.path.exists(tr_map):
            sh(f"cd {Q(self.layout.root)} && {Q(os.path.join(FUZZER_BIN, 'direct'))}")
        assert os.path.exists(tr_map), "Failed to generate syscall pair map"

        for dp in self.datapoints:
            ci = dp['idx']
            tpa_dir = self.layout.tpa(ci)
            os.makedirs(tpa_dir, exist_ok=True)
            bc = self.layout.bc(ci)
            k2s = self.layout.k2s(ci)

            if not os.path.exists(k2s):
                print(f"  [case {ci}] Skipping: no interface result")
                continue

            compact = self.layout.compact(ci)
            pts = self.layout.multi_pts(ci)

            if not os.path.exists(compact):
                sh(f"cd {Q(tpa_dir)} && "
                   f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
                   f"-kernel-interface-file={Q(k2s)} "
                   f"-multi-pos-points={Q(pts)} "
                   f"{Q(bc)} 2>&1 | tee log", big=True)

            dup = self.layout.dup_report(ci)
            if os.path.exists(dup):
                print(f"  [case {ci}] WARNING: duplicate points detected!")
                print(f"    Check {dup} and specify multi-pts file")
                print(f"    Format: '0 function_name' per line")
                continue

            if not os.path.exists(compact):
                print(f"  [case {ci}] ERROR: target_analyzer failed!")
                continue

            print(f"  [case {ci}] Target point analyzed, preparing for fuzzing...")
            sys.path.insert(0, SCRIPT_DIR)
            from SyscallAnalyze.TargetPointAnalyze import PrepareForFuzzing
            PrepareForFuzzing(ci, dp['recommend syscall'])

    def step5_instrument_distance(self):
        print("\n[5/6] INSTRUMENT_DISTANCE")
        import Config
        for dp in self.datapoints:
            ci = dp['idx']
            config_path = dp['config path']

            tfinfo = self.layout.tfinfo(ci)
            if not os.path.exists(tfinfo):
                print(f"  [case {ci}] Skipping: no tfinfo")
                continue

            tfmap = Config.ParseTargetFunctionsInfoFile(ci)
            kernel_dir = self.layout.kwithdist(ci)
            os.makedirs(kernel_dir, exist_ok=True)
            src = self.layout.src(ci)

            for xidx in tfmap.keys():
                target_func = tfmap[xidx][0]
                bz_dst = self.layout.bzimage(ci, xidx)

                if os.path.exists(bz_dst):
                    print(f"  [case {ci} xidx {xidx}] Already instrumented, skipping")
                    continue

                temp = os.path.join(kernel_dir, "temp_build")
                os.makedirs(temp, exist_ok=True)
                dist_dir = self.layout.dist_dir(ci, xidx)

                write_makefile_kcov(src, dist_dir, target_func)

                sh(f"cd {Q(src)} && make clean && make mrproper", check=False)
                shutil.copyfile(config_path, os.path.join(temp, ".config"))
                append_build_config(os.path.join(temp, ".config"))

                sh(f"cd {Q(src)} && "
                   f"make ARCH=x86_64 CC={Q(CLANG_PATH)} O={Q(temp)} olddefconfig && "
                   f"make ARCH=x86_64 CC={Q(CLANG_PATH)} O={Q(temp)} -j{self.cpus}", big=True)

                bz_src = os.path.join(temp, "arch/x86/boot/bzImage")
                if not os.path.exists(bz_src):
                    print(f"  [case {ci} xidx {xidx}] ERROR: Kernel build failed!")
                    continue

                shutil.copyfile(bz_src, bz_dst)
                vm_src = os.path.join(temp, "vmlinux")
                if os.path.exists(vm_src):
                    shutil.copyfile(vm_src, self.layout.vmlinux(ci, xidx))
                shutil.rmtree(temp, ignore_errors=True)
                print(f"  [case {ci} xidx {xidx}] Instrumented kernel built")

    def step6_fuzz(self):
        print("\n[6/6] FUZZ")
        import Fuzz
        Config = configure_runner(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Config.datapoints = self.datapoints
        print(f"Launching fuzzer: {len(self.datapoints)} cases x {self.fuzz_rounds} rounds, "
              f"{self.uptime}h each")
        Fuzz.MultirunFuzzer()


# ──────────────────────────────────────────────────────────────────────────
# Full pipeline for a new CVE
# ──────────────────────────────────────────────────────────────────────────

PIPELINE_STAGES = ["source", "bitcode", "analyze", "target", "distance", "fuzz"]


class NewCVEPipeline:
    """Six-stage SyzDirect pipeline for a new CVE target."""

    def __init__(self, args):
        self.cve_id = args.cve
        self.commit = args.commit
        self.function = args.function
        self.file_path = args.file
        self.config_path = args.config or BIGCONFIG
        self.recommend_syscalls = args.syscalls.split(",") if args.syscalls else []
        self.linux_template = args.linux_template
        self.cpus = args.j
        self.uptime = args.uptime
        self.fuzz_rounds = args.fuzz_rounds
        self.safe_name = self.cve_id.replace("-", "_").lower()
        self.ci = 0  # single target = case 0
        self.layout = WorkdirLayout(args.workdir)

    # ── orchestration ────────────────────────────────────────────────────

    _steps = {
        "source":   "step1_prepare_source",
        "bitcode":  "step2_compile_bitcode",
        "analyze":  "step3_analyze_kernel",
        "target":   "step4_analyze_target_point",
        "distance": "step5_instrument_distance",
        "fuzz":     "step6_fuzz",
    }

    def run(self, from_stage=None):
        print(f"\n{'='*60}")
        print(f"SyzDirect Pipeline: {self.cve_id}")
        print(f"  {self.function} @ {self.file_path}  commit={self.commit}")
        print(f"  workdir={self.layout.root}")
        print(f"{'='*60}\n")

        start = PIPELINE_STAGES.index(from_stage) if from_stage else 0
        for stage in PIPELINE_STAGES[start:]:
            getattr(self, self._steps[stage])()

    # ── stages ───────────────────────────────────────────────────────────

    def step1_prepare_source(self):
        print("\n[1/6] PREPARE_SRC")
        src = self.layout.src(self.ci)
        os.makedirs(os.path.dirname(src), exist_ok=True)

        # Handle relative refs like "abc123~1": fetch the base hash,
        # then checkout the relative ref locally.
        commit = self.commit
        fetch_ref = re.sub(r"[~^]\d*$", "", commit)  # strip ~1, ^2, etc.

        if os.path.isdir(os.path.join(src, ".git")):
            print(f"  Reusing: {src}")
        else:
            shutil.rmtree(src, ignore_errors=True)
            if self.linux_template and os.path.exists(self.linux_template):
                print(f"  Cloning from local template...")
                sh(f"git clone --local --no-checkout {Q(self.linux_template)} {Q(src)}")
            else:
                print("  Cloning from GitHub...")
                sh(f"git clone --depth=1 https://github.com/torvalds/linux.git {Q(src)}")
                # For relative refs (e.g. abc~1), we need depth=2 so the parent exists
                depth = 2 if fetch_ref != commit else 1
                sh(f"cd {Q(src)} && git fetch --depth={depth} origin {fetch_ref}")

        sh(f"cd {Q(src)} && git checkout -f {commit}")
        relax_kernel_build(src)

        result = sh(f"cd {Q(src)} && git apply {Q(KCOV_PATCH)} 2>&1",
                     check=False, capture=True)
        if "patch failed" in (result or ""):
            print("  WARNING: kcov patch failed, applying fallback")
        ensure_kcov_support(src)
        print("  Done.")

    def step2_compile_bitcode(self):
        print("\n[2/6] COMPILE_BITCODE")
        bc = self.layout.bc(self.ci)
        if os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
            print("  Already compiled, skipping.")
            return

        os.makedirs(bc, exist_ok=True)
        emit = self.layout.emit_script()
        write_emit_script(emit)

        config_dst = os.path.join(bc, ".config")
        shutil.copyfile(self.config_path, config_dst)
        append_build_config(config_dst)

        src = Q(self.layout.src(self.ci))
        sh(f"cd {src} && git checkout -- scripts/Makefile.kcov 2>/dev/null; "
           f"make clean && make mrproper && "
           f"make CC={Q(emit)} O={Q(bc)} olddefconfig && "
           f"make CC={Q(emit)} O={Q(bc)} -j{self.cpus}", big=True)

        if not os.path.exists(os.path.join(bc, "arch/x86/boot/bzImage")):
            sys.exit("[2/6] ERROR: Bitcode compilation failed!")
        print("  Done.")

    def step3_analyze_kernel(self):
        print("\n[3/6] ANALYZE_KERNEL")
        ci = self.ci
        os.makedirs(self.layout.interface(ci), exist_ok=True)

        sig = self.layout.kernel_sig(ci)
        if not os.path.exists(sig):
            syz_sig = self.layout.syz_sig()
            if not os.path.exists(syz_sig) or os.stat(syz_sig).st_size == 0:
                sh(f"{Q(os.path.join(FUZZER_BIN, 'syz-features'))} > {Q(syz_sig)}")
            sh(f"cd {Q(self.layout.interface(ci))} && "
               f"{Q(INTERFACE_GENERATOR)} --verbose-level=4 {Q(self.layout.bc(ci))} 2>&1 | tee log",
               big=True)

        if not os.path.exists(sig):
            sys.exit("[3/6] ERROR: interface_generator failed!")

        k2s = self.layout.k2s(ci)
        if not os.path.exists(k2s):
            sys.path.insert(0, SCRIPT_DIR)
            from SyscallAnalyze.InterfaceGenerate import MatchSig
            with open(k2s, "w") as f:
                json.dump(MatchSig(self.layout.syz_sig(), sig), f, indent="\t")
        print("  Done.")

    def step4_analyze_target_point(self):
        print("\n[4/6] ANALYZE_TARGET_POINT")
        ci = self.ci
        os.makedirs(self.layout.tpa(ci), exist_ok=True)

        pts = self.layout.multi_pts(ci)
        os.makedirs(os.path.dirname(pts), exist_ok=True)
        with open(pts, "w") as f:
            f.write(f"0 {self.function}\n")

        if not os.path.exists(self.layout.tr_map()):
            sh(f"cd {Q(self.layout.root)} && {Q(os.path.join(FUZZER_BIN, 'direct'))}")

        compact = self.layout.compact(ci)
        if not os.path.exists(compact):
            sh(f"cd {Q(self.layout.tpa(ci))} && "
               f"{Q(TARGET_ANALYZER)} --verbose-level=4 "
               f"-kernel-interface-file={Q(self.layout.k2s(ci))} "
               f"-multi-pos-points={Q(pts)} "
               f"{Q(self.layout.bc(ci))} 2>&1 | tee log", big=True)

        dup = self.layout.dup_report(ci)
        if os.path.exists(dup):
            print(f"  WARNING: duplicate points — check {dup}")

        if not os.path.exists(compact):
            sys.exit("[4/6] ERROR: target_analyzer failed!")

        if os.path.exists(self.layout.tfinfo(ci)):
            Config = configure_runner(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
            sys.path.insert(0, SCRIPT_DIR)
            from SyscallAnalyze.TargetPointAnalyze import PrepareForFuzzing
            PrepareForFuzzing(ci, self.recommend_syscalls)
        else:
            print("  tfinfo missing, falling back to LLM/heuristic syscalls")
            self._create_fuzzinps()
        print("  Done.")

    def step5_instrument_distance(self):
        print("\n[5/6] INSTRUMENT_DISTANCE")
        ci = self.ci
        os.makedirs(self.layout.kwithdist(ci), exist_ok=True)

        if os.path.exists(self.layout.bzimage(ci)):
            print("  Instrumented kernel exists, skipping.")
            return

        xidx, target_func = "0", self.function
        if os.path.exists(self.layout.tfinfo(ci)):
            with open(self.layout.tfinfo(ci)) as _f:
                parts = _f.readline().split()
            xidx, target_func = parts[0], parts[1]

        dist = self.layout.dist_dir(ci, xidx)
        if not os.path.exists(dist):
            dist = self.layout.dist_dir(ci, 0)

        src = self.layout.src(ci)
        temp = os.path.join(self.layout.kwithdist(ci), "temp_build")
        os.makedirs(temp, exist_ok=True)

        write_makefile_kcov(src, dist, target_func)

        sh(f"cd {Q(src)} && make clean && make mrproper", check=False)
        shutil.copyfile(self.config_path, os.path.join(temp, ".config"))
        append_build_config(os.path.join(temp, ".config"))

        sh(f"cd {Q(src)} && "
           f"make ARCH=x86_64 CC={Q(CLANG_PATH)} O={Q(temp)} olddefconfig && "
           f"make ARCH=x86_64 CC={Q(CLANG_PATH)} O={Q(temp)} -j{self.cpus}", big=True)

        bz_src = os.path.join(temp, "arch/x86/boot/bzImage")
        if not os.path.exists(bz_src):
            sys.exit("[5/6] ERROR: Kernel build failed!")

        shutil.copyfile(bz_src, self.layout.bzimage(ci))
        vm_src = os.path.join(temp, "vmlinux")
        if os.path.exists(vm_src):
            shutil.copyfile(vm_src, self.layout.vmlinux(ci))
        shutil.rmtree(temp, ignore_errors=True)
        print(f"  Done: {self.layout.bzimage(ci)}")

    def step6_fuzz(self):
        target_info = {"idx": self.ci, "name": self.safe_name,
                       "function": self.function, "func_path": self.file_path}
        agent_rounds = getattr(self.args, "agent_rounds", 0)
        if agent_rounds > 0:
            print(f"\n[6/7] FUZZ + AGENT LOOP ({agent_rounds} rounds)")
            agent = AgentLoop(
                layout=self.layout, target_info=target_info,
                max_rounds=agent_rounds,
                window_seconds=getattr(self.args, "agent_window", 300),
                uptime_per_round=getattr(self.args, "agent_uptime", None) or self.uptime,
                cpus=self.cpus, fuzz_rounds=self.fuzz_rounds,
            )
            agent.run()
        else:
            print("\n[6/6] FUZZ")
            launch_fuzzing(
                self.layout, self.cpus, self.uptime, self.fuzz_rounds,
                [target_info],
            )

    # ── helpers ──────────────────────────────────────────────────────────

    def _create_fuzzinps(self):
        """Generate callfile via LLM, falling back to heuristics."""
        ci = self.ci
        os.makedirs(self.layout.fuzzinps(ci), exist_ok=True)

        result = llm_analyze_cve(self.cve_id, self.commit, self.function, self.file_path)
        syscalls = (result.get("syscalls") if result else None) or guess_syscalls(self.file_path)
        print(f"  Syscalls: {[s['Target'] for s in syscalls]}")

        with open(self.layout.callfile(ci), "w") as f:
            json.dump(syscalls, f, indent="\t")

        if not os.path.exists(self.layout.tfinfo(ci)):
            os.makedirs(self.layout.tpa(ci), exist_ok=True)
            with open(self.layout.tfinfo(ci), "w") as f:
                f.write(f"0 {self.function} {self.file_path}\n")


# ──────────────────────────────────────────────────────────────────────────
# Fuzz-only mode (pre-built targets)
# ──────────────────────────────────────────────────────────────────────────

def setup_prebuilt(layout, targets):
    """Symlink pre-built instrumented kernels and write callfiles."""
    for t in targets:
        ci, name = t["idx"], t["name"]
        hunt = os.path.join(RUNTIME_BASE, f"new_hunt_{name}", "instrumented")

        os.makedirs(layout.kwithdist(ci), exist_ok=True)
        for src_name, dst in [("bzImage", layout.bzimage(ci)),
                               ("vmlinux", layout.vmlinux(ci))]:
            src = os.path.join(hunt, src_name)
            if os.path.exists(src) and not os.path.exists(dst):
                os.symlink(src, dst)

        os.makedirs(layout.tpa(ci), exist_ok=True)
        with open(layout.tfinfo(ci), "w") as f:
            f.write(f"0 {t['function']} {t['func_path']}\n")

        os.makedirs(layout.fuzzinps(ci), exist_ok=True)
        with open(layout.callfile(ci), "w") as f:
            json.dump(t["syscalls"], f, indent="\t")

        print(f"  [case {ci}] {name}: ready")


def launch_fuzzing(layout, cpus, uptime, fuzz_rounds, targets):
    """Configure the Runner and start Fuzz.MultirunFuzzer."""
    Config = configure_runner(layout, cpus, uptime, fuzz_rounds)
    import Fuzz

    Config.datapoints = [
        {"idx": t["idx"], "repro bug title": float("nan")}
        for t in targets
    ]

    print(f"\nLaunching: {len(targets)} targets x {fuzz_rounds} rounds, {uptime}h each")
    print(f"Results: {os.path.join(layout.root, 'fuzzres')}\n")
    Fuzz.MultirunFuzzer()


# ──────────────────────────────────────────────────────────────────────────
# Agent Loop: fuzz → assess → triage → enhance → re-fuzz
# ──────────────────────────────────────────────────────────────────────────

# Path to source/agent/ (relative to this repo)
_AGENT_DIR = os.path.normpath(os.path.join(RESOURCE_ROOT, "..", "..", "agent"))


def _ensure_agent_imports():
    """Make source/agent importable."""
    source_dir = os.path.normpath(os.path.join(RESOURCE_ROOT, "..", ".."))
    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)


class AgentLoop:
    """
    Multi-round fuzz → assess → triage → enhance → re-fuzz loop.

    After each fuzzing round, checks health metrics. If the distance is
    stagnant (not decreasing), classifies the failure as R1/R2/R3 and
    dispatches the appropriate agent to enhance the callfile (syscall
    templates). Then re-fuzzes with the enhanced callfile.
    """

    def __init__(self, layout, target_info, max_rounds, window_seconds,
                 uptime_per_round, cpus, fuzz_rounds=1):
        self.layout = layout
        self.target = target_info
        self.max_rounds = max_rounds
        self.window_seconds = window_seconds
        self.uptime = uptime_per_round
        self.cpus = cpus
        self.fuzz_rounds = fuzz_rounds
        self.ci = target_info["idx"]

    def run(self):
        for round_num in range(1, self.max_rounds + 1):
            print(f"\n{'=' * 60}")
            print(f"  AGENT ROUND {round_num}/{self.max_rounds}")
            print(f"{'=' * 60}")

            round_dir = os.path.join(
                self.layout.fuzzres_xidx(self.ci),
                f"agent_round_{round_num}",
            )
            os.makedirs(round_dir, exist_ok=True)

            # ── A. Fuzz with log capture ─────────────────────────────────
            manager_log, metrics_jsonl = self._run_fuzz_round(round_dir, round_num)

            # ── B. Check for crashes (early success) ─────────────────────
            crash_dir = os.path.join(round_dir, "crashes")
            if self._has_crashes(crash_dir, round_dir):
                print("  TARGET CRASHED — SUCCESS!")
                break

            # ── C. Assess health ─────────────────────────────────────────
            health = self._assess_health(metrics_jsonl, manager_log)
            print(f"  Health: status={health['status']}  score={health['score']:.1f}")
            print(f"  Reason: {health['reason']}")

            if health["status"] == "healthy":
                if round_num < self.max_rounds:
                    print("  Fuzzing is healthy, continuing to next round...")
                continue

            if health["status"] == "fatal":
                print("  FATAL: all target calls disabled. Stopping.")
                break

            # ── D. Triage failure ────────────────────────────────────────
            failure_class = self._triage(health, metrics_jsonl, manager_log)
            print(f"  Triage result: {failure_class}")

            if failure_class == "SUCCESS":
                break

            # ── E. Enhance callfile ──────────────────────────────────────
            if round_num < self.max_rounds:
                enhanced = self._enhance_callfile(failure_class, round_dir, round_num)
                if not enhanced:
                    print("  No enhancement produced. Stopping agent loop.")
                    break
                print(f"  Callfile enhanced for next round.")
            else:
                print("  Last round, no more enhancements.")

        self._print_summary()

    # ── Fuzzing ──────────────────────────────────────────────────────────

    def _run_fuzz_round(self, round_dir, round_num):
        """Run one round of syz-manager with log capture."""
        import copy as _copy

        Cfg = configure_runner(
            self.layout, self.cpus, self.uptime, self.fuzz_rounds,
        )
        import Fuzz

        ci = self.ci
        template_config = Cfg.LoadJson(Cfg.TemplateConfigPath)
        assert template_config, "Failed to load fuzzing config template"
        template_config["sshkey"] = Cfg.KeyPath

        syzdirect_path = Cfg.FuzzerDir
        tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)

        last_log, last_metrics = None, None

        for xidx in tfmap.keys():
            callfile = self.layout.callfile(ci, xidx)
            kernel_img = self.layout.bzimage(ci, xidx)
            assert os.path.exists(callfile), f"callfile missing: {callfile}"
            assert os.path.exists(kernel_img), f"bzImage missing: {kernel_img}"

            config = _copy.deepcopy(template_config)
            config["image"] = Cfg.CleanImageTemplatePath
            # Accumulate corpus: do NOT wipe workdir between rounds
            sub_workdir = os.path.join(round_dir, f"workdir_x{xidx}")
            config["workdir"] = sub_workdir
            port = 2345 + (round_num * 10 + int(xidx)) % 60000
            config["http"] = f"0.0.0.0:{port}"
            config["vm"]["kernel"] = kernel_img
            config["syzkaller"] = syzdirect_path
            config["hitindex"] = int(xidx)

            config_path = os.path.join(round_dir, f"config_x{xidx}.json")
            with open(config_path, "w") as f:
                json.dump(config, f, indent="\t")

            fuzzer_file = os.path.join(syzdirect_path, "bin", "syz-manager")
            log_dir = os.path.join(round_dir, f"logs_x{xidx}")

            print(f"  Fuzzing case={ci} xidx={xidx} for {self.uptime}h ...")
            last_log, last_metrics = Fuzz.runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
            )

        return last_log, last_metrics

    # ── Health assessment ─────────────────────────────────────────────────

    def _assess_health(self, metrics_jsonl, manager_log):
        """Score the fuzzing round using the same logic as fuzzing_health_monitor."""
        metrics = []
        if metrics_jsonl and os.path.exists(metrics_jsonl):
            with open(metrics_jsonl) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            metrics.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        log_text = ""
        if manager_log and os.path.exists(manager_log):
            with open(manager_log) as f:
                log_text = f.read().lower()

        if not metrics:
            return {"status": "stagnant", "score": -5.0,
                    "reason": "no metrics collected", "metrics": []}

        # Compute deltas over the window
        window = metrics  # Use all metrics for the round
        first, last = window[0], window[-1]

        exec_delta = max(0, last.get("exec_total", 0) - first.get("exec_total", 0))
        cover_delta = max(0, last.get("corpus_cover", 0) - first.get("corpus_cover", 0))
        crash_delta = max(0, last.get("crashes", 0) - first.get("crashes", 0))
        elapsed = max(1, last.get("timestamp", 0) - first.get("timestamp", 0))

        avg_exec = exec_delta / elapsed
        avg_cover = cover_delta / elapsed

        # Score (same formula as health monitor)
        score = 0.0
        score += min(avg_exec / 5.0, 5.0)
        score += min(avg_cover, 3.0)
        score -= min((crash_delta / elapsed) * 30.0, 5.0)

        fatal = "all target calls are disabled" in log_text

        status = "healthy"
        reason = "fuzzing is progressing"

        if fatal:
            status = "fatal"
            reason = "all target calls are disabled"
            score -= 10.0
        elif exec_delta == 0:
            status = "stagnant"
            reason = "execution count did not increase"
        elif cover_delta == 0 and exec_delta > 100:
            status = "stagnant"
            reason = "coverage stalled despite executions"

        return {
            "status": status, "score": score, "reason": reason,
            "exec_delta": exec_delta, "cover_delta": cover_delta,
            "crash_delta": crash_delta, "elapsed": elapsed,
            "total_exec": last.get("exec_total", 0),
            "total_cover": last.get("corpus_cover", 0),
            "total_crashes": last.get("crashes", 0),
            "fatal": fatal, "metrics": metrics,
        }

    # ── Crash detection ──────────────────────────────────────────────────

    def _has_crashes(self, crash_dir, round_dir):
        """Check if syz-manager found crashes this round."""
        # syz-manager puts crashes in workdir/crashes/
        for dirpath, dirnames, filenames in os.walk(round_dir):
            if os.path.basename(dirpath) == "crashes" and filenames:
                print(f"  Found {len(filenames)} crash files in {dirpath}")
                return True
        return False

    # ── Failure triage ───────────────────────────────────────────────────

    def _triage(self, health, metrics_jsonl, manager_log):
        """
        Classify failure as R1/R2/R3 using heuristics.
        Simpler than full FailureTriageAgent since we lack per-exec distance data.
        """
        if health.get("total_crashes", 0) > 0:
            return "SUCCESS"

        if health.get("fatal"):
            # All target calls disabled → wrong syscalls identified (R1)
            return "R1"

        exec_d = health.get("exec_delta", 0)
        cover_d = health.get("cover_delta", 0)

        if exec_d == 0:
            # Nothing executed → likely missing/wrong syscall (R1)
            return "R1"

        # Check log for EINVAL/EFAULT patterns (R2 indicator)
        einval_count = 0
        if manager_log and os.path.exists(manager_log):
            with open(manager_log) as f:
                log_text = f.read()
                einval_count = log_text.lower().count("einval") + log_text.lower().count("efault")

        if einval_count > 50:
            # High error rate → parameter generation failure (R2)
            return "R2"

        if cover_d == 0 and exec_d > 100:
            # Executions running but no new coverage → dependency chain issue (R3)
            return "R3"

        # Default: distance not decreasing → R3 (context insufficient)
        return "R3"

    # ── Template enhancement ─────────────────────────────────────────────

    def _enhance_callfile(self, failure_class, round_dir, round_num):
        """Enhance the callfile using the appropriate agent."""
        callfile_path = self.layout.callfile(self.ci)
        with open(callfile_path) as f:
            current_callfile = json.load(f)

        # Convert callfile to template_bundle format for agents
        template_data = self._callfile_to_templates(current_callfile)
        triage_result = {
            "failure_class": failure_class,
            "evidence": [f"Agent loop round {round_num} triage: {failure_class}"],
            "recommended_actions": [],
        }

        enhanced_templates = None

        _ensure_agent_imports()

        if failure_class in ("R3", "R1"):
            try:
                from source.agent.related_syscall_agent import RelatedSyscallAgent
                agent = RelatedSyscallAgent(
                    template_data=template_data,
                    triage_result=triage_result,
                )
                enhanced_templates = agent.analyze_and_enhance()
                print(f"  RelatedSyscallAgent produced {len(enhanced_templates)} templates")
            except Exception as e:
                print(f"  WARNING: RelatedSyscallAgent failed: {e}")

        elif failure_class == "R2":
            try:
                from source.agent.object_synthesis_agent import ObjectSynthesisAgent
                image_dir = os.path.join(round_dir, "images")
                agent = ObjectSynthesisAgent(
                    triage_result=triage_result,
                    template_data=template_data,
                    image_dir=image_dir,
                )
                result = agent.analyze_and_synthesize()
                enhanced_templates = result.get("enhanced_templates", [])
                print(f"  ObjectSynthesisAgent produced {len(enhanced_templates)} templates")
            except Exception as e:
                print(f"  WARNING: ObjectSynthesisAgent failed: {e}")

        if not enhanced_templates:
            return False

        # Convert back to callfile format and write
        new_callfile = self._templates_to_callfile(enhanced_templates)
        if not new_callfile:
            return False

        # Backup old callfile
        backup = callfile_path + f".round{round_num}"
        shutil.copyfile(callfile_path, backup)

        # Merge: keep originals + add new entries
        merged = list(current_callfile)
        existing_targets = {e["Target"] for e in merged}
        for entry in new_callfile:
            if entry["Target"] not in existing_targets:
                merged.append(entry)
                existing_targets.add(entry["Target"])

        with open(callfile_path, "w") as f:
            json.dump(merged, f, indent="\t")

        return True

    # ── Format converters ────────────────────────────────────────────────

    # Heuristic: infer resource type from syscall name
    _RESOURCE_HINTS = {
        "sock": {"socket", "bind", "listen", "connect", "accept", "accept4",
                 "send", "sendto", "sendmsg", "sendmmsg", "recv", "recvfrom",
                 "recvmsg", "setsockopt", "getsockopt", "shutdown"},
        "fd": {"open", "openat", "creat", "read", "write", "ioctl", "close",
               "fcntl", "fstat", "lseek", "mmap"},
    }

    @classmethod
    def _infer_resource_type(cls, syscall_name):
        base = syscall_name.split("$")[0] if "$" in syscall_name else syscall_name
        for rtype, names in cls._RESOURCE_HINTS.items():
            if base in names:
                return rtype
        return None

    @classmethod
    def _callfile_to_templates(cls, callfile):
        """Convert callfile JSON to template_bundle format."""
        templates = []
        for i, entry in enumerate(callfile):
            target_name = entry.get("Target", "")
            related_names = entry.get("Relate", [])
            base_name = target_name.split("$")[0] if "$" in target_name else target_name
            rtype = cls._infer_resource_type(target_name)
            templates.append({
                "template_id": f"tmpl_{i}_{target_name}",
                "entry_syscall": {
                    "name": base_name,
                    "syzlang_name": target_name,
                    "resource_type": rtype,
                },
                "related_syscalls": [
                    {
                        "name": r.split("$")[0] if "$" in r else r,
                        "syzlang_name": r,
                        "resource_type": cls._infer_resource_type(r),
                    }
                    for r in related_names
                ],
                "sequence_order": related_names + [target_name],
            })
        return templates

    @staticmethod
    def _templates_to_callfile(templates):
        """Convert template_bundle format back to callfile JSON."""
        callfile = []
        seen = set()
        for t in templates:
            entry = t.get("entry_syscall", {})
            target = entry.get("syzlang_name") or entry.get("name", "")
            if not target or target in seen:
                continue
            seen.add(target)
            related = [
                s.get("syzlang_name") or s.get("name", "")
                for s in t.get("related_syscalls", [])
                if s.get("syzlang_name") or s.get("name")
            ]
            callfile.append({"Target": target, "Relate": related})
        return callfile

    # ── Summary ──────────────────────────────────────────────────────────

    def _print_summary(self):
        print(f"\n{'=' * 60}")
        print("  AGENT LOOP COMPLETE")
        callfile_path = self.layout.callfile(self.ci)
        print(f"  Final callfile: {callfile_path}")
        fuzzres = self.layout.fuzzres_xidx(self.ci)
        print(f"  Results: {fuzzres}")
        print(f"{'=' * 60}")


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────

DATASET_ACTION_NAMES = list(DatasetPipeline.ACTIONS.keys())


def main():
    parser = argparse.ArgumentParser(
        description="SyzDirect CVE Hunt Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Dataset mode (like original Main.py):
  python3 run_hunt.py dataset -dataset dataset_hunt.xlsx -j 8 \\
      prepare_for_manual_instrument compile_kernel_bitcode \\
      analyze_kernel_syscall extract_syscall_entry \\
      instrument_kernel_with_distance fuzz

  # New CVE — full pipeline:
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c -j 8

  # Resume from a specific stage:
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c --from-stage distance

  # Pre-built targets — fuzz only:
  python3 run_hunt.py fuzz --targets 0 3 5 -uptime 12
  python3 run_hunt.py fuzz

  # Agent loop — fuzz + auto triage/enhance (3 rounds, 6h each):
  python3 run_hunt.py new --cve CVE-2025-99999 --commit abc123 \\
      --function vuln_func --file net/core/sock.c \\
      --agent-rounds 3 --agent-uptime 6
  python3 run_hunt.py fuzz --targets 0 --agent-rounds 5

Available dataset actions:
  {', '.join(DATASET_ACTION_NAMES)}
""",
    )
    parser.add_argument("-j", type=int, default=4, help="CPU cores (default: 4)")
    parser.add_argument("-uptime", type=int, default=24, help="Fuzzing hours (default: 24)")
    parser.add_argument("-fuzz-rounds", type=int, default=1, dest="fuzz_rounds")
    parser.add_argument("-workdir", default="./workdir")

    sub = parser.add_subparsers(dest="mode")

    # dataset mode
    p_ds = sub.add_parser("dataset", help="Run pipeline from dataset.xlsx (like Main.py)")
    p_ds.add_argument("actions", nargs="+", choices=DATASET_ACTION_NAMES,
                       metavar="ACTION", help="Pipeline actions to run")
    p_ds.add_argument("-dataset", default="dataset.xlsx",
                       help="Path to dataset .xlsx file (default: dataset.xlsx)")
    p_ds.add_argument("-linux-repo-template", dest="linux_template", default=None,
                       help="Local linux repo to clone from (saves time)")

    # new CVE mode
    p_new = sub.add_parser("new", help="Full pipeline for a new CVE")
    p_new.add_argument("--cve", required=True)
    p_new.add_argument("--commit", default=None,
                        help="Kernel commit to check out (auto-resolved from CVE if omitted)")
    p_new.add_argument("--function", default=None,
                        help="Target function (auto-resolved from CVE patch if omitted)")
    p_new.add_argument("--file", default=None,
                        help="Target source file (auto-resolved from CVE patch if omitted)")
    p_new.add_argument("--verify-patch", action="store_true", dest="verify_patch",
                        help="Patch verification mode: fuzz the FIXED kernel to confirm bug is gone")
    p_new.add_argument("--syscalls", default="")
    p_new.add_argument("--config", default=None)
    p_new.add_argument("--linux-template", default=None)
    p_new.add_argument("--from-stage", default=None, dest="from_stage",
                        choices=PIPELINE_STAGES)

    # fuzz-only mode
    p_fuzz = sub.add_parser("fuzz", help="Fuzz pre-built targets only")
    p_fuzz.add_argument("--targets", nargs="*", type=int, default=None)

    # Agent loop options (shared by new + fuzz modes)
    for p in [p_new, p_fuzz]:
        p.add_argument("--agent-rounds", type=int, default=0, dest="agent_rounds",
                        help="Agent loop iterations (0=off, >0=auto triage+enhance)")
        p.add_argument("--agent-window", type=int, default=300, dest="agent_window",
                        help="Health check window in seconds (default: 300)")
        p.add_argument("--agent-uptime", type=int, default=None, dest="agent_uptime",
                        help="Uptime per agent round in hours (default: same as -uptime)")

    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode == "dataset":
        DatasetPipeline(args).run()

    elif args.mode == "new":
        # Auto-resolve missing --commit/--function/--file from CVE ID
        if not all([args.commit, args.function, args.file]):
            from cve_resolver import CVEResolver, CVEResolveError
            try:
                resolved = CVEResolver(args.cve).resolve()
                if getattr(args, "verify_patch", False):
                    # Patch verification: fuzz the FIXED kernel
                    args.commit = args.commit or resolved["fix_commit"]
                    mode_label = "PATCH VERIFICATION (post-fix)"
                else:
                    # 1-day reproduction: fuzz the VULNERABLE kernel
                    args.commit = args.commit or resolved["commit"]
                    mode_label = "1-DAY REPRODUCTION (pre-fix)"
                args.function = args.function or resolved["function"]
                args.file = args.file or resolved["file"]
                print(f"\n[CVE Resolver] Auto-resolved from {args.cve}:")
                print(f"  mode        : {mode_label}")
                print(f"  fix commit  : {resolved['fix_commit']}")
                print(f"  checkout    : {args.commit}")
                print(f"  function    : {args.function}")
                print(f"  file        : {args.file}")
                print()
            except CVEResolveError as e:
                sys.exit(f"ERROR: CVE auto-resolve failed: {e}")
        NewCVEPipeline(args).run(args.from_stage)

    elif args.mode == "fuzz":
        layout = WorkdirLayout(args.workdir)
        os.makedirs(layout.root, exist_ok=True)

        targets = PREBUILT_TARGETS
        if args.targets is not None:
            targets = [t for t in PREBUILT_TARGETS if t["idx"] in args.targets]
            if not targets:
                sys.exit(f"ERROR: No valid targets in {args.targets}")

        print(f"Targets: {[t['name'] for t in targets]}")
        setup_prebuilt(layout, targets)

        if args.agent_rounds > 0:
            # Agent loop for each target sequentially
            for t in targets:
                agent = AgentLoop(
                    layout=layout, target_info=t,
                    max_rounds=args.agent_rounds,
                    window_seconds=args.agent_window,
                    uptime_per_round=args.agent_uptime or args.uptime,
                    cpus=args.j, fuzz_rounds=args.fuzz_rounds,
                )
                agent.run()
        else:
            launch_fuzzing(layout, args.j, args.uptime, args.fuzz_rounds, targets)


if __name__ == "__main__":
    main()
