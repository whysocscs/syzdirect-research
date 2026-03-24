"""
SyzDirect Runner — path constants, WorkdirLayout, and shared constants.

Single source of truth for all path conventions used by the pipeline.
"""

import os
import shlex


# ──────────────────────────────────────────────────────────────────────────
# Derived paths (from project layout)
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
KNOWN_CRASH_DB = os.path.join(SCRIPT_DIR, "known_crash_signatures.json")

RUNTIME_BASE = os.environ.get("SYZDIRECT_RUNTIME", "/home/ai/syzdirect-runtime/cve")
VM_IMAGE = os.environ.get(
    "SYZDIRECT_VM_IMAGE",
    os.path.join(RUNTIME_BASE, "cve_cve_2025_68205/image-work/bullseye.img"),
)
SSH_KEY = os.environ.get(
    "SYZDIRECT_SSH_KEY",
    os.path.join(RUNTIME_BASE, "cve_cve_2025_68205/image-work/bullseye.id_rsa"),
)


# ──────────────────────────────────────────────────────────────────────────
# Pre-built fuzzing targets
# ──────────────────────────────────────────────────────────────────────────

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
# Shared constants
# ──────────────────────────────────────────────────────────────────────────

HUNT_MODES = ("repro", "harvest", "hybrid")
PIPELINE_STAGES = ["source", "bitcode", "analyze", "target", "distance", "fuzz"]

BOOT_PROFILES = ("default", "boot_safe_x86")
BOOT_SAFE_X86_OVERRIDES = (
    "CONFIG_X86_FRED=n",
    "CONFIG_X86_CET=n",
    "CONFIG_X86_KERNEL_IBT=n",
    "CONFIG_X86_5LEVEL=n",
    "CONFIG_PGTABLE_LEVELS=4",
)

_GENERIC_CONTEXT_TOKENS = {
    "drivers", "driver", "kernel", "linux", "net", "fs", "mm", "arch",
    "core", "common", "generic", "destroy", "create", "setup", "init",
    "sys", "sock", "file", "prog", "device", "dev", "test", "target",
}


# ──────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────

def Q(path):
    """Shell-quote a path for safe embedding in shell commands."""
    return shlex.quote(str(path))


def sh(cmd, check=True, capture=False, big=False):
    """Run a shell command.  big=True for long-running builds (no capture)."""
    import subprocess
    tag = "[BIG] " if big else ""
    print(f"  {tag}$ {cmd}")
    if capture:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and r.returncode != 0:
            print(f"  STDERR: {r.stderr[:500]}")
            raise RuntimeError(f"Command failed: {cmd}")
        return r.stdout.strip()
    subprocess.run(cmd, shell=True, check=check)


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
    def state_file(self, ci=0):     return os.path.join(self.root, "state", f"case_{ci}.json")

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


class BootFallbackRequested(RuntimeError):
    """Raised when the agent loop detects a boot failure and wants to retry."""
    pass
