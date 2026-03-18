import Config
import os
import re
import shlex
import shutil
import subprocess

def _configured_clang_version():
    try:
        proc = subprocess.run(
            [Config.ClangPath, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    version_output = proc.stdout
    match = re.search(r"clang version (\d+)\.(\d+)\.(\d+)", version_output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _relax_kernel_clang_version_check(caseSrcDir):
    clang_version = _configured_clang_version()
    if clang_version is None or clang_version >= (15, 0, 0):
        return

    min_tool_version_path = os.path.join(caseSrcDir, "scripts", "min-tool-version.sh")
    if not os.path.exists(min_tool_version_path):
        return

    with open(min_tool_version_path, "r", encoding="utf-8") as f:
        contents = f.read()

    updated = contents.replace("echo 15.0.0", "echo 13.0.0")
    if updated == contents:
        return

    with open(min_tool_version_path, "w", encoding="utf-8") as f:
        f.write(updated)

    Config.logging.info(
        f"Relaxed minimum LLVM version check in {min_tool_version_path} for clang "
        f"{clang_version[0]}.{clang_version[1]}.{clang_version[2]}"
    )


def _relax_kernel_x86_clang_flags(caseSrcDir):
    clang_version = _configured_clang_version()
    if clang_version is None or clang_version >= (15, 0, 0):
        return

    x86_makefile_path = os.path.join(caseSrcDir, "arch", "x86", "Makefile")
    if not os.path.exists(x86_makefile_path):
        return

    with open(x86_makefile_path, "r", encoding="utf-8") as f:
        contents = f.read()

    replacements = {
        "KBUILD_CFLAGS += -mno-fp-ret-in-387": "KBUILD_CFLAGS += $(call cc-option,-mno-fp-ret-in-387)",
        "KBUILD_CFLAGS += -mskip-rax-setup": "KBUILD_CFLAGS += $(call cc-option,-mskip-rax-setup)",
        "KBUILD_CFLAGS += -mstack-protector-guard-reg=$(percpu_seg)": "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-reg=$(percpu_seg))",
        "KBUILD_CFLAGS += -mstack-protector-guard-symbol=__ref_stack_chk_guard": "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard-symbol=__ref_stack_chk_guard)",
        "KBUILD_CFLAGS += -mstack-protector-guard=global": "KBUILD_CFLAGS += $(call cc-option,-mstack-protector-guard=global)",
    }

    updated = contents
    for original, replacement in replacements.items():
        updated = updated.replace(original, replacement)

    if updated == contents:
        return

    with open(x86_makefile_path, "w", encoding="utf-8") as f:
        f.write(updated)

    Config.logging.info(
        f"Relaxed x86 clang-only build flags in {x86_makefile_path} for clang "
        f"{clang_version[0]}.{clang_version[1]}.{clang_version[2]}"
    )


def _relax_kernel_warning_flags(caseSrcDir):
    clang_version = _configured_clang_version()
    if clang_version is None or clang_version >= (15, 0, 0):
        return

    warn_makefile_path = os.path.join(caseSrcDir, "scripts", "Makefile.warn")
    if not os.path.exists(warn_makefile_path):
        return

    with open(warn_makefile_path, "r", encoding="utf-8") as f:
        contents = f.read()

    replacements = {
        "KBUILD_CFLAGS += -Wno-pointer-to-enum-cast": "KBUILD_CFLAGS += $(call cc-disable-warning,pointer-to-enum-cast)",
        "KBUILD_CFLAGS += -Wno-tautological-constant-out-of-range-compare": "KBUILD_CFLAGS += $(call cc-disable-warning,tautological-constant-out-of-range-compare)",
        "KBUILD_CFLAGS += -Wno-unaligned-access": "KBUILD_CFLAGS += $(call cc-disable-warning,unaligned-access)",
        "KBUILD_CFLAGS += -Wno-enum-compare-conditional": "KBUILD_CFLAGS += $(call cc-disable-warning,enum-compare-conditional)",
    }

    updated = contents
    for original, replacement in replacements.items():
        updated = updated.replace(original, replacement)

    if updated == contents:
        return

    with open(warn_makefile_path, "w", encoding="utf-8") as f:
        f.write(updated)

    Config.logging.info(
        f"Relaxed clang warning flags in {warn_makefile_path} for clang "
        f"{clang_version[0]}.{clang_version[1]}.{clang_version[2]}"
    )


def _replace_once(contents, original, replacement):
    if original not in contents:
        return contents, False
    return contents.replace(original, replacement, 1), True


def _ensure_syzdirect_kcov_support(caseSrcDir):
    header_path = os.path.join(caseSrcDir, "include", "linux", "kcov.h")
    source_path = os.path.join(caseSrcDir, "kernel", "kcov.c")

    header_updated = False
    source_updated = False

    if os.path.exists(header_path):
        with open(header_path, "r", encoding="utf-8") as f:
            header = f.read()

        updated = header
        if "void notrace kcov_mark_block(u32 i);" not in updated:
            updated, changed = _replace_once(
                updated,
                "void kcov_remote_stop(void);\n",
                "void kcov_remote_stop(void);\nvoid notrace kcov_mark_block(u32 i);\n",
            )
            header_updated = header_updated or changed
        if "static inline void kcov_mark_block(u32 i) {}" not in updated:
            updated, changed = _replace_once(
                updated,
                "static inline void kcov_remote_stop_softirq(void) {}\n",
                "static inline void kcov_remote_stop_softirq(void) {}\nstatic inline void kcov_mark_block(u32 i) {}\n",
            )
            header_updated = header_updated or changed

        if updated != header:
            with open(header_path, "w", encoding="utf-8") as f:
                f.write(updated)

    if os.path.exists(source_path):
        with open(source_path, "r", encoding="utf-8") as f:
            source = f.read()

        updated = source
        if "#define DISTBLOCKSIZE 300" not in updated:
            updated, changed = _replace_once(
                updated,
                "#define KCOV_WORDS_PER_CMP 4\n",
                "#define KCOV_WORDS_PER_CMP 4\n\n#define DISTBLOCKSIZE 300\n",
            )
            source_updated = source_updated or changed

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
\t\t/* Previously we write pc before updating pos. However, some
\t\t * early interrupt code could bypass check_kcov_mode() check
\t\t * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
\t\t * raised between writing pc and updating pos, the pc could be
\t\t * overitten by the recursive __sanitizer_cov_trace_pc().
\t\t * Update pos before writing pc to avoid such interleaving.
\t\t */
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
                updated,
                count=1,
                flags=re.S,
            )
            source_updated = source_updated or count == 1

        updated, changed = _replace_once(
            updated,
            "if (size < 2 || size > INT_MAX / sizeof(unsigned long))",
            "if (size < DISTBLOCKSIZE / 2 + 2 || size > INT_MAX / sizeof(unsigned long))",
        )
        source_updated = source_updated or changed

        updated, changed = _replace_once(
            updated,
            "\t\tif ((unsigned long)remote_arg->area_size >\n\t\t    LONG_MAX / sizeof(unsigned long))\n\t\t\treturn -EINVAL;\n",
            "\t\tif ((unsigned long)remote_arg->area_size >\n\t\t    LONG_MAX / sizeof(unsigned long) ||\n\t\t    remote_arg->area_size < DISTBLOCKSIZE / 2)\n\t\t\treturn -EINVAL;\n",
        )
        source_updated = source_updated or changed

        updated, changed = _replace_once(
            updated,
            "\t/* Reset coverage size. */\n\t*(u64 *)area = 0;\n",
            "\t/* Reset coverage size. */\n\tif (mode == KCOV_MODE_TRACE_PC) {\n\t\tu32 *dt_area = area;\n\n\t\tdt_area[0] = 0xffffffff;\n\t\tfor (int i = 1; i < DISTBLOCKSIZE + 2; i++)\n\t\t\tdt_area[i] = 0;\n\t} else {\n\t\t*(u64 *)area = 0;\n\t}\n",
        )
        source_updated = source_updated or changed

        if "u32 *dst_dt_entries, *src_dt_entries;" not in updated:
            updated, changed = _replace_once(
                updated,
                "\tvoid *dst_entries, *src_entries;\n",
                "\tvoid *dst_entries, *src_entries;\n\tu32 *dst_dt_entries, *src_dt_entries;\n",
            )
            source_updated = source_updated or changed

        updated, changed = _replace_once(
            updated,
            "\tcase KCOV_MODE_TRACE_PC:\n\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n\t\tsrc_len = *(unsigned long *)src_area;\n\t\tcount_size = sizeof(unsigned long);\n\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n\t\tbreak;\n",
            "\tcase KCOV_MODE_TRACE_PC:\n\t\tdst_dt_entries = dst_area;\n\t\tsrc_dt_entries = src_area;\n\t\tdst_area_size -= DISTBLOCKSIZE / 2;\n\t\tdst_area = dst_dt_entries + DISTBLOCKSIZE;\n\t\tsrc_area = src_dt_entries + DISTBLOCKSIZE;\n\t\tdst_len = READ_ONCE(*(unsigned long *)dst_area);\n\t\tsrc_len = *(unsigned long *)src_area;\n\t\tcount_size = sizeof(unsigned long);\n\t\tentry_size_log = __ilog2_u64(sizeof(unsigned long));\n\t\tbreak;\n",
        )
        source_updated = source_updated or changed

        if "dst_dt_entries[0] =" not in updated:
            updated, changed = _replace_once(
                updated,
                "\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
                "\tif (mode == KCOV_MODE_TRACE_PC) {\n\t\tif (src_dt_entries[0] < dst_dt_entries[0])\n\t\t\tdst_dt_entries[0] = src_dt_entries[0];\n\t\tfor (int i = 1; i < DISTBLOCKSIZE; i++)\n\t\t\tWRITE_ONCE(dst_dt_entries[i], READ_ONCE(dst_dt_entries[i]) + READ_ONCE(src_dt_entries[i]));\n\t}\n\t\n\tdst_occupied = count_size + (dst_len << entry_size_log);\n",
            )
            source_updated = source_updated or changed

        if updated != source:
            with open(source_path, "w", encoding="utf-8") as f:
                f.write(updated)

    if header_updated or source_updated:
        Config.logging.info(
            f"Applied fallback SyzDirect KCOV compatibility patch in {caseSrcDir}"
        )


def _append_kernel_build_config_overrides(config_path):
    disabled_configs = [
        "CONFIG_KASAN",
        "CONFIG_KCSAN",
        "CONFIG_UBSAN",
        "CONFIG_HAVE_DEBUG_KMEMLEAK",
        "CONFIG_DEBUG_INFO",
        "CONFIG_DEBUG_INFO_REDUCED",
        "CONFIG_DEBUG_INFO_COMPRESSED",
        "CONFIG_DEBUG_INFO_SPLIT",
        "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT",
        "CONFIG_DEBUG_INFO_DWARF4",
        "CONFIG_DEBUG_INFO_DWARF5",
        "CONFIG_GDB_SCRIPTS",
    ]
    with open(config_path, "a", encoding="utf-8") as f:
        f.writelines([f"{config}=n\n" for config in disabled_configs])
        f.writelines("\nCONFIG_DEBUG_INFO_NONE=y\n")
        f.writelines("\nCONFIG_KCOV=y\n")


def PrepareSourceCode():
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        kernel_commit=datapoint['kernel commit']
        caseSrcDir=Config.getSrcDirByCase(caseIdx)
        if os.path.exists(caseSrcDir) and not os.path.exists(os.path.join(caseSrcDir, ".git")):
            shutil.rmtree(caseSrcDir, ignore_errors=True)
        if not os.path.exists(caseSrcDir):
            if Config.LinuxSrcTemplate!=None:
                template_git_dir = os.path.join(Config.LinuxSrcTemplate, ".git")
                if os.path.exists(template_git_dir):
                    clonecmd = (
                        f"git clone --local --no-checkout {Config.Q(Config.LinuxSrcTemplate)} "
                        f"{Config.Q(caseSrcDir)}"
                    )
                    Config.ExecuteCMD(clonecmd)
                    if not os.path.exists(caseSrcDir):
                        shutil.copytree(Config.LinuxSrcTemplate,caseSrcDir)
                else:
                    shutil.copytree(Config.LinuxSrcTemplate,caseSrcDir)
            else:
                clonecmd=f'cd {Config.Q(Config.SrcDirRoot)} && git clone https://github.com/torvalds/linux.git case_{caseIdx}'
                Config.ExecuteCMD(clonecmd)
        assert os.path.exists(caseSrcDir)
        
        checkoutcmd=f"cd {Config.Q(caseSrcDir)} && git checkout -f {kernel_commit}"
        Config.ExecuteCMD(checkoutcmd)
        _relax_kernel_clang_version_check(caseSrcDir)
        _relax_kernel_x86_clang_flags(caseSrcDir)
        _relax_kernel_warning_flags(caseSrcDir)
        
        applykcovcmd=f"cd {Config.Q(caseSrcDir)} && git apply {Config.Q(Config.KcovPatchPath)}"
        if Config.ExecuteCMD(applykcovcmd)[1].find("patch failed") != -1:
            Config.logging.error(f"[case {caseIdx}] Fail to apply kcov patch!!! Please manually apply!!!")
        _ensure_syzdirect_kcov_support(caseSrcDir)
        
        
        Config.logging.info(f"[case {caseIdx}] Finished preparing source code")
        
    
    
    
def CompileKernelToBitcodeNormal():
    emit_contents=f'''#!/bin/sh
CLANG={Config.ClangPath}
if [ ! -e $CLANG ]
then
    exit
fi
OFILE=`echo $* | sed -e 's/^.* \(.*\.o\) .*$/\\1/'`
if [ "x$OFILE" != x -a "$OFILE" != "$*" ] ; then
    $CLANG -emit-llvm -g "$@" >/dev/null 2>&1 > /dev/null
    if [ -f "$OFILE" ] ; then
        BCFILE=`echo $OFILE | sed -e 's/o$/llbc/'`
        #file $OFILE | grep -q "LLVM IR bitcode" && mv $OFILE $BCFILE || true
        if [ `file $OFILE | grep -c "LLVM IR bitcode"` -eq 1 ]; then
            mv $OFILE $BCFILE
        else
            touch $BCFILE
        fi
    fi
fi
exec $CLANG "$@"
    
    '''
    if os.path.exists(Config.EmitScriptPath):
        os.remove(Config.EmitScriptPath)
    with open(Config.EmitScriptPath,"w") as f:
        f.write(emit_contents)
    os.chmod(Config.EmitScriptPath,0o775)
    
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        configPath=datapoint['config path']
        caseBCDir=Config.getBitcodeDirByCase(caseIdx)
        
        if IsCompilationSuccessfulByCase(caseBCDir):
            Config.logging.info(f"[case {caseIdx}] Already compiled. Skip")
            continue
        elif os.path.exists(caseBCDir):
            shutil.rmtree(caseBCDir, ignore_errors=True)
        
        Config.logging.info(f"[case {caseIdx}] starting compiling, target output to {caseBCDir}")
        Config.PrepareDir(caseBCDir)
        
        cpcmd=f"cp {Config.Q(configPath)} {Config.Q(os.path.join(caseBCDir, '.config'))}"
        Config.ExecuteCMD(cpcmd)
        _append_kernel_build_config_overrides(os.path.join(caseBCDir, '.config'))

        
        
        compile_command = (
            f"cd {Config.Q(Config.getSrcDirByCase(caseIdx))} && "
            "git checkout -- scripts/Makefile.kcov && "
            "make clean && make mrproper && "
            f"make CC={Config.Q(Config.EmitScriptPath)} O={Config.Q(caseBCDir)} olddefconfig && "
            f"make CC={Config.Q(Config.EmitScriptPath)} O={Config.Q(caseBCDir)} -j{Config.CPUNum}"
        )
        # print(Config.ExecuteCMD(compile_command))
        Config.ExecuteBigCMD(compile_command)
        if IsCompilationSuccessfulByCase(caseBCDir):
            Config.logging.info(f"[case {caseIdx}] Successfully compiled bitcode")
        else:
            Config.logging.info(f"[case {caseIdx}] Error compiling bitcode!!!")
            
        
    
def CompileKernelToBitcodeWithDistance():
    for datapoint in Config.datapoints:
        caseIdx=datapoint['idx']
        configPath=datapoint['config path']
        tfmap=Config.ParseTargetFunctionsInfoFile(caseIdx)
        
        caseKernelRoot=Config.PrepareDir(Config.getInstrumentedKernelDirByCase(caseIdx))
        
        caseSrcDir=Config.getSrcDirByCase(caseIdx)
        for xidx in tfmap.keys():
            tempBuildDir=Config.PrepareDir(os.path.join(caseKernelRoot,"temp_build"))
            targetFunction=tfmap[xidx][0]
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Starting instrumenting kernel with distance")
            dst_config=os.path.join(tempBuildDir,".config")
            currentDistDir=Config.getDistanceResultDir(caseIdx,xidx)
            
            kcov_config = '''# SPDX-License-Identifier: GPL-2.0-only
kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC) += -fsanitize-coverage=trace-pc,second -fsanitize-coverage-kernel-src-dir=%s -fsanitize-coverage-distance-dir=%s -fsanitize-coverage-target-function=%s
kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)    += -fsanitize-coverage=trace-cmp
kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)      += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so

export CFLAGS_KCOV := $(kcov-flags-y)
    '''%(caseSrcDir, currentDistDir, targetFunction)
            with open(os.path.join(caseSrcDir,"scripts/Makefile.kcov"), mode="w") as f:
                f.write(kcov_config)
            mk_cmd=f"cd {Config.Q(caseSrcDir)} && make clean && make mrproper"
            Config.ExecuteCMD(mk_cmd)
            
            shutil.copyfile(configPath,dst_config)
            _append_kernel_build_config_overrides(dst_config)
                
            compile_script = '''#!/bin/sh
cd %s
CC=%s
make ARCH=x86_64 CC="$CC" O=%s olddefconfig
make ARCH=x86_64 CC="$CC" O=%s -j%s
    '''%(
                shlex.quote(caseSrcDir),
                shlex.quote(Config.ClangPath),
                shlex.quote(tempBuildDir),
                shlex.quote(tempBuildDir),
                Config.CPUNum,
            )

            compile_script_path = os.path.join(currentDistDir, "distance_kernel_compile.sh")
            with open(compile_script_path, mode="w") as f:
                f.write(compile_script)
            
            Config.ExecuteBigCMD(f"chmod +x {Config.Q(compile_script_path)}")
            Config.ExecuteBigCMD(Config.Q(compile_script_path))

            targetOutBzimage=os.path.join(tempBuildDir,"arch/x86/boot/bzImage")
            targetVMLinux=os.path.join(tempBuildDir,"vmlinux")
            if not os.path.exists(targetOutBzimage):
                Config.logging.error(f"[case {caseIdx} xidx {xidx}] Fail to instrument kernel with distance!!! Please check!!!!")
                continue
        
            
            shutil.copyfile(targetVMLinux,os.path.join(caseKernelRoot,f"vmlinux_{xidx}"))
            shutil.copyfile(targetOutBzimage,Config.getInstrumentedKernelImageByCaseAndXidx(caseIdx,xidx))
            shutil.rmtree(tempBuildDir)
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Instrument kernel with distance succeed!")
            
            
            
    
    
    

def IsCompilationSuccessfulByCase(caseBCDir):
    bc_bzImage_path = os.path.join(caseBCDir, "arch/x86/boot/bzImage")
    return os.path.exists(caseBCDir) and os.path.exists(bc_bzImage_path)
        
    
    # return all fail cases, [] if all succeed
def IsCompilationSuccessful():
    return [
        datapoint['idx'] for datapoint in Config.datapoints if not IsCompilationSuccessfulByCase(Config.getBitcodeDirByCase(datapoint['idx']))
    ]
