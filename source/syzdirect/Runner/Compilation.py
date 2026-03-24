import Config
import os
import shlex
import shutil
import subprocess

from kernel_build import (
    get_clang_version,
    relax_kernel_build,
    ensure_kcov_support,
    append_build_config,
)


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
        relax_kernel_build(caseSrcDir, Config.ClangPath)

        applykcovcmd=f"cd {Config.Q(caseSrcDir)} && git apply {Config.Q(Config.KcovPatchPath)}"
        if Config.ExecuteCMD(applykcovcmd)[1].find("patch failed") != -1:
            Config.logging.error(f"[case {caseIdx}] Fail to apply kcov patch!!! Please manually apply!!!")
        ensure_kcov_support(caseSrcDir)


        Config.logging.info(f"[case {caseIdx}] Finished preparing source code")




def CompileKernelToBitcodeNormal():
    emit_contents=f'''#!/bin/sh
CLANG={Config.ClangPath}
if [ ! -e $CLANG ]
then
    exit
fi
OFILE=`echo $* | sed -e 's/^.* \\(.*\\.o\\) .*$/\\1/'`
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
        append_build_config(os.path.join(caseBCDir, '.config'))



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
            append_build_config(dst_config)

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
