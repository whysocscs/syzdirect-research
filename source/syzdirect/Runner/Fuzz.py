
import os, json, re, shlex, socket, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import datetime, time
import copy, shutil
import pandas as pd
import Config


# syz-manager stats line pattern:
# 2026/03/17 14:41:12 VMs 1, executed 2, cover 248, signal 285/0, crashes 0, repro 0, dist 42/100
_STATS_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*"
    r"executed (\d+).*cover (\d+).*signal (\d+).*crashes (\d+)"
    r"(?:.*dist (\d+)/(\d+))?"
)


def _parse_stats_line(line):
    """Parse a syz-manager stats line into a metrics dict, or None."""
    m = _STATS_RE.search(line)
    if not m:
        return None
    try:
        ts = int(datetime.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").timestamp())
    except ValueError:
        ts = int(time.time())
    result = {
        "timestamp": ts,
        "exec_total": int(m.group(2)),
        "corpus_cover": int(m.group(3)),
        "signal": int(m.group(4)),
        "crashes": int(m.group(5)),
    }
    if m.group(6) is not None:
        result["dist_min"] = int(m.group(6))
        result["dist_max"] = int(m.group(7))
    return result


def _ensure_syzkaller_ready(syzdirect_path):
    """Use an existing syzkaller build if present; only build when a Makefile exists."""
    manager = os.path.join(syzdirect_path, "bin", "syz-manager")
    if os.path.exists(manager):
        return manager

    makefile_names = ("Makefile", "makefile", "GNUmakefile")
    if any(os.path.exists(os.path.join(syzdirect_path, name)) for name in makefile_names):
        rc = os.system(f"cd {syzdirect_path}; make")
        assert rc == 0, f"failed to build syzdirect_fuzzer in {syzdirect_path}"

    assert os.path.exists(manager), (
        f"syz-manager not found: {manager}. "
        f"Provide a built syzdirect_fuzzer/bin tree or a Makefile-backed source tree."
    )
    return manager


def _alloc_free_tcp_port():
    """Pick an ephemeral TCP port for syz-manager's HTTP endpoint."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.getsockname()[1]


def MultirunFuzzer():
    runItems=[]
    CLEAN_IMAGE_PATH = Config.CleanImageTemplatePath
    syzdirect_path = Config.FuzzerDir

    manager_path = _ensure_syzkaller_ready(syzdirect_path)

    runCount = 1
    for datapoint in Config.datapoints:

        caseIdx=datapoint['idx']
        template_config=Config.LoadJson(Config.TemplateConfigPath)
        assert template_config, "Fail to load fuzzing config template "
        template_config["sshkey"]=Config.KeyPath

        # collect all xidxs
        tfmap=Config.ParseTargetFunctionsInfoFile(caseIdx)
        print(tfmap)

        Config.PrepareDir(Config.getFuzzInpDirPathByCase(caseIdx))

        for xidx in tfmap.keys():
            ### check fuzzinp and kernel image ready to fuzz

            callfile = Config.getFuzzInpDirPathByCaseAndXidx(caseIdx,xidx)

            kernelImage = Config.getInstrumentedKernelImageByCaseAndXidx(caseIdx,xidx)
            assert os.path.exists(callfile), f"[case {caseIdx} xidx {xidx}] fuzz input file not exists, please check!"

            assert os.path.exists(kernelImage), f"[case {caseIdx} xidx {xidx}] bzimage file not exists, please check!"


            workRootDir = Config.getFuzzResultDirByCaseAndXidx(caseIdx, xidx)

            customized_syzkaller=Config.getCustomizedSyzByCaseAndXidx(caseIdx,xidx)
            if os.path.exists(customized_syzkaller):
                syzkaller_path = customized_syzkaller
            else:
                syzkaller_path = syzdirect_path
            os.makedirs(workRootDir, exist_ok=True)


            rounds=Config.FuzzRounds
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Preparing fuzzing for {rounds}")
            for i in range(rounds):
                configPath = os.path.join(workRootDir, f"config{i}")

                subWorkDir = os.path.join(workRootDir, f"run{i}")
                config = copy.deepcopy(template_config)

                shutil.rmtree(subWorkDir, ignore_errors=True)

                config["image"] = CLEAN_IMAGE_PATH
                config["workdir"] = subWorkDir
                config["http"] = f"0.0.0.0:{_alloc_free_tcp_port()}"
                config['vm']['kernel'] = kernelImage
                config['syzkaller'] = syzkaller_path
                config['hitindex']=int(xidx)

                bug_title=datapoint['repro bug title']
                if not pd.isna(bug_title):
                    config['bugdesc']=bug_title


                with open(configPath, "w") as fp:
                    json.dump(config, fp, indent="\t")

                fuzzer_file = manager_path if syzkaller_path == syzdirect_path else os.path.join(
                    syzkaller_path, "bin", "syz-manager")

                runItems.append((fuzzer_file, configPath, callfile))
                runCount += 1


    with ThreadPoolExecutor(max_workers=75) as executor:
        futures = []
        for runArg in runItems:
            futures.append(executor.submit(runFuzzer, *runArg))
            time.sleep(5)
        for future in concurrent.futures.as_completed(futures):
            future.result()


def runFuzzer(fuzzerFile, configPath, callFile, log_dir=None, stall_timeout=0):
    """Run syz-manager. If log_dir is given, capture output to manager.log + metrics.jsonl.

    stall_timeout: seconds of zero coverage growth before early termination (0=disabled).
                   Only active when log_dir is set (agent-loop mode).
    """
    command = f"{fuzzerFile} -config={configPath} -callfile={callFile} -uptime={Config.FuzzUptime}"
    Config.logging.info(f"Start running {command}")

    if log_dir is None:
        rc = os.system(command)
        Config.logging.info(f"Finish running {command} (exit={rc})")
        if rc != 0:
            raise RuntimeError(f"syz-manager exited with status {rc}: {command}")
        return None, None

    os.makedirs(log_dir, exist_ok=True)
    manager_log = os.path.join(log_dir, "manager.log")
    metrics_jsonl = os.path.join(log_dir, "metrics.jsonl")

    with open(manager_log, "w") as log_f, open(metrics_jsonl, "w") as met_f:
        proc = subprocess.Popen(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        saw_metric = False
        qemu_eof_count = 0
        early_boot_failure = False
        stall_terminated = False
        last_cover_growth_ts = time.time()
        peak_cover = 0
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log_f.write(line)
            log_f.flush()
            metric = _parse_stats_line(line)
            if metric:
                saw_metric = True
                met_f.write(json.dumps(metric) + "\n")
                met_f.flush()
                # stall detection: track coverage growth
                if metric["corpus_cover"] > peak_cover:
                    peak_cover = metric["corpus_cover"]
                    last_cover_growth_ts = time.time()
                elif stall_timeout > 0 and peak_cover > 0:
                    stall_seconds = time.time() - last_cover_growth_ts
                    if stall_seconds >= stall_timeout:
                        stall_terminated = True
                        msg = (f"STALL_TIMEOUT: coverage stuck at {peak_cover} "
                               f"for {int(stall_seconds)}s (limit={stall_timeout}s), "
                               f"terminating early\n")
                        log_f.write(msg)
                        log_f.flush()
                        Config.logging.info(msg.strip())
                        proc.terminate()
                        break
            if "failed to create instance: failed to read from qemu: EOF" in line:
                qemu_eof_count += 1
                if not saw_metric and qemu_eof_count >= 6:
                    early_boot_failure = True
                    log_f.write("EARLY_BOOT_FAILURE: repeated qemu EOF before metrics\n")
                    log_f.flush()
                    proc.terminate()
                    break
        proc.wait()

    Config.logging.info(f"Finish running {command} (exit={proc.returncode})")
    if proc.returncode != 0 and not early_boot_failure and not stall_terminated:
        raise RuntimeError(f"syz-manager exited with status {proc.returncode}: {command}")
    return manager_log, metrics_jsonl
