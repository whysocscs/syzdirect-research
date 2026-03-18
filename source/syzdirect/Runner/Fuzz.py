
import os, json, re, shlex, subprocess
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import datetime, time
import copy, shutil
import pandas as pd
import Config


# syz-manager stats line pattern:
# 2026/03/17 14:41:12 VMs 1, executed 2, cover 248, signal 285/0, crashes 0, repro 0
_STATS_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*"
    r"executed (\d+).*cover (\d+).*signal (\d+).*crashes (\d+)"
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
    return {
        "timestamp": ts,
        "exec_total": int(m.group(2)),
        "corpus_cover": int(m.group(3)),
        "signal": int(m.group(4)),
        "crashes": int(m.group(5)),
    }


def MultirunFuzzer():
    runItems=[]
    CLEAN_IMAGE_PATH = Config.CleanImageTemplatePath
    syzdirect_path = Config.FuzzerDir

    # Build fuzzer once before all runs
    os.system(f"cd {syzdirect_path}; make")

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
                config["http"] = f"0.0.0.0:{2345+runCount}"
                config['vm']['kernel'] = kernelImage
                config['syzkaller'] = syzkaller_path
                config['hitindex']=int(xidx)

                bug_title=datapoint['repro bug title']
                if not pd.isna(bug_title):
                    config['bugdesc']=bug_title


                with open(configPath, "w") as fp:
                    json.dump(config, fp, indent="\t")

                fuzzer_file = os.path.join(syzkaller_path, "bin",
                                        "syz-manager")

                runItems.append((fuzzer_file, configPath, callfile))
                runCount += 1


    with ThreadPoolExecutor(max_workers=75) as executor:
        futures = []
        for runArg in runItems:
            futures.append(executor.submit(runFuzzer, *runArg))
            time.sleep(5)
        for future in concurrent.futures.as_completed(futures):
            future.result()


def runFuzzer(fuzzerFile, configPath, callFile, log_dir=None):
    """Run syz-manager. If log_dir is given, capture output to manager.log + metrics.jsonl."""
    command = f"{fuzzerFile} -config={configPath} -callfile={callFile} -uptime={Config.FuzzUptime}"
    Config.logging.info(f"Start running {command}")

    if log_dir is None:
        os.system(command)
        Config.logging.info(f"Finish running {command}")
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
        for line in proc.stdout:
            log_f.write(line)
            log_f.flush()
            metric = _parse_stats_line(line)
            if metric:
                met_f.write(json.dumps(metric) + "\n")
                met_f.flush()
        proc.wait()

    Config.logging.info(f"Finish running {command} (exit={proc.returncode})")
    return manager_log, metrics_jsonl
