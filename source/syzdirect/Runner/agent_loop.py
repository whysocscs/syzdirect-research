"""
SyzDirect Runner — AgentLoop: fuzz → assess → triage → enhance → re-fuzz.

Multi-round fuzzing loop that automatically triages failures and enhances
syscall templates between rounds. Health assessment, triage logic, and
format converters live in separate modules.
"""

import copy as _copy
import json
import os
import shutil
import sys

from paths import (
    HUNT_MODES, KNOWN_CRASH_DB, RESOURCE_ROOT,
    BootFallbackRequested,
)
from Fuzz import _alloc_free_tcp_port, runFuzzer
from crash_triage import collect_crashes, load_known_crash_db
from agent_health import assess_round_health
from agent_triage import (
    triage_failure, callfile_to_templates, templates_to_callfile,
)
from syscall_scoring import collect_target_context
from llm_enhance import (
    extract_distance_roadmap, llm_enhance_callfile_for_distance,
    read_stepping_stone_sources,
)
from pipeline_new_cve import ensure_target_function_info, load_target_function_map
from runner_config import RunnerConfig


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
    stagnant (not decreasing), classifies the failure as R1/R2/R3/R4 and
    dispatches the appropriate agent to enhance the callfile (syscall
    templates). Then re-fuzzes with the enhanced callfile.
    """

    def __init__(self, layout, target_info, max_rounds, window_seconds,
                 uptime_per_round, cpus, fuzz_rounds=1,
                 hunt_mode="hybrid", known_crash_db=None,
                 allow_boot_fallback=False, stall_timeout=0):
        self.layout = layout
        self.target = target_info
        self.max_rounds = max_rounds
        self.window_seconds = window_seconds
        self.uptime = uptime_per_round
        self.cpus = cpus
        self.fuzz_rounds = fuzz_rounds
        self.ci = target_info["idx"]
        self.hunt_mode = hunt_mode if hunt_mode in HUNT_MODES else "hybrid"
        self.known_rules = load_known_crash_db(KNOWN_CRASH_DB, known_crash_db)
        self.target_context = collect_target_context(
            target_info.get("func_path", ""),
            target_info.get("function", ""),
        )
        self.target_call_names = self._load_current_call_targets()
        self.allow_boot_fallback = allow_boot_fallback
        self.stall_timeout = stall_timeout
        self.best_dist_min_ever = None
        self.dist_history = []

    # ── Main loop ────────────────────────────────────────────────────────

    def run(self):
        for round_num in range(1, self.max_rounds + 1):
            print(f"\n{'=' * 60}")
            print(f"  AGENT ROUND {round_num}/{self.max_rounds}")
            print(f"{'=' * 60}")

            round_dir = os.path.join(
                self.layout.fuzzres_xidx(self.ci),
                f"agent_round_{round_num}",
            )
            shutil.rmtree(round_dir, ignore_errors=True)
            os.makedirs(round_dir, exist_ok=True)

            # ── A. Fuzz ──────────────────────────────────────────────
            manager_log, metrics_jsonl = self._run_fuzz_round(round_dir, round_num)
            crash_summary = self._collect_crashes(round_dir, round_num)

            # ── B. Early success (repro mode only) ───────────────────
            if self._should_stop_early(crash_summary):
                print(f"  Crash summary: {crash_summary['counts']}")
                print(f"  Success condition met for hunt_mode={self.hunt_mode}")
                break
            if crash_summary.get("counts", {}).get("total", 0) > 0:
                print(f"  Crash summary: {crash_summary['counts']}")

            # ── C. Assess health ─────────────────────────────────────
            health = assess_round_health(
                metrics_jsonl, manager_log, crash_summary,
                best_dist_min_ever=self.best_dist_min_ever,
                stall_timeout=self.stall_timeout,
            )
            print(f"  Health: status={health['status']}  score={health['score']:.1f}")
            print(f"  Reason: {health['reason']}")

            # Update cross-round distance tracking
            dist_best = health.get("dist_min_best")
            if dist_best is not None:
                self.dist_history.append(dist_best)
                if self.best_dist_min_ever is None or dist_best < self.best_dist_min_ever:
                    self.best_dist_min_ever = dist_best
                print(f"  Distance: best_this_round={dist_best}  best_ever={self.best_dist_min_ever}")

            if health["status"] == "healthy":
                if round_num < self.max_rounds:
                    print("  Fuzzing is healthy, continuing to next round...")
                continue

            if health["status"] == "boot_failed":
                if self.allow_boot_fallback:
                    raise BootFallbackRequested(health["reason"])
                print("  Boot failed and no fallback retries remain. Stopping.")
                break

            if health["status"] == "fatal":
                print("  FATAL: all target calls disabled. Stopping.")
                break

            # ── D. Triage ────────────────────────────────────────────
            failure_class = triage_failure(
                health, manager_log, crash_summary, self.hunt_mode,
            )
            print(f"  Triage result: {failure_class}")

            if failure_class == "SUCCESS":
                break

            # ── E. Enhance callfile ──────────────────────────────────
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
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()

        ci = self.ci
        template_config = Cfg.LoadJson(Cfg.TemplateConfigPath)
        assert template_config, "Failed to load fuzzing config template"
        template_config["sshkey"] = Cfg.KeyPath

        syzdirect_path = Cfg.FuzzerDir
        tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)
        if not tfmap:
            ensure_target_function_info(
                self.layout.tfinfo(ci),
                self.target["function"],
                self.target["func_path"],
            )
            tfmap = Cfg.ParseTargetFunctionsInfoFile(ci)
        assert tfmap, f"target function map missing for case {ci}: {self.layout.tfinfo(ci)}"

        last_log, last_metrics = None, None

        for xidx in tfmap.keys():
            callfile = self.layout.callfile(ci, xidx)
            kernel_img = self.layout.bzimage(ci, xidx)
            assert os.path.exists(callfile), f"callfile missing: {callfile}"
            assert os.path.exists(kernel_img), f"bzImage missing: {kernel_img}"

            config = _copy.deepcopy(template_config)
            config["image"] = Cfg.CleanImageTemplatePath
            sub_workdir = os.path.join(round_dir, f"workdir_x{xidx}")
            config["workdir"] = sub_workdir
            port = _alloc_free_tcp_port()
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
            if self.stall_timeout > 0:
                print(f"  Stall detection: terminate if coverage stuck for {self.stall_timeout}s")
            last_log, last_metrics = runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
                stall_timeout=self.stall_timeout,
            )

        return last_log, last_metrics

    # ── Crash detection ──────────────────────────────────────────────────

    def _collect_crashes(self, round_dir, round_num):
        return collect_crashes(
            round_dir, round_num, self.hunt_mode, self.known_rules,
            self.target, self.target_context, self.target_call_names,
        )

    def _should_stop_early(self, crash_summary):
        """Only repro mode stops early on a target-related crash."""
        counts = crash_summary.get("counts", {})
        return self.hunt_mode == "repro" and counts.get("target_related", 0) > 0

    # ── Callfile management ──────────────────────────────────────────────

    def _load_current_call_targets(self):
        call_names = set()
        callfile = self.layout.callfile(self.ci)
        if not os.path.exists(callfile):
            return call_names
        try:
            with open(callfile) as f:
                entries = json.load(f)
        except (OSError, json.JSONDecodeError):
            return call_names
        for entry in entries:
            target = entry.get("Target")
            if target:
                call_names.add(target.lower())
                call_names.add(target.split("$", 1)[0].lower())
            for related in entry.get("Relate", []):
                if related:
                    call_names.add(related.lower())
                    call_names.add(related.split("$", 1)[0].lower())
        return call_names

    # ── Template enhancement ─────────────────────────────────────────────

    def _enhance_callfile(self, failure_class, round_dir, round_num):
        """Enhance the callfile using the appropriate agent."""
        callfile_path = self.layout.callfile(self.ci)
        with open(callfile_path) as f:
            current_callfile = json.load(f)

        template_data = callfile_to_templates(current_callfile)
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

        elif failure_class == "R4":
            enhanced_templates = self._enhance_for_distance_stall(
                current_callfile, round_dir, round_num,
            )

        if not enhanced_templates:
            return False

        # R4 returns callfile entries directly; others use template format
        if failure_class == "R4":
            new_callfile = enhanced_templates
        else:
            new_callfile = templates_to_callfile(enhanced_templates)
        if not new_callfile:
            return False

        backup = callfile_path + f".round{round_num}"
        shutil.copyfile(callfile_path, backup)

        merged = list(current_callfile)
        existing_targets = {e["Target"] for e in merged}
        for entry in new_callfile:
            if entry["Target"] not in existing_targets:
                merged.append(entry)
                existing_targets.add(entry["Target"])

        with open(callfile_path, "w") as f:
            json.dump(merged, f, indent="\t")

        self.target_call_names = self._load_current_call_targets()
        return True

    # ── Distance-stall enhancement ──────────────────────────────────────

    def _enhance_for_distance_stall(self, current_callfile, round_dir, round_num):
        """Use LLM with distance roadmap to suggest better syscalls (R4)."""
        ci = self.ci
        dist_dir = self.layout.dist_dir(ci, 0)
        src_dir = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        current_dist = self.best_dist_min_ever

        if not current_dist or current_dist <= 0:
            print("  [R4] No valid distance data, skipping LLM enhancement")
            return None

        print(f"  [R4] Distance stagnant at {current_dist}, building roadmap...")

        roadmap = extract_distance_roadmap(
            dist_dir, target_func, current_dist,
            k2s_path=k2s_path if os.path.exists(k2s_path) else None,
        )
        if not roadmap or not roadmap.get("stepping_stones"):
            print("  [R4] No stepping stones found in roadmap")
            return None

        stones = roadmap["stepping_stones"]
        print(f"  [R4] Roadmap: {len(stones)} stepping stones, "
              f"closest={stones[0]['function']}(dist={stones[0]['distance']}), "
              f"total_in_range={roadmap['total_functions_in_range']}")

        snippets = read_stepping_stone_sources(src_dir, roadmap)
        if snippets:
            print(f"  [R4] Read {snippets.count('---') + 1} source snippets")

        print(f"  [R4] Querying LLM for syscall suggestions...")
        new_entries = llm_enhance_callfile_for_distance(
            current_callfile, roadmap,
            target_func, target_file,
            source_snippets=snippets,
        )

        if not new_entries:
            print("  [R4] LLM returned no usable suggestions")
            return None

        print(f"  [R4] LLM suggested {len(new_entries)} syscall entries")
        return [{"Target": e["Target"], "Relate": e.get("Relate", [])}
                for e in new_entries]

    # ── Summary ──────────────────────────────────────────────────────────

    def _print_summary(self):
        print(f"\n{'=' * 60}")
        print("  AGENT LOOP COMPLETE")
        callfile_path = self.layout.callfile(self.ci)
        print(f"  Final callfile: {callfile_path}")
        fuzzres = self.layout.fuzzres_xidx(self.ci)
        print(f"  Results: {fuzzres}")
        print(f"{'=' * 60}")
