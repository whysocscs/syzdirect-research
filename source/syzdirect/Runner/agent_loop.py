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
    llm_generate_seed_program, read_stepping_stone_sources,
)
from pipeline_new_cve import (
    ensure_target_function_info, load_target_function_map, resolve_prebuilt_target,
)
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
                 allow_boot_fallback=False, stall_timeout=0,
                 dist_stall_timeout=600, seed_corpus=None,
                 proactive_seed=False):
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
        self.dist_stall_timeout = dist_stall_timeout
        self.seed_corpus = seed_corpus  # path to corpus.db for round 1 seeding
        self.proactive_seed = proactive_seed
        self.best_dist_min_ever = None
        self.dist_history = []
        self._sync_target_metadata()

    def _relevant_repeat_threshold(self):
        """Tighten relevant-distance frontier for stateful message/config targets."""
        targets = []
        callfile = self.layout.callfile(self.ci)
        if os.path.exists(callfile):
            try:
                with open(callfile) as f:
                    entries = json.load(f)
                targets = [e.get("Target", "") for e in entries if e.get("Target")]
            except (OSError, json.JSONDecodeError):
                targets = []
        if len(targets) != 1:
            return 1
        base = targets[0].split("$", 1)[0].lower()
        if base in {"sendmsg", "ioctl", "setsockopt", "mount", "bpf"}:
            return 2
        return 1

    def _roadmap_allowed_targets(self, roadmap, current_callfile):
        allowed = set()
        for entry in current_callfile:
            target = entry.get("Target")
            if target:
                allowed.add(target.lower())
                allowed.add(target.split("$", 1)[0].lower())
            for relate in entry.get("Relate", []):
                if relate:
                    allowed.add(relate.lower())
                    allowed.add(relate.split("$", 1)[0].lower())
        for stone in (roadmap or {}).get("stepping_stones", []):
            for call in stone.get("reachable_via", []) or []:
                if call:
                    allowed.add(call.lower())
                    allowed.add(call.split("$", 1)[0].lower())
        return allowed

    def _allow_new_r4_target(self, target, current_callfile, roadmap):
        if not target:
            return False
        current_targets = {e.get("Target", "").lower() for e in current_callfile if e.get("Target")}
        target_l = target.lower()
        if target_l in current_targets:
            return True
        target_base = target_l.split("$", 1)[0]
        # Do not broaden from a specific current variant to a generic base call
        # during R4 unless that exact generic call is already grounded in the roadmap.
        if "$" not in target_l:
            for existing in current_targets:
                if "$" in existing and existing.split("$", 1)[0] == target_base:
                    return False
        allowed = self._roadmap_allowed_targets(roadmap, current_callfile)
        return target_l in allowed

    def _sync_target_metadata(self):
        resolved = resolve_prebuilt_target(self.layout, self.target)
        self.target.update(resolved)
        tfinfo_path = self.layout.tfinfo(self.ci)
        func = self.target.get("function", "")
        func_path = self.target.get("func_path", "")
        if func and func_path:
            ensure_target_function_info(tfinfo_path, func, func_path)
        self.target_context = collect_target_context(
            self.target.get("func_path", ""),
            self.target.get("function", ""),
        )

    def _seed_matches_target(self, seed_db):
        if not seed_db:
            return False
        expected = (self.target.get("function") or "").strip().lower()
        if not expected:
            return True
        basename = os.path.basename(seed_db).lower()
        return expected in basename

    # ── Main loop ────────────────────────────────────────────────────────

    def run(self):
        if self.proactive_seed and self.seed_corpus is None:
            self._generate_proactive_seed()

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
            manager_log, metrics_jsonl, detail_corpus = self._run_fuzz_round(round_dir, round_num)
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
                detail_corpus_path=detail_corpus,
                relevant_call_names=self.target_call_names,
                relevant_repeat_threshold=self._relevant_repeat_threshold(),
            )
            print(f"  Health: status={health['status']}  score={health['score']:.1f}")
            print(f"  Reason: {health['reason']}")

            # Update cross-round distance tracking
            # Only update best_dist_min_ever with real non-zero values;
            # dist_best==0 means target reached (skip LLM), but a false 0
            # from warmup metrics would permanently block LLM enhancement.
            dist_best = health.get("effective_dist_min_best")
            if dist_best is not None:
                self.dist_history.append(dist_best)
                if dist_best > 0:
                    if self.best_dist_min_ever is None or dist_best < self.best_dist_min_ever:
                        self.best_dist_min_ever = dist_best
                raw_best = health.get("dist_min_best")
                relevant_best = health.get("relevant_dist_min_best")
                if relevant_best is not None:
                    print(f"  Distance: best_this_round={dist_best}  raw_best={raw_best}  best_ever={self.best_dist_min_ever}")
                else:
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
            triage_result = triage_failure(
                health, manager_log, crash_summary, self.hunt_mode,
            )
            failure_class = triage_result.get("primary", "R3")
            print(f"  Triage result: {failure_class}")
            if triage_result.get("secondary"):
                print(f"  Secondary signals: {triage_result['secondary']}")
            for ev in triage_result.get("evidence", []):
                print(f"    · {ev}")

            if failure_class == "SUCCESS":
                break

            # ── E. Enhance callfile ──────────────────────────────────
            if round_num < self.max_rounds:
                enhanced = self._enhance_callfile(triage_result, round_dir, round_num)
                if enhanced:
                    print(f"  Callfile enhanced for next round.")
                else:
                    print("  No enhancement produced, continuing to next round anyway.")
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
            if self.dist_stall_timeout > 0:
                print(f"  Dist stall detection: terminate if dist_min stuck for {self.dist_stall_timeout}s")
            last_log, last_metrics = runFuzzer(
                fuzzer_file, config_path, callfile, log_dir=log_dir,
                stall_timeout=self.stall_timeout,
                dist_stall_timeout=self.dist_stall_timeout,
                seed_corpus=self.seed_corpus,
            )

        detail_corpus = os.path.join(sub_workdir, "detailCorpus.txt")
        return last_log, last_metrics, detail_corpus

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

    def _enhance_callfile(self, triage_result, round_dir, round_num):
        """Enhance the callfile using the appropriate agent."""
        failure_class = triage_result.get("primary", "R3")
        callfile_path = self.layout.callfile(self.ci)
        with open(callfile_path) as f:
            current_callfile = json.load(f)

        template_data = callfile_to_templates(current_callfile)
        agent_input = {
            "failure_class": failure_class,
            "evidence": [f"Agent loop round {round_num} triage: {failure_class}"] + triage_result.get("evidence", []),
            "recommended_actions": [],
        }

        enhanced_templates = None
        _ensure_agent_imports()

        if failure_class in ("R3", "R1"):
            print(f"  [{failure_class}] Using RelatedSyscallAgent (rule-based syscall discovery)")
            print(f"  [{failure_class}] Current targets: {[e.get('Target') for e in current_callfile]}")
            try:
                from source.agent.related_syscall_agent import RelatedSyscallAgent
                agent = RelatedSyscallAgent(
                    template_data=template_data,
                    triage_result=agent_input,
                )
                enhanced_templates = agent.analyze_and_enhance()
                print(f"  [{failure_class}] RelatedSyscallAgent produced {len(enhanced_templates)} templates")
                for t in enhanced_templates:
                    entry = t.get("entry_syscall", {})
                    related = [s.get("syzlang_name", s.get("name", "")) for s in t.get("related_syscalls", [])]
                    print(f"    → {entry.get('syzlang_name', entry.get('name', '?'))}  relate={related}")
            except Exception as e:
                print(f"  WARNING: RelatedSyscallAgent failed: {e}")

        elif failure_class == "R2":
            try:
                from source.agent.object_synthesis_agent import ObjectSynthesisAgent
                image_dir = os.path.join(round_dir, "images")
                agent = ObjectSynthesisAgent(
                    triage_result=agent_input,
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
            # R4 failed → fallback to R1 (related syscall discovery)
            if not enhanced_templates:
                print("  [R4] LLM roadmap failed, falling back to R1 (related syscalls)")
                failure_class = "R1"
                agent_input["failure_class"] = "R1"
                print(f"  [R1-fallback] Current targets: {[e.get('Target') for e in current_callfile]}")
                try:
                    from source.agent.related_syscall_agent import RelatedSyscallAgent
                    agent = RelatedSyscallAgent(
                        template_data=template_data,
                        triage_result=agent_input,
                    )
                    enhanced_templates = agent.analyze_and_enhance()
                    print(f"  [R1-fallback] RelatedSyscallAgent produced {len(enhanced_templates)} templates")
                    for t in enhanced_templates:
                        entry = t.get("entry_syscall", {})
                        related = [s.get("syzlang_name", s.get("name", "")) for s in t.get("related_syscalls", [])]
                        print(f"    → {entry.get('syzlang_name', entry.get('name', '?'))}  relate={related}")
                except Exception as e:
                    print(f"  WARNING: RelatedSyscallAgent fallback failed: {e}")

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
        merged_by_target = {e["Target"]: e for e in merged if e.get("Target")}
        added = []
        updated = []
        for entry in new_callfile:
            target = entry.get("Target")
            if not target:
                continue
            if target not in merged_by_target:
                merged.append(entry)
                merged_by_target[target] = entry
                added.append(entry)
                continue

            existing = merged_by_target[target]
            before = list(existing.get("Relate", []))
            seen = set(before)
            merged_related = list(before)
            for relate in entry.get("Relate", []):
                if relate and relate != target and relate not in seen:
                    merged_related.append(relate)
                    seen.add(relate)
            if merged_related != before:
                existing["Relate"] = merged_related
                updated.append({
                    "Target": target,
                    "Before": before,
                    "After": merged_related,
                })

        if added:
            print(f"  [enhance] Before: {[e['Target'] for e in current_callfile]}")
            print(f"  [enhance] Adding {len(added)} new entries:")
            for entry in added:
                print(f"    + Target: {entry['Target']}  Relate: {entry.get('Relate', [])}")
            print(f"  [enhance] After: {[e['Target'] for e in merged]}")
        if updated:
            print(f"  [enhance] Updated {len(updated)} existing target(s):")
            for entry in updated:
                print(f"    ~ Target: {entry['Target']}  Relate: {entry['After']}")
        if not added and not updated:
            print(f"  [enhance] No new entries (all duplicates of existing targets)")

        with open(callfile_path, "w") as f:
            json.dump(merged, f, indent="\t")

        self.target_call_names = self._load_current_call_targets()
        return True

    # ── Proactive seed generation ────────────────────────────────────────

    def _generate_proactive_seed(self):
        """Generate LLM seed corpus BEFORE Round 1 using static dist analysis only.

        Reads the dist_dir (static analysis output) and callfile, builds a full
        roadmap of all functions between the entry and target, then asks the LLM
        to synthesize seed programs. Sets self.seed_corpus so Round 1 starts with
        an empty corpus and the seeds become the mutation foundation.
        """
        ci = self.ci
        self._sync_target_metadata()
        dist_dir = self.layout.dist_dir(ci, 0)
        src_dir = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        callfile_path = self.layout.callfile(ci)
        print(f"  [proactive] Target metadata: function={target_func} file={target_file}")

        if not os.path.isdir(dist_dir):
            print(f"  [proactive] No dist_dir at {dist_dir}, skipping proactive seed")
            return

        print(f"  [proactive] Building static roadmap for {target_func}...")

        # Use large current_dist so all functions are included as stepping stones
        roadmap = extract_distance_roadmap(
            dist_dir, target_func, current_dist_min=99999,
            k2s_path=k2s_path if os.path.exists(k2s_path) else None,
        )

        if not roadmap:
            print("  [proactive] No roadmap from dist files, skipping proactive seed")
            return

        stones = roadmap.get("stepping_stones", [])
        print(f"  [proactive] Static roadmap: {len(stones)} stepping stones, "
              f"total_in_range={roadmap['total_functions_in_range']}")
        if stones:
            print(f"  [proactive] Closest stone: {stones[0]['function']}(dist={stones[0]['distance']})")

        current_callfile = []
        if os.path.exists(callfile_path):
            try:
                with open(callfile_path) as f:
                    current_callfile = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        snippets = ""
        if stones:
            snippets = read_stepping_stone_sources(src_dir, roadmap)
            if snippets:
                print(f"  [proactive] Read {snippets.count('---') + 1} source snippets")

        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()
        syz_db_path = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
        seed_out_dir = self.layout.fuzzres_xidx(ci)

        print("  [proactive] Querying LLM for seed programs...")
        seed_db = llm_generate_seed_program(
            roadmap=roadmap,
            source_snippets=snippets,
            target_function=target_func,
            target_file=target_file,
            current_callfile=current_callfile,
            syz_db_path=syz_db_path,
            output_dir=seed_out_dir,
        )
        if seed_db and self._seed_matches_target(seed_db):
            print(f"  [proactive] Seed corpus ready: {seed_db}")
            self.seed_corpus = seed_db
        elif seed_db:
            print(f"  [proactive] Rejecting inconsistent seed corpus: {seed_db}")
        else:
            print("  [proactive] Seed generation failed, Round 1 starts with empty corpus")

    # ── Distance-stall enhancement ──────────────────────────────────────

    def _enhance_for_distance_stall(self, current_callfile, round_dir, round_num):
        """Use LLM with distance roadmap to suggest better syscalls (R4)."""
        ci = self.ci
        self._sync_target_metadata()
        dist_dir = self.layout.dist_dir(ci, 0)
        src_dir = self.layout.src(ci)
        k2s_path = self.layout.k2s(ci)
        target_func = self.target.get("function", "")
        target_file = self.target.get("func_path", "")
        current_dist = self.best_dist_min_ever
        print(f"  [R4] Target metadata: function={target_func} file={target_file}")

        if not current_dist or current_dist <= 0:
            print("  [R4] No valid distance data, skipping LLM enhancement")
            return None

        print(f"  [R4] Distance stagnant at {current_dist}, building roadmap...")

        roadmap = extract_distance_roadmap(
            dist_dir, target_func, current_dist,
            k2s_path=k2s_path if os.path.exists(k2s_path) else None,
        )

        snippets = ""
        if roadmap and roadmap.get("stepping_stones"):
            stones = roadmap["stepping_stones"]
            print(f"  [R4] Roadmap: {len(stones)} stepping stones, "
                  f"closest={stones[0]['function']}(dist={stones[0]['distance']}), "
                  f"total_in_range={roadmap['total_functions_in_range']}")
            snippets = read_stepping_stone_sources(src_dir, roadmap)
            if snippets:
                print(f"  [R4] Read {snippets.count('---') + 1} source snippets")
        else:
            print("  [R4] No stepping stones, will query LLM with CVE context only")
            # Build minimal roadmap so LLM still gets context
            roadmap = {
                "target_function": target_func,
                "current_dist_min": current_dist,
                "stepping_stones": [],
                "total_functions_in_range": 0,
            }

        print(f"  [R4] Querying LLM for syscall suggestions...")
        new_entries = llm_enhance_callfile_for_distance(
            current_callfile, roadmap,
            target_func, target_file,
            source_snippets=snippets,
        )

        if new_entries:
            filtered = []
            for entry in new_entries:
                target = entry.get("Target", "")
                related = [r for r in entry.get("Relate", []) if r and r != target]
                if not target:
                    continue
                if not self._allow_new_r4_target(target, current_callfile, roadmap):
                    continue
                filtered.append({"Target": target, "Relate": related})
            new_entries = filtered

        if not new_entries:
            print("  [R4] LLM returned no usable suggestions")
            new_entries = []
        else:
            print(f"  [R4] LLM suggested {len(new_entries)} syscall entries")

        # ── Also generate seed corpus via LLM ────────────────────────────
        print(f"  [R4] Generating LLM seed programs for next round...")
        rcfg = RunnerConfig(self.layout, self.cpus, self.uptime, self.fuzz_rounds)
        Cfg = rcfg.apply_to_legacy_config()
        syz_db_path = os.path.join(Cfg.FuzzerDir, "bin", "syz-db")
        seed_out_dir = self.layout.fuzzres_xidx(ci)

        seed_db = llm_generate_seed_program(
            roadmap=roadmap,
            source_snippets=snippets,
            target_function=target_func,
            target_file=target_file,
            current_callfile=current_callfile,
            syz_db_path=syz_db_path,
            output_dir=seed_out_dir,
        )
        if seed_db and self._seed_matches_target(seed_db):
            print(f"  [R4] Seed corpus generated: {seed_db}")
            self.seed_corpus = seed_db
        elif seed_db:
            print(f"  [R4] Rejecting inconsistent seed corpus: {seed_db}")
        else:
            print(f"  [R4] Seed corpus generation failed, continuing without seed")

        if not new_entries:
            return None

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
