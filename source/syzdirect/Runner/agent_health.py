"""
SyzDirect Runner — fuzzing health assessment.

Standalone function that scores a fuzzing round using metrics, logs,
and crash data. Extracted from AgentLoop._assess_health() to enable
unit testing and reuse.
"""

import json
import os


def assess_round_health(metrics_jsonl, manager_log, crash_summary=None,
                        best_dist_min_ever=None, stall_timeout=0):
    """Score a fuzzing round and determine its health status.

    Args:
        metrics_jsonl: Path to metrics JSONL file from syz-manager.
        manager_log: Path to syz-manager log file.
        crash_summary: Dict with crash counts from crash_triage.
        best_dist_min_ever: Previous best minimum distance (cross-round).
        stall_timeout: Stall timeout in seconds (0 = disabled).

    Returns:
        Dict with status, score, reason, and detailed metrics.
        status is one of: "healthy", "stagnant", "boot_failed", "fatal"
    """
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

    qemu_eof = "failed to create instance: failed to read from qemu: eof" in log_text
    stall_terminated = "stall_timeout:" in log_text

    if not metrics:
        if qemu_eof:
            return {"status": "boot_failed", "score": -9.0,
                    "reason": "qemu EOF during guest boot", "metrics": []}
        return {"status": "stagnant", "score": -5.0,
                "reason": "no metrics collected", "metrics": []}

    first, last = metrics[0], metrics[-1]

    exec_delta = max(0, last.get("exec_total", 0) - first.get("exec_total", 0))
    cover_delta = max(0, last.get("corpus_cover", 0) - first.get("corpus_cover", 0))
    crash_delta = max(0, last.get("crashes", 0) - first.get("crashes", 0))
    elapsed = max(1, last.get("timestamp", 0) - first.get("timestamp", 0))

    avg_exec = exec_delta / elapsed
    avg_cover = cover_delta / elapsed

    score = 0.0
    score += min(avg_exec / 5.0, 5.0)
    score += min(avg_cover, 3.0)
    score -= min((crash_delta / elapsed) * 30.0, 5.0)

    fatal = "all target calls are disabled" in log_text
    unknown_input_calls = log_text.count("unknown input call")
    machine_check_failed = "machine check failed" in log_text
    target_focus = 0.0
    crash_counts = (crash_summary or {}).get("counts", {})
    target_focus += crash_counts.get("target_related", 0) * 3.0
    target_focus += crash_counts.get("incidental", 0) * 0.5
    target_focus -= crash_counts.get("infra", 0) * 1.5
    target_focus -= unknown_input_calls * 0.25

    # ── Distance tracking ────────────────────────────────────────────
    dist_vals = [m["dist_min"] for m in metrics if "dist_min" in m]
    dist_min_first = dist_vals[0] if dist_vals else None
    dist_min_last = dist_vals[-1] if dist_vals else None
    dist_min_best = min(dist_vals) if dist_vals else None

    dist_stagnant = False
    if dist_min_best is not None and dist_min_best > 0:
        if best_dist_min_ever is not None:
            dist_stagnant = dist_min_best >= best_dist_min_ever
        elif len(dist_vals) > 5:
            dist_stagnant = dist_min_last >= dist_min_first

    # ── Status determination ─────────────────────────────────────────
    status = "healthy"
    reason = "fuzzing is progressing"

    if fatal:
        status = "fatal"
        reason = "all target calls are disabled"
        score -= 10.0
    elif machine_check_failed:
        status = "stagnant"
        reason = "machine check failed before stable coverage"
    elif exec_delta == 0:
        status = "stagnant"
        reason = "execution count did not increase"
    elif stall_terminated:
        status = "stagnant"
        reason = f"coverage stalled for stall_timeout ({stall_timeout}s), terminated early"
    elif cover_delta == 0 and exec_delta > 100:
        status = "stagnant"
        reason = "coverage stalled despite executions"
    elif dist_stagnant and exec_delta > 500 and cover_delta > 0:
        status = "stagnant"
        reason = f"distance stagnant at {dist_min_best} (coverage grows but not getting closer to target)"

    return {
        "status": status, "score": score, "reason": reason,
        "exec_delta": exec_delta, "cover_delta": cover_delta,
        "crash_delta": crash_delta, "elapsed": elapsed,
        "total_exec": last.get("exec_total", 0),
        "total_cover": last.get("corpus_cover", 0),
        "total_crashes": last.get("crashes", 0),
        "fatal": fatal, "metrics": metrics,
        "stall_terminated": stall_terminated,
        "unknown_input_calls": unknown_input_calls,
        "machine_check_failed": machine_check_failed,
        "qemu_eof": qemu_eof,
        "target_focus": target_focus,
        "crash_counts": crash_counts,
        "dist_min_first": dist_min_first,
        "dist_min_last": dist_min_last,
        "dist_min_best": dist_min_best,
        "dist_stagnant": dist_stagnant,
    }
