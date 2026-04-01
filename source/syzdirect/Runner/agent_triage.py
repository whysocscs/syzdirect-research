"""
SyzDirect Runner — failure triage and callfile format conversion.

Classifies fuzzing failures as R1/R2/R3/R4 and provides conversion
between callfile JSON format and template_bundle format used by
the agent APIs.
"""

import os


# ──────────────────────────────────────────────────────────────────────────
# Failure classification
# ──────────────────────────────────────────────────────────────────────────

def triage_failure(health, manager_log, crash_summary=None, hunt_mode="hybrid"):
    """Classify failure as R1/R2/R3/R4/SUCCESS using heuristics.

    R1 = fatal/unknown calls — callfile has invalid syscall names
    R2 = argument errors — syscalls run but get EINVAL/EFAULT
    R3 = coverage stagnant — coverage doesn't grow
    R4 = distance stagnant — coverage grows but not getting closer to target
    """
    def _uniq(items):
        out = []
        seen = set()
        for item in items:
            if item and item not in seen:
                out.append(item)
                seen.add(item)
        return out

    crash_counts = (crash_summary or {}).get("counts", {})
    evidence = []
    secondary = []
    if crash_counts.get("target_related", 0) > 0:
        return {"primary": "SUCCESS", "secondary": [], "evidence": ["target-related crash found"]}
    if hunt_mode != "repro" and crash_counts.get("incidental_unknown", 0) > 0:
        # Log incidental crashes but do NOT stop — keep fuzzing toward the target.
        secondary.append("incidental_crash_found")
        evidence.append("new incidental crash found (not target-related, continuing)")

    if health.get("fatal"):
        evidence.append("all target calls disabled")
        return {"primary": "R1", "secondary": [], "evidence": evidence}

    exec_d = health.get("exec_delta", 0)
    cover_d = health.get("cover_delta", 0)

    # R1 when no executions, OR when callfile has unknown calls but
    # fuzzer barely ran (exec_d < 500 means the unknown calls are the
    # main issue). If exec_d is large, unknown calls are just ignored
    # by syz-manager and coverage/distance stall is the real problem.
    unknown_calls = health.get("unknown_input_calls", 0)
    if unknown_calls > 0:
        secondary.append("R1")
        evidence.append(f"unknown input calls={unknown_calls}")
    if exec_d == 0 or (unknown_calls > 0 and exec_d < 500):
        return {"primary": "R1", "secondary": _uniq(secondary), "evidence": evidence}

    einval_count = 0
    if manager_log and os.path.exists(manager_log):
        with open(manager_log) as f:
            log_text = f.read()
            einval_count = log_text.lower().count("einval") + log_text.lower().count("efault")

    if einval_count > 0:
        secondary.append("R2")
        evidence.append(f"einval_or_efault={einval_count}")

    if einval_count > 50:
        return {"primary": "R2", "secondary": _uniq(secondary), "evidence": evidence}

    # R4: distance stagnant — dist_stall_timeout fired OR dist didn't improve
    if (health.get("dist_stagnant") or health.get("dist_stall_terminated")) and exec_d > 500:
        evidence.append(
            f"distance stagnant via {health.get('distance_basis', 'raw')} signal "
            f"(relevant_progs={health.get('relevant_prog_count', 0)})"
        )
        if cover_d == 0:
            secondary.append("R3")
        if health.get("relevant_prog_count", 0) == 0:
            secondary.append("R1")
        return {"primary": "R4", "secondary": _uniq(secondary), "evidence": evidence}

    if cover_d == 0 and exec_d > 100:
        evidence.append("coverage stalled despite executions")
        return {"primary": "R3", "secondary": _uniq(secondary), "evidence": evidence}

    if hunt_mode == "repro" and health.get("target_focus", 0.0) < 0:
        evidence.append("negative target focus in repro mode")
        return {"primary": "R3", "secondary": _uniq(secondary), "evidence": evidence}

    return {"primary": "R3", "secondary": _uniq(secondary), "evidence": evidence}


# ──────────────────────────────────────────────────────────────────────────
# Callfile <-> template format converters
# ──────────────────────────────────────────────────────────────────────────

_RESOURCE_HINTS = {
    "sock": {"socket", "bind", "listen", "connect", "accept", "accept4",
             "send", "sendto", "sendmsg", "sendmmsg", "recv", "recvfrom",
             "recvmsg", "setsockopt", "getsockopt", "shutdown"},
    "fd": {"open", "openat", "creat", "read", "write", "ioctl", "close",
           "fcntl", "fstat", "lseek", "mmap"},
}


def _infer_resource_type(syscall_name):
    """Infer the resource type (sock, fd, etc.) from a syscall name."""
    base = syscall_name.split("$")[0] if "$" in syscall_name else syscall_name
    for rtype, names in _RESOURCE_HINTS.items():
        if base in names:
            return rtype
    return None


def callfile_to_templates(callfile):
    """Convert callfile JSON to template_bundle format for agent APIs."""
    templates = []
    for i, entry in enumerate(callfile):
        target_name = entry.get("Target", "")
        related_names = entry.get("Relate", [])
        base_name = target_name.split("$")[0] if "$" in target_name else target_name
        rtype = _infer_resource_type(target_name)
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
                    "resource_type": _infer_resource_type(r),
                }
                for r in related_names
            ],
            "sequence_order": related_names + [target_name],
        })
    return templates


def templates_to_callfile(templates):
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
