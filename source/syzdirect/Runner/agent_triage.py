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
    crash_counts = (crash_summary or {}).get("counts", {})
    if crash_counts.get("target_related", 0) > 0:
        return "SUCCESS"
    if hunt_mode != "repro" and crash_counts.get("incidental_unknown", 0) > 0:
        return "SUCCESS"

    if health.get("fatal"):
        return "R1"

    exec_d = health.get("exec_delta", 0)
    cover_d = health.get("cover_delta", 0)

    if exec_d == 0 or health.get("unknown_input_calls", 0) > 0:
        return "R1"

    einval_count = 0
    if manager_log and os.path.exists(manager_log):
        with open(manager_log) as f:
            log_text = f.read()
            einval_count = log_text.lower().count("einval") + log_text.lower().count("efault")

    if einval_count > 50:
        return "R2"

    # R4: distance stagnant — coverage grows but not getting closer
    if health.get("dist_stagnant") and exec_d > 500:
        return "R4"

    if cover_d == 0 and exec_d > 100:
        return "R3"

    if hunt_mode == "repro" and health.get("target_focus", 0.0) < 0:
        return "R3"

    return "R3"


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
