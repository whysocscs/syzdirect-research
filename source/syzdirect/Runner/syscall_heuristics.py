"""
SyzDirect Runner — syscall heuristics (backward-compatible re-export).

All functionality has been split into focused modules:
  - syscall_normalize: name normalization, callfile normalization
  - syscall_scoring: context scoring, narrowing, heuristic guessing
  - llm_enhance: LLM calls, distance roadmap, source reading

This file re-exports everything for backward compatibility.
"""

# ── syscall_normalize ────────────────────────────────────────────────────
from syscall_normalize import (  # noqa: F401
    load_syzkaller_call_names,
    normalize_callfile_entries,
    normalize_syscall_name,
)

# ── syscall_scoring ──────────────────────────────────────────────────────
from syscall_scoring import (  # noqa: F401
    collect_target_context,
    guess_syscalls,
    narrow_callfile_entries,
    subsystem_prep_syscalls,
)

# ── llm_enhance ──────────────────────────────────────────────────────────
from llm_enhance import (  # noqa: F401
    extract_distance_roadmap,
    llm_analyze_cve,
    llm_enhance_callfile_for_distance,
    read_stepping_stone_sources,
)
