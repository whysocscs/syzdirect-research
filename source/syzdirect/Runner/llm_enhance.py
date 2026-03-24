"""
SyzDirect Runner — LLM-driven syscall analysis and distance roadmap.

Handles all LLM interactions: CVE-based syscall suggestion, distance
roadmap extraction from .dist files, kernel source reading for
stepping-stone functions, and LLM-driven callfile enhancement when
the fuzzer's distance stagnates.
"""

import json
import os
import subprocess

from syscall_normalize import load_syzkaller_call_names, normalize_syscall_name


# ──────────────────────────────────────────────────────────────────────────
# LLM-based CVE analysis
# ──────────────────────────────────────────────────────────────────────────

def llm_analyze_cve(cve_id, kernel_commit, target_function, file_path):
    """Ask Claude for syzkaller syscall suggestions. Returns dict or None."""
    prompt = (
        "You are a Linux kernel security researcher.\n"
        f"CVE: {cve_id}\nKernel commit: {kernel_commit}\n"
        f"Target function: {target_function}\nFile: {file_path}\n\n"
        "Suggest the most relevant syzkaller syscalls to reach this function.\n"
        "Return ONLY valid JSON:\n"
        '{"syscalls": [{"Target": "name$variant", "Relate": ["setup1", "setup2"]}]}\n'
        "Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, "
        "bpf$PROG_LOAD, connect$vsock_stream). 1-3 Target entries, 3-6 Relate each."
    )
    try:
        r = subprocess.run(
            ["claude", "--print", "--model", "haiku", prompt],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            print(f"  [LLM] claude failed: {r.stderr[:200]}")
            return None
        text = r.stdout.strip()
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [LLM] Error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# Distance roadmap extraction
# ──────────────────────────────────────────────────────────────────────────

# Function name prefixes that are noise (tracepoints, debug helpers)
_NOISE_PREFIXES = (
    "__traceiter_", "__trace_", "trace_", "perf_trace_",
    "decompress_", "early_", "__pfx_",
)


def extract_distance_roadmap(dist_dir, target_function, current_dist_min,
                             k2s_path=None, max_stones=12):
    """Build a stepping-stone roadmap from .dist files.

    Returns a dict with target info and a list of intermediate functions
    sorted by distance (ascending, closest to target first).
    """
    if not os.path.isdir(dist_dir):
        return None

    # Parse all .dist files: collect min distance per function
    func_min_dist = {}
    for fname in os.listdir(dist_dir):
        if not fname.endswith(".dist"):
            continue
        fpath = os.path.join(dist_dir, fname)
        try:
            with open(fpath) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    fn, _blk, dist_s = parts[0], parts[1], parts[2]
                    dist = int(dist_s)
                    if fn not in func_min_dist or dist < func_min_dist[fn]:
                        func_min_dist[fn] = dist
        except (OSError, ValueError):
            continue

    # Filter to stepping stones: 0 < dist < current_dist_min
    stones = []
    for fn, d in func_min_dist.items():
        if 0 < d < current_dist_min and fn != target_function:
            stones.append({"function": fn, "distance": d})

    # Filter out noise
    stones = [s for s in stones if not any(
        s["function"].startswith(p) for p in _NOISE_PREFIXES
    )]

    # Sort: prioritize functions related to target (same prefix), then by distance
    target_prefix = target_function.split("_")[0] if "_" in target_function else ""

    def _stone_sort_key(s):
        fn = s["function"]
        related = 0 if (target_prefix and target_prefix in fn) else 1
        return (related, s["distance"])
    stones.sort(key=_stone_sort_key)

    # Sample: keep closest stones + evenly spaced rest
    if len(stones) > max_stones:
        top = stones[:4]
        rest = stones[4:]
        step = len(rest) / (max_stones - 4)
        sampled = [rest[int(i * step)] for i in range(max_stones - 4)]
        stones = top + sampled

    # Annotate with reachable syscalls from k2s
    if k2s_path and os.path.exists(k2s_path):
        try:
            with open(k2s_path) as f:
                k2s = json.load(f)
            for stone in stones:
                syscalls = k2s.get(stone["function"], [])
                stone["reachable_via"] = syscalls[:5] if syscalls else []
        except (OSError, json.JSONDecodeError):
            pass

    return {
        "target_function": target_function,
        "current_dist_min": current_dist_min,
        "stepping_stones": stones,
        "total_functions_in_range": len([
            fn for fn, d in func_min_dist.items()
            if 0 < d < current_dist_min
        ]),
    }


# ──────────────────────────────────────────────────────────────────────────
# Kernel source reading for stepping stones
# ──────────────────────────────────────────────────────────────────────────

def read_stepping_stone_sources(src_dir, roadmap, max_funcs=5, max_lines=40):
    """Read kernel source snippets for stepping-stone functions.

    Returns a string with annotated source excerpts.
    """
    if not roadmap or not roadmap.get("stepping_stones"):
        return ""

    stones = roadmap["stepping_stones"][:max_funcs]
    snippets = []

    for stone in stones:
        fn = stone["function"]
        dist = stone["distance"]
        try:
            result = subprocess.run(
                ["grep", "-rn", f"^[a-zA-Z_].*\\b{fn}\\b", "--include=*.c",
                 "-l", src_dir],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not result.stdout.strip():
            continue

        src_file = result.stdout.strip().split("\n")[0]
        try:
            result2 = subprocess.run(
                ["grep", "-n", f"\\b{fn}\\b", src_file],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        if not result2.stdout.strip():
            continue

        first_line = result2.stdout.strip().split("\n")[0]
        try:
            lineno = int(first_line.split(":")[0])
        except ValueError:
            continue

        try:
            with open(src_file) as f:
                lines = f.readlines()
            start = max(0, lineno - 3)
            end = min(len(lines), lineno + max_lines)
            rel_path = os.path.relpath(src_file, src_dir)
            snippet = f"// {rel_path}:{lineno} (distance={dist})\n"
            snippet += "".join(lines[start:end])
            snippets.append(snippet)
        except OSError:
            continue

    return "\n---\n".join(snippets)


# ──────────────────────────────────────────────────────────────────────────
# LLM-driven callfile enhancement for distance stagnation
# ──────────────────────────────────────────────────────────────────────────

def llm_enhance_callfile_for_distance(current_callfile, roadmap,
                                       target_function, target_file,
                                       source_snippets=""):
    """Ask Claude to suggest better syscalls based on distance roadmap."""
    if not roadmap or not roadmap.get("stepping_stones"):
        return None

    stones_text = "\n".join(
        f"  dist={s['distance']:>6}  {s['function']}"
        + (f"  (reachable via: {', '.join(s['reachable_via'])})"
           if s.get('reachable_via') else "")
        for s in roadmap["stepping_stones"]
    )

    current_dist = roadmap["current_dist_min"]
    closest = roadmap["stepping_stones"][0]

    prompt = f"""You are a Linux kernel security researcher helping a distance-guided fuzzer.

TARGET FUNCTION: {target_function} in {target_file} (distance=0)
CURRENT STATE: Fuzzer's minimum distance is {current_dist}. It has been stuck here.

CURRENT CALLFILE (syscalls being fuzzed):
{json.dumps(current_callfile, indent=2)}

DISTANCE ROADMAP (intermediate functions between fuzzer and target):
{stones_text}

The closest reachable stepping stone is {closest['function']} at distance={closest['distance']}.
There are {roadmap['total_functions_in_range']} functions between current position and target.

{('KERNEL SOURCE (showing how stepping-stone functions are called):' + chr(10) + source_snippets) if source_snippets else ''}

The fuzzer needs syscall sequences that execute kernel code passing through the stepping-stone functions listed above, especially those closest to the target (lowest distance).

Analyze the function names, source code, and call relationships. Think about:
1. What Linux subsystem do the stepping-stone functions belong to?
2. What syscalls trigger those code paths?
3. What setup syscalls are needed (socket creation, device open, etc.)?
4. What sequence of operations would traverse multiple stepping stones?

Return ONLY valid JSON:
{{"syscalls": [{{"Target": "name$variant", "Relate": ["setup1", "setup2", ...]}}], "reasoning": "brief explanation"}}

Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, bpf$PROG_LOAD, connect$vsock_stream, ioctl$KVM_RUN).
Provide 1-4 Target entries with 3-6 Relate syscalls each."""

    try:
        r = subprocess.run(
            ["claude", "--print", "--model", "sonnet", prompt],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            print(f"  [LLM-dist] claude failed: {r.stderr[:200]}")
            return None
        text = r.stdout.strip()
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(text[start:end])
            reasoning = result.pop("reasoning", "")
            if reasoning:
                print(f"  [LLM-dist] Reasoning: {reasoning[:200]}")
            syscalls = result.get("syscalls", [])
            if syscalls:
                validated = []
                for entry in syscalls:
                    target = entry.get("Target", "")
                    normalized = normalize_syscall_name(target, target_file)
                    if normalized:
                        entry["Target"] = normalized
                    relates = []
                    for r_name in entry.get("Relate", []):
                        nr = normalize_syscall_name(r_name, target_file)
                        if nr:
                            relates.append(nr)
                    entry["Relate"] = relates or entry.get("Relate", [])
                    validated.append(entry)
                return validated
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [LLM-dist] Error: {e}")
    return None
