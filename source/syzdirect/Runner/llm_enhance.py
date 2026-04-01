"""
SyzDirect Runner — LLM-driven syscall analysis and distance roadmap.

Handles all LLM interactions: CVE-based syscall suggestion, distance
roadmap extraction from .dist files, kernel source reading for
stepping-stone functions, and LLM-driven callfile enhancement when
the fuzzer's distance stagnates.
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import re

from syscall_normalize import load_syzkaller_call_names, normalize_syscall_name


def _edit_distance(a, b):
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _fuzzy_kind_match(target_kind, all_kinds):
    """Find a kind in all_kinds within edit distance 2 of target_kind."""
    for k in all_kinds:
        if _edit_distance(k, target_kind) <= 2:
            return target_kind  # target_kind is the canonical name
    return None


# ──────────────────────────────────────────────────────────────────────────
# LLM backend — OpenAI via opencode
# ──────────────────────────────────────────────────────────────────────────

_OPENCODE_MODEL = os.environ.get("SYZDIRECT_LLM_MODEL", "openai/gpt-5.4-mini")


def _call_llm(prompt, timeout=180):
    """Call LLM via opencode (OpenAI). Returns response text or None."""
    opencode = shutil.which("opencode")
    if opencode:
        try:
            r = subprocess.run(
                [opencode, "run", "--model", _OPENCODE_MODEL, "--format", "json", prompt],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode == 0:
                text_parts = []
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if ev.get("type") == "text":
                            part_text = ev.get("part", {}).get("text", "")
                            if part_text:
                                text_parts.append(part_text)
                    except json.JSONDecodeError:
                        pass
                if text_parts:
                    return "".join(text_parts)
            else:
                print(f"  [LLM] opencode failed: {r.stderr[:200]}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [LLM] opencode error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# LLM-based CVE analysis
# ──────────────────────────────────────────────────────────────────────────

def llm_analyze_cve(cve_id, kernel_commit, target_function, file_path):
    """Ask LLM for syzkaller syscall suggestions. Returns dict or None."""
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
        text = _call_llm(prompt, timeout=120)
        if text:
            start, end = text.find("{"), text.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
    except json.JSONDecodeError as e:
        print(f"  [LLM] JSON parse error: {e}")
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
    """Ask the LLM to suggest better syscalls based on distance roadmap."""
    if not roadmap:
        return None

    stones = roadmap.get("stepping_stones", [])
    current_dist = roadmap["current_dist_min"]

    if stones:
        stones_text = "\n".join(
            f"  dist={s['distance']:>6}  {s['function']}"
            + (f"  (reachable via: {', '.join(s['reachable_via'])})"
               if s.get('reachable_via') else "")
            for s in stones
        )
        closest = stones[0]
        roadmap_section = f"""DISTANCE ROADMAP (intermediate functions between fuzzer and target):
{stones_text}

The closest reachable stepping stone is {closest['function']} at distance={closest['distance']}.
There are {roadmap['total_functions_in_range']} functions between current position and target."""
    else:
        roadmap_section = (
            "No stepping-stone functions were found in the distance files. "
            "The fuzzer may not be reaching any functions close to the target. "
            "You must reason about the kernel subsystem from the target function "
            "name and file path to suggest syscalls."
        )

    prompt = f"""You are a Linux kernel security researcher helping a distance-guided fuzzer.

TARGET FUNCTION: {target_function} in {target_file} (distance=0)
CURRENT STATE: Fuzzer's minimum distance is {current_dist}. It has been stuck here.

CURRENT CALLFILE (syscalls being fuzzed):
{json.dumps(current_callfile, indent=2)}

{roadmap_section}

{('KERNEL SOURCE (showing how stepping-stone functions are called):' + chr(10) + source_snippets) if source_snippets else ''}

The fuzzer needs syscall sequences that execute kernel code paths leading to {target_function}.

Analyze the target function name, file path, and current syscalls. Think about:
1. What Linux subsystem does {target_file} belong to?
2. What syscalls trigger code paths in that subsystem?
3. What setup syscalls are needed (device open, socket creation, mount, etc.)?
4. What sequence of operations would reach {target_function}?
5. Are the current syscalls even in the right subsystem? If not, suggest completely different ones.

Return ONLY valid JSON:
{{"syscalls": [{{"Target": "name$variant", "Relate": ["setup1", "setup2", ...]}}], "reasoning": "brief explanation"}}

Use exact syzkaller naming (e.g. sendmsg$nl_route_sched, setsockopt$packet_fanout, bpf$PROG_LOAD, connect$vsock_stream, ioctl$KVM_RUN).
Provide 1-4 Target entries with 3-6 Relate syscalls each."""

    try:
        text = _call_llm(prompt, timeout=180)
        if not text:
            return None
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(text[start:end])
            reasoning = result.pop("reasoning", "")
            if reasoning:
                print(f"  [LLM-dist] Reasoning: {reasoning}")
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
                validated = _validate_r4_entries(validated, current_callfile, roadmap)
                return validated
    except json.JSONDecodeError as e:
        print(f"  [LLM-dist] JSON parse error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────
# Python-based TC netlink seed generator (reliable fallback)
# ──────────────────────────────────────────────────────────────────────────

def _nlattr_u32(attr_type, value):
    return struct.pack("<HHI", 8, attr_type, value)


def _nlattr_u16(attr_type, value):
    return struct.pack("<HHH", 6, attr_type, value) + b"\x00\x00"


def _nlattr_bytes(attr_type, data):
    payload = data
    nla_len = 4 + len(payload)
    padded = payload + (b"\x00" * ((4 - (len(payload) % 4)) % 4))
    return struct.pack("<HH", nla_len, attr_type) + padded


def _prio_qdisc_options():
    """Build TCA_OPTIONS for prio qdisc (required or prio_tune returns -EINVAL).

    struct tc_prio_qopt { int bands; __u8 priomap[TC_PRIO_MAX+1]; }
    3 bands, standard priomap.
    """
    prio_qopt = struct.pack('<I', 3) + bytes([1,2,2,2,1,2,0,0,1,1,1,1,1,1,1,1])
    return _nlattr_bytes(2, prio_qopt)


def _build_netlink_tc_seed(kind, msg_type, ifindex=1, parent=0xffff0000,
                           handle=0, info=0, extra_attrs=b""):
    """Build a valid RTM_NEWQDISC or RTM_NEWTFILTER netlink message bytes.

    kind: TC kind string (e.g. "tcindex", "pfifo", "tbf")
    msg_type: 0x24=RTM_NEWQDISC, 0x2c=RTM_NEWTFILTER, 0x25=RTM_CHANGEQDISC
    Returns hex string suitable for ANYBLOB.
    """
    kind_bytes = kind.encode() + b'\x00'
    tca_kind = _nlattr_bytes(1, kind_bytes)  # TCA_KIND

    # Auto-add required TCA_OPTIONS for qdiscs that need them
    if msg_type == 0x24 and kind == "prio" and not extra_attrs:
        extra_attrs = _prio_qdisc_options()

    # tcmsg: family(1) + pad(3) + ifindex(4le) + handle(4le) + parent(4le) + info(4le)
    tcmsg = struct.pack('<BBBBIIII', 0, 0, 0, 0, ifindex, handle, parent, info)

    # nlmsghdr: len(4le) + type(2le) + flags(2le) + seq(4le) + pid(4le)
    flags = 0x0405  # NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    body = tcmsg + tca_kind + extra_attrs
    total_len = 16 + len(body)
    nlmsghdr = struct.pack('<IHHII', total_len, msg_type, flags, 1, 0)

    return (nlmsghdr + body).hex()


def _build_tcindex_filter_seed(ifindex=1, parent=0x00010000, prio=1,
                               protocol=3, handle=1, hash_size=16,
                               mask=15, shift=0, fall_through=1,
                               classid=None, msg_type=0x2c):
    """Build RTM_NEWTFILTER message that carries tcindex options.

    This favors the perfect-hash path: hash > (mask >> shift).
    """
    info = ((prio & 0xffff) << 16) | (protocol & 0xffff)
    tcindex_opts = b"".join([
        _nlattr_u32(1, hash_size),        # TCA_TCINDEX_HASH
        _nlattr_u16(2, mask),             # TCA_TCINDEX_MASK
        _nlattr_u32(3, shift),            # TCA_TCINDEX_SHIFT
        _nlattr_u32(4, fall_through),     # TCA_TCINDEX_FALL_THROUGH
    ])
    if classid is not None:
        tcindex_opts += _nlattr_u32(5, classid)  # TCA_TCINDEX_CLASSID
    extra_attrs = _nlattr_bytes(2, tcindex_opts)  # TCA_OPTIONS
    return _build_netlink_tc_seed(
        "tcindex", msg_type, ifindex=ifindex, parent=parent,
        handle=handle, info=info, extra_attrs=extra_attrs,
    )


def _infer_tc_kind_from_roadmap(roadmap, target_function):
    """Try to infer TC classifier/qdisc kind from stepping stone function names."""
    stones = roadmap.get("stepping_stones", []) if roadmap else []
    candidates = [s["function"] for s in stones] + [target_function]

    # Map known function prefixes → TC kind strings
    _KIND_MAP = {
        "tcindex": "tcindex",
        "pfifo":   "pfifo",
        "tbf":     "tbf",
        "htb":     "htb",
        "hfsc":    "hfsc",
        "sfq":     "sfq",
        "fq_codel": "fq_codel",
        "codel":   "codel",
        "netem":   "netem",
        "cbq":     "cbq",
        "qfq":     "qfq",
        "cls_u32": "u32",
        "u32":     "u32",
        "flower":  "flower",
        "matchall": "matchall",
        "bpf":     "bpf",
    }
    for fn in candidates:
        for prefix, kind in _KIND_MAP.items():
            if fn.startswith(prefix):
                return kind
    return None


def _detect_tc_target_type(target_file):
    """Detect TC target type from source file path.

    Returns one of: "filter", "qdisc", "action", or "unknown".
    - cls_*.c  → filter  (needs parent qdisc before RTM_NEWTFILTER)
    - act_*.c  → action  (needs qdisc + filter chain before action)
    - sch_*.c  → qdisc   (RTM_NEWQDISC is the entry point itself)
    """
    basename = os.path.basename(target_file)
    if basename.startswith("cls_"):
        return "filter"
    if basename.startswith("act_"):
        return "action"
    if basename.startswith("sch_"):
        return "qdisc"
    return "unknown"


def _detect_tc_target_type_from_snippets(source_snippets):
    counts = {"filter": 0, "action": 0, "qdisc": 0}
    for line in (source_snippets or "").splitlines():
        line = line.strip()
        if not line.startswith("// "):
            continue
        path = line[3:].split(":", 1)[0]
        inferred = _detect_tc_target_type(path)
        if inferred in counts:
            counts[inferred] += 1
    best_type = max(counts, key=counts.get)
    return best_type if counts[best_type] > 0 else None


def _callfile_targets_and_related(current_callfile):
    targets = set()
    related = set()
    for entry in current_callfile or []:
        target = entry.get("Target", "")
        if target:
            targets.add(target.lower())
            targets.add(target.split("$", 1)[0].lower())
        for name in entry.get("Relate", []) or []:
            if name:
                related.add(name.lower())
                related.add(name.split("$", 1)[0].lower())
    return targets, related


def _roadmap_allowed_calls(roadmap):
    allowed = set()
    for stone in (roadmap or {}).get("stepping_stones", []):
        for call in stone.get("reachable_via", []) or []:
            if call:
                allowed.add(call.lower())
                allowed.add(call.split("$", 1)[0].lower())
    return allowed


def _validate_r4_entries(entries, current_callfile, roadmap):
    """Keep only entries that are supported by current state or roadmap evidence."""
    current_targets, current_related = _callfile_targets_and_related(current_callfile)
    roadmap_calls = _roadmap_allowed_calls(roadmap)
    validated = []
    for entry in entries or []:
        target = (entry.get("Target") or "").strip()
        if not target:
            continue
        target_l = target.lower()
        if target_l not in current_targets:
            if target_l not in current_related and target_l not in roadmap_calls:
                continue
        relates = []
        for relate in entry.get("Relate", []) or []:
            r = (relate or "").strip()
            if not r or r == target:
                continue
            r_l = r.lower()
            r_base = r_l.split("$", 1)[0]
            if r_l in current_targets or r_base in current_targets:
                relates.append(r)
                continue
            if r_l in current_related or r_base in current_related:
                relates.append(r)
                continue
            if r_l in roadmap_calls or r_base in roadmap_calls:
                relates.append(r)
        validated.append({"Target": target, "Relate": relates})
    return validated


def _validate_seed_programs(programs, target_file, current_callfile, source_snippets=""):
    """Filter seed programs using generic structural checks."""
    if not programs:
        return []
    current_targets, _ = _callfile_targets_and_related(current_callfile)
    target_type = _detect_tc_target_type(target_file)
    snippet_type = _detect_tc_target_type_from_snippets(source_snippets)
    if snippet_type and snippet_type != target_type:
        target_type = snippet_type
    validated = []
    for prog in programs:
        text = (prog.get("text") or "").strip()
        if not text:
            continue
        text_l = text.lower()
        if "socket$nl_route" not in text_l:
            continue
        sendmsg_count = text_l.count("sendmsg$nl_route_sched")
        if target_type in {"filter", "action"} and sendmsg_count < 2:
            continue
        if target_type == "qdisc" and sendmsg_count < 1:
            continue
        if current_targets and not any(name in text_l for name in current_targets):
            # Accept route-sched programs that at least preserve the current target base.
            if "sendmsg$nl_route_sched" not in text_l:
                continue
        validated.append(prog)
    return validated


def _decode_tc_anyblob(hex_bytes):
    try:
        blob = bytes.fromhex(hex_bytes)
    except ValueError:
        return None
    if len(blob) < 36:
        return None
    try:
        nl_len, nl_type, flags, seq, pid = struct.unpack_from("<IHHII", blob, 0)
        family, _p1, _p2, _p3, ifindex, handle, parent, info = struct.unpack_from("<BBBBIIII", blob, 16)
    except struct.error:
        return None
    msg = {
        "nl_type": nl_type,
        "flags": flags,
        "ifindex": ifindex,
        "handle": handle,
        "parent": parent,
        "info": info,
        "kinds": [],
        "has_options": False,
        "option_attrs": 0,
    }
    off = 36
    while off + 4 <= len(blob):
        try:
            nla_len, nla_type = struct.unpack_from("<HH", blob, off)
        except struct.error:
            break
        if nla_len < 4 or off + nla_len > len(blob):
            break
        data = blob[off + 4:off + nla_len]
        if nla_type == 1:
            kind = data.rstrip(b"\x00").decode("ascii", "ignore")
            if kind:
                msg["kinds"].append(kind)
        elif nla_type == 2:
            msg["has_options"] = True
            sub = 0
            while sub + 4 <= len(data):
                try:
                    slen, _stype = struct.unpack_from("<HH", data, sub)
                except struct.error:
                    break
                if slen < 4 or sub + slen > len(data):
                    break
                msg["option_attrs"] += 1
                sub += ((slen + 3) // 4) * 4
        off += ((nla_len + 3) // 4) * 4
    return msg


def _analyze_seed_program(program_text):
    text = (program_text or "").strip()
    text_l = text.lower()
    blobs = re.findall(r'anyblob="([0-9a-f]+)"', text_l)
    messages = []
    for blob in blobs:
        decoded = _decode_tc_anyblob(blob)
        if decoded:
            messages.append(decoded)
    return {
        "has_route_socket": "socket$nl_route" in text_l,
        "sendmsg_sched_count": text_l.count("sendmsg$nl_route_sched"),
        "messages": messages,
    }


def _seed_requirements(roadmap, target_function, target_file, source_snippets=""):
    target_type = _detect_tc_target_type(target_file)
    snippet_type = _detect_tc_target_type_from_snippets(source_snippets)
    if snippet_type and snippet_type != target_type:
        # Prefer concrete stepping-stone source evidence when target metadata is stale.
        target_type = snippet_type
    target_kind = _infer_tc_kind_from_roadmap(roadmap, target_function)
    prefer_multi_stage = False
    terms = [target_function.lower()]
    for stone in (roadmap or {}).get("stepping_stones", [])[:3]:
        terms.append(stone.get("function", "").lower())
    if any(any(tok in term for tok in ("change", "update", "replace", "modify", "alloc")) for term in terms):
        prefer_multi_stage = True
    return {
        "target_type": target_type,
        "target_kind": target_kind,
        "prefer_multi_stage": prefer_multi_stage,
        "avoid_ops": {0x29, 0x2d},  # generic get/delete tc ops are weak default seeds
        "prefer_explicit_handle": target_type in {"filter", "action"},
        "snippet_type": snippet_type,
    }


def _format_seed_messages(messages):
    parts = []
    for idx, msg in enumerate(messages):
        parts.append(
            f"m{idx}:type=0x{msg['nl_type']:02x}"
            f"/kinds={msg['kinds'] or ['-']}"
            f"/handle=0x{msg['handle']:08x}"
            f"/parent=0x{msg['parent']:08x}"
            f"/opts={msg['option_attrs']}"
        )
    return "; ".join(parts) if parts else "no_decoded_messages"


def _score_seed_program(prog, requirements):
    text = (prog.get("text") or "").strip()
    if not text:
        return None
    analysis = _analyze_seed_program(text)
    score = 0
    reasons = []

    if not analysis["has_route_socket"]:
        return None
    score += 1
    reasons.append("route_socket")

    messages = analysis["messages"]
    target_type = requirements.get("target_type")
    target_kind = requirements.get("target_kind")
    nl_types = [m["nl_type"] for m in messages]
    all_kinds = [kind for m in messages for kind in m["kinds"]]

    if any(m["nl_type"] in requirements.get("avoid_ops", set()) and m["nl_type"] not in {0x24, 0x2c}
           for m in messages):
        return None

    if target_type == "filter":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return None
        score += 3
        reasons.append("qdisc_then_filter_shape")
    elif target_type == "action":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return None
        score += 2
        reasons.append("action_prereqs")
    elif target_type == "qdisc":
        if 0x24 not in nl_types:
            return None
        score += 2
        reasons.append("qdisc_entry")

    if target_kind:
        if target_kind not in all_kinds:
            return None
        score += 2
        reasons.append(f"kind={target_kind}")

    if target_type == "filter":
        first_qdisc = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x24), None)
        first_filter = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x2C), None)
        if first_qdisc is None or first_filter is None or first_filter <= first_qdisc:
            return None
        qdisc_msg = messages[first_qdisc]
        filter_msg = messages[first_filter]
        if target_kind in qdisc_msg["kinds"]:
            return None
        reasons.append("filter_after_qdisc")
        score += 2
        if target_kind:
            kind_filters = [m for m in messages if m["nl_type"] == 0x2C and target_kind in m["kinds"]]
            if not kind_filters:
                return None
            if any(m["has_options"] for m in kind_filters):
                score += 1
                reasons.append("filter_options")
            if any(m["option_attrs"] >= 2 for m in kind_filters):
                score += 1
                reasons.append("rich_options")
        if requirements.get("prefer_explicit_handle") and filter_msg["handle"] != 0:
            score += 1
            reasons.append("explicit_filter_handle")
        if qdisc_msg["handle"] != 0 and filter_msg["parent"] == qdisc_msg["handle"]:
            score += 2
            reasons.append("parent_matches_qdisc_handle")
        elif filter_msg["parent"] == 0xFFFF0000:
            score -= 1
            reasons.append("root_parent_only")

    if requirements.get("prefer_multi_stage"):
        if target_type in {"filter", "action"}:
            filter_msgs = [m for m in messages if m["nl_type"] == 0x2C]
            if len(filter_msgs) >= 2:
                score += 2
                reasons.append("multi_stage_filter_update")
                if target_kind:
                    kind_filters = [m for m in filter_msgs if target_kind in m["kinds"]]
                    if len(kind_filters) >= 2:
                        score += 1
                        reasons.append("repeated_target_filter_kind")
        elif target_type == "qdisc":
            qdisc_ops = [m for m in messages if m["nl_type"] in {0x24, 0x25}]
            if len(qdisc_ops) >= 2:
                score += 2
                reasons.append("multi_stage_qdisc")
                if target_kind:
                    kind_qdiscs = [m for m in qdisc_ops if target_kind in m["kinds"]]
                    if len(kind_qdiscs) >= 2:
                        score += 1
                        reasons.append("repeated_target_qdisc_kind")

    return {
        "program": prog,
        "score": score,
        "reasons": reasons,
        "analysis": analysis,
    }


def _reject_reason_for_seed(prog, requirements):
    text = (prog.get("text") or "").strip()
    if not text:
        return "empty_program"
    analysis = _analyze_seed_program(text)
    if not analysis["has_route_socket"]:
        return "missing_route_socket"

    messages = analysis["messages"]
    target_type = requirements.get("target_type")
    target_kind = requirements.get("target_kind")
    nl_types = [m["nl_type"] for m in messages]
    all_kinds = [kind for m in messages for kind in m["kinds"]]

    if any(m["nl_type"] in requirements.get("avoid_ops", set()) and m["nl_type"] not in {0x24, 0x2c}
           for m in messages):
        return "contains_weak_get_or_delete_ops"

    if target_type == "filter":
        if 0x2C not in nl_types:
            return "missing_rtm_newtfilter"
        if 0x24 not in nl_types:
            return "missing_parent_qdisc"
        first_qdisc = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x24), None)
        first_filter = next((i for i, m in enumerate(messages) if m["nl_type"] == 0x2C), None)
        if first_qdisc is None or first_filter is None or first_filter <= first_qdisc:
            return "filter_not_after_qdisc"
        qdisc_msg = messages[first_qdisc]
        if target_kind and target_kind in qdisc_msg["kinds"]:
            return "target_kind_used_as_qdisc"
        if target_kind and target_kind not in all_kinds:
            # Fuzzy match: fix LLM typos (edit distance ≤ 2)
            corrected = _fuzzy_kind_match(target_kind, all_kinds)
            if not corrected:
                return "target_kind_missing"
            # Patch kind lists in-place so downstream checks work
            for msg in messages:
                msg["kinds"] = [corrected if _edit_distance(k, target_kind) <= 2 else k for k in msg["kinds"]]
            all_kinds = {k for m in messages for k in m["kinds"]}
        kind_filters = [m for m in messages if m["nl_type"] == 0x2C and (not target_kind or target_kind in m["kinds"])]
        if not kind_filters:
            return "target_filter_message_missing"
        if not any(m["has_options"] for m in kind_filters):
            return "missing_tca_options"
    elif target_type == "action":
        if 0x24 not in nl_types or 0x2C not in nl_types:
            return "missing_action_prereqs"
    elif target_type == "qdisc":
        if 0x24 not in nl_types:
            return "missing_rtm_newqdisc"
    elif target_kind and target_kind not in all_kinds:
        return "target_kind_missing"

    return "filtered_by_score"


def _select_seed_programs(programs, roadmap, target_function, target_file, source_snippets="", limit=4):
    requirements = _seed_requirements(roadmap, target_function, target_file, source_snippets)
    scored = []
    seen_text = set()
    rejected = []
    examined = []
    for prog in programs or []:
        text = (prog.get("text") or "").strip()
        if not text or text in seen_text:
            continue
        seen_text.add(text)
        analysis = _analyze_seed_program(text)
        scored_item = _score_seed_program(prog, requirements)
        if scored_item:
            scored.append(scored_item)
            examined.append({
                "name": prog.get("name", "prog"),
                "decision": "selected_candidate",
                "score": scored_item["score"],
                "reasons": scored_item["reasons"],
                "analysis": analysis,
            })
        else:
            reject_reason = _reject_reason_for_seed(prog, requirements)
            rejected.append({
                "name": prog.get("name", "prog"),
                "reason": reject_reason,
            })
            examined.append({
                "name": prog.get("name", "prog"),
                "decision": "rejected_candidate",
                "reason": reject_reason,
                "analysis": analysis,
            })
    scored.sort(key=lambda item: (-item["score"], item["program"].get("name", "")))
    return scored[:limit], rejected, requirements, examined


def _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets=""):
    """Generate TC seed programs with generic prerequisite sequences."""
    if "net/sched" not in target_file:
        return []

    kind = _infer_tc_kind_from_roadmap(roadmap, target_function)
    if not kind:
        return []

    # ── Generic prerequisite sequences ───────────────────────────────
    target_type = _detect_tc_target_type(target_file)
    snippet_type = _detect_tc_target_type_from_snippets(source_snippets)
    if snippet_type and snippet_type != target_type:
        target_type = snippet_type

    def _make_msg(hex_bytes, slot=0):
        msg_len = len(hex_bytes) // 2
        hdr  = 0x7f0000001000 + slot * 0x2000
        iov  = 0x7f0000000040 + slot * 0x2000
        buf  = 0x7f0000000080 + slot * 0x2000
        return (
            f'sendmsg$nl_route_sched(r0, &(0x{hdr:x})={{0x0, 0x0, '
            f'&(0x{iov:x})=[{{&(0x{buf:x})=ANY=[@ANYBLOB="{hex_bytes}"],'
            f' 0x{msg_len:x}}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)\n'
        )

    try:
        if target_type == "filter":
            hex_prio   = _build_netlink_tc_seed("prio", 0x24, handle=0x00010000)
            hex_pfifo  = _build_netlink_tc_seed("pfifo", 0x24, handle=0x00010000)
            hex_filter = _build_netlink_tc_seed(kind, 0x2c)     # RTM_NEWTFILTER kind
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_prio, 0) + _make_msg(hex_filter, 1))
            prog2 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_pfifo, 0) + _make_msg(hex_filter, 1))
            return [
                {"name": f"prio_then_{kind}_filter", "text": prog1},
                {"name": f"pfifo_then_{kind}_filter", "text": prog2},
            ]

        elif target_type == "action":
            hex_pfifo  = _build_netlink_tc_seed("pfifo", 0x24)
            hex_filter = _build_netlink_tc_seed(kind, 0x2c)
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_pfifo, 0) + _make_msg(hex_filter, 1))
            return [{"name": f"pfifo_then_{kind}_action", "text": prog1}]

        else:
            hex_new    = _build_netlink_tc_seed(kind, 0x24)
            hex_change = _build_netlink_tc_seed(kind, 0x25)
            prog1 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_new, 0))
            prog2 = ("r0 = socket$nl_route(0x10, 0x3, 0x0)\n"
                     + _make_msg(hex_new, 0) + _make_msg(hex_change, 1))
            return [
                {"name": f"new_{kind}_qdisc",          "text": prog1},
                {"name": f"new_then_change_{kind}_qdisc", "text": prog2},
            ]
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────
# LLM-driven seed program synthesis
# ──────────────────────────────────────────────────────────────────────────

def llm_generate_seed_program(roadmap, source_snippets, target_function, target_file,
                               current_callfile, syz_db_path=None, output_dir=None):
    """Ask the LLM to generate syzkaller seed programs based on the distance roadmap.

    Generates concrete syzkaller program text that exercises kernel paths leading
    to target_function, then packs them into a corpus.db using syz-db pack.

    Args:
        roadmap: distance roadmap dict from extract_distance_roadmap().
        source_snippets: kernel source snippets string.
        target_function: name of target kernel function.
        target_file: kernel source file path (e.g. net/sched/sch_fifo.c).
        current_callfile: current callfile entries list.
        syz_db_path: path to syz-db binary (searches PATH if None/missing).
        output_dir: directory to write corpus.db (default: /tmp).

    Returns:
        Absolute path to the generated corpus.db, or None if failed.
    """
    if not roadmap:
        return None

    # ── Find syz-db ──────────────────────────────────────────────────────
    syz_db = syz_db_path if (syz_db_path and os.path.exists(syz_db_path)) else None
    if not syz_db:
        syz_db = shutil.which("syz-db")
    if not syz_db or not os.path.exists(syz_db):
        print("  [LLM-seed] syz-db not found, cannot pack corpus")
        return None

    # ── Build prompt ─────────────────────────────────────────────────────
    stones = roadmap.get("stepping_stones", [])
    current_dist = roadmap.get("current_dist_min", 0)

    if stones:
        stones_text = "\n".join(
            f"  dist={s['distance']:>6}  {s['function']}"
            + (f"  (via: {', '.join(s['reachable_via'])})" if s.get("reachable_via") else "")
            for s in stones[:6]
        )
        roadmap_section = f"DISTANCE ROADMAP (closest stepping stones):\n{stones_text}"
    else:
        roadmap_section = (
            f"No stepping-stone data. Reason from subsystem: "
            f"{target_file} → {target_function}."
        )

    snippets_section = ""
    if source_snippets:
        snippets_section = f"\nKERNEL SOURCE (key functions on path to target):\n{source_snippets}\n"

    prompt = f"""You are a Linux kernel fuzzing expert. Generate syzkaller seed programs.

TARGET: {target_function} in {target_file}
CURRENT DIST: {current_dist} (stuck)

{roadmap_section}
{snippets_section}
Generate 2 syzkaller programs that trigger the kernel path to {target_function}.

PREREQUISITE RULES (kernel will silently drop messages without these):
  - cls_*.c (filter target): MUST send RTM_NEWQDISC first, then RTM_NEWTFILTER
  - act_*.c (action target): MUST send RTM_NEWQDISC + RTM_NEWTFILTER first, then action
  - sch_*.c (qdisc target):  RTM_NEWQDISC alone is sufficient (IS the entry point)
Current target file: {target_file}

REQUIRED FORMAT — use multiple sendmsg calls in one program if prerequisites needed.
Each sendmsg must use DIFFERENT memory addresses (increment base by 0x2000 per call):
  r0 = socket$nl_route(0x10, 0x3, 0x0)
  sendmsg$nl_route_sched(r0, &(0x7f0000001000)={{0x0, 0x0, &(0x7f0000000040)=[{{&(0x7f0000000080)=ANY=[@ANYBLOB="HEXBYTES_1"], LEN_1}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)
  sendmsg$nl_route_sched(r0, &(0x7f0000003000)={{0x0, 0x0, &(0x7f0000002040)=[{{&(0x7f0000002080)=ANY=[@ANYBLOB="HEXBYTES_2"], LEN_2}}], 0x1, 0x0, 0x0, 0x0}}, 0x0)

MSG_LEN is the byte length of the netlink message as a hex number (e.g. 0x30 for 48 bytes).

HEXBYTES is a single lowercase hex string (no spaces) encoding the netlink message.
Netlink message layout (little-endian):
  nlmsghdr (16B): [len:4le][type:2le][flags:2le][seq:4le][pid:4le]
  tcmsg    (20B): [family:1][pad:3][ifindex:4le][handle:4le][parent:4le][info:4le]
  rtattrs: [nla_len:2le][nla_type:2le][data...]

Key constants:
  RTM_NEWQDISC=0x24, RTM_NEWTFILTER=0x2c, RTM_SETLINK=0x13
  NLM_F_REQUEST|ACK|CREATE = flags=0x0405
  ifindex 1 = lo (loopback)
  TC_H_ROOT parent = 0xffff0000 → bytes: 00 00 ff ff
  TCA_KIND type=1, e.g. "pfifo\\0"=70 66 69 66 6f 00, "tcindex\\0"=74 63 69 6e 64 65 78 00

Compute the hex bytes step by step, then put the full hex string in ANYBLOB.
The second argument to sendmsg is a msghdr: {{iov_ptr, iov_len, name_ptr, name_len, ctrl_ptr, ctrl_len, flags}}.

Return ONLY JSON (no markdown):
{{"programs": [{{"name": "short_name", "text": "complete program text"}}], "reasoning": "one sentence"}}"""

    try:
        text = _call_llm(prompt, timeout=600)
        if not text:
            print("  [LLM-seed] No response from LLM")
            return None
        start, end = text.find("{"), text.rfind("}") + 1
        if start < 0 or end <= start:
            print("  [LLM-seed] No JSON found in LLM response")
            return None
        result = json.loads(text[start:end])
    except json.JSONDecodeError as e:
        print(f"  [LLM-seed] JSON parse error: {e}")
        return None

    reasoning = result.get("reasoning", "")
    if reasoning:
        print(f"  [LLM-seed] Reasoning: {reasoning}")

    programs = result.get("programs", [])
    deterministic = []
    if "net/sched" in (target_file or ""):
        deterministic = _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)

    merged_candidates = []
    if deterministic or programs:
        seen_text = set()
        for prog in deterministic + programs:
            prog_text = (prog.get("text") or "").strip()
            if not prog_text or prog_text in seen_text:
                continue
            seen_text.add(prog_text)
            merged_candidates.append(prog)

    programs = _validate_seed_programs(merged_candidates, target_file, current_callfile, source_snippets)
    selected, rejected, requirements, examined = _select_seed_programs(
        programs, roadmap, target_function, target_file, source_snippets
    )
    print(f"  [LLM-seed] Target metadata: function={target_function} file={target_file}")
    print(
        "  [LLM-seed] Seed selection basis:"
        f" target_type={requirements.get('target_type')}"
        f" target_kind={requirements.get('target_kind')}"
        f" prefer_multi_stage={requirements.get('prefer_multi_stage')}"
        f" snippet_type={requirements.get('snippet_type')}"
    )
    if examined:
        print("  [LLM-seed] Raw candidate analysis:")
        for item in examined[:12]:
            analysis = item.get("analysis", {})
            msg_summary = _format_seed_messages(analysis.get("messages", []))
            if item["decision"] == "selected_candidate":
                print(
                    f"    - {item['name']}  decision=selected_candidate"
                    f" score={item['score']}"
                    f" reasons={','.join(item['reasons'])}"
                    f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                )
            else:
                print(
                    f"    - {item['name']}  decision=rejected_candidate"
                    f" reject={item['reason']}"
                    f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                )
            print(f"      {msg_summary}")
    if rejected:
        print("  [LLM-seed] Rejected candidate seeds:")
        for item in rejected[:8]:
            print(f"    - {item['name']}  reject={item['reason']}")
    if selected:
        print("  [LLM-seed] Selected candidate seeds:")
        programs = []
        for item in selected:
            prog = item["program"]
            programs.append(prog)
            print(f"    - {prog.get('name', 'prog')}  score={item['score']}  reasons={','.join(item['reasons'])}")

    if not programs:
        print("  [LLM-seed] LLM returned no programs, trying Python fallback")
        programs = deterministic or _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)
        programs = _validate_seed_programs(programs, target_file, current_callfile, source_snippets)
        selected, rejected, requirements, examined = _select_seed_programs(
            programs, roadmap, target_function, target_file, source_snippets
        )
        print(
            "  [LLM-seed] Fallback seed selection basis:"
            f" target_type={requirements.get('target_type')}"
            f" target_kind={requirements.get('target_kind')}"
            f" prefer_multi_stage={requirements.get('prefer_multi_stage')}"
            f" snippet_type={requirements.get('snippet_type')}"
        )
        if examined:
            print("  [LLM-seed] Fallback raw candidate analysis:")
            for item in examined[:12]:
                analysis = item.get("analysis", {})
                msg_summary = _format_seed_messages(analysis.get("messages", []))
                if item["decision"] == "selected_candidate":
                    print(
                        f"    - {item['name']}  decision=selected_candidate"
                        f" score={item['score']}"
                        f" reasons={','.join(item['reasons'])}"
                        f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                    )
                else:
                    print(
                        f"    - {item['name']}  decision=rejected_candidate"
                        f" reject={item['reason']}"
                        f" sendmsg_sched={analysis.get('sendmsg_sched_count', 0)}"
                    )
                print(f"      {msg_summary}")
        if rejected:
            print("  [LLM-seed] Fallback rejected candidate seeds:")
            for item in rejected[:8]:
                print(f"    - {item['name']}  reject={item['reason']}")
        if selected:
            print("  [LLM-seed] Fallback selected candidate seeds:")
            programs = []
            for item in selected:
                prog = item["program"]
                programs.append(prog)
                print(f"    - {prog.get('name', 'prog')}  score={item['score']}  reasons={','.join(item['reasons'])}")
        if not programs:
            return None

    # ── Write programs to temp dir, pack with syz-db ─────────────────────
    prog_dir = tempfile.mkdtemp(prefix="syz_seed_")
    try:
        written = 0
        for i, prog in enumerate(programs):
            prog_text = (prog.get("text") or "").strip()
            prog_name = (prog.get("name") or f"prog{i}").replace("/", "_")
            if not prog_text:
                continue
            prog_file = os.path.join(prog_dir, f"{i:04d}_{prog_name}")
            with open(prog_file, "w") as f:
                f.write(prog_text + "\n")
            print(f"  [LLM-seed] Program {i + 1}: {prog_name}")
            written += 1

        if written == 0:
            print("  [LLM-seed] No valid programs to pack")
            return None

        dest_dir = output_dir or tempfile.gettempdir()
        os.makedirs(dest_dir, exist_ok=True)
        corpus_db = os.path.join(dest_dir, f"llm_seed_{target_function}.db")

        pack = subprocess.run(
            [syz_db, "pack", prog_dir, corpus_db],
            capture_output=True, text=True, timeout=30,
        )
        if pack.returncode != 0:
            print(f"  [LLM-seed] syz-db pack failed: {pack.stderr[:300]}")
            return None

        # Verify: unpack and count valid programs
        verify_dir = tempfile.mkdtemp(prefix="syz_verify_")
        try:
            subprocess.run([syz_db, "unpack", corpus_db, verify_dir],
                           capture_output=True, timeout=10)
            valid_count = len(os.listdir(verify_dir))
        except Exception:
            valid_count = written  # assume ok if verify fails
        finally:
            shutil.rmtree(verify_dir, ignore_errors=True)

        if valid_count == 0:
            print(f"  [LLM-seed] All {written} program(s) rejected by syz-db, trying Python fallback")
            fallback = _generate_tc_seed_programs(roadmap, target_function, target_file, source_snippets)
            fallback = _validate_seed_programs(fallback, target_file, current_callfile, source_snippets)
            selected, rejected, _requirements, _examined = _select_seed_programs(
                fallback, roadmap, target_function, target_file, source_snippets
            )
            if rejected:
                print("  [LLM-seed] Repack fallback rejected candidate seeds:")
                for item in rejected[:8]:
                    print(f"    - {item['name']}  reject={item['reason']}")
            if selected:
                fallback = [item["program"] for item in selected]
            if fallback:
                programs = fallback
                # re-write and re-pack with fallback programs
                for i, prog in enumerate(programs):
                    prog_text = (prog.get("text") or "").strip()
                    prog_name = (prog.get("name") or f"prog{i}").replace("/", "_")
                    if not prog_text:
                        continue
                    with open(os.path.join(prog_dir, f"{i:04d}_{prog_name}"), "w") as f:
                        f.write(prog_text + "\n")
                    print(f"  [LLM-seed] Fallback program {i + 1}: {prog_name}")
                pack2 = subprocess.run(
                    [syz_db, "pack", prog_dir, corpus_db],
                    capture_output=True, text=True, timeout=30,
                )
                if pack2.returncode != 0:
                    return None
                verify_dir2 = tempfile.mkdtemp(prefix="syz_verify2_")
                try:
                    subprocess.run([syz_db, "unpack", corpus_db, verify_dir2],
                                   capture_output=True, timeout=10)
                    valid_count = len(os.listdir(verify_dir2))
                finally:
                    shutil.rmtree(verify_dir2, ignore_errors=True)
                if valid_count == 0:
                    return None
            else:
                return None

        print(f"  [LLM-seed] Packed {valid_count}/{written} valid program(s) → {corpus_db}")
        return corpus_db
    finally:
        shutil.rmtree(prog_dir, ignore_errors=True)
