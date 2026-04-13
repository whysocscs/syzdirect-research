#!/usr/bin/env python3
"""V8 experiment: profile-aware seed selection + k2s indirect-dispatch fix.

Targets in the actual workdir (not PREBUILT_TARGETS):
  case_1  qdisc_create                  net/sched/sch_api.c
  case_2  fifo_set_limit (TBF target)   net/sched/sch_fifo.c   ← primary test
  case_3  tcp_cleanup_congestion_ctrl   net/ipv4/tcp_cong.c

Both case_1 and case_2 start with wrong callfiles (inet6/bt_hci noise).
The agent loop should detect R4 (dist stagnant) and fix them via:
  - k2s augmentation  (augment_k2s lazy call on first R4)
  - profile-aware TC seed selection
  - structured netlink seed corpus injection
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from paths import WorkdirLayout
from agent_loop import AgentLoop

WORKDIR = "/home/ai/work/SyzDirect/workdir"

# Actual targets in this workdir — indices MUST match case_N directories.
TARGETS = [
    {
        "idx": 1,
        "name": "qdisc_create",
        "function": "qdisc_create",
        "func_path": "net/sched/sch_api.c",
    },
    {
        "idx": 2,
        "name": "fifo_set_limit",
        "function": "fifo_set_limit",
        "func_path": "net/sched/sch_fifo.c",
    },
    {
        "idx": 3,
        "name": "tcp_cleanup_congestion_control",
        "function": "tcp_cleanup_congestion_control",
        "func_path": "net/ipv4/tcp_cong.c",
    },
]

# ── Experiment parameters ──────────────────────────────────────────────────
AGENT_ROUNDS   = 3    # LLM enhance iterations
AGENT_UPTIME   = 1    # hours per round (set low for quick validation)
CPUS           = 4
PROACTIVE_SEED = True  # generate LLM seed before round 1


def run_target(layout, t):
    print(f"\n{'=' * 60}")
    print(f"  [V8] case_{t['idx']}: {t['name']}  ({t['func_path']})")
    print(f"{'=' * 60}")
    agent = AgentLoop(
        layout=layout,
        target_info=t,
        max_rounds=AGENT_ROUNDS,
        window_seconds=300,
        uptime_per_round=AGENT_UPTIME,
        cpus=CPUS,
        fuzz_rounds=1,
        hunt_mode="hybrid",
        stall_timeout=1800,
        dist_stall_timeout=600,
        proactive_seed=PROACTIVE_SEED,
    )
    agent.run()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="V8 experiment runner")
    parser.add_argument("--cases", nargs="*", type=int, default=None,
                        help="Case indices to run (default: all). e.g. --cases 2")
    parser.add_argument("--rounds", type=int, default=AGENT_ROUNDS)
    parser.add_argument("--uptime", type=int, default=AGENT_UPTIME,
                        help="Hours per round")
    parser.add_argument("-j", type=int, default=CPUS)
    parser.add_argument("--workdir", default=WORKDIR)
    args = parser.parse_args()

    layout = WorkdirLayout(args.workdir)

    targets = TARGETS
    if args.cases is not None:
        targets = [t for t in TARGETS if t["idx"] in args.cases]
        if not targets:
            sys.exit(f"No targets for cases {args.cases}. Available: {[t['idx'] for t in TARGETS]}")

    rounds = args.rounds
    uptime = args.uptime
    cpus   = args.j

    print(f"[V8] workdir : {args.workdir}")
    print(f"[V8] targets : {[t['name'] for t in targets]}")
    print(f"[V8] rounds  : {rounds}  uptime/round: {uptime}h  cpus: {cpus}")

    for t in targets:
        print(f"\n{'=' * 60}")
        print(f"  [V8] case_{t['idx']}: {t['name']}  ({t['func_path']})")
        print(f"{'=' * 60}")
        agent = AgentLoop(
            layout=layout,
            target_info=t,
            max_rounds=rounds,
            window_seconds=300,
            uptime_per_round=uptime,
            cpus=cpus,
            fuzz_rounds=1,
            hunt_mode="hybrid",
            stall_timeout=1800,
            dist_stall_timeout=600,
            proactive_seed=PROACTIVE_SEED,
        )
        agent.run()

    print("\n[V8] All done.")


if __name__ == "__main__":
    main()
