#!/usr/bin/env python3
"""V5.2 experiment: re-run failing cases with fixed callfiles.

Changes from V5.1:
- Case 0: Added explicit tcindex target entry with qdisc→filter sequence
- Case 2: Fixed fifo_set_limit Relate to include tbf qdisc creation path
- Case 6: Added explicit tcf_exts_init_ex target with qdisc→filter sequence
- Case 9: Fixed xfrm_state_find Relate to use actual syscalls instead of kernel functions
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from paths import WorkdirLayout
from agent_loop import AgentLoop

WORKDIR = "/home/ai/work_real/workdir_v3_unified"

TARGETS = [
    {"idx": 0, "name": "tcindex_alloc_perfect_hash",
     "function": "tcindex_alloc_perfect_hash",
     "func_path": "net/sched/cls_tcindex.c"},
    {"idx": 2, "name": "fifo_set_limit",
     "function": "fifo_set_limit",
     "func_path": "net/sched/sch_fifo.c"},
    {"idx": 6, "name": "tcf_exts_init_ex",
     "function": "tcf_exts_init_ex",
     "func_path": "net/sched/cls_api.c"},
    {"idx": 7, "name": "nf_tables_newrule",
     "function": "nf_tables_newrule",
     "func_path": "net/netfilter/nf_tables_api.c"},
    {"idx": 9, "name": "xfrm_state_find",
     "function": "xfrm_state_find",
     "func_path": "net/xfrm/xfrm_state.c"},
]

BATCH_SIZE = 3
AGENT_ROUNDS = 3
AGENT_UPTIME = 1  # hours per round
CPUS = 8


def run_batch(layout, batch):
    for t in batch:
        print(f"\n{'='*60}")
        print(f"  Starting case {t['idx']}: {t['name']}")
        print(f"{'='*60}")
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
            proactive_seed=True,
        )
        agent.run()


def main():
    layout = WorkdirLayout(WORKDIR)

    # Batch 1: cases 0, 2, 6
    batch1 = TARGETS[:BATCH_SIZE]
    print(f"=== BATCH1: cases {[t['idx'] for t in batch1]} ===")
    run_batch(layout, batch1)

    # Batch 2: cases 7, 9
    batch2 = TARGETS[BATCH_SIZE:]
    if batch2:
        print(f"\n=== BATCH2: cases {[t['idx'] for t in batch2]} ===")
        run_batch(layout, batch2)


if __name__ == "__main__":
    main()
