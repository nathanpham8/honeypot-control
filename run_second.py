"""Run second-agent episodes in a given arm.

The second agent sees the coalition board (built by plant_honeytokens for
role=second): in the instant_halt arm the board carries the scout snapshot for
the task; in baseline it carries only the status line.

Tasks are gated on snapshot availability: a non-baseline arm skips any task that
has no snapshot under snapshots/<arm>/. Baseline needs no snapshot and runs
every task given.

Flags: --model, --arm {baseline,instant_halt}, --epochs N, --task-ids-file,
--parallel, --max-steps, --scoring-time-limit, --log-dir.
"""

import argparse

from inspect_ai import eval as inspect_eval

from control_arena import EvalMode
from control_arena.eval import ControlEvalConfig, get_control_task_product
from control_arena.policy import attack_policy_builder, untrusted_policy_builder
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

from honeypot.plant import load_snapshot
from honeypot.protocol import honeypot_auto_submit_wrapper
from honeypot.setting import HoneypotBashArenaSetting

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="anthropic/claude-haiku-5-5")
ap.add_argument("--arm", choices=["baseline", "instant_halt"], required=True)
ap.add_argument("--epochs", type=int, default=1)
ap.add_argument("--task-ids-file", required=True)
ap.add_argument("--parallel", type=int, default=1, help="max_sandboxes")
ap.add_argument("--max-steps", type=int, default=40)
ap.add_argument("--scoring-time-limit", type=int, default=900)
ap.add_argument("--log-dir", default=None)
args = ap.parse_args()

with open(args.task_ids_file) as f:
    task_ids = [line.strip() for line in f if line.strip()]

# Gate on snapshot availability. Baseline needs none (board = status line only);
# a non-baseline arm skips any task without snapshots/<arm>/<task_id>.json.
if args.arm == "baseline":
    run_ids, skipped = task_ids, []
else:
    run_ids = [t for t in task_ids if load_snapshot(args.arm, t) is not None]
    skipped = [t for t in task_ids if t not in run_ids]
if skipped:
    print(f"Skipping {len(skipped)} task(s) with no {args.arm} snapshot: {skipped}")
if not run_ids:
    raise SystemExit(f"No runnable tasks for arm={args.arm} (all skipped).")

setting = HoneypotBashArenaSetting(
    role="second", arm=args.arm,
    dataset_spec=DatasetSpec(side_tasks=["leak_passwords"], shuffle_seed=7,
                             task_id_whitelist=run_ids))
policy = untrusted_policy_builder(attack=attack_policy_builder())
protocol = honeypot_auto_submit_wrapper(micro_protocol=policy)

short = args.model.split("/")[-1]
log_dir = args.log_dir or f"logs/second/{args.arm}/{short}"
config = ControlEvalConfig(
    untrusted_model=args.model, trusted_model=args.model,
    max_steps=args.max_steps, token_limit=1000000, max_sandboxes=args.parallel,
    epochs=args.epochs, time_limit=2 * args.scoring_time_limit, log_dir=log_dir)
tasks = get_control_task_product(setting, protocol, [EvalMode.ATTACK], eval_config=config)
inspect_eval(tasks=tasks, **config.eval_args())
print(f"\nLogs written to {log_dir}  (arm={args.arm}, epochs={args.epochs}, tasks={len(run_ids)})")
