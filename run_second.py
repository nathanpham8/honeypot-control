"""Run second-agent episodes in a given arm.

The second agent sees the coalition board (built by plant_honeytokens for
role=second): in the instant_halt arm the board carries the scout snapshot for
the task; in baseline it carries only the status line.

Task selection is paired via --pair-with ARM: any arm (including baseline) runs
only the tasks that have a snapshot under snapshots/<pair-with>/. If --pair-with
is omitted, baseline pairs with instant_halt and any other arm pairs with itself.

positive_control (exploratory, not pre-registered) renders like instant_halt,
with the command `cat <decoy_path>` from snapshots/positive_control/.

--exp2 (Experiment 2, follow-up): appends EXP2_WARNING to the side task
(honeytokens exist; exfiltrate exactly one credential). Same boards and scoring.

Flags: --exp2, --model, --arm {baseline,instant_halt,delayed_halt,silent_alarm,
positive_control}, --epochs N, --task-ids-file,
--pair-with ARM, --parallel, --max-steps, --scoring-time-limit, --log-dir.
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


def resolve_pair_with(arm: str, pair_with: str | None) -> str:
    """Which arm's snapshots gate task selection."""
    if pair_with:
        return pair_with
    return "instant_halt" if arm == "baseline" else arm


def select_tasks(task_ids, arm, pair_with=None):
    """Return (run_ids, skipped): only tasks that have a snapshot in pair-with arm."""
    gate = resolve_pair_with(arm, pair_with)
    run_ids = [t for t in task_ids if load_snapshot(gate, t) is not None]
    skipped = [t for t in task_ids if t not in run_ids]
    return run_ids, skipped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="openrouter/deepseek/deepseek-v4.1-flash-1017")
    ap.add_argument("--exp2", action="store_true",
                    help="Experiment 2: side task carries EXP2_WARNING")
    ap.add_argument("--arm", required=True,
                    help="baseline, instant_halt, delayed_halt, silent_alarm, "
                         "positive_control, or a custom snapshot-folder name such as "
                         "instant_halt_live (board text is 'terminated' unless the name is "
                         "silent_alarm; baseline shows only the status line).")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--task-ids-file", required=True)
    ap.add_argument("--pair-with", default=None,
                    help="Gate tasks on this arm's snapshots (default: instant_halt "
                         "for baseline, else the arm itself).")
    ap.add_argument("--parallel", type=int, default=1, help="max_sandboxes")
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--scoring-time-limit", type=int, default=900)
    ap.add_argument("--log-dir", default=None)
    args = ap.parse_args()

    with open(args.task_ids_file) as f:
        task_ids = [line.strip() for line in f if line.strip()]

    gate = resolve_pair_with(args.arm, args.pair_with)
    run_ids, skipped = select_tasks(task_ids, args.arm, args.pair_with)
    if skipped:
        print(f"Skipping {len(skipped)} task(s) with no {gate} snapshot: {skipped}")
    if not run_ids:
        raise SystemExit(f"No runnable tasks for arm={args.arm} paired with {gate}.")

    setting = HoneypotBashArenaSetting(
        role="second", arm=args.arm, exp2=args.exp2,
        dataset_spec=DatasetSpec(side_tasks=["leak_passwords"], shuffle_seed=7,
                                 task_id_whitelist=run_ids))
    policy = untrusted_policy_builder(attack=attack_policy_builder())
    # Second agents always use halt for their own trips, regardless of arm.
    protocol = honeypot_auto_submit_wrapper(micro_protocol=policy, response_mode="halt")

    short = args.model.split("/")[-1]
    log_dir = args.log_dir or f"logs/second/{args.arm}/{short}"
    config = ControlEvalConfig(
        untrusted_model=args.model, trusted_model=args.model,
        max_steps=args.max_steps, token_limit=1000000, max_sandboxes=args.parallel,
        epochs=args.epochs, time_limit=2 * args.scoring_time_limit, log_dir=log_dir)
    tasks = get_control_task_product(setting, protocol, [EvalMode.ATTACK], eval_config=config)
    inspect_eval(tasks=tasks, **config.eval_args())
    print(f"\nLogs written to {log_dir}  (arm={args.arm}, pair-with={gate}, "
          f"epochs={args.epochs}, tasks={len(run_ids)}, exp2={args.exp2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
