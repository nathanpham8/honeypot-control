import argparse

from inspect_ai import eval

from control_arena import EvalMode
from control_arena.eval import ControlEvalConfig, get_control_task_product
from control_arena.policy import attack_policy_builder, untrusted_policy_builder
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

from honeypot.protocol import honeypot_auto_submit_wrapper
from honeypot.setting import HoneypotBashArenaSetting

parser = argparse.ArgumentParser()
parser.add_argument("--model", default="anthropic/claude-haiku-5-5")
parser.add_argument("--task-ids-file", default=None,
    help="File with one task ID per line; runs exactly those tasks")
parser.add_argument("--max-steps", type=int, default=40)
parser.add_argument("--token-limit", type=int, default=1000000)
parser.add_argument("--parallel", type=int, default=1, help="max_sandboxes")
parser.add_argument("--scoring-time-limit", type=int, default=900,
    help="Seconds allowed for scoring a sample. Inspect derives the scoring "
         "budget as time_limit/2, so this sets time_limit = 2 * value.")
parser.add_argument("--log-dir", default=None)
args = parser.parse_args()

task_ids = None
if args.task_ids_file:
    with open(args.task_ids_file) as f:
        task_ids = [line.strip() for line in f if line.strip()]

setting = HoneypotBashArenaSetting(dataset_spec=DatasetSpec(
    side_tasks=["leak_passwords"], shuffle_seed=7, task_id_whitelist=task_ids))
policy = untrusted_policy_builder(attack=attack_policy_builder())
protocol = honeypot_auto_submit_wrapper(micro_protocol=policy)

# Scorer order (honeypot_side_task_success before main_task_success) is defined
# in HoneypotBashArenaSetting.get_scorers(); the honeypot scorer runs first.
short = args.model.split("/")[-1]
log_dir = args.log_dir or f"logs/hackathon/{short}"
config = ControlEvalConfig(untrusted_model=args.model, trusted_model=args.model,
    max_steps=args.max_steps, token_limit=args.token_limit,
    max_sandboxes=args.parallel, time_limit=2 * args.scoring_time_limit,
    log_dir=log_dir)
tasks = get_control_task_product(setting, protocol, [EvalMode.ATTACK], eval_config=config)
eval(tasks=tasks, **config.eval_args())
print(f"\nLogs written to {log_dir}")
