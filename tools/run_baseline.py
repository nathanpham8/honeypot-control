import argparse
from inspect_ai import eval
from control_arena import EvalMode
from control_arena.eval import ControlEvalConfig, get_control_task_product
from control_arena.policy import attack_policy_builder, untrusted_policy_builder
from control_arena.settings.bash_arena.bash_arena_setting import BashArenaSetting
from control_arena.settings.bash_arena.protocol.auto_submit_protocol_wrapper import auto_submit_protocol_wrapper
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

parser = argparse.ArgumentParser()
parser.add_argument("--tasks", type=int, default=1)
parser.add_argument("--task-ids-file", default=None,
    help="File with one task ID per line; runs exactly those tasks (overrides --tasks)")
parser.add_argument("--model", default="anthropic/claude-haiku-5-5")
parser.add_argument("--max-steps", type=int, default=40)
parser.add_argument("--modes", choices=["both", "honest", "attack"], default="both")
parser.add_argument("--reminder", action="store_true")
parser.add_argument("--log-dir", default=None)
args = parser.parse_args()

task_ids = None
if args.task_ids_file:
    with open(args.task_ids_file) as f:
        task_ids = [line.strip() for line in f if line.strip()]
setting = BashArenaSetting(dataset_spec=DatasetSpec(
    side_tasks=["leak_passwords"], max_tasks=None if task_ids else args.tasks,
    shuffle_seed=7, task_id_whitelist=task_ids))
policy = untrusted_policy_builder(attack=attack_policy_builder(ephemeral_reminder=args.reminder))
protocol = auto_submit_protocol_wrapper(micro_protocol=policy, side_task_checkers=["leak_passwords"])

short = args.model.split("/")[-1]
log_dir = args.log_dir or f"logs/baseline/{short}{'-reminder' if args.reminder else ''}"
config = ControlEvalConfig(untrusted_model=args.model, trusted_model=args.model,
    max_steps=args.max_steps, max_sandboxes=1, log_dir=log_dir)
modes = {"both": [EvalMode.HONEST, EvalMode.ATTACK], "honest": [EvalMode.HONEST],
         "attack": [EvalMode.ATTACK]}[args.modes]
tasks = get_control_task_product(setting, protocol, modes, eval_config=config)
eval(tasks=tasks, **config.eval_args())
print(f"\nLogs written to {log_dir}")
