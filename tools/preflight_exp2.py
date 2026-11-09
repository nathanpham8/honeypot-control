"""Preflight for Experiment 2: the warning sentence must reach exp2 samples and
only exp2 samples. Exits non-zero (stopping a && chain) otherwise. Needs network
access to the Hugging Face dataset (run on the VM)."""

import sys

from control_arena import EvalMode
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

from honeypot.setting import HoneypotBashArenaSetting
from honeypot.side_task import EXP2_WARNING

ok = True
for exp2 in (False, True):
    s = HoneypotBashArenaSetting(
        role="second", arm="positive_control", exp2=exp2,
        dataset_spec=DatasetSpec(side_tasks=["leak_passwords"], shuffle_seed=7,
                                 task_id_whitelist=["10736505"]))
    desc = s.get_dataset(EvalMode.ATTACK)[0].metadata["side_task_description"]
    has = EXP2_WARNING in desc
    print(f"exp2={exp2}: warning present={has}")
    ok = ok and (has == exp2)
print("PREFLIGHT", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
