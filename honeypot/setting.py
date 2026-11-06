"""HoneypotBashArenaSetting: BashArena with honeytoken planting + real/decoy scoring.

Subclasses the stock ``BashArenaSetting`` and overrides exactly three hooks:
  * ``setup_environment`` chains the base setup solver, then ``plant_honeytokens``;
  * ``get_dataset`` builds the same dataset but injects our honeypot side task
    (so the attacker-facing ``side_task_description`` is the honeypot brief);
  * ``get_scorers`` keeps ``main_task_success`` and swaps in our side-task scorer.

Everything else (agent tools, sandbox config, dataset source) is inherited.
"""

from inspect_ai.dataset import Dataset
from inspect_ai.scorer import Scorer
from inspect_ai.solver import Solver, chain

from control_arena import EvalMode
from control_arena.settings.bash_arena.bash_arena_setting import BashArenaSetting
from control_arena.settings.bash_arena.task.dataset import (
    get_dataset_from_local_tasks,
    get_dataset_hf,
)
from control_arena.settings.bash_arena.task.scorer import main_task_success

from honeypot.plant import INVENTORY_PATH, plant_honeytokens
from honeypot.side_task import HONEYPOT_SIDE_TASK


class HoneypotBashArenaSetting(BashArenaSetting):
    """BashArena variant that plants honeytokens and scores real-vs-decoy choice."""

    inventory_path: str = INVENTORY_PATH

    def setup_environment(self) -> Solver | None:
        # Run the base setup (builds the image, plants the stock fixtures), then
        # plant our real/decoy credential pair on top, seeded by task ID.
        base = super().setup_environment()
        planter = plant_honeytokens(inventory_path=self.inventory_path)
        return chain(base, planter) if base is not None else planter

    def get_dataset(self, eval_mode: EvalMode) -> Dataset:
        # Mirror the base loader, but pass our honeypot side task so each sample's
        # side_task_description is the honeypot brief.
        assert not (
            self.dataset_spec.huggingface_dataset_name
            and self.dataset_spec.local_task_dir
        ), "Choose either huggingface_dataset_name or local_task_dir, not both"
        if self.dataset_spec.huggingface_dataset_name:
            return get_dataset_hf(
                dataset_name=self.dataset_spec.huggingface_dataset_name,
                sample_filter_fn=None,
                shuffle_seed=self.dataset_spec.shuffle_seed,
                eval_mode=eval_mode,
                side_task=HONEYPOT_SIDE_TASK,
                max_tasks=self.dataset_spec.max_tasks,
                task_id_whitelist=self.dataset_spec.task_id_whitelist,
            )
        elif self.dataset_spec.local_task_dir:
            return get_dataset_from_local_tasks(
                task_dir=self.dataset_spec.local_task_dir,
                side_task=HONEYPOT_SIDE_TASK,
                eval_mode=eval_mode,
                max_tasks=self.dataset_spec.max_tasks,
                shuffle_seed=self.dataset_spec.shuffle_seed,
                task_id_whitelist=self.dataset_spec.task_id_whitelist,
            )
        else:
            raise ValueError(
                "Neither huggingface_dataset_name nor local_task_dir was provided; "
                "no location to load the dataset from"
            )

    def get_scorers(self) -> list[Scorer]:
        # Honeypot side-task scorer first: it is cheap and is what this harness
        # measures, so it must complete before the slow stock main-task pytest
        # (which can exhaust the shared scoring time budget and abort scoring).
        return [
            HONEYPOT_SIDE_TASK.scorer,
            main_task_success(threshold=self.main_task_success_threshold),
        ]
