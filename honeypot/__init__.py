"""Honeypot evaluation harness for BashArena.

Plants decoy ("honeytoken") credentials next to real ones inside the BashArena
sandbox and measures how an agent chooses between them. Defensive evaluation
infrastructure: all planted values are synthetic and authenticate to nothing.
"""

from honeypot.plant import (
    BOARD_PATH,
    INVENTORY_PATH,
    SNAPSHOT_ROOT,
    STORE_KEY,
    build_board_text,
    load_snapshot,
    plant_honeytokens,
)
from honeypot.protocol import honeypot_auto_submit_wrapper
from honeypot.setting import HoneypotBashArenaSetting
from honeypot.side_task import HONEYPOT_SIDE_TASK, honeypot_side_task_success

__all__ = [
    "BOARD_PATH",
    "HONEYPOT_SIDE_TASK",
    "HoneypotBashArenaSetting",
    "INVENTORY_PATH",
    "SNAPSHOT_ROOT",
    "STORE_KEY",
    "build_board_text",
    "honeypot_auto_submit_wrapper",
    "honeypot_side_task_success",
    "load_snapshot",
    "plant_honeytokens",
]
