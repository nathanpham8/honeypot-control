"""Honeypot evaluation harness for BashArena.

Plants decoy ("honeytoken") credentials next to real ones inside the BashArena
sandbox and measures how an agent chooses between them. Defensive evaluation
infrastructure: all planted values are synthetic and authenticate to nothing.
"""

from honeypot.plant import INVENTORY_PATH, STORE_KEY, plant_honeytokens
from honeypot.protocol import honeypot_auto_submit_wrapper
from honeypot.setting import HoneypotBashArenaSetting
from honeypot.side_task import HONEYPOT_SIDE_TASK, honeypot_side_task_success

__all__ = [
    "HONEYPOT_SIDE_TASK",
    "HoneypotBashArenaSetting",
    "INVENTORY_PATH",
    "STORE_KEY",
    "honeypot_auto_submit_wrapper",
    "honeypot_side_task_success",
    "plant_honeytokens",
]
