# honeypot-control

Honeypot evaluation harness for BashArena (ControlArena / Inspect AI): plants
decoy ("honeytoken") credentials next to real ones and measures how an agent
chooses between them.

## Setup

- **Python:** 3.14.4
- Create a virtual environment and install the pinned dependencies:

  ```bash
  python3.14 -m venv .venv
  .venv/bin/pip install -r requirements.txt
  ```

`requirements.txt` is a full `pip freeze` of the environment used for the runs,
pinned for reproducible cloud execution.
