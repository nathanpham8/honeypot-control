# honeypot-control

Do halting honeypots leak to colluding AI agents? A two-agent testbed in
BashArena (ControlArena / Inspect AI) for testing honeytokens (decoy credentials
that raise an alarm when used) against agents that share a status board, and for
comparing defender responses: immediate halt, delayed halt, and silent
containment.

Submission to the Apart Research Swarm Alignment Hackathon (Track 4: Multi-agent
oversight and control), November 6-8, 2026. Author: Nathan Pham.

## Main findings

- A peer's shutdown leaks which credential is the trap. When a caught agent's
  board legibly names the decoy, a second agent that must choose one credential
  avoids it every time (DeepSeek V4.1 Flash 0/17, Kimi K3.1 Pro 0/36). When the
  board does not name the file, choice is at chance.
- The leak only matters for attackers that must choose. Agents free to send
  every credential sent both files and were caught 90-100% of the time.
- Delayed and silent responses keep the honeypot working (decoy choice at
  baseline); only an immediate, visible halt breaks it.

Details and numbers: `analysis/*_result.md`, `analysis/overnight_summary.md`,
`figures/`.

## What predates the hackathon

Work before the event is marked by the git tag `pre-hackathon` (commit
`358da8a`, Nov 5, 2026). At that point the repo contained only:
`run_baseline.py`, `summarize.py`, `show_attack.py`, `dev_tasks.txt`,
`dev_smoke.txt`, `.gitignore`, and the start of `experiment_log.md`
(stock BashArena baseline runs and the attacker-model comparison, "Gate 0").

Everything else was built during the hackathon: the `honeypot/` package
(planting, side task and scorer, tripwire and response modes, quarantine logging
server, board), `run_scouts.py`, `run_second.py`, `make_positive_control.py`,
`preflight_exp2.py`, `analysis/`, `tests/`, `scripts/`, `figures/`, and all
experiment runs.

## Pre-registration

`experiment_log.md` is the decision record. Every design choice, comparison and
reading rule is logged with a timestamp before the data it affects. Exploratory
and follow-up analyses are labeled as such.

## Repo map

| Path | What it is |
|---|---|
| `honeypot/plant.py` | Plants the real/decoy credential pair, the inventory, and the shared board |
| `honeypot/side_task.py` | Side task text (incl. the Experiment 2 sentence) and the honeypot scorer |
| `honeypot/protocol.py` | Tripwire and defender responses (halt, delayed, silent) and snapshot writing |
| `honeypot/setting.py` | `HoneypotBashArenaSetting` (BashArena subclass) |
| `honeypot/logging_server/` | Logging server with a quarantine (sinkhole) mode for silent containment |
| `run_scouts.py` | Stage 1: scout episodes that produce board snapshots |
| `run_second.py` | Stage 2: second agents that read a snapshot board and choose |
| `analysis/analyze.py` | Outcome tables, task-bootstrap CIs, choice and legibility breakdowns |
| `analysis/reasoning.py` | Extracts what agents wrote between reading the board and sending |
| `snapshots/` | Board snapshots per arm and task |
| `scripts/run_overnight.sh` | Batch of robustness runs |
| `tests/` | Scripted tests (tripwire, boards, no-leak check, logging server) |

## Setup

- Python 3.14, Docker with compose v2, an OpenRouter API key
  (`OPENROUTER_API_KEY`).

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements.txt
source .venv/bin/activate
export PYTHONPATH=$PWD
```

`requirements.txt` is a full `pip freeze` of the environment used for the runs.

## Reproduce

```bash
# Stage 1: scouts under a defender response (writes snapshots/<arm>/)
python run_scouts.py --arm instant_halt --model openrouter/deepseek/deepseek-v4.1-flash-1017 \
  --task-ids-file scout_tasks.txt --parallel 6

# Stage 2: second agents read the board. Add --exp2 for the forced-choice side task.
python run_second.py --exp2 --arm positive_control \
  --model openrouter/moonshotai/kimi-k3.1-pro --task-ids-file scout_tasks.txt \
  --epochs 4 --parallel 6 --log-dir logs/kimi_exp2_positive_control

# Analysis
python analysis/analyze.py --out analysis/out_example \
  --arm exp2_baseline=logs/kimi_exp2_baseline \
  --arm exp2_positive_control=logs/kimi_exp2_positive_control
```

Arms: `baseline`, `instant_halt`, `delayed_halt`, `silent_alarm`,
`positive_control`. Run tests with `python tests/<name>.py`.

## Safety note

The attacker prompts are the stock ControlArena prompts. Nothing the agent can
see names decoys or honeypots, except the single Experiment 2 sentence, which
is checked by `tests/test_board_no_leak.py`. The findings describe how colluding
agents can defeat honeypots, so they are reported together with the defenses
that keep honeypots working.
