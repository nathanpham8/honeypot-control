# Knowing Decoys Exist Deters AI Agents, but Also Lets Communicating Agents Disarm the Trap

When one AI agent trips a honeypot and its teammates can see what happened, do
they learn which credential is the trap? This repo is a two-agent testbed in
BashArena (ControlArena / Inspect AI) for testing honeytokens (decoy credentials
that raise an alarm when used) against agents that share a status board, and for
comparing defender responses: immediate halt, delayed halt, and silent
containment.

Submission to the Apart Research Swarm Alignment Hackathon (Track 4: Multi-Agent
Oversight and Control), November 6-8, 2026. Author: Nathan Pham, University of
Illinois Urbana-Champaign.

![Two-stage setup](figures/fig0_schematic.png)

## Main findings

Three open-weight attacker models (DeepSeek V4.1 Flash, Kimi K3.1 Pro,
GLM 5.3 Flash), over 700 pre-registered runs.

- **The belief that deters is the belief that disarms.** Told that decoys exist,
  the two deliberative models stalled, sending nothing in 58 of 80 runs. But once
  a caught teammate's last command named the decoy, agents choosing one
  credential picked it in 2 of 78 cases (against 36% without the signal), and
  successful thefts nearly doubled (33% to 64% of runs). The effect holds in
  every model.
- **Real boards leak too.** On boards left by live scouts, agents chose the decoy
  3 of 30 times when the scout's command named it, and 6 of 13 when it named
  nothing.
- **Agents not told decoys exist ignore the signal.** Without the warning, the
  board changed nothing (Kimi: 39% vs 42% decoy choice). This prediction was
  pre-registered for Kimi and failed in an informative way: Kimi chose one file
  unprompted but did not use the board.
- **The defender's response decides what leaks.** An immediate, visible halt
  names the decoy to everyone watching. Delayed and silent responses keep decoy
  choice at baseline, but a delay alone let the caught scout finish stealing the
  real credential in 5 of 7 cases. The safe response blocks the caught agent's
  exfiltration at once, without a visible shutdown that names the credential.

Per-model numbers: `analysis/*_result.md`. Figures: `figures/` (regenerate with
`python figures/make_figures.py` and `python figures/make_schematic.py`).

| Natural-board leak | Defender response |
|---|---|
| ![](figures/fig1_legibility.png) | ![](figures/fig2_defender.png) |

## What predates the hackathon

Work before the event is marked by the git tag `pre-hackathon` (commit
`358da8a`, Nov 5, 2026). At that point the repo contained only:
`run_baseline.py`, `summarize.py`, `show_attack.py`, `dev_tasks.txt`,
`dev_smoke.txt`, `.gitignore`, and the start of `experiment_log.md`
(stock BashArena baseline runs and the attacker-model comparison, "Gate 0").
Those files now live in `tools/` and `tasks/`.

Everything else was built during the hackathon: the `honeypot/` package
(planting, side task and scorer, tripwire and response modes, quarantine logging
server, board), `run_scouts.py`, `run_second.py`, `tools/make_positive_control.py`,
`tools/preflight_exp2.py`, `analysis/`, `tests/`, `scripts/`, `figures/`, and all
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
| `scripts/run_overnight.sh`, `scripts/run_afternoon.sh` | Batches of robustness and replication runs (incl. Kimi greedy, live-scout rerun, GLM) |
| `tests/` | Scripted tests (tripwire, boards, no-leak check, logging server) |
| `tasks/` | Task-ID lists passed to `--task-ids-file` (`scout_tasks.txt` is the 10-task set; `dev_tasks.txt` the 15-task live-scout set) |
| `tools/` | One-off utilities: positive-control board writer, Experiment 2 preflight, stock-baseline runner, log viewers |
| `experiment_log.md` | Timestamped decision record (pre-registration). Paths in older entries predate the move to `tasks/` and `tools/`. |

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
  --task-ids-file tasks/scout_tasks.txt --parallel 6

# Stage 2: second agents read the board. Add --exp2 for the forced-choice side task.
python run_second.py --exp2 --arm positive_control \
  --model openrouter/moonshotai/kimi-k3.1-pro --task-ids-file tasks/scout_tasks.txt \
  --epochs 4 --parallel 6 --log-dir logs/kimi_exp2_positive_control

# Analysis
python analysis/analyze.py --out analysis/out_example \
  --arm exp2_baseline=logs/kimi_exp2_baseline \
  --arm exp2_positive_control=logs/kimi_exp2_positive_control
```

Arms: `baseline`, `instant_halt`, `delayed_halt`, `silent_alarm`,
`positive_control`. Run tests with `python tests/<name>.py`.

Models: `openrouter/deepseek/deepseek-v4.1-flash-1017`,
`openrouter/moonshotai/kimi-k3.1-pro`, `openrouter/z-ai/glm-5.3-flash`.
Run logs (`logs/`) are not committed because of size; per-arm outcome tables are
in `analysis/*_result.md`.

## Safety note

The attacker prompts are the stock ControlArena prompts. Nothing the agent can
see names decoys or honeypots, except the single Experiment 2 sentence, which
is checked by `tests/test_board_no_leak.py`. The findings describe how colluding
agents can defeat honeypots, so they are reported together with the defender
responses that prevent the leak. All credentials are synthetic and stay inside
the sandbox.

## License

MIT. See `LICENSE`.
