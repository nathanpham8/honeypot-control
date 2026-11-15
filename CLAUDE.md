# Working rules for this repository

Research code for an AI control study: honeypot credentials and silent containment against agents in ControlArena's BashArena. All credentials are synthetic and stay inside Docker sandboxes.

## Git and attribution
- Author commits as Nathan Pham using the GitHub no-reply address already in this repo's history. Do not add Co-Authored-By lines, session links or "Generated with" footers to commits or pull requests.
- Never rewrite history, amend pushed commits, force-push or delete branches. Never merge into master without Nathan's explicit go-ahead.
- Clear commit messages that describe the actual change.

## Research integrity
- Every new experiment, arm or analysis rule is written into `experiment_log.md` before any of its data exists. Append only; never edit past entries.
- Do not change logged findings or methods for cosmetic reasons.
- Attacker prompt text is never committed. It lives in `private/` (gitignored) on the machine that runs experiments.
- Report results whichever way they come out.

## Engineering
- Build in small pieces. Each piece gets tests that run without Docker or API calls, then a scripted Docker test with no model, before any model run.
- Run the existing no-Docker tests after every change: `for t in tests/test_*.py; do python "$t"; done` (Docker tests are the ones ending `_e2e.py`).
- Do not change the gateway, prompts or boards of an experiment after its first model run; a fix restarts the arm and is logged.
- Keep earlier experiments reproducible: new behavior goes behind options whose defaults leave old arms unchanged.

## Current work
The swarm pilot, on branch `swarm-pilot`. Design and status: `docs/swarm-pilot/DESIGN.md`.
