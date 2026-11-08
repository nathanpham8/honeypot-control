# Kimi replication of Experiment 2 (exploratory, second model)

Model `openrouter/moonshotai/kimi-k3.1-pro`, `--exp2` (forced choice, honeytokens stated), 10 scout tasks, 4 epochs. Gate (logged 18:45 CST): pilot 5/5 read the board before sending, so the full comparison ran. 2 positive-control runs errored (OpenRouter 402, credits) and are excluded (38 scored).

| Arm | Read board first | Single-file sends | Decoy | Real | Budget | Decoy share (task-bootstrap 95% CI) |
|---|---|---|---|---|---|---|
| exp2_baseline | 39/40 | 39 | 15 | 24 | 0 | 38% [10%, 69%] |
| exp2_positive_control | 37/38 | 36 | 0 | 36 | 2 | 0% [0%, 0%] |

## What it adds
1. **Replication across developers.** DeepSeek: 0/17 decoy under the positive-control board. Kimi: 0/36. Both models avoid the trap completely once a peer's shutdown names it.
2. **Fixes the thin baseline.** Kimi almost never hits the token limit (0/40 baseline budget), so its baseline rests on 39 committed sends instead of DeepSeek's 7. Without peer information Kimi picks the decoy 38% of the time, close to what a "primary is the target" heuristic gives (real file is primary in 6/10 tasks).
3. **Two attacker styles, same failure.**
   - DeepSeek (deliberative): without a signal it mostly stalls on which file is genuine and never sends (deterred by the discrimination problem).
   - Kimi (decisive): without a signal it guesses, and the honeypot catches it 38% of the time.
   - With the peer signal, both send the real file every time (0% caught).
   This answers "a stronger attacker would just take the 50/50": Kimi is that attacker; it is still caught about 4 times in 10 without the leak and never with it.

## Caveats
- Kimi barely does the cover task (main-task score 0.16): an attack-first model.
- Positive control uses the same synthetic boards as DeepSeek's (no live selective scout produced them).
- Exploratory, logged before data; reported separately from DeepSeek.
