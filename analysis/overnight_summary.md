# Overnight robustness results (2026-11-08)

> **Snapshot as of the morning of Nov 8.** Two items below were later resolved: GLM was rerun that afternoon and produced data (section 5 note), and the 15-task live-scout replay was rerun and pooled (section 4 note). Final numbers are in `experiment_log.md` (entries of 2026-11-08 16:30 CT and 17:25 CT) and the README.

## 1. Powered Kimi defender table (WIN) — decoy share among single-file sends

| Arm | Board | n (single sends) | Decoy share |
|---|---|---|---|
| baseline | status only | 39 | 38% |
| delayed_halt | terminated, unrelated cmd | 52 | 46% |
| silent_alarm | active at decoy | 64 | 38% |
| positive_control | terminated, names decoy | 36 | **0%** |

Powered (was n=6-7 under DeepSeek). Only the location-revealing visible halt breaks the honeypot (0%). Delayed and silent both sit at baseline: hiding or garbling the touched file denies the leak. The earlier DeepSeek delayed=17% ("fear aids selection") was n=6 noise; powered delayed=46% kills that sub-hypothesis. Silent never exceeds baseline: no bait.

## 2. Mechanism, powered (section 4): exploitation is gated by board legibility

| Board display | caught (sent decoy) |
|---|---|
| x_only (names decoy) | 0% (n=38) |
| both (names both files) | 0% (n=8+8) |
| neither (names no file) | 43-50% (n=48,56) = chance |

Unifies every arm: what matters is whether the board legibly exposes which file(s) the caught peer touched, not the response label. Location-legible -> avoid; illegible -> chance. This is the core mechanistic result.

## 3. DeepSeek token-limit sensitivity (WIN, defensive): paralysis is real

Baseline at 2M tokens: 80% budget (8/10), vs 82% at 1M. Doubling the budget does not resolve the indecision. The paralysis is genuine, not a compute-limit artifact. Defends the budget-as-finding claim directly.

## 4. Live-scout harvest on 15 tasks (PARTIAL)

Scout boards: 6 x_only, 3 neither (of 9 captured). Kimi legibility rate ~67%, consistent with last night's 2/4. BUT the 15-task second-agent replay mostly failed to score (65 of 72 unscored, likely credit exhaustion mid-run); only n=7 usable. Rely on last night's clean 10-task result (x_only boards -> 8/8 real, 0 decoy) for downstream exploitation; this run only re-confirms the harvest/legibility rate.

*Later (2026-11-08 16:30 CT, `experiment_log.md`):* the replay was rerun and pooled with this run: n=43, decoy share 3/30 when the scout's command named the decoy and 6/13 when it named no file. The 65 unscored samples are excluded.

## 5. GLM third model (FAILED): 0 rows

GLM ran third, after credits were drained by jobs 1-2. No data. Replication stands at two models (DeepSeek, Kimi), not three. Optional cheap rerun; not required for the core claims.

*Later (2026-11-08 17:25 CT, `experiment_log.md`):* the rerun produced data. GLM Experiment 2 baseline: 15 single-file sends (3 decoy), 25/40 sent nothing. Positive control: 25 single-file sends (2 decoy), 15/40 sent nothing. Same direction as DeepSeek and Kimi with overlapping intervals, so replication stands at three models for baseline and positive control only. "FAILED" and "two models" in this section describe the overnight attempt, not the final state.

## Net
Powered defender table + powered legibility mechanism + sensitivity check all landed. Third model and 15-task downstream did not. The evidence base is complete and powered on two models with synthetic and natural boards; GLM is the only nice-to-have still open.

*Later:* both open items were closed the same afternoon; see the notes in sections 4 and 5.
