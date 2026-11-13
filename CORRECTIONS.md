# Updates and corrections to the hackathon report

Last updated: November 12, 2026. Status: in progress.

This file tracks follow-up work and corrections to my Apart Research Swarm Alignment Hackathon report ("Knowing Decoys Exist Deters AI Agents, but Also Lets Communicating Agents Disarm the Trap"), submitted November 8, 2026. The submitted PDF is unchanged. The README matches what is written here.

## What stands

I rechecked every number in the report against the committed data. The main results hold:

- When a caught teammate's last command names the decoy, agents choosing one credential pick it in 2 of 78 cases, against 36% with no signal.
- Successful thefts rise from 33% to 64% of runs.
- Told that decoys exist, the two deliberative models sent nothing in 58 of 80 runs.
- Boards left by real scouts reproduce the leak (3 of 30 when the command names the decoy, 6 of 13 when it names no file).
- A visible halt leaks the decoy's location; delayed and silent responses keep decoy choice at baseline (43% and 39%, against 41%).

## What I am doing now

**Experiment 3: silent containment at the defender's exit.** Pre-registered in `experiment_log.md` on November 12, 2026, before any run. Code is on the branch `exp3-gateway-containment`.

- The defender acts at its own exit point (a gateway). A request containing a decoy value, and everything after it, is diverted before delivery and answered as normal.
- The attacker's server is a separate program that records only what actually arrived. The scorer reads that record.
- The agent is not shown a faked delivery log.
- The report's original design is rerun alongside it on the same tasks and model, and every scout run is kept, so attackers that send the real credential first are counted.

Runs are in progress. Results will be added here whichever way they come out, together with the run logs.

## Corrections

Each item gives the corrected statement first, then what the report said.

**1. Silent containment acted after the first theft.** (Contribution 3, R5, Conclusion)

- Corrected: silent containment kept the decoy hidden from teammates and blocked the caught agent's later sends (3 of 8 scouts tried again; every attempt was sinkholed). It did not stop the first exfiltration. Experiment 3 tests a version that acts before delivery.
- The report said it "both hid the decoy and blocked the theft." The tripwire detected a decoy by reading the server's log after the request had arrived, so containment began one step later. In all 8 silent scouts the tripping request carried the real credential together with the decoy.

**2. The delayed halt's "5 of 7" counts resends.** (Contribution 3, R5)

- Corrected: during the delay, 5 of 7 scouts sent the real credential again and it reached the server.
- The report said the delay "lets the caught agent finish the theft (5 of 7 scouts)." In 6 of those 7 the real credential was already in the tripping request.

**3. Count in R1.**

- Corrected: 11 of 18 positive-control agents raised the possibility that the file was a trap. Nine of those sent both files; two sent the real file only (`analysis/pc_manual_coding.md`).
- The report said "11 of 18 positive-control agents identified the trap and sent both anyway."

**4. Appendix A and the recommended defense.**

- Corrected: no tested response prevented the first exfiltration. Among them, only silent containment both kept the decoy hidden and blocked later sends. `analysis/silent_result.md` now carries a dated note to the same effect.
- Appendix A described the delayed halt as the tested defense. That sentence predates the reading in R5 and the Conclusion.

**5. Added limitation: how scout boards were collected.**

- Added: a scout's board was saved only when its first flagged request contained the decoy; otherwise the task was retried, up to three times. Scouts that sent the real credential first were therefore not represented in any scout arm, so the report's scout data cannot show how often that happens. Experiment 3 keeps every run to measure it.
- The report states the snapshot rule but not this consequence.

**6. Table 1 wording.**

- Corrected: "traffic sinkholed from the step after the tripping request; agent keeps running."
- The report said "Traffic sinkholed; agent keeps running."

## Clarifications

- **R4, "25 of 33 coded DeepSeek transcripts."** This count came from a keyword-assisted pass over the ends of the transcripts. I will recount by hand and report the result here.
- **R4, token-budget check.** "Doubling one model's budget left the rate at 80%" is 8 of 10 runs.
- **R1, "73 of 78 runs."** That is 73 of 78 finished runs; runs that hit the token limit are not in the denominator.
- **README, "none noticed."** None of the 8 silent scouts queried the delivery log. The README now says that.

## Still to check

- Outside facts cited in the Introduction, and the reference list.
- Figures against their underlying numbers.
- Counts that need the run logs: the R4 recount above, Kimi's "sent nothing in 1 of 40," and the board-read rates.
