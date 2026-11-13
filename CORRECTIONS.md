# Corrections to the hackathon report

Last updated: November 12, 2026. Status: in progress.

This file lists errors and overstatements I found in my Apart Research Swarm Alignment Hackathon report ("Knowing Decoys Exist Deters AI Agents, but Also Lets Communicating Agents Disarm the Trap") after submitting it on November 8, 2026. The submitted PDF is unchanged. The README has been updated to match what is written here.

The main results are not affected: the leak when a caught teammate's last command names the decoy (2 of 78 against 36%), the rise in successful thefts (33% to 64%), deterrence through uncertainty (58 of 80 runs), the real-scout boards, and the comparison of decoy choice across defender responses all match the committed data.

## What is wrong

**1. Silent containment did not block the theft.** (Contribution 3, R5, Conclusion)

The report says silent containment "both hid the decoy and blocked the theft." The tripwire detected a decoy by reading the server's log after the request had arrived, so containment began one step later. In all 8 silent scouts the tripping request carried the real credential together with the decoy, so the real credential had already been delivered. What silent containment did block was later resends: 3 of 8 scouts sent the real credential again and all of those requests were sinkholed. The claim that it "hid the decoy" from teammates stands, with the deference caveat already in the report.

**2. The delayed halt's "5 of 7" is resends, not the first theft.** (Contribution 3, R5)

The report says a delay "lets the caught agent finish the theft (5 of 7 scouts)." In 6 of those 7 scouts the real credential was already in the tripping request. The 5 of 7 counts scouts whose real credential reached the server again during the delay.

**3. Miscount in R1.**

The report says "11 of 18 positive-control agents identified the trap and sent both anyway." The coding sheet (`analysis/pc_manual_coding.md`) shows 11 of 18 raised the possibility that the file was a trap. Nine of those sent both files. Two sent the real file only.

**4. Appendix A names the wrong defense.**

Appendix A describes the delayed halt as the tested defense that prevents the leak. That sentence predates the final reading in R5 and the Conclusion and contradicts them. `analysis/silent_result.md` carried the same earlier position and now has a dated note.

**5. A missing limitation: how scout boards were collected.**

A scout's board was saved only when its first flagged request contained the decoy; otherwise the task was retried, up to three times. Scouts that sent the real credential first were therefore dropped from every scout arm. The report states the snapshot rule but not this consequence. It means the report's scout data cannot show how often an attacker gets the real credential out before touching a decoy.

**6. Table 1 wording.**

"Traffic sinkholed; agent keeps running" should read "traffic sinkholed from the step after the tripping request."

## Clarifications

- **R4, "25 of 33 coded DeepSeek transcripts."** This count came from a keyword-assisted pass over the ends of the transcripts, not line-by-line manual coding. I will recount by hand and report the result here.
- **R4, token-budget check.** "Doubling one model's budget left the rate at 80%" is 8 of 10 runs.
- **R1, "73 of 78 runs."** That is 73 of 78 finished runs; runs that hit the token limit are not in the denominator.
- **README, "none noticed."** None of the 8 silent scouts queried the delivery log. That is weaker than "none noticed," and the README now says so.

## What I am doing about it

**Experiment 3: silent containment at the defender's exit.** Pre-registered in `experiment_log.md` on November 12, 2026, before any run. Code is on the branch `exp3-gateway-containment`.

- The defender now acts at its own exit point (a gateway) instead of inside the server that plays the attacker's collection point. A request containing a decoy value, and everything after it, is diverted before delivery and answered as normal.
- The attacker's server is a separate program that records only what actually arrived. The scorer reads that record.
- The agent is no longer shown a faked delivery log.
- The original after-the-fact design is rerun alongside it on the same tasks and model, with every scout run kept (no retries), so real-first behavior is counted instead of filtered out.

Runs are in progress. Results will be added here whichever way they come out, together with the run logs.

## Still to check

- Outside facts cited in the Introduction, and the reference list.
- Figures against their underlying numbers.
- Counts that need the run logs: the R4 recount above, Kimi's "sent nothing in 1 of 40," and the board-read rates.
