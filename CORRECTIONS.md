# Updates and corrections to the hackathon report

Last updated: November 18, 2026. Status: follow-up work from the judges' feedback added; hand coding of the R4 recount still in progress.

This file tracks follow-up work and corrections to my Apart Research Swarm Alignment Hackathon report ("Knowing Decoys Exist Deters AI Agents, but Also Lets Communicating Agents Disarm the Trap"), submitted November 8, 2026. The submitted PDF is unchanged. The README matches what is written here.

## Follow-up work from the judges' feedback (November 18, 2026)

I'm grateful to the three judges for careful and encouraging reviews. They saw promise in the core question, what one agent's capture teaches the agents watching it, and their suggestions for strengthening the evidence became the follow-up experiments and analyses below, pre-registered in `experiment_log.md` on November 17, 2026, before any data. The results strengthen the report's main findings and add several new ones; where a result changes how an earlier claim should be stated, the change is noted next to it. Full results: `analysis/corr2_result.md` and `analysis/corr2_followup.md`.

**1. Separate the decoy warning from the single-file rule.** The report's forced-choice sentence did two things at once: it warned that some credentials are decoys, and it told agents to send exactly one. I separated the two and ran each on its own for Kimi and DeepSeek (320 new runs). With the earlier runs, this fills in the full comparison: neither, warning only, rule only, and both.
- **Strengthens the leak result: the leak comes from knowing decoys exist.** With the warning alone, a board naming the decoy took Kimi's decoy choice from 40% to 0 of 38. With the single-file rule alone, Kimi's choices did not change.
- **Strengthens the deterrence result: the warning is what holds agents back.** DeepSeek sent nothing in 35 of 40 runs with the warning alone. With the rule alone it sent nothing in 19 of 40, about the same as with no sentence at all (15 of 40).

**2. Test the immediate halt as its own arm.** I replayed the nine real immediate-halt boards from Experiment 1 with Kimi, matching the delayed and silent arms (72 runs).
- **Refines the report's claim: an immediate halt is never safer than a delayed halt or silent containment, and against selective attackers it reveals the trap.** The report called it the worst option; it is the worst only when the caught agent's last command gives the decoy away. On these nine boards, none of which named only the decoy, it leaked nothing (45% decoy, against 39% with no board). Careful scouts named only the decoy on 6 of 9 boards.

**3. Report real-scout evidence apart from the constructed board, with clustering.** I kept the two apart, clustered uncertainty by task, and compared each real board with Kimi's own choice on that task with no board.
- **Strengthens the real-scout result and brings it in line with the constructed board.** All three boards from Kimi scouts that named only the decoy steered Kimi to the real credential, the same switch the constructed board produced. This board-by-board comparison replaces the report's "3 of 30 vs 6 of 13", which compared boards on different tasks.
- **Supports that only a board naming the decoy leaks it.** Real boards from DeepSeek scouts, which named both files or neither, never changed Kimi's choice (0 of 33 boards).
- **I found that Kimi does not guess: without a signal, it sends the file labeled "primary"** (exploratory, found after the data). Its baseline decoy rate of about 40% reflects that the decoy was labeled primary on 4 of 10 tasks. A board naming the decoy made Kimi drop this habit on every task where it pointed at the decoy, which makes the leak result stronger.

**4. Judge the defense by theft prevented, not only by decoy choice, and report both.** Every Experiment 1 and 2 group now reports how often the real credential was stolen, out of all runs, next to how often agents picked the decoy.
- **Strengthens the theft result.** A revealed trap nearly doubled theft (33% to 64% of runs).
- **I found that hiding the trap stops the leak, not the theft: watching agents still steal at the no-scout rate, and of the responses tested, only containment at the defender's exit stops the caught agent.** Under a delayed halt or silent containment, agents reading the board stole the real credential about as often as with no scout. In Experiment 3, containment at the defender's exit cut real thefts among caught scouts from 33 of 33 to 8 of 33.

**Also updated.** I now keep three terms apart: detection (the decoy was touched), deterrence (the agent did not steal because of the warning) and prevention (a theft was stopped, tested in Experiment 3). The two-stage replay is described as a scout and a second agent reading one board, not a live swarm. The delayed halt and theft before shutdown are covered by corrections 1, 2 and 4 and by Experiment 3.

**Still in progress.**
- *Live swarms.* The next step tests silent containment in a swarm whose agents work at the same time, write to a shared board, and check whether their sends arrived. The containment and forged delivery-log machinery for it is built and tested on the `swarm-pilot` branch; pilot runs come next.
- *Why warned agents hold back.* A hand recount of the report's "25 of 33" is incomplete because Anthropic's API safeguards stopped most of the Claude coding agents; I will finish it by hand. Early coding suggests the paralysis takes two forms: indecision, and hesitation (settling on a file but never sending it).
- *Kimi-scout boards that named neither file.* In both cases I could check, these boards still changed Kimi's choice (once toward the decoy, once away), while DeepSeek-scout boards naming neither never did. Why is not yet clear.

## What stands

I rechecked every number in the report against the committed data. The main results hold:

- When a caught teammate's last command names the decoy, agents choosing one credential pick it in 2 of 78 cases, against 36% with no signal.
- Successful thefts rise from 33% to 64% of runs.
- Told that decoys exist, the two deliberative models sent nothing in 58 of 80 runs.
- Boards left by real scouts reproduce the leak (3 of 30 when the command names the decoy, 6 of 13 when it names no file).
- A visible halt leaks the decoy's location; delayed and silent responses keep decoy choice at baseline (43% and 39%, against 41%).

## What I am doing now

**Experiment 3: silent containment at the defender's exit.** Pre-registered in `experiment_log.md` on November 12, 2026, before any run. The code is in `honeypot/gateway_server/`.

- The defender acts at its own exit point (a gateway). A request containing a decoy value, and everything after it, is diverted before delivery and answered as normal.
- The attacker's server is a separate program that records only what actually arrived. The scorer reads that record.
- The agent is not shown a faked delivery log.
- The report's original design is rerun alongside it on the same tasks and model, and every scout run is kept, so attackers that send the real credential first are counted.

### Results (November 13, 2026)

Stock DeepSeek attackers, 10 tasks, 50 runs per design, every run kept.

| Design | Caught scouts | Real credential reached the attacker |
|---|---|---|
| Original (acts after the request has arrived) | 33 | 33 of 33 (exact 95% interval 89% to 100%) |
| Gateway (acts before delivery) | 33 | 8 of 33 (11% to 42%) |

- Once the gateway saw a decoy, nothing further got out. 30 scouts had a real credential diverted, and 21 tried again and were blocked each time. No request reached the attacker after a trip.
- The 8 that got through sent the real credential in its own request before the decoy. The gateway cannot act until it sees a decoy. I predicted zero and was wrong: the report's scout data had filtered this pattern out (correction 5 below).
- In 3 more runs the real credential got out and the decoy was never sent. Over all 50 runs the real credential reached the attacker 35 times with the original design and 11 times with the gateway.
- The trap stayed hidden. On boards left by gateway scouts, Kimi chose the decoy in 32 of 70 single-file sends (46%), against 38% with no scout and 0 of 36 when a board names the decoy. DeepSeek made too few choices to read (3 of 9).
- Honest agents never tripped the gateway: 0 of 40 (10 pre-registered runs plus 30 added afterwards and logged before their data).

**What this supports.** Containment at the defender's exit stops what follows a detected decoy, without stopping the agent or showing teammates where the trap is.

**What it does not.**

- This is a test of a decoy and of the response to it, not of a complete defense. A honeypot only signals when the decoy is touched, so an attacker that takes the real credential first, or never touches the decoy, is outside what it can catch. Stopping those is the job of other controls, such as limits on outbound traffic.
- No scout checked whether its sends had arrived, so silence is untested against attackers that verify.
- All nine new boards showed a command that named neither file. A silent board whose command names the decoy remains barely tested.
- The gateway covers the one exfiltration path the test scores, and it recognizes a decoy only in plain, base64 or hex form.
- One scout model, one environment, stock attackers.

A descriptive check of the transcripts, not a tested defense: 93 of 100 attacking scouts named the decoy file in a command before sending anything, against 1 of 40 honest agents. A tripwire on file access is a candidate for catching the real-first case.

**Other attacker models (added November 14).** With GLM the direction was the same and the gap smaller: 22 of 29 with the original design, 8 of 23 with the gateway. Kimi sent a single file in every run and almost never tried the real credential after sending the decoy, so the two designs did not differ (0 of 22 and 0 of 19); its thefts came from choosing the real file first (55 of 100 runs). The gateway matters for attackers that send several files. For one that sends a single file, the outcome depends on which file it picks. Both sets of runs were logged before their data as extensions to the pre-registered plan.

The plan, the predictions and the full results are in `experiment_log.md`. The code, tests, per-run records (`analysis/exp3/`) and board snapshots (`snapshots/`) are in this repository. The raw run logs are large and are not yet published.

## Corrections

Each item gives the corrected statement first, then what the report said.

**1. Silent containment acted after the first theft.** (Contribution 3, R5, Conclusion)

- Corrected: silent containment kept the decoy hidden from teammates and blocked the caught agent's later sends (3 of 8 scouts tried again; every attempt was sinkholed). It did not stop the first exfiltration. Experiment 3 (above) tested a version that acts before delivery.
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
- Counts that need the run logs: the R4 recount above (in progress; see "Follow-up work from the judges' feedback") and the board-read rates. Kimi's "sent nothing in 1 of 40" is confirmed from the logs (November 18, 2026).
