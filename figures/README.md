# Figures

Regenerate: `python figures/make_figures.py` and `python figures/make_schematic.py`.
Palette: blue `#2a78d6`.

- `fig0_schematic.png`: the two-stage setup. A scout trips the decoy, the defender
  responds, the attackers' shared board shows the scout's status and last command,
  and a second agent chooses which credential to steal.
- `fig1_legibility.png`: decoy choice on boards left by real Kimi scouts, split by
  whether the scout's last command named the decoy (3/30 vs 6/13). Exact binomial
  95% intervals.
- `fig2_defender.png`: Kimi decoy choice by defender response (baseline 38%,
  delayed halt 46%, silent alarm 38%, positive control 0%). 95% task-bootstrap
  intervals; the positive-control bound is exact binomial.
