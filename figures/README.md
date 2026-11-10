# Figures

Regenerate from the repo root: `python figures/make_figures.py` and `python figures/make_schematic.py`.
Palette: blue `#2a78d6`, light blue `#a9c8ef`.

- `fig_headline.png`: the leak (paper R2). Left: decoy choice among single-credential sends, no board (22 of 61) vs a board naming the decoy (2 of 78), pooled over three models. Right: successful thefts by model, no board vs board naming the decoy (DeepSeek 3/40 to 17/40, Kimi 24/40 to 36/38, GLM 12/40 to 23/40; pooled 39/120 to 76/118).
- `fig0_schematic.png`: the two-stage setup. A scout trips the decoy, the defender responds, the attackers' shared board shows the scout's status and last command, and a second agent chooses which credential to steal.
- `fig1_legibility.png`: decoy choice on boards left by real Kimi scouts, split by whether the scout's last command named the decoy (3/30 vs 6/13). Exact binomial 95% intervals.
- `fig2_defender.png`: Kimi decoy choice by defender response (baseline 38%, delayed halt 46%, silent containment 38%, board naming the decoy 0%). 95% task-bootstrap intervals; the zero-count bound is exact binomial.
