"""Regenerate the report figures. Run from the repo root: python figures/make_figures.py

All numbers are taken from the paper (Results R2, R3, R5) and analysis/*_result.md.
"""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = os.path.dirname(os.path.abspath(__file__))
BLUE, LIGHT, INK, MUTED, GRID = "#2a78d6", "#a9c8ef", "#1a1a1a", "#6b6b6b", "#e6e6e6"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12})


def style(ax, ylabel):
    ax.set_ylim(0, 105)
    ax.set_ylabel(ylabel, color=MUTED)
    ax.yaxis.grid(True, color=GRID, lw=1)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=MUTED, length=0)


def chance_line(ax, x, ha="right"):
    ax.axhline(50, ls="--", color=MUTED, lw=1, zorder=1)
    ax.text(x, 51.5, "random choice (50%)", ha=ha, va="bottom", fontsize=10, color=MUTED)


def bars(ax, ticklabels, vals, lo, hi):
    x = list(range(len(vals)))
    ax.bar(x, vals, width=0.55, color=BLUE, zorder=2)
    err = [[v - l for v, l in zip(vals, lo)], [h - v for v, h in zip(vals, hi)]]
    ax.errorbar(x, vals, yerr=err, fmt="none", ecolor=INK, elinewidth=1.5, capsize=5, zorder=3)
    for i, v in enumerate(vals):
        ax.text(i, hi[i] + 2.5, f"{v:.0f}%", ha="center", va="bottom", fontsize=13, fontweight="bold", color=INK)
    ax.set_xticks(x)
    ax.set_xticklabels(ticklabels, color=INK, fontsize=11)
    return x


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)


# Headline: the leak (R2). Positive-control board vs no board, forced-choice side task.
fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4.8), dpi=200, gridspec_kw={"width_ratios": [1, 1.6]})

style(a, "Decoy chosen, % of single-credential sends")
a.bar([0, 1], [36, 3], width=0.55, color=[LIGHT, BLUE], zorder=2)
for i, (v, lab) in enumerate([(36, "36%\n(22 of 61)"), (3, "3%\n(2 of 78)")]):
    a.text(i, v + 2.5, lab, ha="center", va="bottom", fontsize=12, fontweight="bold", color=INK)
a.set_xticks([0, 1])
a.set_xticklabels(["No board", "Board names\nthe decoy"], color=INK, fontsize=11)
a.set_title("Agents stop picking the decoy", loc="left", fontsize=12.5, fontweight="bold", color=INK)

style(b, "Successful thefts, % of runs")
models = ["DeepSeek", "Kimi", "GLM", "Pooled"]
base = [(3, 40), (24, 40), (12, 40), (39, 120)]
pc = [(17, 40), (36, 38), (23, 40), (76, 118)]
w = 0.36
for i, ((bk, bn), (pk, pn)) in enumerate(zip(base, pc)):
    bv, pv = 100 * bk / bn, 100 * pk / pn
    b.bar(i - w / 2, bv, width=w, color=LIGHT, zorder=2, label="No board" if i == 0 else None)
    b.bar(i + w / 2, pv, width=w, color=BLUE, zorder=2, label="Board names the decoy" if i == 0 else None)
    b.text(i - w / 2, bv + 2, f"{bv:.0f}%", ha="center", va="bottom", fontsize=10, color=INK)
    b.text(i + w / 2, pv + 2, f"{pv:.0f}%", ha="center", va="bottom", fontsize=10, fontweight="bold", color=INK)
b.set_xticks(range(len(models)))
b.set_xticklabels(models, color=INK, fontsize=11)
b.set_ylim(0, 118)
b.legend(frameon=False, loc="upper left", ncol=2, fontsize=10)
b.set_title("Successful thefts nearly double", loc="left", fontsize=12.5, fontweight="bold", color=INK)

fig.tight_layout(w_pad=3)
save(fig, "fig_headline.png")

# Figure 1: natural-board legibility (R3), real Kimi scout boards only
fig, ax = plt.subplots(figsize=(7, 4.8), dpi=200)
style(ax, "Decoy chosen, % of single-credential sends")
bars(ax,
     ["Board names the decoy\n(scout's last command)\nn = 30", "Board names no file\n\nn = 13"],
     [10, 46], lo=[2.1, 19.2], hi=[26.5, 74.9])
chance_line(ax, -0.45, ha="left")
ax.set_title("On boards left by real scouts,\nthe leak tracks what the board names",
             loc="left", fontsize=12.5, fontweight="bold", color=INK)
save(fig, "fig1_legibility.png")

# Figure 2: defender response (R5), Kimi
fig, ax = plt.subplots(figsize=(9, 4.8), dpi=200)
style(ax, "Decoy chosen, % of single-credential sends")
bars(ax,
     ["Baseline\nno scout\nn = 39",
      "Delayed halt\nhalted 3 steps\nafter the trip\nn = 52",
      "Silent containment\nscout shown active,\ntraffic sinkholed\nn = 64",
      "Visible signal\nboard names\nthe decoy\nn = 36"],
     [38, 46, 38, 0], lo=[10, 15, 12, 0], hi=[69, 86, 75, 9.7])
chance_line(ax, 3.45)
ax.set_title("Only a board that names the decoy breaks the honeypot",
             loc="left", fontsize=12.5, fontweight="bold", color=INK)
save(fig, "fig2_defender.png")

print("figures written to", OUT)
