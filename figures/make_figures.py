"""Regenerate the two report figures. Run: python figures/make_figures.py"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BLUE, INK, MUTED, GRID = "#2a78d6", "#1a1a1a", "#6b6b6b", "#e6e6e6"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12})

def style(ax, ylabel):
    ax.set_ylim(0, 100); ax.set_ylabel(ylabel, color=MUTED)
    ax.yaxis.grid(True, color=GRID, lw=1); ax.set_axisbelow(True)
    for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(MUTED); ax.tick_params(colors=MUTED, length=0)

def bars(ax, labels, sub, ns, vals, lo, hi, chance=True):
    x = range(len(vals))
    ax.bar(x, vals, width=0.55, color=BLUE, zorder=2)
    err = [[v - l for v, l in zip(vals, lo)], [h - v for v, h in zip(vals, hi)]]
    ax.errorbar(x, vals, yerr=err, fmt="none", ecolor=INK, elinewidth=1.5, capsize=5, zorder=3)
    for i, v in enumerate(vals):
        ax.text(i, hi[i] + 2.5, f"{v:.0f}%", ha="center", va="bottom", fontsize=13, fontweight="bold", color=INK)
    if chance:
        ax.axhline(50, ls="--", color=MUTED, lw=1, zorder=1)
        ax.text(-0.45, 51.5, "random choice (50%)", ha="left", va="bottom", fontsize=10, color=MUTED)
    ax.set_xticks(list(x)); ax.set_xticklabels([f"{l}\n{s}\nn = {n}" for l, s, n in zip(labels, sub, ns)], color=INK, fontsize=11)

# Figure 1: natural-board legibility (R3), real scout boards only
fig, ax = plt.subplots(figsize=(7, 4.6), dpi=200)
style(ax, "Decoy chosen, % of single-file sends")
bars(ax, ["Board points to the decoy", "Board points to nothing"],
     ["(scout's last command names it)", "(no file named)"], [30, 13], [10, 46],
     lo=[2.1, 19.2], hi=[26.5, 74.9])
ax.set_title("On boards left by real scouts, the leak tracks what the board names", loc="left", fontsize=12.5, fontweight="bold", color=INK)
fig.tight_layout(); fig.savefig("fig1_legibility.png"); plt.close(fig)

# Figure 2: defender response (R5)
fig, ax = plt.subplots(figsize=(7.4, 4.6), dpi=200)
style(ax, "Decoy chosen, % of single-file sends")
bars(ax, ["Baseline", "Delayed halt", "Silent alarm", "Positive control"],
     ["no scout", "scout halted 3 steps later", "scout shown active", "board points to decoy"],
     [39, 52, 64, 36], [38, 46, 38, 0], lo=[10, 15, 12, 0], hi=[69, 86, 75, 9.7])
ax.set_title("Only a board pointing to the decoy breaks the honeypot", loc="left", fontsize=12.5, fontweight="bold", color=INK)
fig.tight_layout(); fig.savefig("fig2_defender.png"); plt.close(fig)
print("figs ok")
