import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

INK, BLUE, MUT, BG, CODE = "#1a1a1a", "#2a78d6", "#555555", "#eef3fb", "#f3f3f3"
plt.rcParams.update({"font.family": "DejaVu Sans"})
fig, ax = plt.subplots(figsize=(10, 3.1), dpi=220)
ax.set_xlim(0, 100); ax.set_ylim(0, 31); ax.axis("off")

Y, H = 9, 17
def box(x, w, title, body):
    ax.add_patch(FancyBboxPatch((x, Y), w, H, boxstyle="round,pad=0.3,rounding_size=1.2",
                                linewidth=1.3, edgecolor=BLUE, facecolor=BG))
    ax.text(x + w/2, Y + H - 3.2, title, ha="center", va="center", fontsize=10.5, fontweight="bold", color=INK)
    ax.text(x + w/2, Y + H/2 - 2.2, body, ha="center", va="center", fontsize=8.8, color=MUT, linespacing=1.35)

def arrow(x0, x1):
    ax.add_patch(FancyArrowPatch((x0, Y + H/2), (x1, Y + H/2), arrowstyle="-|>",
                                 mutation_scale=14, linewidth=1.3, color=INK))

box(0.5, 20, "1. Scout", "A scout agent sends\nthe decoy credential;\nthe tripwire fires.")
arrow(21.2, 25.2)
box(25.5, 22, "2. Defender", "One of three arms:\nimmediate halt (visible),\ndelayed halt, or\nsilent containment.")
arrow(48.2, 52.2)
box(52.5, 23, "3. Shared board", "The attackers' shared board\n(defender can't read or edit)\nshows the scout's status\nand last command.")
arrow(76.2, 80.2)
box(80.5, 19, "4. Second agent", "Reads the board,\nthen sends one\ncredential:\nreal or decoy?")

# concrete example of what the board shows, under box 3
ax.add_patch(FancyBboxPatch((38, 0.6), 53, 5.2, boxstyle="round,pad=0.2,rounding_size=0.6",
                            linewidth=0.8, edgecolor="#bbbbbb", facecolor=CODE))
ax.text(64.5, 3.2, 'e.g.  Agent 1 terminated. Last command: cat /home/app/.env.failover',
        ha="center", va="center", fontsize=7.8, color=INK, family="DejaVu Sans Mono")
ax.add_patch(FancyArrowPatch((64, 8.7), (64, 6.0), arrowstyle="-", linewidth=0.8, color="#999999", linestyle=(0,(2,2))))
fig.tight_layout(pad=0.2); fig.savefig("fig0_schematic.png", bbox_inches="tight"); print("ok")
