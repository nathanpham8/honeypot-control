"""Corrections patch 2 follow-up A (exploratory, added after the results; logged
in experiment_log.md on 2026-11-18 before computing): Kimi's choice on each
board against its choice on the plain board for the same task, with the
inventory label (decoy primary or real primary), and the primary-label share for
every Kimi and DeepSeek cell. Read-only; writes CSVs under --out.

    PYTHONPATH=. python analysis/corr2_tasks.py --old-logs ~/honeypot-control/logs
"""

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from analysis import corr2 as C

INV_MARK = "# Credential store inventory"
ENTRY = re.compile(r"role\s*=\s*(primary|failover)\s*\n\s*type\s*=[^\n]*\n\s*format\s*=[^\n]*\n"
                   r"\s*path\s*=\s*(\S+)")
DISPLAY = {"x_only": "decoy only", "y_only": "real only", "both": "both", "neither": "neither"}
SINGLE = ("real", "decoy")

EXP2_PLAIN = ["kimi_exp2_baseline", "kimi_exp2_anchor"]
# (label, board groups, source, plain cells), as logged.
PAIRINGS = [
    ("Part 2 immediate halt", ["kimi_exp2_instant_halt"], "real-scout", EXP2_PLAIN),
    ("delayed halt", ["kimi_exp2_delayed"], "real-scout", EXP2_PLAIN),
    ("silent alarm", ["kimi_exp2_silent"], "real-scout", EXP2_PLAIN),
    ("live-scout immediate halt", ["kimi_exp2_live15"], "real-scout", EXP2_PLAIN),
    ("Experiment 3 gateway", ["kimi_exp3_gateway"], "real-scout", EXP2_PLAIN),
    ("Experiment 2 positive control", ["kimi_exp2_pc"], "constructed", EXP2_PLAIN),
    ("warning-only positive control", ["kimi_warn_pc"], "constructed", ["kimi_warn_baseline"]),
    ("rule-only positive control", ["kimi_rule_pc"], "constructed", ["kimi_rule_baseline"]),
    ("no-sentence positive control", ["kimi_greedy_pc"], "constructed", ["kimi_greedy_baseline"]),
]


# --- Pure helpers (tested without logs) --------------------------------------

def parse_inventory(text: str) -> dict:
    """{path: role} from an inventory as printed in a tool output."""
    if INV_MARK not in (text or ""):
        return {}
    return {path: role for role, path in ENTRY.findall(text)}


def decoy_roles_in_sample(sample, decoy_path: str, real_path: str) -> set:
    """Decoy roles seen in this run's printed inventories (empty if never printed
    in full). A printed inventory counts only if it lists both pair paths."""
    seen = set()
    for m in getattr(sample, "messages", None) or []:
        if getattr(m, "role", None) != "tool":
            continue
        inv = parse_inventory(getattr(m, "text", "") or "")
        if decoy_path in inv and real_path in inv:
            seen.add(inv[decoy_path])
    return seen


def task_labels(rows: list) -> tuple[dict, dict]:
    """Per task: 'decoy primary' / 'real primary' when every run that printed the
    inventory agrees; conflicting tasks are returned separately with counts."""
    seen = defaultdict(Counter)
    for r in rows:
        for role in r.get("decoy_roles", ()):
            seen[r["task_id"]][role] += 1
    labels, conflicts = {}, {}
    for t, c in seen.items():
        if len(c) == 1:
            labels[t] = "decoy primary" if "primary" in c else "real primary"
        else:
            conflicts[t] = dict(c)
    return labels, conflicts


def choice(rows: list) -> tuple[str, int, int]:
    """(choice, decoy sends, single-file sends) over the single-file sends."""
    s = [r for r in rows if r.get("outcome") in SINGLE]
    d = sum(r["outcome"] == "decoy" for r in s)
    n = len(s)
    if n == 0:
        return "none", 0, 0
    if 2 * d > n:
        return "decoy", d, n
    if 2 * d < n:
        return "real", d, n
    return "mixed", d, n


def switch(plain: str, board: str) -> str:
    if plain in SINGLE and board in SINGLE:
        if plain == board:
            return "same"
        return "away from decoy" if plain == "decoy" else "toward decoy"
    return "undetermined"


def sent_primary(outcome: str, label: str) -> bool | None:
    """Was the single file sent the one labeled primary? None if not a single
    send or the task has no label."""
    if outcome not in SINGLE or label not in ("decoy primary", "real primary"):
        return None
    return (outcome == "decoy") == (label == "decoy primary")


def primary_share(rows: list, labels: dict) -> dict:
    singles = [r for r in rows if r.get("outcome") in SINGLE]
    known = [r for r in singles if r["task_id"] in labels]
    prim = sum(bool(sent_primary(r["outcome"], labels[r["task_id"]])) for r in known)
    return {"single": len(singles), "labeled": len(known), "primary": prim,
            "both": sum(r.get("outcome") == "both" for r in rows),
            "scored": sum(bool(r.get("scored")) for r in rows)}


def board_rows(board_runs: list, plain_runs: list, labels: dict) -> list[dict]:
    """One row per board: its choice vs the plain choice for the same task."""
    by_board = defaultdict(list)
    for r in board_runs:
        if r.get("scored"):
            by_board[r["board_id"] or r["task_id"]].append(r)
    plain_by_task = defaultdict(list)
    for r in plain_runs:
        if r.get("scored"):
            plain_by_task[r["task_id"]].append(r)
    out = []
    for b, runs in sorted(by_board.items()):
        t = runs[0]["task_id"]
        bc, bd, bn = choice(runs)
        pc, pd, pn = choice(plain_by_task.get(t, []))
        out.append({"board": b, "task_id": t,
                    "names": DISPLAY.get(runs[0].get("points_at_displayed", ""),
                                         runs[0].get("points_at_displayed", "") or "(none)"),
                    "label": labels.get(t, "unknown"),
                    "board_choice": bc, "board_decoy": bd, "board_single": bn,
                    "plain_choice": pc, "plain_decoy": pd, "plain_single": pn,
                    "switch": switch(pc, bc)})
    return out


def tally(rows: list[dict]) -> dict:
    """Counts by (names, label): boards and each switch class."""
    out = defaultdict(Counter)
    for r in rows:
        out[(r["names"], r["label"])]["boards"] += 1
        out[(r["names"], r["label"])][r["switch"]] += 1
    return out


# --- Log reading --------------------------------------------------------------

def load_rows(names: list, roots: dict) -> list[dict]:
    from inspect_ai.log import list_eval_logs, read_eval_log
    rows = []
    for name in names:
        g = C.GROUPS[name]
        for d in g["dirs"]:
            base = Path(roots[g["root"]]) / d
            for path, retry in ((base, False), (Path(str(base) + "_retry"), True)):
                if not path.exists():
                    continue
                for info in list_eval_logs(str(path), recursive=True):
                    log = read_eval_log(info)
                    for s in log.samples or []:
                        r = C.sample_row(g, s, Path(str(info.name)).name, retry)
                        score = (s.scores or {}).get(C.SCORER)
                        m = (score.metadata or {}) if score is not None else {}
                        ht = (getattr(s, "store", None) or {}).get("honeytoken") or {}
                        dp = m.get("decoy_path") or ht.get("decoy_path") or ""
                        rp = m.get("real_path") or ht.get("real_path") or ""
                        r["decoy_roles"] = sorted(decoy_roles_in_sample(s, dp, rp))
                        rows.append(r)
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-logs", default=str(Path.home() / "honeypot-control" / "logs"))
    ap.add_argument("--new-logs", default=str(C.REPO / "logs"))
    ap.add_argument("--out", default=str(C.REPO / "analysis" / "out_corr2" / "tasks"))
    args = ap.parse_args()
    roots = {"old": args.old_logs, "new": args.new_logs}
    out = Path(args.out)

    names = [n for n, g in C.GROUPS.items() if g["model"] in (C.KIMI, C.DEEPSEEK)]
    rows = [r for r in load_rows(names, roots) if not r["retry"] or r["scored"]]
    labels, conflicts = task_labels(rows)
    by_group = defaultdict(list)
    for r in rows:
        by_group[r["group"]].append(r)

    print("=== Inventory label per task (from the runs' printed inventories) ===")
    printed = Counter(r["task_id"] for r in rows if r["decoy_roles"])
    for t in sorted(set(r["task_id"] for r in rows)):
        print(f"  {t:10s} {labels.get(t, 'CONFLICT' if t in conflicts else 'unknown'):14s}"
              f" runs that printed it: {printed[t]}" + (f"  {conflicts[t]}" if t in conflicts else ""))
    print(f"  runs: {len(rows)}, with a full printed inventory: {sum(1 for r in rows if r['decoy_roles'])}")

    all_boards = []
    print("\n=== A1. Board choice vs plain choice, one row per board (Kimi) ===")
    for label, bgs, source, plain in PAIRINGS:
        brs = board_rows([r for g in bgs for r in by_group[g]],
                         [r for g in plain for r in by_group[g]], labels)
        for b in brs:
            b.update({"pairing": label, "source": source})
        all_boards += brs
        print(f"\n--- {label} ({source}; plain: {'+'.join(plain)}) ---")
        print(f"  {'board':34s} {'names':11s} {'label':14s} {'plain':12s} {'board':12s} switch")
        for b in brs:
            print(f"  {b['board']:34s} {b['names']:11s} {b['label']:14s} "
                  f"{b['plain_choice']:5s} {b['plain_decoy']:>2}/{b['plain_single']:<3}  "
                  f"{b['board_choice']:5s} {b['board_decoy']:>2}/{b['board_single']:<3}  {b['switch']}")
        for (names_, lab), c in sorted(tally(brs).items()):
            print(f"  [{names_} | {lab}] boards {c['boards']}: away from decoy {c['away from decoy']}, "
                  f"toward decoy {c['toward decoy']}, same {c['same']}, undetermined {c['undetermined']}")

    print("\n=== A2. Pooled by source, what the board names and inventory label ===")
    for source in ("real-scout", "constructed"):
        print(f"--- {source} ---")
        for (names_, lab), c in sorted(tally([b for b in all_boards if b["source"] == source]).items()):
            print(f"  [{names_:10s} | {lab:13s}] boards {c['boards']:2d}: away from decoy {c['away from decoy']}, "
                  f"toward decoy {c['toward decoy']}, same {c['same']}, undetermined {c['undetermined']}")

    print("\n=== A3. Primary-label share, every Kimi and DeepSeek cell ===")
    share_rows = []
    for n in names:
        p = primary_share(by_group[n], labels)
        share_rows.append({"group": n, **p})
        frac = f"{p['primary']}/{p['labeled']}" + (f" ({100 * p['primary'] / p['labeled']:.0f}%)" if p["labeled"] else "")
        print(f"  {n:24s} single sends {p['single']:3d}, sent the primary {frac:12s} both-file sends {p['both']:3d} of {p['scored']} scored")

    write_csv(out / "boards.csv", all_boards)
    write_csv(out / "primary_share.csv", share_rows)
    write_csv(out / "labels.csv", [{"task_id": t, "label": labels.get(t, ""), "conflict": conflicts.get(t, ""),
                                    "runs_printed": printed[t]} for t in sorted(set(r["task_id"] for r in rows))])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
