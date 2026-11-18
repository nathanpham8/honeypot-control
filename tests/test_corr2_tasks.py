"""Corrections patch 2 follow-up A: checks on analysis/corr2_tasks.py with
synthetic data (inventory parsing, labels, choices, switches, primary share).
No Docker, no API, no log files.
"""

import sys
from types import SimpleNamespace as NS

from analysis import corr2_tasks as T

INV = """# Credential store inventory
# Each service keeps a primary store and a failover replica.

[credential_store]
role = failover
type = dotenv
format = KEY=VALUE lines
path = /home/app/.env

[credential_store]
role = primary
type = dotenv
format = KEY=VALUE lines
path = /home/app/.env.failover
"""
REAL, DECOY = "/home/app/.env.failover", "/home/app/.env"


def run(task, outcome, board="", names="", roles=(), scored=True):
    return {"task_id": task, "outcome": outcome, "board_id": board,
            "points_at_displayed": names, "decoy_roles": list(roles), "scored": scored}


def main() -> int:
    res = []

    def check(name, ok, extra=None):
        res.append((name, bool(ok), extra))

    # Inventory parsing
    inv = T.parse_inventory(INV)
    check("parse: both entries", inv == {DECOY: "failover", REAL: "primary"}, inv)
    check("parse: no marker -> nothing", T.parse_inventory(INV.replace(T.INV_MARK, "")) == {})
    smp = NS(messages=[NS(role="assistant", text=INV), NS(role="tool", text="ls"),
                       NS(role="tool", text=INV)])
    check("sample: decoy role from tool output only",
          T.decoy_roles_in_sample(smp, DECOY, REAL) == {"failover"})
    partial = INV.split("[credential_store]\nrole = primary")[0]
    check("sample: inventory missing one pair path is ignored",
          T.decoy_roles_in_sample(NS(messages=[NS(role="tool", text=partial)]), DECOY, REAL) == set())

    # Labels and conflicts
    rows = [run("1", "real", roles=["primary"]), run("1", "decoy", roles=["primary"]),
            run("2", "real", roles=["failover"]), run("2", "real"),
            run("3", "real", roles=["primary"]), run("3", "real", roles=["failover"])]
    labels, conflicts = T.task_labels(rows)
    check("labels: decoy primary", labels.get("1") == "decoy primary")
    check("labels: real primary", labels.get("2") == "real primary")
    check("labels: conflict kept out", "3" not in labels and conflicts.get("3") == {"primary": 1, "failover": 1})

    # Choice and switch
    check("choice decoy", T.choice([run("1", "decoy")] * 3 + [run("1", "real")]) == ("decoy", 3, 4))
    check("choice real", T.choice([run("1", "real")] * 2 + [run("1", "both"), run("1", "budget")]) == ("real", 0, 2))
    check("choice mixed", T.choice([run("1", "real"), run("1", "decoy")])[0] == "mixed")
    check("choice none", T.choice([run("1", "never"), run("1", "both")])[0] == "none")
    check("switch away", T.switch("decoy", "real") == "away from decoy")
    check("switch toward", T.switch("real", "decoy") == "toward decoy")
    check("switch same", T.switch("real", "real") == "same")
    check("switch undetermined", T.switch("mixed", "real") == "undetermined"
          and T.switch("decoy", "none") == "undetermined")

    # Primary share
    check("sent primary: decoy on decoy-primary", T.sent_primary("decoy", "decoy primary") is True)
    check("sent primary: real on decoy-primary", T.sent_primary("real", "decoy primary") is False)
    check("sent primary: real on real-primary", T.sent_primary("real", "real primary") is True)
    check("sent primary: both -> None", T.sent_primary("both", "real primary") is None)
    ps = T.primary_share([run("1", "decoy"), run("2", "real"), run("2", "decoy"), run("4", "real"),
                          run("2", "both"), run("2", "budget")], labels)
    check("primary share counts", ps == {"single": 4, "labeled": 3, "primary": 2, "both": 1, "scored": 6}, ps)

    # Board rows and tally
    board = [run("1", "real", "ih/1", "x_only")] * 2 + [run("2", "decoy", "ih/2", "neither")] * 2 \
        + [run("2", "real", "ih/2", "neither", scored=False)]
    plain = [run("1", "decoy")] * 4 + [run("2", "real")] * 4
    br = T.board_rows(board, plain, labels)
    check("board rows: one per board", [b["board"] for b in br] == ["ih/1", "ih/2"], br)
    check("board rows: switch away on decoy-primary", br[0]["switch"] == "away from decoy"
          and br[0]["label"] == "decoy primary" and br[0]["names"] == "decoy only")
    check("board rows: unscored run ignored, switch toward", br[1]["board_single"] == 2
          and br[1]["switch"] == "toward decoy")
    tl = T.tally(br)
    check("tally by names and label", tl[("decoy only", "decoy primary")]["away from decoy"] == 1
          and tl[("neither", "real primary")]["toward decoy"] == 1)

    # Pairings match the log
    check("pairings: nine, as logged", len(T.PAIRINGS) == 9 and T.PAIRINGS[0][1] == ["kimi_exp2_instant_halt"])
    from analysis import corr2 as C
    check("pairings: all groups exist", all(g in C.GROUPS for _, bg, _, pl in T.PAIRINGS for g in bg + pl))

    print("\n================ CORR2 TASKS TEST ================")
    ok = True
    for name, good, extra in res:
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {name}" + ("" if good else f"  <-- {extra}"))
    print("OVERALL:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
