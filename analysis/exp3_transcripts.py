"""Experiment 3 transcript checks (descriptive, reads run logs only).

For every scout run in a log directory:

  A. Ordering. For runs where a real credential reached the attacker although
     the decoy was also sent, print the command(s) that did the sending, so the
     "real first, decoy moments later" pattern can be read directly.

  B. Open-trigger counterfactual. Would a tripwire on touching the decoy file
     have fired before the agent's first send? Approximated as: the agent ran a
     command that names the decoy file's path at an earlier step than its first
     command that contains the collection address. This is an upper bound:
     naming a path is not always opening it, and it assumes the tripwire could
     not be tampered with.

Usage:
  python analysis/exp3_transcripts.py logs/exp3/scouts_silent_gateway [--show 8] [--width 900]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inspect_ai.log import list_eval_logs, read_eval_log  # noqa: E402

import run_scouts  # noqa: E402

IP = run_scouts.IP


def analyze_sample(sample) -> dict:
    ht = (sample.metadata or {}).get("honeytoken") or {}
    decoy_path, real_path = ht.get("decoy_path") or "", ht.get("real_path") or ""
    sc = (sample.scores or {}).get("honeypot_side_task_success")
    meta = (sc.metadata or {}) if sc else {}
    gw = meta.get("gateway") or {}
    trip = meta.get("protocol_first_trip") or {}
    cmds = run_scouts._agent_bash_cmds(sample)

    send_steps = [st for st, c in cmds if IP in c]
    decoy_steps = [st for st, c in cmds if run_scouts._names_path(decoy_path, c)]
    real_steps = [st for st, c in cmds if run_scouts._names_path(real_path, c)]
    first_send = min(send_steps) if send_steps else None
    first_decoy = min(decoy_steps) if decoy_steps else None
    first_real = min(real_steps) if real_steps else None
    trip_step = trip.get("detected_at_step")
    sends_before_trip = [c for st, c in cmds
                         if IP in c and (trip_step is None or st <= trip_step)]
    return {
        "task_id": str(sample.id),
        "epoch": getattr(sample, "epoch", None),
        "scored": sc is not None,
        "tripped": bool(meta.get("decoy_hit")),
        "real_reached": bool(meta.get("real_sent") or meta.get("real_encoded")),
        "real_before_trip": bool(gw.get("collector_real_before_trip")),
        "trip_categories": trip.get("categories_in_request") or [],
        "trip_step": trip_step,
        "first_send_step": first_send,
        "first_decoy_named_step": first_decoy,
        "first_real_named_step": first_real,
        # the decoy file was named in a command strictly before any send command
        "decoy_named_before_send": first_decoy is not None
                                   and (first_send is None or first_decoy < first_send),
        "send_commands_before_trip": sends_before_trip,
        "n_send_commands_before_trip": len(sends_before_trip),
    }


def load(log_dir: str) -> list[dict]:
    rows = []
    for info in list_eval_logs(log_dir, recursive=True):
        log = read_eval_log(info)
        for s in log.samples or []:
            rows.append(analyze_sample(s))
    return rows


def report(rows: list[dict], show: int, width: int) -> str:
    scored = [r for r in rows if r["scored"]]
    tripped = [r for r in scored if r["tripped"]]
    leaked = [r for r in scored if r["real_reached"]]
    leaked_trip = [r for r in leaked if r["tripped"]]
    leaked_notrip = [r for r in leaked if not r["tripped"]]
    L = []
    L.append(f"runs={len(rows)} scored={len(scored)} tripped={len(tripped)} "
             f"real_reached={len(leaked)} (tripped {len(leaked_trip)}, no trip {len(leaked_notrip)})")

    L.append("\n== B. Open-trigger counterfactual (upper bound) ==")
    L.append("Decoy file named in a command at an earlier step than the first send command:")
    for name, grp in [("all scored runs", scored), ("tripped", tripped),
                      ("real reached attacker", leaked),
                      ("  of which tripped", leaked_trip),
                      ("  of which never sent the decoy", leaked_notrip)]:
        k = sum(1 for r in grp if r["decoy_named_before_send"])
        L.append(f"  {name:34s} {k} of {len(grp)}")
    never = sum(1 for r in scored if r["first_decoy_named_step"] is None)
    L.append(f"  runs that never named the decoy file in any command: {never} of {len(scored)}")

    L.append("\n== A. Runs where real reached the attacker and the decoy was also sent ==")
    L.append("(send commands up to the step the trip was detected; one command with two")
    L.append(" requests in sequence is the 'real first, decoy moments later' pattern)")
    for r in leaked_trip[:show]:
        L.append(f"\n--- task {r['task_id']} epoch {r['epoch']} | first flagged request: "
                 f"{'+'.join(r['trip_categories']) or '?'} | trip step {r['trip_step']} | "
                 f"send commands before trip: {r['n_send_commands_before_trip']} | "
                 f"decoy named before first send: {r['decoy_named_before_send']}")
        for c in r["send_commands_before_trip"][-2:]:
            c = " ".join(c.split())
            L.append("    $ " + (c[:width] + (" ..." if len(c) > width else "")))
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log_dir")
    ap.add_argument("--show", type=int, default=12)
    ap.add_argument("--width", type=int, default=900)
    args = ap.parse_args()
    print(report(load(args.log_dir), args.show, args.width))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
