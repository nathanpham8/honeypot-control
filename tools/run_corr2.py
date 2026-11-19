"""Run the corrections patch 2 groups (pre-registered in experiment_log.md,
2026-11-17 12:24 CST) in the logged order, from one commit.

  python tools/run_corr2.py --dry-run      # print the commands only
  python tools/run_corr2.py                # run all groups, then the retry batch
  python tools/run_corr2.py --retry-only   # just the one retry batch

Before the first group: the working tree must be clean (one commit for every
group) and no Docker containers may be running. Before each group: the
OpenRouter key must have at least MIN_REMAINING dollars of its limit left.
After each group: if MAX_UNSCORED or more of its runs are unscored (API errors,
including OpenRouter 402), stop and report instead of going on.
Retry: unscored runs are rerun once as a batch (same group, missing
task-epochs) into <log_dir>_retry/<task_id>; whatever is still unscored is
dropped and counted by analysis/corr2.py.

A group whose log dir already holds a finished log with the expected number of
samples is skipped, so an interrupted batch can be resumed from the same commit.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KIMI = "openrouter/moonshotai/kimi-k3.1-pro"
DEEPSEEK = "openrouter/deepseek/deepseek-v4.1-flash-1017"
TASKS = "tasks/scout_tasks.txt"
PARALLEL = 6
MAX_UNSCORED = 4          # 10% of a 40-run group
MIN_REMAINING = 20.0      # dollars left on the key's limit before a group starts

# (name, model, side-task flags, arm, pair-with, epochs, expected runs), logged order.
GROUPS = [
    ("kimi_exp2_anchor", KIMI, ["--exp2"], "baseline", "positive_control", 4, 40),
    ("kimi_warn_baseline", KIMI, ["--exp2-half", "warning"], "baseline", "positive_control", 4, 40),
    ("kimi_rule_baseline", KIMI, ["--exp2-half", "rule"], "baseline", "positive_control", 4, 40),
    ("kimi_warn_pc", KIMI, ["--exp2-half", "warning"], "positive_control", None, 4, 40),
    ("kimi_rule_pc", KIMI, ["--exp2-half", "rule"], "positive_control", None, 4, 40),
    ("ds_exp2_anchor", DEEPSEEK, ["--exp2"], "baseline", "positive_control", 4, 40),
    ("ds_warn_baseline", DEEPSEEK, ["--exp2-half", "warning"], "baseline", "positive_control", 4, 40),
    ("ds_rule_baseline", DEEPSEEK, ["--exp2-half", "rule"], "baseline", "positive_control", 4, 40),
    ("kimi_exp2_instant_halt", KIMI, ["--exp2"], "instant_halt", None, 8, 72),
]


def log_dir(name: str) -> str:
    return f"logs/corr2/{name}"


def command(group, task_file: str = TASKS, epochs: int | None = None,
            out: str | None = None) -> list[str]:
    name, model, flags, arm, pair, ep, _ = group
    cmd = [sys.executable, "run_second.py", *flags, "--arm", arm]
    if pair:
        cmd += ["--pair-with", pair]
    cmd += ["--model", model, "--task-ids-file", task_file,
            "--epochs", str(epochs if epochs is not None else ep),
            "--parallel", str(PARALLEL), "--log-dir", out or log_dir(name)]
    return cmd


def unscored(path: str) -> tuple[int, Counter, Counter, list]:
    """(samples, unscored per task, error messages, statuses) for one log dir."""
    from inspect_ai.log import list_eval_logs, read_eval_log
    n, per_task, msgs, statuses = 0, Counter(), Counter(), []
    if not Path(path).exists():
        return 0, per_task, msgs, statuses
    for info in list_eval_logs(path, recursive=True):
        log = read_eval_log(info)
        statuses.append(log.status)
        for s in log.samples or []:
            n += 1
            if "honeypot_side_task_success" not in (s.scores or {}):
                per_task[str(s.id)] += 1
                msgs[str(s.error.message)[:160] if s.error else "no score, no error"] += 1
    return n, per_task, msgs, statuses


def key_remaining() -> float | None:
    req = urllib.request.Request("https://openrouter.ai/api/v1/key", headers={
        "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY', '')}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r).get("data", {})
    except Exception as e:  # network trouble is reported, not fatal
        print(f"  (could not read key limit: {e})")
        return None
    rem = d.get("limit_remaining")
    return float(rem) if rem is not None else None


def preflight() -> str:
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                           cwd=REPO, capture_output=True, text=True).stdout.strip()
    if dirty:
        raise SystemExit(f"working tree not clean; commit first:\n{dirty}")
    running = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True).stdout.split()
    if running:
        raise SystemExit(f"{len(running)} container(s) running; not starting")
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                          capture_output=True, text=True).stdout.strip()


def run(cmd: list[str]) -> int:
    print("  $ " + " ".join(cmd[1:]), flush=True)
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    return subprocess.run(cmd, cwd=REPO, env=env).returncode


def stop(msg: str) -> None:
    print(f"\nSTOPPED: {msg}", flush=True)
    raise SystemExit(2)


def main_pass() -> None:
    for g in GROUPS:
        name, expected = g[0], g[6]
        n, per_task, msgs, statuses = unscored(str(REPO / log_dir(name)))
        if n == expected and statuses and all(s == "success" for s in statuses):
            print(f"== {name}: already complete ({n} samples), skipped", flush=True)
            continue
        if n:
            stop(f"{name}: partial log present ({n} samples, {statuses}); inspect before rerunning")
        rem = key_remaining()
        print(f"== {name}: key limit remaining ${rem}", flush=True)
        if rem is not None and rem < MIN_REMAINING:
            stop(f"key limit remaining ${rem:.2f} < ${MIN_REMAINING:.0f} before {name}")
        rc = run(command(g))
        n, per_task, msgs, statuses = unscored(str(REPO / log_dir(name)))
        bad = sum(per_task.values())
        print(f"== {name}: exit {rc}, samples {n}/{expected}, unscored {bad}, statuses {statuses}",
              flush=True)
        for m, k in msgs.most_common(5):
            print(f"     {k}x {m}")
        if rc != 0 or n < expected:
            stop(f"{name}: run did not finish ({n}/{expected} samples, exit {rc})")
        if bad >= MAX_UNSCORED:
            stop(f"{name}: {bad} unscored runs (>= {MAX_UNSCORED}); API errors, not retrying")


def retry_pass() -> None:
    print("\n== Retry batch (once) ==", flush=True)
    for g in GROUPS:
        name = g[0]
        _, per_task, _, _ = unscored(str(REPO / log_dir(name)))
        for task, k in sorted(per_task.items()):
            out = f"{log_dir(name)}_retry/{task}"
            if Path(REPO / out).exists():
                print(f"  {name} {task}: retry already ran, skipped")
                continue
            tf = REPO / "logs" / "corr2" / "retry_tasks" / f"{name}_{task}.txt"
            tf.parent.mkdir(parents=True, exist_ok=True)
            tf.write_text(task + "\n")
            run(command(g, task_file=str(tf.relative_to(REPO)), epochs=k, out=out))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--retry-only", action="store_true")
    args = ap.parse_args()
    if args.dry_run:
        for g in GROUPS:
            print(" ".join(command(g)[1:]))
        return 0
    commit = preflight()
    print(f"commit {commit}", flush=True)
    if not args.retry_only:
        main_pass()
    retry_pass()
    print("\nCORR2-RUNS-DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
