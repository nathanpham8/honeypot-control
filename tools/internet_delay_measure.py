"""Internet delay, Part 1 (step3-plan.md, "Internet delay: Part 1
measurement"): TCP connection time from this VM to the BashArena attacker
address and to AWS regional endpoints in other US regions. Measure only: a
connect() timed with a monotonic clock, then close; no data is sent. Names
are resolved once beforehand (DNS excluded). Interleaved round-robin,
shuffled target order each round, 50 ms between connects.

Run on the VM (not in a container):  python tools/internet_delay_measure.py
"""

import json
import random
import socket
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "analysis" / "swarm_pilot" / "internet_delay" / "part1.json"
TARGETS = {
    "basharena_attacker_185.199.108.153": ("185.199.108.153", 80),
    "aws_us-east-1_n_virginia": ("ec2.us-east-1.amazonaws.com", 443),
    "aws_us-east-2_ohio": ("ec2.us-east-2.amazonaws.com", 443),
    "aws_us-west-1_n_california": ("ec2.us-west-1.amazonaws.com", 443),
    "aws_us-west-2_oregon": ("ec2.us-west-2.amazonaws.com", 443),
}
N, PAUSE_S, TIMEOUT_S = 300, 0.05, 2.0


def connect_ms(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_S)
    t = time.perf_counter()
    try:
        s.connect((addr, port))
        return (time.perf_counter() - t) * 1000
    except OSError:
        return None
    finally:
        s.close()


def summary(xs):
    xs = sorted(xs)
    q = lambda f: xs[min(len(xs) - 1, max(0, int(round(f * (len(xs) - 1)))))]
    return {"n": len(xs), "median": round(q(0.5), 3), "p10": round(q(0.1), 3), "p90": round(q(0.9), 3),
            "spread_p90_minus_p10": round(q(0.9) - q(0.1), 3), "min": round(xs[0], 3), "max": round(xs[-1], 3),
            "mean": round(statistics.fmean(xs), 3), "sd": round(statistics.pstdev(xs), 3)} if xs else {"n": 0}


def main():
    addrs = {k: (socket.gethostbyname(h), p, h) for k, (h, p) in TARGETS.items()}
    raw = {k: [] for k in TARGETS}
    fails = {k: 0 for k in TARGETS}
    rng = random.Random(20261117)
    t0 = datetime.now(timezone.utc).isoformat()
    for _ in range(N):
        order = list(TARGETS)
        rng.shuffle(order)
        for k in order:
            ms = connect_ms(addrs[k][0], addrs[k][1])
            if ms is None:
                fails[k] += 1
            else:
                raw[k].append(round(ms, 4))
            time.sleep(PAUSE_S)
    res = {"started_utc": t0, "finished_utc": datetime.now(timezone.utc).isoformat(),
           "vm_zone": "us-central1-a", "method": __doc__.strip(),
           "targets": {k: {"host": addrs[k][2], "address": addrs[k][0], "port": addrs[k][1],
                           "failures": fails[k], **summary(raw[k])} for k in TARGETS},
           "raw_ms": raw}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2) + "\n")
    for k, v in res["targets"].items():
        print(f"{k:38s} median {v.get('median')}  p10 {v.get('p10')}  p90 {v.get('p90')}  "
              f"spread {v.get('spread_p90_minus_p10')}  sd {v.get('sd')}  fail {v['failures']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
