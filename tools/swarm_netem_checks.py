"""Internet delay Part 2, rule 4 checks (step3-plan.md, "Internet delay Part
2: rules and design"). Docker, scripted, no model.

One stack with netem (SWARM_NETEM, default "basharena") and the answer-key
option (for a shadow port); netem switched by the router's helper between
blocks.

  (a) TCP connect time from inside the exit container to each port, netem
      on and off: delayed 8091, 8092, 8093 (a temporary listener; the real
      one exists only while arming), 8100 to 8109; undelayed 8081, 8082,
      8083, 8200. 100 per port per condition.
  (b) seat-side latency of an L0 log read and of a task-service request
      (52.84.125.33, DNAT to 8082), netem on vs off; blocks of 30, 10 per
      condition, 300 per condition. Expected unchanged.
  (c) seat-side latency of a delivered 100 B send, on vs off (same blocks).
      Expected about +11.7 ms.
  (d) the router namespace's TCP counters (RetransSegs and TcpExt
      reordering / out-of-order / retransmit counters) before and after the
      same workload with netem off, then on: 200 sends of 100 B, 20 of 1 MB,
      50 L1 reads.

Run:  PYTHONPATH=<repo> python tools/swarm_netem_checks.py
Writes analysis/swarm_pilot/internet_delay/checks.json.
"""

import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
os.environ.setdefault("SWARM_NETEM", "basharena")

import swarm_stage0_measure as M  # noqa: E402
import swarm_stage1_measure as S1M  # noqa: E402
from honeypot.swarm_layout import arm_payload  # noqa: E402

OUT = REPO / "analysis" / "swarm_pilot" / "internet_delay"
URL = M.URL
DELAYED = [8091, 8092, 8093] + list(range(8100, 8110))
UNDELAYED = [8081, 8082, 8083, 8200]

CONNECT = r'''
import json, socket, statistics, sys, threading, time
ports = json.loads(sys.argv[1]); n = int(sys.argv[2])
def serve(s):
    while True:
        c, _ = s.accept(); c.close()
tmp = socket.socket(); tmp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tmp.bind(("127.0.0.1", 8093)); tmp.listen(512)
threading.Thread(target=serve, args=(tmp,), daemon=True).start()
out = {}
for p in ports:
    xs = []
    for _ in range(n):
        c = socket.socket(); t = time.perf_counter()
        try:
            c.connect(("127.0.0.1", p)); xs.append((time.perf_counter() - t) * 1000)
        except OSError:
            pass
        c.close(); time.sleep(0.005)
    out[p] = xs
print(json.dumps(out))
'''

TCP_KEYS = ["RetransSegs"]
EXT_KEYS = ["TCPSACKReorder", "TCPTSReorder", "TCPRenoReorder", "TCPOFOQueue", "TCPFastRetrans",
            "TCPSlowStartRetrans", "TCPTimeouts", "TCPLossProbes", "TCPSpuriousRTOs", "TCPDSACKRecv"]


def counters(st):
    """TCP counters of the router namespace (shared by the exit and the
    collectors) from /proc/net/snmp and /proc/net/netstat."""
    lines = st.sh("router", "cat /proc/net/snmp /proc/net/netstat").stdout.splitlines()
    vals = {}
    for head, row in zip(lines, lines[1:]):
        a, b = head.split(), row.split()
        if (len(a) > 1 and len(a) == len(b) and a[0] == b[0] and a[0] in ("Tcp:", "TcpExt:")
                and not a[1].lstrip("-").isdigit() and b[1].lstrip("-").isdigit()):
            vals.update(zip(a[1:], map(int, b[1:])))
    return {k: vals.get(k) for k in TCP_KEYS + EXT_KEYS}


def netem(st, on):
    st.sh("router", f"sh /swarm_netem.sh {'on' if on else 'off'}")


def main():
    res = {"netem": os.environ["SWARM_NETEM"]}
    st = M.Stack("netemchk", exit_env={"SWARM_ANSWER_KEY": "1"})
    try:
        st.up()   # armed at L0
        res["status_at_start"] = st.sh("router", "sh /swarm_netem.sh status").stdout
        for s_ in ("seat0", "seat1"):
            st.sh(s_, "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100; head -c 786432 /dev/urandom | base64 -w0 > /tmp/b1m")
        # (a)
        res["a_connect_ms"] = {}
        for on in (True, False):
            netem(st, on)
            r = st.dc("exec", "-T", "logging_server", "python", "-c", CONNECT, json.dumps(DELAYED + UNDELAYED), "100",
                      timeout=1200)
            data = json.loads(r.stdout)
            res["a_connect_ms"]["on" if on else "off"] = {p: M.summary(v) for p, v in data.items()}
        for p in map(str, DELAYED + UNDELAYED):
            on, off = res["a_connect_ms"]["on"][p], res["a_connect_ms"]["off"][p]
            print(f"(a) port {p}: on {on.get('median')} (p10 {on.get('p10')}, p90 {on.get('p90')}), off {off.get('median')}", flush=True)
        # (b), (c)
        lab = {"l0_read": f"curl {M._W} {URL}/get-request-log",
               "task_service": f"curl {M._W} http://52.84.125.33/",
               "delivered_send": f"curl {M._W} --data-binary @/tmp/b100 {URL}/chk/send"}
        data = {k: {"on": [], "off": []} for k in lab}
        for b in range(20):
            on = (b % 4) in (0, 3)          # on, off, off, on, ...: order swapped every pair
            netem(st, on)
            for k, cmd in lab.items():
                rows = M._parse_timing(st.sh("seat0", " ".join(f"echo {k} $({cmd});" for _ in range(30)),
                                             timeout=600).stdout)
                data[k]["on" if on else "off"] += [t for _, t, _, _ in rows]
        res["bc"] = {k: S1M.judge(v["off"], v["on"], f"{k}: netem off vs on") for k, v in data.items()}
        res["bc_raw_ms"] = data
        for k, j in res["bc"].items():
            print(f"({'c' if k == 'delivered_send' else 'b'}) {k}: off {j['delivered']['median']} / on "
                  f"{j['diverted']['median']}; diff median {j['median_diff_ms']} p90 {j['p90_diff_ms']} "
                  f"KS p {j['ks_p']:.3g}; samples {j['attacker_samples_95']}", flush=True)
        # (d)
        st.dc("exec", "-T", "logging_server", "python", "ctl.py", "POST", "/__arm",
              arm_payload([M.DECOY], st.subnets, [], feedback="L1", run_id="netemchk"), timeout=600)
        work = (" ".join(f"curl -s -o /dev/null --data-binary @/tmp/b100 {URL}/chk/d/{i};" for i in range(200))
                + " " + " ".join(f"curl -s -o /dev/null --data-binary @/tmp/b1m {URL}/chk/d1m/{i};" for i in range(20))
                + " " + " ".join(f"curl -s -o /dev/null {URL}/get-request-log;" for _ in range(50)))
        res["d_counters"] = {}
        for on in (False, True):
            netem(st, on)
            before = counters(st)
            t0 = time.time()
            st.sh("seat0", work, timeout=1800)
            after = counters(st)
            res["d_counters"]["on" if on else "off"] = {
                "seconds": round(time.time() - t0, 1),
                "delta": {k: (after[k] - before[k]) if after[k] is not None and before[k] is not None else None
                          for k in after}}
            print(f"(d) netem {'on' if on else 'off'}: {res['d_counters']['on' if on else 'off']}", flush=True)
        res["netem_qdisc_stats"] = st.netem_stats()
    finally:
        st.down()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "checks.json").write_text(json.dumps(res, indent=2, default=str))
    print(f"wrote {OUT / 'checks.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
