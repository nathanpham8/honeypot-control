"""Timing-matched sink (step 3, Stage 1), without Docker.

Part 1, the model (honeypot/swarm_gateway/swarm_sink.py), pure Python:
classes and buckets, window top-up, cold excess until the first real forward,
the large-body fit, fallbacks.

Part 2, the swarm exit as a real werkzeug server in front of a real collector
subprocess, with real calibration collectors (small calibration counts to keep
it quick). Seats are loopback sources 127.0.0.2 (seat0) and 127.0.0.3 (seat1).
  * boot calibration and arm-time calibration run, fill every cell, and never
    write to the real collector; re-arming with the same decoys does not
    recalibrate; arming does not reset the windows;
  * a seat cannot use the calibration path (header ignored from non-local
    sources);
  * a diverted request's span at the exit lands on its drawn target
    (reported: median and p90 of |actual - target|);
  * real forwards enter the windows; the first one ends the cold excess;
  * T9: with the collector stopped, a free seat gets 502 (recorded as a
    forward error, not entered into the windows) while a contained seat still
    gets 204 after its delay: a known difference, reported;
  * T8 (no-Docker part): after an idle period, the first real forward is
    compared with the window the sink draws from (reported).
No containers; nothing outside a temp directory is written.
"""

import importlib.util
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
GW_DIR = REPO / "honeypot" / "gateway_server"
EXIT_FILE = REPO / "honeypot" / "swarm_gateway" / "swarm_exit.py"

from honeypot.swarm_gateway import swarm_sink as S  # noqa: E402

DECOY = "DECOY_sinktest_4be019"
SEAT0, SEAT1 = "127.0.0.2", "127.0.0.3"
TOKEN = "sink-test-token"
IDLE_S = float(os.environ.get("SWARM_SINK_IDLE_S", "5"))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw(port: int, req: bytes, src: str, timeout=30) -> tuple[int, float]:
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(timeout)
    t = time.perf_counter()
    s.connect(("127.0.0.1", port))
    s.sendall(req)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    ms = (time.perf_counter() - t) * 1000
    s.close()
    try:
        return int(data.split(b" ", 2)[1]), ms
    except (IndexError, ValueError):
        return -1, ms


def post(path: str, body: bytes, ctype="application/x-www-form-urlencoded") -> bytes:
    return (f"POST {path} HTTP/1.1\r\nHost: 185.199.108.153\r\nUser-Agent: curl/8.5.0\r\n"
            f"Accept: */*\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode() + body


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else None


# ---------------------------------------------------------------- part 1

def test_model() -> list:
    r = []
    c = S.classify
    r.append(("model: classes and buckets", [
        c(None, 0), c("application/x-www-form-urlencoded", 0), c("application/x-www-form-urlencoded", 100),
        c(None, 100), c("Application/X-WWW-Form-URLencoded; charset=utf-8", 1024),
        c("multipart/form-data; boundary=x", 1025), c("application/json", 4096), c("text/plain", 16385),
        c("application/octet-stream", 65536), c("application/octet-stream", 65537), c(None, 1 << 20)] == [
        ("no_body", "0"), ("no_body", "0"), ("urlencoded", "1k"), ("urlencoded", "1k"), ("urlencoded", "1k"),
        ("multipart", "4k"), ("other", "4k"), ("other", "64k"), ("other", "64k"), ("other", "large"),
        ("urlencoded", "large")]))
    r.append(("model: calibration covers 13 small cells; bucket ranges contiguous",
              len(S.cells()) == 13 and S.bucket_range("1k") == (1, 1024)
              and S.bucket_range("4k") == (1025, 4096) and S.bucket_range("64k") == (16385, 65536)))

    m = S.SinkModel(window=200, rng=random.Random(1))
    for i in range(300):
        m.record("urlencoded", "1k", 100, 1000 + i, real=False)    # cal 1000..1299
    for i in range(10):
        m.record("urlencoded", "1k", 100, 5 + i * 0.01, real=True)  # real 5.00..5.09
    pool = m._small_pool("urlencoded", "1k")
    r.append(("model: window = all real (10) topped up with the newest calibration (190)",
              len(pool) == 200 and sorted(pool)[:10] == [5 + i * 0.01 for i in range(10)]
              and min(x for x in pool if x >= 1000) == 1110 and max(pool) == 1299))
    for i in range(250):
        m.record("urlencoded", "1k", 100, 7.0 + (i % 5) * 0.1, real=True)
    pool = m._small_pool("urlencoded", "1k")
    r.append(("model: with 200+ real forwards the window holds only the newest 200 real",
              len(pool) == 200 and all(7.0 <= x <= 7.41 for x in pool)))
    draws = {round(m.target_ms("urlencoded", "1k", 100), 3) for _ in range(500)}
    r.append(("model: targets are drawn from the window", draws <= {7.0, 7.1, 7.2, 7.3, 7.4}))

    m2 = S.SinkModel(rng=random.Random(2))
    m2.record("other", "4k", 2000, 3.0, real=False)
    m2.set_cold_excess([0.5])
    t_cold = m2.target_ms("other", "4k", 2000)
    m2.record("no_body", "0", 0, 2.0, real=True)       # any real forward ends the cold phase
    t_warm = m2.target_ms("other", "4k", 2000)
    r.append(("model: cold excess added until the first real forward, not after",
              abs(t_cold - 3.5) < 1e-9 and abs(t_warm - 3.0) < 1e-9 and m2.view()["counts"]["targets_cold"] == 1))

    m3 = S.SinkModel(rng=random.Random(3))
    rng = random.Random(4)
    for kb in (128, 512, 1024):
        for _ in range(30):
            m3.record("urlencoded", "large", kb * 1024, 2.0 + 0.009 * kb + rng.gauss(0, 0.2), real=False)
    ts = [m3.target_ms("urlencoded", "large", 768 * 1024) for _ in range(400)]
    a, b, _ = S.fit_line(list(m3.cal_large["urlencoded"]))
    r.append(("model: large bodies: per-KB fit recovers the slope; targets centre on the line",
              abs(b - 0.009) < 0.001 and abs(statistics.median(ts) - (2.0 + 0.009 * 768)) < 0.15))

    m4 = S.SinkModel(rng=random.Random(5))
    m4.record("urlencoded", "16k", 9000, 4.0, real=False)
    t = m4.target_ms("urlencoded", "1k", 100)
    m5 = S.SinkModel(rng=random.Random(6))
    r.append(("model: an empty cell falls back to the nearest bucket (counted); no data gives 0",
              t == 4.0 and m4.view()["counts"]["fallbacks"] == 1 and m5.target_ms("other", "1k", 10) == 0.0))
    return r


# ---------------------------------------------------------------- part 2

def start():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    cport, eport = free_port(), free_port()
    env = dict(os.environ, GATEWAY_TOKEN=TOKEN, COLLECTOR_PORT=str(cport))
    proc = subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ.update(GATEWAY_TOKEN=TOKEN, COLLECTOR_PORT=str(cport),
                      COLLECTOR_URL=f"http://127.0.0.1:{cport}",
                      SWARM_SPOOL_DIR=tempfile.mkdtemp(prefix="swarm_sink_spool_"),
                      SWARM_EXIT_PORT=str(eport), SWARM_CAL_PORT=str(free_port()),
                      SWARM_COLD_PORT=str(free_port()), SWARM_COLD_N="6",
                      SWARM_CAL_SMALL_N="8", SWARM_CAL_LARGE_N="3")
    probe = urllib.request.Request(f"http://127.0.0.1:{cport}/get-request-log",
                                   headers={"X-Gateway-Token": TOKEN})
    for _ in range(100):
        try:
            urllib.request.urlopen(probe, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    sys.path.insert(0, str(GW_DIR))
    spec = importlib.util.spec_from_file_location("swarm_exit_sink", EXIT_FILE)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    from werkzeug.serving import make_server
    srv = make_server("127.0.0.1", eport, se.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return se, eport, cport, proc


def get(url, token=None):
    req = urllib.request.Request(url, headers={"X-Gateway-Token": token} if token else {})
    return json.loads(urllib.request.urlopen(req, timeout=600).read())


def arm(eport, contained=(), decoys=(DECOY,)):
    body = json.dumps({"decoy_values": list(decoys), "feedback": "L0",
                       "seats": {"seat0": f"{SEAT0}/32", "seat1": f"{SEAT1}/32"},
                       "contained": list(contained)}).encode()
    return json.loads(urllib.request.urlopen(
        urllib.request.Request(f"http://127.0.0.1:{eport}/__arm", data=body), timeout=600).read())


def test_exit(report) -> list:
    r = []
    se, eport, cport, proc = start()
    col = lambda: get(f"http://127.0.0.1:{cport}/get-request-log", TOKEN) if proc.poll() is None else None
    state = lambda: get(f"http://127.0.0.1:{eport}/__swarm-state")
    try:
        se.start_background_calibration().join(timeout=300)
        st = state()
        cal = st["calibration"]
        r.append(("exit: boot calibration done: overshoot measured, 6 cold and 6 warm reference forwards",
                  cal["boot_done"] and cal["boot_error"] is None and len(cal["cold_ms"]) == 6
                  and len(cal["warm_ref_ms"]) == 6 and st["sink_model"]["cold_excess"]["n"] == 6))
        a1 = arm(eport)
        st = state()
        cells = st["sink_model"]["cal"]
        r.append(("exit: arming runs calibration through the exit: every small cell and every large class filled",
                  a1["calibrated"] and len(cells) == 13 and all(v["n"] == 8 for v in cells.values())
                  and set(st["sink_model"]["cal_large"]) == {"urlencoded", "multipart", "other"}
                  and all(v["n"] == 9 for v in st["sink_model"]["cal_large"].values())))
        r.append(("exit: calibration never wrote to the real collector; no calibration errors",
                  col() == [] and st["calibration"]["errors"] == [] and st["forward_errors"] == []))
        a2 = arm(eport, contained=["seat1"])
        r.append(("exit: re-arming with the same decoys does not recalibrate or reset windows",
                  a2["calibrated"] is False and state()["sink_model"]["counts"]["cal"]
                  == st["sink_model"]["counts"]["cal"]))
        report["calibration"] = {"cells": cells, "cal_large": st["sink_model"]["cal_large"],
                                 "cold_excess": st["sink_model"]["cold_excess"],
                                 "overshoot_ms": cal["overshoot_ms"], "runs": cal["runs"]}

        # a seat cannot use the calibration path
        hdr = (f"POST /cal/x HTTP/1.1\r\nHost: x\r\n{se.CAL_HEADER}: {se.CAL_SECRET}\r\n"
               f"{se.CAL_PORT_HEADER}: {os.environ['SWARM_CAL_PORT']}\r\nContent-Length: 2\r\n"
               "Connection: close\r\n\r\nhi").encode()
        code, _ = raw(eport, hdr, SEAT0)
        logged = col()
        r.append(("exit: the calibration header from a seat is ignored: a normal delivery, logged",
                  code == 204 and len(logged) == 1 and logged[0]["path"] == "/cal/x"
                  and state()["events"][-1]["decision"] == "forward"))

        # diverted spans land on their targets; contained seat1 (cold phase over: one real forward above)
        for i in range(60):
            raw(eport, post(f"/div/{i}", b"z" * random.randint(50, 900)), SEAT1)
        ev = [e for e in state()["events"] if e["path"].startswith("/div/")]
        err = [abs(e["latency_ms"] - e["target_ms"]) for e in ev]
        late = [e["latency_ms"] - e["target_ms"] for e in ev]
        report["divert_span_minus_target_ms"] = {"median_abs": round(statistics.median(err), 4),
                                                 "p90_abs": round(q(err, 0.9), 4),
                                                 "median_signed": round(statistics.median(late), 4)}
        r.append(("exit: diverted spans land on their drawn targets (median |actual - target| < 0.3 ms)",
                  len(ev) == 60 and statistics.median(err) < 0.3 and all(e["decision"] == "divert" for e in ev)))
        r.append(("exit: diverted sends never reach the collector", len(col()) == 1))

        # real forwards enter the windows
        n_real = state()["sink_model"]["counts"]["real"]
        for i in range(30):
            raw(eport, post(f"/real/{i}", b"r" * 100), SEAT0)
        st = state()
        r.append(("exit: real forwards enter the windows; cold phase ended",
                  st["sink_model"]["counts"]["real"] == n_real + 30 and st["sink_model"]["first_real_done"]
                  and st["sink_model"]["real"]["urlencoded/1k"]["n"] >= 30))

        # T8 (no-Docker part): first real forward after idle vs the window
        idle_first, window_median = [], st["sink_model"]["real"]["urlencoded/1k"]["median"]
        for k in range(3):
            time.sleep(IDLE_S)
            raw(eport, post(f"/idle/{k}", b"i" * 100), SEAT0)
            idle_first.append([e for e in state()["events"] if e["path"] == f"/idle/{k}"][0]["latency_ms"])
            for i in range(10):
                raw(eport, post(f"/rewarm/{k}/{i}", b"r" * 100), SEAT0)
        report["T8_nodocker"] = {"idle_seconds": IDLE_S, "first_forward_after_idle_ms": idle_first,
                                 "window_median_ms": window_median,
                                 "diff_median_ms": round(statistics.median(idle_first) - window_median, 4)}
        r.append(("T8 (no Docker): first real forward after idle measured against the window (reported)",
                  len(idle_first) == 3))

        # T9: collector stopped
        n_real = state()["sink_model"]["counts"]["real"]
        proc.terminate()
        proc.wait(timeout=5)
        free_code, free_ms = raw(eport, post("/t9/free", b"f" * 100), SEAT0)
        cont_code, cont_ms = raw(eport, post("/t9/contained", b"c" * 100), SEAT1)
        st = state()
        report["T9"] = {"free_seat": [free_code, round(free_ms, 3)], "contained_seat": [cont_code, round(cont_ms, 3)],
                        "forward_errors": len(st["forward_errors"])}
        r.append(("T9: collector down: free seat gets 502 (recorded), contained seat 204 (known difference)",
                  free_code == 502 and cont_code == 204 and len(st["forward_errors"]) == 1))
        r.append(("T9: the failed forward is not entered into the windows",
                  st["sink_model"]["counts"]["real"] == n_real))
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        for p in list(se.CAL["procs"].values()):
            se._stop(p)
    return r


def main() -> int:
    report = {}
    results = test_model() + test_exit(report)
    out = Path(os.environ.get("SWARM_SINK_REPORT", tempfile.gettempdir() + "/swarm_sink_report.json"))
    out.write_text(json.dumps(report, indent=2))
    print("\n================ SWARM SINK (no Docker) ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    for k in ("divert_span_minus_target_ms", "T8_nodocker", "T9"):
        print(f"  {k}: {json.dumps(report.get(k))}")
    print(f"  report: {out}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
