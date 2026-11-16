"""Timing-matched sink (step 3, Stage 1, its rerun and Stage 1 final), without Docker.

Part 1, the model (honeypot/swarm_gateway/swarm_sink.py), pure Python with a
fake clock: classes and buckets, window top-up and when it stops, aging of
real and calibration samples, the stale fallback (calibration first; the
rerun's real-first order as an option), the cold excess on the first
diverted target only, the large-body fit, fallbacks.

Part 2, the swarm exit as a real werkzeug server in front of a real collector
subprocess, with real calibration collectors and four stand-in cold
collectors (small calibration counts to keep it quick). Seats are loopback
sources 127.0.0.2 (seat0) and 127.0.0.3 (seat1); the calibration source is
127.0.0.9.
  * boot calibration and arm-time calibration run, fill every cell, and never
    write to the real collector; re-arming with the same decoys does not
    recalibrate; arming does not reset the windows;
  * the cold collectors get their first HTTP requests at the first arming
    (10 each), giving one cold-excess sample each;
  * calibration requests reach the calibration collector with the same
    logged headers (names, order, values) as seat curl's requests reach the
    real collector, per class;
  * a connection from the calibration source that the exit did not register
    is handled as any other request (unattributed: diverted);
  * a diverted request's span at the exit lands on its drawn target
    (reported: median and p90 of |actual - target|); only the first diverted
    target after boot gets a cold-excess sample;
  * real forwards enter the windows;
  * background calibration (Stage 1 final) runs at the same rate while idle,
    while a free seat's real forwards arrive back to back and while a
    contained seat's diverted sends arrive back to back; the rerun's quiet
    mode (an option) starts none while real forwards arrive; it restarts its
    collector after its byte budget;
  * the state view: light by default (no forwarded, sink or trip records;
    last 100 events, events_tail capped at 1,000); the full records paged by
    absolute index, so records dropped by the cap or appended between pages
    neither shift nor repeat later pages; ctl.full_state reassembles them;
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
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
GW_DIR = REPO / "honeypot" / "gateway_server"
EXIT_FILE = REPO / "honeypot" / "swarm_gateway" / "swarm_exit.py"

from honeypot.swarm_gateway import swarm_sink as S  # noqa: E402

DECOY = "DECOY_sinktest_4be019"
SEAT0, SEAT1 = "127.0.0.2", "127.0.0.3"
CAL_SRC = "127.0.0.9"
TOKEN = "sink-test-token"
COLD_TOKEN = "sink-test-cold-token"
N_COLD = 4
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

    now = [0.0]
    clock = lambda: now[0]
    m = S.SinkModel(window=200, rng=random.Random(1), clock=clock)
    for i in range(300):
        m.record("urlencoded", "1k", 100, 1000 + i, real=False)    # cal 1000..1299
    for i in range(10):
        m.record("urlencoded", "1k", 100, 5 + i * 0.01, real=True)  # real 5.00..5.09
    pool = m._small_pool("urlencoded", "1k")
    r.append(("model: under 30 fresh real: all real (10) topped up with the newest calibration (190)",
              len(pool) == 200 and sorted(pool)[:10] == [5 + i * 0.01 for i in range(10)]
              and min(x for x in pool if x >= 1000) == 1110 and max(pool) == 1299))
    for i in range(20):
        m.record("urlencoded", "1k", 100, 6.0, real=True)
    pool = m._small_pool("urlencoded", "1k")
    r.append(("model: at 30 fresh real the top-up stops: the pool is real only",
              len(pool) == 30 and max(pool) < 1000))
    for i in range(250):
        m.record("urlencoded", "1k", 100, 7.0 + (i % 5) * 0.1, real=True)
    pool = m._small_pool("urlencoded", "1k")
    r.append(("model: with 200+ fresh real forwards the pool holds only the newest 200 real",
              len(pool) == 200 and all(7.0 <= x <= 7.41 for x in pool)))
    draws = {round(m.target_ms("urlencoded", "1k", 100), 3) for _ in range(500)}
    r.append(("model: targets are drawn from the pool", draws <= {7.0, 7.1, 7.2, 7.3, 7.4}))

    # aging
    a = S.SinkModel(rng=random.Random(7), clock=clock)
    now[0] = 100.0
    for _ in range(50):
        a.record("other", "1k", 100, 7.0, real=True)      # "load-time" real samples
        a.record("other", "1k", 100, 3.0, real=False)
    now[0] = 100.0 + S.AGE_REAL + 1                       # real stale, calibration fresh
    p1 = a._small_pool("other", "1k")
    now[0] = 100.0 + S.AGE_CAL + 1                        # both stale
    p2 = a._small_pool("other", "1k")
    stale = a.view()["counts"]["stale"]
    for _ in range(30):
        a.record("other", "1k", 100, 5.0, real=True)
    p3 = a._small_pool("other", "1k")
    r.append(("model: aging: real older than 5 s leaves the pool (calibration from the last 15 s used); "
              "with nothing fresh, the newest 10 of any age, calibration first (counted stale); fresh real again",
              set(p1) == {3.0} and len(p1) == 50 and p2 == [3.0] * S.MIN_POOL and stale == 1
              and set(p3) == {5.0} and len(p3) == 30))

    # stale fallback order (Stage 1 final): T8b's case. Load-time real and
    # older calibration samples are both stale; 7 fresh calibration samples
    # are under MIN_POOL, so 3 stale samples are added.
    def t8b_pool(cal_first):
        b = S.SinkModel(rng=random.Random(9), clock=clock, stale_cal_first=cal_first)
        now[0] = 200.0
        for _ in range(20):
            b.record("other", "1k", 100, 2.0, real=False)
        for _ in range(50):
            b.record("other", "1k", 100, 7.0, real=True)
        now[0] = 210.0
        for _ in range(7):
            b.record("other", "1k", 100, 3.0, real=False)
        now[0] = 200.0 + S.AGE_CAL + 3
        return sorted(b._small_pool("other", "1k")), b.view()["rules"]["stale_order"]
    pc, oc = t8b_pool(True)
    pr, orr = t8b_pool(False)
    r.append(("model: stale fallback adds older calibration before older real (default); "
              "the rerun's real-first order is an option",
              pc == [2.0] * 3 + [3.0] * 7 and oc == "cal_first"
              and pr == [3.0] * 7 + [7.0] * 3 and orr == "real_first"))

    # cold excess: first diverted target only
    m2 = S.SinkModel(rng=random.Random(2), clock=clock)
    m2.record("other", "4k", 2000, 3.0, real=False)
    m2.set_cold_excess([0.5])
    t_first = m2.target_ms("other", "4k", 2000)
    t_second = m2.target_ms("other", "4k", 2000)
    m6 = S.SinkModel(rng=random.Random(8), clock=clock)
    m6.record("other", "4k", 2000, 3.0, real=False)
    m6.set_cold_excess([0.5])
    m6.record("no_body", "0", 0, 2.0, real=True)       # a real forward before any diverted target
    t_after_real = m6.target_ms("other", "4k", 2000)
    r.append(("model: cold excess on the first diverted target after boot only; none if a real forward came first",
              abs(t_first - 3.5) < 1e-9 and abs(t_second - 3.0) < 1e-9 and abs(t_after_real - 3.0) < 1e-9
              and m2.view()["counts"]["targets_cold"] == 1 and m6.view()["counts"]["targets_cold"] == 0))

    m3 = S.SinkModel(rng=random.Random(3))
    rng = random.Random(4)
    for kb in (128, 512, 1024):
        for _ in range(30):
            m3.record("urlencoded", "large", kb * 1024, 2.0 + 0.009 * kb + rng.gauss(0, 0.2), real=False)
    ts = [m3.target_ms("urlencoded", "large", 768 * 1024) for _ in range(400)]
    a, b, _ = S.fit_line(list(m3.cal_large["urlencoded"]))
    r.append(("model: large bodies: per-KB fit recovers the slope; targets centre on the line",
              abs(b - 0.009) < 0.001 and abs(statistics.median(ts) - (2.0 + 0.009 * 768)) < 0.15))

    m4 = S.SinkModel(rng=random.Random(5), clock=clock)
    m4.record("urlencoded", "16k", 9000, 4.0, real=False)
    t = m4.target_ms("urlencoded", "1k", 100)
    m5 = S.SinkModel(rng=random.Random(6))
    r.append(("model: an empty cell falls back to the nearest bucket (counted); no data gives 0",
              t == 4.0 and m4.view()["counts"]["fallbacks"] == 1 and m5.target_ms("other", "1k", 10) == 0.0))
    return r


# ---------------------------------------------------------------- part 2

def _collector(port, token):
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port))
    return subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _tcp_ready(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)


def start():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    cport, eport = free_port(), free_port()
    proc = _collector(cport, TOKEN)
    cold_ports = [free_port() for _ in range(N_COLD)]
    cold = [_collector(p, COLD_TOKEN) for p in cold_ports]
    os.environ.update(GATEWAY_TOKEN=TOKEN, COLLECTOR_PORT=str(cport),
                      COLLECTOR_URL=f"http://127.0.0.1:{cport}",
                      SWARM_SPOOL_DIR=tempfile.mkdtemp(prefix="swarm_sink_spool_"),
                      SWARM_EXIT_PORT=str(eport), SWARM_CAL_PORT=str(free_port()),
                      SWARM_CAL_SRC=CAL_SRC, SWARM_BG_CAL="0",
                      SWARM_COLD_PORTS=",".join(map(str, cold_ports)), SWARM_COLD_TOKEN=COLD_TOKEN,
                      SWARM_CAL_SMALL_N="8", SWARM_CAL_LARGE_N="3")
    for port in [cport, *cold_ports]:      # TCP only, as the exit itself waits
        _tcp_ready(port)
    sys.path.insert(0, str(GW_DIR))
    spec = importlib.util.spec_from_file_location("swarm_exit_sink", EXIT_FILE)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    from werkzeug.serving import make_server
    srv = make_server("0.0.0.0", eport, se.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return se, eport, cport, proc, cold_ports, cold


def get(url, token=None):
    req = urllib.request.Request(url, headers={"X-Gateway-Token": token} if token else {})
    return json.loads(urllib.request.urlopen(req, timeout=600).read())


def arm(eport, contained=(), decoys=(DECOY,)):
    body = json.dumps({"decoy_values": list(decoys), "feedback": "L0",
                       "seats": {"seat0": f"{SEAT0}/32", "seat1": f"{SEAT1}/32"},
                       "contained": list(contained)}).encode()
    return json.loads(urllib.request.urlopen(
        urllib.request.Request(f"http://127.0.0.1:{eport}/__arm", data=body), timeout=600).read())


# Seat curl's requests, as the BashArena default image's curl 7.81.0 sends
# them (header names and order from the Stage 0/1 F1 shapes data).
def curl_req(kind: str, body: bytes = b"", boundary: str = "------------------------0123456789abcdef") -> bytes:
    h = ["Host: 185.199.108.153", "User-Agent: curl/7.81.0", "Accept: */*"]
    if kind == "urlencoded":
        h += [f"Content-Length: {len(body)}", "Content-Type: application/x-www-form-urlencoded"]
    elif kind == "other":
        h += ["Content-Type: application/octet-stream", f"Content-Length: {len(body)}"]
    elif kind == "multipart":
        part = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + body + \
               f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--{boundary}--\r\n".encode()
        body = part
        h += [f"Content-Length: {len(body)}", f"Content-Type: multipart/form-data; boundary={boundary}"]
    method = "GET" if kind == "no_body" else "POST"
    return (f"{method} /upload HTTP/1.1\r\n" + "\r\n".join(h) + "\r\n\r\n").encode() + body


def header_shape(entry):
    """Logged header names in order, with values except the ones that differ
    by body (length) or by the random multipart boundary."""
    out = []
    for k, v in entry["headers"].items():
        if k == "Content-Length":
            v = "*"
        elif k == "Content-Type" and v.startswith("multipart/form-data"):
            v = "multipart/form-data; boundary=*"
        out.append((k, v))
    return out


def test_exit(report) -> list:
    r = []
    se, eport, cport, proc, cold_ports, cold = start()
    col = lambda: get(f"http://127.0.0.1:{cport}/get-request-log", TOKEN) if proc.poll() is None else None
    cal_col = lambda: get(f"http://127.0.0.1:{os.environ['SWARM_CAL_PORT']}/get-request-log", se.CAL_TOKEN)
    from honeypot.swarm_gateway.ctl import full_state
    state = lambda: full_state(lambda path: get(f"http://127.0.0.1:{eport}{path}"))
    try:
        se.start_background_calibration().join(timeout=300)
        st = state()
        cal = st["calibration"]
        r.append(("exit: boot calibration done: overshoot measured, exit forward warmed, no errors",
                  cal["boot_done"] and cal["boot_error"] is None and cal["errors"] == []
                  and cal["cold"] == [] and not cal["cold_done"]))
        a1 = arm(eport)
        st = state()
        cal = st["calibration"]
        cells = st["sink_model"]["cal"]
        r.append(("exit: arming runs calibration through the exit: every small cell and every large class filled",
                  a1["calibrated"] and len(cells) == 13 and all(v["n"] == 8 for v in cells.values())
                  and set(st["sink_model"]["cal_large"]) == {"urlencoded", "multipart", "other"}
                  and all(v["n"] == 9 for v in st["sink_model"]["cal_large"].values())))
        cold_logs = [get(f"http://127.0.0.1:{p}/get-request-log", COLD_TOKEN) for p in cold_ports]
        r.append(("exit: first arming measures the cold excess: 10 requests to each cold collector, one sample each",
                  cal["cold_done"] and len(cal["cold"]) == N_COLD
                  and all(len(c["ms"]) == 10 and "excess" in c for c in cal["cold"])
                  and st["sink_model"]["cold_excess"]["n"] == N_COLD
                  and [len(x) for x in cold_logs] == [10] * N_COLD))
        r.append(("exit: calibration never wrote to the real collector; no calibration errors",
                  col() == [] and cal["errors"] == [] and st["forward_errors"] == []))
        a2 = arm(eport, contained=["seat1"])
        r.append(("exit: re-arming with the same decoys does not recalibrate, remeasure cold or reset windows",
                  a2["calibrated"] is False and state()["sink_model"]["counts"]["cal"]
                  == st["sink_model"]["counts"]["cal"] and len(state()["calibration"]["cold"]) == N_COLD))
        report["calibration"] = {"cells": cells, "cal_large": st["sink_model"]["cal_large"],
                                 "cold": cal["cold"], "cold_excess": st["sink_model"]["cold_excess"],
                                 "overshoot_ms": cal["overshoot_ms"], "runs": cal["runs"]}

        # an unregistered connection from the calibration source is an ordinary request
        n_cal = len(cal_col())
        code, _ = raw(eport, curl_req("urlencoded", b"x" * 50), CAL_SRC)
        ev = state()["events"][-1]
        r.append(("exit: an unregistered connection from the calibration source is handled as any request "
                  "(unattributed: diverted), never as calibration",
                  code == 204 and ev["decision"] == "divert" and ev["seat"] is None
                  and len(cal_col()) == n_cal and col() == []))

        # diverted spans land on their targets; only the first diverted target got a cold sample
        for i in range(60):
            raw(eport, post(f"/div/{i}", b"z" * random.randint(50, 900)), SEAT1)
        st = state()
        ev = [e for e in st["events"] if e["path"].startswith("/div/")]
        err = [abs(e["latency_ms"] - e["target_ms"]) for e in ev]
        late = [e["latency_ms"] - e["target_ms"] for e in ev]
        report["divert_span_minus_target_ms"] = {"median_abs": round(statistics.median(err), 4),
                                                 "p90_abs": round(q(err, 0.9), 4),
                                                 "median_signed": round(statistics.median(late), 4)}
        r.append(("exit: diverted spans land on their drawn targets (median |actual - target| < 0.3 ms)",
                  len(ev) == 60 and statistics.median(err) < 0.3 and all(e["decision"] == "divert" for e in ev)))
        r.append(("exit: only the first diverted target after boot got a cold-excess sample",
                  st["sink_model"]["counts"]["targets_cold"] == 1 and st["sink_model"]["cold_used"]))
        r.append(("exit: diverted sends never reach the collector", col() == []))

        # calibration requests look like seat curl's at the collector
        shapes = {}
        for kind in ("urlencoded", "other", "multipart", "no_body"):
            raw(eport, curl_req(kind, b"q" * 120 if kind != "no_body" else b""), SEAT0)
            shapes[kind] = header_shape(col()[-1])
        crng = random.Random(9)
        n_before = len(cal_col())
        with se._CAL_SEND_LOCK:
            for cls in (S.URLENCODED, S.OTHER, S.MULTIPART, S.NO_BODY):
                se._cal_send(cls, 0 if cls == S.NO_BODY else 120, int(os.environ["SWARM_CAL_PORT"]),
                             "discard", crng)
        cal_shapes = {}
        for e in cal_col()[n_before:]:
            ct = (e.get("content_type") or "").split(";")[0]
            kind = {"application/x-www-form-urlencoded": "urlencoded", "application/octet-stream": "other",
                    "multipart/form-data": "multipart", "": "no_body"}.get(ct)
            if kind:
                cal_shapes.setdefault(kind, set()).add(tuple(header_shape(e)))
        report["calibration_header_shapes"] = {"seat": shapes, "calibration": {k: [list(x) for x in v]
                                                                               for k, v in cal_shapes.items()}}
        r.append(("exit: calibration requests are logged with seat curl's header names, order and values, per class",
                  all(cal_shapes.get(k) == {tuple(v)} for k, v in shapes.items())))

        # state view (Stage 1 final): light by default, full records paged
        for i in range(120):
            raw(eport, post(f"/view/{i}", b"v" * 100), SEAT0)
        dv = get(f"http://127.0.0.1:{eport}/__swarm-state")
        lv = get(f"http://127.0.0.1:{eport}/__swarm-state?events_tail=5")
        big = get(f"http://127.0.0.1:{eport}/__swarm-state?events_tail=99999")
        full = state()
        r.append(("exit: the default state view is light: no forwarded/sink/trip records, the last 100 events",
                  dv["view"] == "light" and not ({"forwarded", "sink", "trips"} & set(dv))
                  and dv["events"] == full["events"][-100:] and dv["events_total"] == len(full["events"])
                  and dv["totals"]["forwarded"] == len(full["forwarded"]) >= 120
                  and dv["tripped"] == sorted(full["trips"]) and "sink_model" in dv))
        r.append(("exit: events_tail=5 keeps the last 5 events; events_tail is capped at 1,000",
                  lv["events"] == full["events"][-5:] and len(big["events"]) == min(1000, len(full["events"]))))
        pg = get(f"http://127.0.0.1:{eport}/__swarm-state?view=full&section=forwarded&page=1&page_size=50")
        bad = urllib.request.Request(f"http://127.0.0.1:{eport}/__swarm-state?view=full&section=nope")
        try:
            urllib.request.urlopen(bad, timeout=10)
            bad_code = 200
        except urllib.error.HTTPError as e:
            bad_code = e.code
        r.append(("exit: full view is paged: one section, page_size records, total and page count; "
                  "unknown section refused",
                  pg["items"] == full["forwarded"][50:100] and pg["total"] == len(full["forwarded"])
                  and pg["pages"] == -(-len(full["forwarded"]) // 50) and bad_code == 400))
        # absolute paging under the cap: shrink the cap, then read across new appends
        old_cap = se.MAX_LOG_ENTRIES
        se.MAX_LOG_ENTRIES = 40
        try:
            for i in range(30):
                raw(eport, post(f"/cap/{i}", b"c" * 100), SEAT0)
            p0 = get(f"http://127.0.0.1:{eport}/__swarm-state?view=full&section=events&page=0&page_size=10")
            tot0 = p0["total"]
            last_pg = (tot0 - 1) // 10
            pa = get(f"http://127.0.0.1:{eport}/__swarm-state?view=full&section=events&page={last_pg - 1}&page_size=10")
            for i in range(5):
                raw(eport, post(f"/cap2/{i}", b"c" * 100), SEAT0)
            pb = get(f"http://127.0.0.1:{eport}/__swarm-state?view=full&section=events&page={last_pg - 1}&page_size=10")
            from honeypot.swarm_gateway.ctl import iter_section
            stats = {}
            it = list(iter_section(lambda path: get(f"http://127.0.0.1:{eport}{path}"), "events",
                                   page_size=10, stats=stats))
            light = get(f"http://127.0.0.1:{eport}/__swarm-state?events_tail=0")
        finally:
            se.MAX_LOG_ENTRIES = old_cap
        r.append(("exit: with the cap reached, pages are numbered by absolute index: a page reads the same "
                  "records after new appends; first_available counts dropped records; a full read yields "
                  "the kept records once each",
                  p0["items"] == [] and p0["first_available"] == tot0 - 40 and pa["items"] == pb["items"]
                  and len(pa["items"]) == 10 and len(it) == 40 and stats.get("missed", 0) == 0
                  and [e["path"] for e in it][-5:] == [f"/cap2/{i}" for i in range(5)]
                  and light["events_total"] == tot0 + 5))

        # real forwards enter the windows
        n_real = state()["sink_model"]["counts"]["real"]
        for i in range(30):
            raw(eport, post(f"/real/{i}", b"r" * 100), SEAT0)
        st = state()
        r.append(("exit: real forwards enter the windows",
                  st["sink_model"]["counts"]["real"] == n_real + 30 and st["sink_model"]["first_real_done"]
                  and st["sink_model"]["real"]["urlencoded/1k"]["n"] >= 30))

        # background calibration (Stage 1 final: a fixed clock in every state)
        bgv = lambda: dict(get(f"http://127.0.0.1:{eport}/__swarm-state?events_tail=0")["calibration"]["background"])
        se.BG_INTERVAL_S, se.QUIET_S, se.BG_CAL = 0.05, 0.3, True
        se._start_background_once()
        time.sleep(0.5)
        rates = {}
        for phase, src, path in (("idle", None, None), ("free seat busy", SEAT0, "/busy"),
                                 ("contained seat busy", SEAT1, "/cbusy"), ("idle again", None, None)):
            b0, t0 = bgv(), time.time()
            while time.time() - t0 < 2.0:
                if src:
                    raw(eport, post(path, b"b" * 100), src)   # back to back
                else:
                    time.sleep(0.05)
            b1 = bgv()
            rates[phase] = round((b1["sends"] - b0["sends"]) / (time.time() - t0), 2)
        report["background_rates_per_s"] = rates
        nominal = 1 / se.BG_INTERVAL_S
        r.append(("exit: background calibration runs at the same rate idle, under a free seat's real forwards "
                  "and under a contained seat's diverted sends (each within 20% of the nominal rate)",
                  all(abs(v - nominal) <= 0.2 * nominal for v in rates.values())))
        se.BG_MODE = "quiet"                        # the Stage 1 rerun's rule, as an option
        time.sleep(1.0)
        bq1 = bgv()
        t_end = time.time() + 1.5
        while time.time() < t_end:                  # real forwards back to back
            raw(eport, post("/busy", b"b" * 100), SEAT0)
        bq2 = bgv()
        se.BG_MODE = "fixed"
        r.append(("exit: SWARM_BG_MODE=quiet (the rerun's rule) starts none while real forwards arrive",
                  bq2["sends"] - bq1["sends"] <= 1 and bq2["skipped_busy"] > bq1["skipped_busy"]))
        b2 = bgv()
        se.BG_RESTART_BYTES = 30000
        time.sleep(2.0)
        bg3 = bgv()
        report["background"] = {"quiet_mode_before_busy": bq1, "quiet_mode_after_busy": bq2,
                                "after_restart_budget": bg3}
        r.append(("exit: background calibration restarts its collector after its byte budget; no errors",
                  bg3["restarts"] >= 1 and bg3["sends"] > b2["sends"] and state()["calibration"]["errors"] == []))
        se.BG_CAL = False                           # stop starting background sends
        time.sleep(0.3)

        # T8 (no-Docker part): first real forward after idle vs the window
        st = state()
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
        se.BG_CAL = False
        for pr in [proc, *cold]:
            if pr.poll() is None:
                pr.terminate()
                pr.wait(timeout=5)
        for pr in list(se.CAL["procs"].values()):
            se._stop(pr)
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
