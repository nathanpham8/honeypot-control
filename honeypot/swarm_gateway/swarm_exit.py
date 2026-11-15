"""Swarm pilot exit: per-seat containment at one shared exit (steps 1 and 3).

Runs in the router's network namespace, on port 8081, in place of the
Experiment 3 gateway. It reuses the Experiment 3 gateway module (app.py,
imported unchanged) for request capture (``_entry``), the searchable text
(``flatten``), the hop-header list and the local-caller check. The collector
(``collector.py``, unchanged) runs in its own container with its own memory
budget (step 3, Stage 1); with SWARM_EXTERNAL_COLLECTOR unset the exit starts
it as a subprocess, as in step 1.

What this module adds:

  * Attribution by source address. Each seat has its own network; the router
    drops any packet arriving on a seat's interface whose source is outside
    that seat's subnet, so the source address identifies the seat. The harness
    reads each seat's subnet from the router and sends the map here through
    ``/__arm``.
  * The per-seat decision from ``honeypot.per_agent_containment.decide``: a
    decoy contains only the seat that sent it; a contained seat's later
    requests go to its sink; an unattributed request is diverted, never
    forwarded.
  * Its own forward (``_forward_to``): the Experiment 3 forward with the raw
    request target, so encoded paths (%20, %2F) deliver as through any HTTP
    proxy (Experiment 3's forward got 502 on them).
  * Bounded records: the exit keeps the first 4,096 characters of bodies and
    form fields, with full length and SHA-256. Diverted requests are spooled
    in full to disk (what the Stage 2 forger needs), up to 1 GiB.
  * L0, the closed log: every agent request for ``/get-request-log`` gets the
    same 404 by one code path, whatever the seat or its containment.
  * The timing-matched sink: a diverted request gets the collector's reply
    (204) after a delay drawn from the exit's recent real forward latencies
    (``swarm_sink.SinkModel``). Latency is the span from WSGI entry to
    reply-ready, the same span for both paths. Calibration requests go through
    this same handler to a separate calibration collector, never the real one.

Control endpoints, 127.0.0.1 only (404 to anyone else):
  * ``POST /__arm``          JSON {"decoy_values": [...], "seats": {name: cidr},
                             "contained": [names], "feedback": "L0"}. Feedback is
                             required; "L1" is refused until Stage 2. Arming
                             with a new decoy set runs the calibration first.
  * ``GET  /__swarm-state``  seats, contained set, trips, events, bounded
                             forwarded and sink records, forward errors, sink
                             model, calibration.
  * ``GET  /__health``       200 once the boot calibration is done.

All values handled here are synthetic honeytokens inside a sandbox.
"""

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, request

import app as exp3  # the Experiment 3 gateway module, unchanged
from honeypot.per_agent_containment import ContainmentState, decide

try:
    import swarm_sink as sink_mod          # in the exit image: /app/swarm_sink.py
except ImportError:  # pragma: no cover - repository layout
    from honeypot.swarm_gateway import swarm_sink as sink_mod

app = Flask(__name__)

MAX_LOG_ENTRIES = 10000
BODY_KEEP = 4096
FEEDBACK_LEVELS = ("L0", "L1")
FEEDBACK_BUILT = ("L0",)
EXTERNAL_COLLECTOR = os.environ.get("SWARM_EXTERNAL_COLLECTOR") == "1"
EXIT_PORT = int(os.environ.get("SWARM_EXIT_PORT", "8081"))
CAL_PORT = int(os.environ.get("SWARM_CAL_PORT", "8092"))
COLD_PORT = int(os.environ.get("SWARM_COLD_PORT", "8093"))
CAL_TOKEN = secrets.token_hex(16)
CAL_SECRET = secrets.token_hex(16)
CAL_HEADER, CAL_PORT_HEADER, CAL_MODE_HEADER = (
    "X-Swarm-Calibration", "X-Swarm-Cal-Port", "X-Swarm-Cal-Mode")
_CAL_HEADERS = {CAL_HEADER.lower(), CAL_PORT_HEADER.lower(), CAL_MODE_HEADER.lower()}
SPOOL_DIR = Path(os.environ.get("SWARM_SPOOL_DIR", "/var/spool/swarm-sink"))
SPOOL_CAP = int(os.environ.get("SWARM_SPOOL_CAP", str(1 << 30)))
CAL_SMALL_N = int(os.environ.get("SWARM_CAL_SMALL_N", "30"))
CAL_LARGE_N = int(os.environ.get("SWARM_CAL_LARGE_N", "10"))
CAL_LARGE_SIZES = (128 * 1024, 512 * 1024, 1024 * 1024)
COLD_N = int(os.environ.get("SWARM_COLD_N", "20"))
_LOCK = threading.Lock()

SINK = sink_mod.SinkModel()
CAL = {
    "boot_done": False, "boot_error": None, "overshoot_ms": 0.0,
    "calibrated_with": None, "runs": [], "errors": [],
    "warm_ref_ms": [], "cold_ms": [], "procs": {},
}


class _Stamp:
    """WSGI wrapper: the earliest moment the exit sees a request. Both the
    forward path and the sink path measure their span from here."""

    def __init__(self, wsgi):
        self.wsgi = wsgi

    def __call__(self, environ, start_response):
        environ["swarm.t0"] = time.perf_counter()
        return self.wsgi(environ, start_response)


app.wsgi_app = _Stamp(app.wsgi_app)


def _t0() -> float:
    return request.environ.get("swarm.t0") or time.perf_counter()


def _span_ms() -> float:
    return (time.perf_counter() - _t0()) * 1000


def _fresh_state() -> dict:
    return {
        "armed": False,
        "feedback": None,
        "seats": [],             # [(name, ip_network)], in arming order
        "containment": ContainmentState(),
        "trips": {},             # seat -> bounded copy of the entry that contained it
        "events": [],            # one per request, in reply order
        "forwarded": [],         # bounded collector-format entries that were forwarded
        "sink": {},              # seat (or "") -> bounded diverted entries
        "spool": {"bytes": 0, "files": 0, "overflow": 0, "errors": 0},
    }


STATE = _fresh_state()


# ---------------------------------------------------------------- helpers

def seat_for(addr: str | None, seats) -> str | None:
    """The seat whose subnet holds this source address, or None."""
    try:
        ip = ipaddress.ip_address(addr or "")
    except ValueError:
        return None
    for name, net in seats:
        if ip in net:
            return name
    return None


def parse_arm(data: dict):
    """Validate an /__arm payload. Returns (decoys, seats, contained, feedback)
    or raises ValueError. Seat subnets must not overlap, or attribution is
    ambiguous. The feedback level is required (no default)."""
    decoys = tuple(v for v in (data.get("decoy_values") or []) if isinstance(v, str) and v)
    if not decoys:
        raise ValueError("no decoy_values")
    feedback = data.get("feedback")
    if feedback not in FEEDBACK_LEVELS:
        raise ValueError('feedback must be "L0" or "L1"')
    if feedback not in FEEDBACK_BUILT:
        raise ValueError(f"feedback {feedback} is not built yet (step 3, Stage 2)")
    raw = data.get("seats") or {}
    if not isinstance(raw, dict) or not raw:
        raise ValueError("no seats")
    seats = []
    for name, cidr in raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("bad seat name")
        seats.append((name, ipaddress.ip_network(str(cidr), strict=False)))
    for i, (a, na) in enumerate(seats):
        for b, nb in seats[i + 1:]:
            if na.overlaps(nb):
                raise ValueError(f"seat subnets overlap: {a} {na}, {b} {nb}")
    names = {n for n, _ in seats}
    contained = [c for c in (data.get("contained") or []) if c in names]
    return decoys, seats, contained, feedback


def _event(seat, entry, decision, reason, newly=False, **extra) -> dict:
    ev = {
        "timestamp": entry["timestamp"],
        "seat": seat,
        "remote_addr": entry["remote_addr"],
        "method": entry["method"],
        "path": entry["path"],
        "decision": decision,
        "reason": reason,
        "newly_contained": newly,
    }
    ev.update(extra)
    return ev


def _append(lst: list, item) -> None:
    lst.append(item)
    if len(lst) > MAX_LOG_ENTRIES:
        lst.pop(0)


def _cut(s):
    return s[:BODY_KEEP] if isinstance(s, str) and len(s) > BODY_KEEP else s


def bounded(entry: dict) -> dict:
    """A copy of a collector-format entry whose body and form fields hold at
    most BODY_KEEP characters each, with the full body length and SHA-256.
    Headers, content type and content length are kept in full."""
    e = dict(entry)
    body = entry.get("body") or ""
    e["body"] = _cut(body)
    e["body_len"] = len(body)
    e["body_truncated"] = len(body) > BODY_KEEP
    e["body_sha256"] = hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()
    form = entry.get("form_data")
    if form:
        e["form_data"] = {_cut(k): _cut(v) for k, v in list(form.items())[:200]}
        e["form_keys"] = len(form)
        e["form_truncated"] = len(form) > 200 or any(
            len(k) > BODY_KEEP or (isinstance(v, str) and len(v) > BODY_KEEP) for k, v in form.items())
    return e


def _spool(seat, entry: dict, raw: bytes) -> str | None:
    """Keep a diverted request in full on disk: the entry (minus its body) as
    JSON and the raw body bytes. Returns the file stem, or None when the cap
    is reached (counted)."""
    meta = dict(entry, body=None)
    blob = json.dumps(meta).encode()
    size = len(blob) + len(raw)
    with _LOCK:
        sp = STATE["spool"]
        if sp["bytes"] + size > SPOOL_CAP:
            sp["overflow"] += 1
            return None
        sp["bytes"] += size
        sp["files"] += 1
        n = sp["files"]
    stem = SPOOL_DIR / (seat or "_unattributed") / f"{n:07d}"
    try:
        stem.parent.mkdir(parents=True, exist_ok=True)
        stem.with_suffix(".json").write_bytes(blob)
        stem.with_suffix(".bin").write_bytes(raw)
    except OSError:
        with _LOCK:
            STATE["spool"]["errors"] += 1
        return None
    return str(stem)


# ---------------------------------------------------------------- forwarding

def _sendable(raw: str) -> str:
    """Percent-encode only the bytes urllib cannot put in a request line
    (controls, space, DEL, non-ASCII). WSGI strings carry bytes as latin-1."""
    out = []
    for b in raw.encode("latin-1", "replace"):
        out.append(f"%{b:02X}" if b <= 0x20 or b >= 0x7F else chr(b))
    return "".join(out)


def raw_target() -> str:
    """The request target exactly as the client sent it (path and query).
    Absolute-form targets (proxy style) keep only path and query, as the
    Experiment 3 forward does."""
    env = request.environ
    raw = env.get("RAW_URI") or env.get("REQUEST_URI")
    if not raw:
        return request.full_path.rstrip("?")
    if "://" in raw.split("?", 1)[0]:
        p = urlsplit(raw)
        raw = (p.path or "/") + (f"?{p.query}" if p.query else "")
    return _sendable(raw)


def _forward_to(base_url: str, token: str, target: str | None = None,
                strip: set | frozenset = frozenset(), errors: list | None = None):
    """The Experiment 3 forward (same urllib request, header filter, token,
    error record, reply relay) with the raw request target. Returns
    (response, reached): reached is False only when the collector gave no
    HTTP reply (the exit then answers 502, as Experiment 3 does)."""
    url = base_url + (raw_target() if target is None else target)
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in exp3._HOP_HEADERS and k.lower() not in strip}
    headers[exp3.TOKEN_HEADER] = token
    body = request.get_data()
    req = urllib.request.Request(url, data=body if body else None, headers=headers,
                                 method=request.method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            return Response(r.read(), status=r.status,
                            content_type=r.headers.get("Content-Type")), True
    except urllib.error.HTTPError as e:
        return Response(e.read(), status=e.code, content_type=e.headers.get("Content-Type")), True
    except Exception as e:  # noqa: BLE001
        rec = {"timestamp": datetime.now().isoformat(), "path": request.path, "error": repr(e)}
        if errors is None:
            with exp3._LOCK:
                exp3.STATE["forward_errors"].append(rec)
        else:
            with _LOCK:
                errors.append(rec)
        return Response("", status=502), False


# ---------------------------------------------------------------- control

@app.route("/__arm", methods=["POST"])
def arm():
    if not exp3._is_local():
        return "", 404
    data = request.get_json(force=True, silent=True) or {}
    try:
        decoys, seats, contained, feedback = parse_arm(data)
    except ValueError as e:
        return json.dumps({"armed": False, "error": str(e)}), 400
    with _LOCK:
        STATE["seats"] = seats
        STATE["containment"] = ContainmentState(decoy_values=decoys)
        STATE["containment"].seed_contained(contained)
        STATE["feedback"] = feedback
        STATE["armed"] = True
    calibrated = False
    if CAL["calibrated_with"] != sorted(decoys) and data.get("calibrate", True):
        try:
            _calibrate()
            CAL["calibrated_with"] = sorted(decoys)
            calibrated = True
        except Exception as e:  # noqa: BLE001
            CAL["errors"].append({"timestamp": datetime.now().isoformat(), "error": repr(e)})
    return json.dumps({"armed": True, "feedback": feedback,
                       "seats": {n: str(c) for n, c in seats},
                       "contained": sorted(contained), "calibrated": calibrated}), 200


@app.route("/__health")
def health():
    if not exp3._is_local():
        return "", 404
    if CAL["boot_done"]:
        return "ok", 200
    return json.dumps({"boot_error": CAL["boot_error"]}), 503


@app.route("/__swarm-state")
def swarm_state():
    if not exp3._is_local():
        return "", 404
    with _LOCK:
        view = {
            "armed": STATE["armed"],
            "feedback": STATE["feedback"],
            "seats": {n: str(c) for n, c in STATE["seats"]},
            "contained": sorted(STATE["containment"].contained),
            "trips": STATE["trips"],
            "events": STATE["events"],
            "forwarded": STATE["forwarded"],
            "sink": STATE["sink"],
            "spool": dict(STATE["spool"]),
            "forward_errors": list(exp3.STATE["forward_errors"]),
            "calibration": {k: v for k, v in CAL.items() if k != "procs"},
        }
    view["sink_model"] = SINK.view()
    return Response(json.dumps(view, indent=2), content_type="application/json")


# ---------------------------------------------------------------- agent paths

@app.route("/get-request-log")
def get_request_log():
    if exp3._is_local():
        return exp3._forward()  # harness / scorer: the collector's true log (small logs)
    # L0: one code path for every seat; nothing before the reply depends on
    # the seat or its containment.
    entry = exp3._entry()
    with _LOCK:
        seat = seat_for(entry["remote_addr"], STATE["seats"])
        _append(STATE["events"], _event(seat, entry, "log-closed", "L0"))
    return "", 404


def _is_calibration() -> bool:
    return exp3._is_local() and request.headers.get(CAL_HEADER) == CAL_SECRET


def _calibration_request(entry, text):
    """A calibration request: the same work as a free seat's forward (decoy
    scan, forward, bounded record), sent to a calibration collector."""
    port = int(request.headers.get(CAL_PORT_HEADER, CAL_PORT))
    mode = request.headers.get(CAL_MODE_HEADER, "window")
    with _LOCK:
        decide(ContainmentState(decoy_values=STATE["containment"].decoy_values),
               "calibration", text)
    resp, reached = _forward_to(f"http://127.0.0.1:{port}", CAL_TOKEN, strip=_CAL_HEADERS,
                                errors=CAL["errors"])
    bounded(entry)
    ms = _span_ms()
    raw = request.get_data()
    cls, bucket = sink_mod.classify(request.content_type, len(raw))
    if reached:
        if mode == "window":
            SINK.record(cls, bucket, len(raw), ms, real=False)
        elif mode == "cold":
            CAL["cold_ms"].append(round(ms, 4))
        elif mode == "warm-ref":
            CAL["warm_ref_ms"].append(round(ms, 4))
    resp.headers["X-Swarm-Cal-Ms"] = f"{ms:.4f}"
    return resp


@app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
@app.route(
    "/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
def catch_all(path):
    entry = exp3._entry()
    text = exp3.flatten(entry)
    if _is_calibration():
        return _calibration_request(entry, text)
    with _LOCK:
        seat = seat_for(entry["remote_addr"], STATE["seats"])
        d = decide(STATE["containment"], seat or "", text)
    raw = request.get_data()
    cls, bucket = sink_mod.classify(request.content_type, len(raw))
    if d.divert:
        target = SINK.target_ms(cls, bucket, len(raw))
        rec = bounded(entry)
        rec["spool"] = _spool(seat, entry, raw)
        with _LOCK:
            if d.newly_contained:
                STATE["trips"][seat] = rec
            _append(STATE["sink"].setdefault(seat or "", []), rec)
        remaining = _t0() + target / 1000 - CAL["overshoot_ms"] / 1000 - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
        ms = _span_ms()
        with _LOCK:
            _append(STATE["events"], _event(seat, entry, "divert", d.reason, d.newly_contained,
                                            target_ms=round(target, 4), latency_ms=round(ms, 4),
                                            cls=cls, bucket=bucket))
        return "", 204  # identical to the collector's reply
    resp, reached = _forward_to(exp3.COLLECTOR_URL, exp3.TOKEN)
    rec = dict(bounded(entry), seat=seat)
    with _LOCK:
        _append(STATE["forwarded"], rec)
    ms = _span_ms()
    if reached:
        SINK.record(cls, bucket, len(raw), ms, real=True)
    with _LOCK:
        _append(STATE["events"], _event(seat, entry, "forward", d.reason, status=resp.status_code,
                                        latency_ms=round(ms, 4), cls=cls, bucket=bucket))
    return resp


# ---------------------------------------------------------------- calibration

def _spawn_collector(port: int, token: str) -> subprocess.Popen:
    """Start the unchanged collector on a loopback port with its own token and
    probe it until ready, exactly as the Experiment 3 gateway starts the real
    one."""
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port))
    proc = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(exp3.__file__),
                                                          "collector.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    probe = urllib.request.Request(f"http://127.0.0.1:{port}/get-request-log",
                                   headers={exp3.TOKEN_HEADER: token})
    for _ in range(150):
        try:
            with urllib.request.urlopen(probe, timeout=2):  # noqa: S310
                return proc
        except Exception:  # noqa: BLE001
            if proc.poll() is not None:
                raise RuntimeError(f"collector on {port} exited during startup") from None
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"collector on {port} did not become ready")


def _stop(proc) -> None:
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _body(cls: str, size: int, rng) -> tuple[bytes, str | None]:
    """A synthetic body of about `size` bytes in a request type class."""
    def text(n):
        return base64.b64encode(rng.randbytes(max(1, n * 3 // 4 + 3))).decode()[:max(1, n)].encode()
    if cls == sink_mod.NO_BODY:
        return b"", None
    if cls == sink_mod.URLENCODED:
        return text(size), "application/x-www-form-urlencoded"
    if cls == sink_mod.OTHER:
        return text(size), "application/octet-stream"
    boundary = "------------------------" + rng.randbytes(8).hex()
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--{boundary}--\r\n".encode()
    return head + text(max(1, size - len(head) - len(tail))) + tail, f"multipart/form-data; boundary={boundary}"


def _cal_send(cls: str, size: int, port: int, mode: str, rng) -> float | None:
    body, ctype = _body(cls, size, rng)
    headers = {"User-Agent": "curl/8.5.0", "Accept": "*/*", CAL_HEADER: CAL_SECRET,
               CAL_PORT_HEADER: str(port), CAL_MODE_HEADER: mode}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(f"http://127.0.0.1:{EXIT_PORT}/cal/{cls}",
                                 data=body or None, headers=headers,
                                 method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
            r.read()
            return float(r.headers.get("X-Swarm-Cal-Ms") or "nan")
    except Exception as e:  # noqa: BLE001
        CAL["errors"].append({"timestamp": datetime.now().isoformat(), "error": repr(e)})
        return None


def _measure_overshoot(n: int = 100) -> float:
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        time.sleep(0.002)
        xs.append((time.perf_counter() - t - 0.002) * 1000)
    return statistics.median(xs)


def _boot_calibration() -> None:
    """Before the exit reports healthy: sleep overshoot, a warm-up of the
    exit's own forward, and the first-forward (cold collector) distribution."""
    import random
    rng = random.Random(secrets.randbits(64))
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", EXIT_PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        CAL["overshoot_ms"] = round(_measure_overshoot(), 4)
        CAL["procs"]["cal"] = _spawn_collector(CAL_PORT, CAL_TOKEN)
        for _ in range(5):
            _cal_send(sink_mod.URLENCODED, 100, CAL_PORT, "discard", rng)
        for _ in range(COLD_N):
            _cal_send(sink_mod.URLENCODED, rng.randint(60, 140), CAL_PORT, "warm-ref", rng)
            cold = _spawn_collector(COLD_PORT, CAL_TOKEN)
            try:
                _cal_send(sink_mod.URLENCODED, rng.randint(60, 140), COLD_PORT, "cold", rng)
            finally:
                _stop(cold)
        ref = statistics.median(CAL["warm_ref_ms"]) if CAL["warm_ref_ms"] else 0.0
        SINK.set_cold_excess([c - ref for c in CAL["cold_ms"]])
        CAL["boot_done"] = True
    except Exception as e:  # noqa: BLE001
        CAL["boot_error"] = repr(e)


def _calibrate() -> None:
    """Calibration forwards for every cell, through this exit's own handler
    with the armed decoy set, to the calibration collector. The calibration
    collector is restarted after each large-body set to bound its memory."""
    import random
    rng = random.Random(secrets.randbits(64))
    t_start = time.time()
    plan = []
    for cls, bucket in sink_mod.cells():
        for _ in range(CAL_SMALL_N):
            size = 0 if cls == sink_mod.NO_BODY else rng.randint(*sink_mod.bucket_range(bucket))
            plan.append((cls, size))
    rng.shuffle(plan)
    if CAL["procs"].get("cal") is None or CAL["procs"]["cal"].poll() is not None:
        CAL["procs"]["cal"] = _spawn_collector(CAL_PORT, CAL_TOKEN)
        _cal_send(sink_mod.URLENCODED, 100, CAL_PORT, "discard", rng)
    for cls, size in plan:
        _cal_send(cls, size, CAL_PORT, "window", rng)
    for cls in (sink_mod.URLENCODED, sink_mod.MULTIPART, sink_mod.OTHER):
        big = [s for s in CAL_LARGE_SIZES for _ in range(CAL_LARGE_N)]
        rng.shuffle(big)
        for size in big:
            _cal_send(cls, size, CAL_PORT, "window", rng)
        _stop(CAL["procs"]["cal"])
        CAL["procs"]["cal"] = _spawn_collector(CAL_PORT, CAL_TOKEN)
        _cal_send(sink_mod.URLENCODED, 100, CAL_PORT, "discard", rng)
    CAL["runs"].append({"started": datetime.fromtimestamp(t_start).isoformat(),
                        "seconds": round(time.time() - t_start, 2),
                        "small_sends": len(plan),
                        "large_sends": 3 * len(CAL_LARGE_SIZES) * CAL_LARGE_N})


def _wait_for_external_collector() -> None:
    probe = urllib.request.Request(exp3.COLLECTOR_URL + "/get-request-log",
                                   headers={exp3.TOKEN_HEADER: exp3.TOKEN})
    for _ in range(600):
        try:
            with urllib.request.urlopen(probe, timeout=2):  # noqa: S310
                return
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    raise RuntimeError("external collector did not become ready")


def reset() -> None:
    """Tests only: back to the unarmed state (sink windows are kept)."""
    with _LOCK:
        STATE.clear()
        STATE.update(_fresh_state())


def start_background_calibration() -> threading.Thread:
    t = threading.Thread(target=_boot_calibration, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    if EXTERNAL_COLLECTOR:
        _wait_for_external_collector()
    else:
        exp3._start_collector()
    print(f"swarm exit up {datetime.now().isoformat()}", flush=True)
    start_background_calibration()
    app.run(host="0.0.0.0", port=EXIT_PORT, debug=False, threaded=True)  # noqa: S104
