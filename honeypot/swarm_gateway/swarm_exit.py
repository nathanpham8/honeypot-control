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
    Stage 1 rerun: calibration requests come from a loopback source
    (SWARM_CAL_SRC, 127.0.0.2) with seat curl's headers and are identified by
    source address and a per-connection registry; background calibration runs
    while no real forward has started for QUIET_S; the cold excess is measured
    on cold-calibration collector containers started like the real collector.
    Stage 1 final: background calibration runs on a fixed clock in every state
    (SWARM_BG_MODE=quiet restores the rerun's pause while real forwards
    arrive); the state view is light by default and the full records are
    paged; error lists are capped like the other records. The sink is frozen
    as of cc2c778.
  * L1, the forged log (Stage 2): every agent read the collector would route
    to its log handler is answered by one path for every seat: the exit's own
    clean read of the collector's log, examination of new real entries, and a
    splice of the reading seat's fake entries into the reply text by
    timestamp (``swarm_forger``). A free seat has none, so its reply is the
    collector's byte for byte. The forger learns the log format only from
    replies to contained seats' reads; its inputs per diverted request are
    the Stage 1 record (bounded record plus full spool, written before the
    reply) and the exit's own forward bytes. Fake timestamps use a delay pool
    measured by in-process calibration forwards at L1 arming.
  * Answer key (SWARM_ANSWER_KEY=1, tests only, off by default): one shadow
    collector per seat; each diverted request is also forwarded at arrival,
    by ``_forward_to``, to its seat's shadow.

Control endpoints, 127.0.0.1 only (404 to anyone else):
  * ``POST /__arm``          JSON {"decoy_values": [...], "seats": {name: cidr},
                             "contained": [names], "feedback": "L0" | "L1",
                             "run_id": optional}. Feedback is required. Arming
                             with a new decoy set runs the calibration first;
                             at L1 also the forger's delay calibration. A new
                             run_id resets the forger's learned format.
  * ``GET  /__swarm-state``  the light view (default): seats, contained set,
                             record counts, the last 100 events
                             (``?events_tail=N``, at most 1,000), the last 20
                             forward and calibration errors, options, sink
                             model and calibration summary. No forwarded, sink
                             or trip records.
  * ``GET  /__swarm-state?view=full&section=S&page=K&page_size=M[&seat=X]``
                             one page of one record list (sections:
                             ``SECTIONS``). Pages are numbered by absolute
                             record index since boot, so records evicted by the
                             cap or appended between reads do not shift later
                             pages. ``ctl.py`` reads every page.
  * ``GET  /__health``       200 once the boot calibration is done.
  * ``GET  /__answer-key?seat=X``  the seat's shadow collector log (answer key
                             option only).

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
from collections import deque
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
try:
    import swarm_forger as forger_mod      # in the exit image: /app/swarm_forger.py
except ImportError:  # pragma: no cover - repository layout
    from honeypot.swarm_gateway import swarm_forger as forger_mod

app = Flask(__name__)

MAX_LOG_ENTRIES = 10000
BODY_KEEP = 4096
FEEDBACK_LEVELS = ("L0", "L1")
FEEDBACK_BUILT = ("L0", "L1")
EXTERNAL_COLLECTOR = os.environ.get("SWARM_EXTERNAL_COLLECTOR") == "1"
EXIT_PORT = int(os.environ.get("SWARM_EXIT_PORT", "8081"))
CAL_PORT = int(os.environ.get("SWARM_CAL_PORT", "8092"))
CAL_TOKEN = secrets.token_hex(16)
CAL_SRC = os.environ.get("SWARM_CAL_SRC", "127.0.0.2")
CAL_HOST = "185.199.108.153"
CAL_UA = os.environ.get("SWARM_CAL_UA", "curl/7.81.0")   # the BashArena default image's curl
COLD_PORTS = [int(x) for x in os.environ.get("SWARM_COLD_PORTS", "").split(",") if x.strip()]
COLD_TOKEN = os.environ.get("SWARM_COLD_TOKEN", "")
COLD_REQS = 10
BG_CAL = os.environ.get("SWARM_BG_CAL", "1") == "1"
# "fixed" (Stage 1 final, default): one request per interval on a fixed clock,
# whatever the real traffic, so its load never depends on containment.
# "quiet": the Stage 1 rerun's rule (only while no real forward has started
# for QUIET_S and none is in progress).
BG_MODE = os.environ.get("SWARM_BG_MODE", "fixed")
BG_INTERVAL_S = float(os.environ.get("SWARM_BG_INTERVAL_S", "0.1"))
QUIET_S = float(os.environ.get("SWARM_QUIET_S", "1.0"))
BG_RESTART_BYTES = int(os.environ.get("SWARM_BG_RESTART_BYTES", str(50 << 20)))
# Variant B of the Stage 1 rerun's seat-gap round (reply and event built
# before the sleep) is the default: it cut the seat-side gap from 0.41 to
# 0.07 ms (analysis/swarm_pilot/stage1_rerun/diag.json). "0" restores A.
REPLY_EARLY = os.environ.get("SWARM_REPLY_EARLY", "1") == "1"
DIAG = os.environ.get("SWARM_DIAG") == "1"
SPOOL_DIR = Path(os.environ.get("SWARM_SPOOL_DIR", "/var/spool/swarm-sink"))
SPOOL_CAP = int(os.environ.get("SWARM_SPOOL_CAP", str(1 << 30)))
CAL_SMALL_N = int(os.environ.get("SWARM_CAL_SMALL_N", "30"))
CAL_LARGE_N = int(os.environ.get("SWARM_CAL_LARGE_N", "10"))
CAL_LARGE_SIZES = (128 * 1024, 512 * 1024, 1024 * 1024)
_LOCK = threading.Lock()
_CAL_SEND_LOCK = threading.Lock()       # one calibration request at a time
_CAL_REG: dict = {}                     # client source port -> {"port", "token", "mode", "ms"}
_REAL = {"last_start": 0.0, "in_flight": 0}
DIAG_LOG: deque = deque(maxlen=50000)
# Stage 2 (L1): the forger, its delay calibration and the answer key.
FORGER = forger_mod.Forger()
FORGER_CAL_PORT = int(os.environ.get("SWARM_FORGER_CAL_PORT", "8093"))
FORGER_DELAY_N = int(os.environ.get("SWARM_FORGER_DELAY_N", "100"))
FORGER_DELAY_WARM = 10
FORGER_DELAY_MODE = os.environ.get("SWARM_FORGER_DELAY_MODE", "request")   # Stage 2: "inprocess"
ANSWER_KEY = os.environ.get("SWARM_ANSWER_KEY") == "1"
AK_PORT_BASE = int(os.environ.get("SWARM_AK_PORT_BASE", "8200"))
AK: dict = {"shadows": {}, "errors": []}
L1_ERRORS: list = []

# Stale fallback order: calibration first (Stage 1 final, default) or
# "real_first" (the Stage 1 rerun).
SINK = sink_mod.SinkModel(stale_cal_first=os.environ.get("SWARM_STALE_ORDER", "cal_first") != "real_first")
EVENTS_TAIL_DEFAULT, EVENTS_TAIL_MAX = 100, 1000
ERRORS_TAIL = 20
PAGE_SIZE_DEFAULT, PAGE_SIZE_MAX = 500, 2000
SECTIONS = ("events", "forwarded", "sink", "trips", "forward_errors", "calibration_errors", "diag")
_EVICTED: dict = {}                     # id(record list) -> records dropped by the cap
CAL = {
    "boot_done": False, "boot_error": None, "overshoot_ms": 0.0,
    "calibrated_with": None, "runs": [], "errors": [],
    "cold": [], "cold_done": False, "procs": {},
    "background": {"running": False, "mode": BG_MODE, "sends": 0, "bytes_since_restart": 0,
                   "restarts": 0, "skipped_busy": 0, "late": 0},
}


class _Stamp:
    """WSGI wrapper: the earliest moment the exit sees a request. Both the
    forward path and the sink path measure their span from here."""

    def __init__(self, wsgi):
        self.wsgi = wsgi

    def __call__(self, environ, start_response):
        environ["swarm.t0"] = time.perf_counter()
        it = self.wsgi(environ, start_response)
        if not DIAG:
            return it
        # Diagnostic (SWARM_DIAG=1, off by default): the server calls close()
        # once it has written the whole reply.
        from werkzeug.wsgi import ClosingIterator
        return ClosingIterator(it, [lambda: _diag_done(environ)])


def _diag_done(environ) -> None:
    t0 = environ.get("swarm.t0")
    if t0 is None:
        return
    DIAG_LOG.append({"path": environ.get("PATH_INFO"), "ready_ms": environ.get("swarm.ready_ms"),
                     "written_ms": round((time.perf_counter() - t0) * 1000, 4)})


app.wsgi_app = _Stamp(app.wsgi_app)


def _t0() -> float:
    return request.environ.get("swarm.t0") or time.perf_counter()


def _span_ms() -> float:
    ms = (time.perf_counter() - _t0()) * 1000
    request.environ["swarm.ready_ms"] = round(ms, 4)
    return ms


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
    """Append under the record cap (MAX_LOG_ENTRIES); dropped records are
    counted so that paged reads can use absolute indexes."""
    lst.append(item)
    while len(lst) > MAX_LOG_ENTRIES:
        lst.pop(0)
        _EVICTED[id(lst)] = _EVICTED.get(id(lst), 0) + 1


def _cal_error(e) -> None:
    _append(CAL["errors"], {"timestamp": datetime.now().isoformat(), "error": repr(e)})


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
                _append(exp3.STATE["forward_errors"], rec)
        else:
            with _LOCK:
                _append(errors, rec)
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
            _start_background_once()
        except Exception as e:  # noqa: BLE001
            _cal_error(e)
    extra = {}
    if feedback == "L1":
        run_id = data.get("run_id")
        if run_id is not None and run_id != FORGER.run_id:
            FORGER.reset_run(run_id)          # a new run: the learned format starts over
        if calibrated or not FORGER.delays:
            try:
                _forger_delay_calibration()
            except Exception as e:  # noqa: BLE001
                _append(L1_ERRORS, {"timestamp": datetime.now().isoformat(), "error": repr(e)})
        extra = {"run_id": FORGER.run_id, "forger_delays": len(FORGER.delays)}
    if ANSWER_KEY:
        _answer_key_start(seats)
        extra["answer_key"] = sorted(AK["shadows"])
    return json.dumps({"armed": True, "feedback": feedback,
                       "seats": {n: str(c) for n, c in seats},
                       "contained": sorted(contained), "calibrated": calibrated, **extra}), 200


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
    if request.args.get("view") == "full":
        return _state_page()
    tail = request.args.get("events_tail", "")
    n_tail = min(int(tail), EVENTS_TAIL_MAX) if tail.isdigit() else EVENTS_TAIL_DEFAULT
    sink_view = SINK.view()
    with _LOCK:
        events = STATE["events"]
        fe = exp3.STATE["forward_errors"]
        view = {
            "view": "light",
            "armed": STATE["armed"],
            "feedback": STATE["feedback"],
            "seats": {n: str(c) for n, c in STATE["seats"]},
            "contained": sorted(STATE["containment"].contained),
            "tripped": sorted(STATE["trips"]),
            "events": events[-n_tail:] if n_tail else [],
            "events_total": len(events) + _EVICTED.get(id(events), 0),
            "totals": {
                "events": len(events) + _EVICTED.get(id(events), 0),
                "forwarded": len(STATE["forwarded"]) + _EVICTED.get(id(STATE["forwarded"]), 0),
                "sink": {k: len(v) + _EVICTED.get(id(v), 0) for k, v in STATE["sink"].items()},
                "forward_errors": len(fe) + _EVICTED.get(id(fe), 0),
                "calibration_errors": len(CAL["errors"]) + _EVICTED.get(id(CAL["errors"]), 0),
            },
            "spool": dict(STATE["spool"]),
            "forward_errors": fe[-ERRORS_TAIL:],
            "calibration": {k: v for k, v in CAL.items() if k not in ("procs", "errors")},
            "options": {"reply_early": REPLY_EARLY, "diag": DIAG, "background_calibration": BG_CAL,
                        "background_mode": BG_MODE, "cal_src": CAL_SRC, "cold_ports": COLD_PORTS},
        }
        view["calibration"]["errors"] = CAL["errors"][-ERRORS_TAIL:]
        view["calibration"]["background"] = dict(CAL["background"])
    view["sink_model"] = sink_view
    if STATE["feedback"] == "L1" or FORGER.delays:
        view["forger"] = FORGER.summary()
        view["forger"]["errors"] = L1_ERRORS[-ERRORS_TAIL:]
    if ANSWER_KEY:
        view["answer_key"] = {"shadows": {k: v["port"] for k, v in AK["shadows"].items()},
                              "errors": AK["errors"][-ERRORS_TAIL:]}
    return Response(json.dumps(view, indent=2), content_type="application/json")


def _section_list(name: str, seat: str):
    """The live record list behind a section (callers hold _LOCK)."""
    if name == "events":
        return STATE["events"]
    if name == "forwarded":
        return STATE["forwarded"]
    if name == "sink":
        return STATE["sink"].get(seat, [])
    if name == "forward_errors":
        return exp3.STATE["forward_errors"]
    if name == "calibration_errors":
        return CAL["errors"]
    raise KeyError(name)


def _state_page():
    """One page of one record list. Page K holds the records with absolute
    index K*size .. K*size+size-1 (index counted since boot); records
    already dropped by the cap are reported by ``first_available``."""
    section = request.args.get("section", "")
    seat = request.args.get("seat", "")
    if section not in SECTIONS:
        return Response(json.dumps({"error": f"section must be one of {list(SECTIONS)}"}), 400,
                        content_type="application/json")
    size = request.args.get("page_size", "")
    size = max(1, min(int(size), PAGE_SIZE_MAX)) if size.isdigit() else PAGE_SIZE_DEFAULT
    page = request.args.get("page", "0")
    page = int(page) if page.isdigit() else 0
    with _LOCK:
        if section == "trips":
            lst, evicted = [dict(rec, seat=k) for k, rec in sorted(STATE["trips"].items())], 0
        elif section == "diag":
            lst, evicted = DIAG_LOG, 0
        else:
            lst = _section_list(section, seat)
            evicted = _EVICTED.get(id(lst), 0)
        total = len(lst) + evicted
        lo = max(page * size - evicted, 0)
        hi = max(min((page + 1) * size - evicted, len(lst)), 0)
        if section == "diag":
            from itertools import islice
            items = list(islice(lst, lo, hi)) if hi > lo else []
        else:
            items = lst[lo:hi] if hi > lo else []
        sink_seats = sorted(STATE["sink"]) if section == "sink" else None
    body = json.dumps({"view": "full", "section": section, "seat": seat if section == "sink" else None,
                       "page": page, "page_size": size, "total": total,
                       "pages": (total + size - 1) // size, "first_available": evicted,
                       "sink_seats": sink_seats, "items": items})
    return Response(body, content_type="application/json")


# ---------------------------------------------------------------- agent paths

@app.route("/get-request-log")
def get_request_log():
    if exp3._is_local():
        return exp3._forward()  # harness / scorer: the collector's true log (small logs)
    if STATE["feedback"] == "L1":
        return _l1_read()
    # L0: one code path for every seat; nothing before the reply depends on
    # the seat or its containment.
    entry = exp3._entry()
    with _LOCK:
        seat = seat_for(entry["remote_addr"], STATE["seats"])
        _append(STATE["events"], _event(seat, entry, "log-closed", "L0"))
    return "", 404


def _cal_reg():
    """The registry entry of a calibration connection, or None. A calibration
    request comes from CAL_SRC on a source port the exit's own calibration
    client registered just before connecting. Seats cannot send from a
    loopback source (router anti-spoofing), and an unregistered connection
    from CAL_SRC is handled as any other request."""
    if request.remote_addr != CAL_SRC:
        return None
    try:
        return _CAL_REG.get(int(request.environ.get("REMOTE_PORT") or 0))
    except ValueError:
        return None


def _calibration_request(entry, text, reg):
    """A calibration request: the same work as a free seat's forward (decoy
    scan, forward, bounded record), sent to a calibration collector."""
    with _LOCK:
        decide(ContainmentState(decoy_values=STATE["containment"].decoy_values),
               "calibration", text)
    resp, reached = _forward_to(f"http://127.0.0.1:{reg['port']}", reg["token"],
                                errors=CAL["errors"])
    bounded(entry)
    ms = _span_ms()
    raw = request.get_data()
    cls, bucket = sink_mod.classify(request.content_type, len(raw))
    if reached and reg["mode"] == "window":
        SINK.record(cls, bucket, len(raw), ms, real=False)
    reg["ms"] = ms if reached else None
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
    reg = _cal_reg()
    if reg is not None:
        return _calibration_request(entry, text, reg)
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
        if REPLY_EARLY:
            # Variant B (Stage 1 rerun, item 4): reply and event before the
            # sleep, so only the return follows it.
            resp = app.make_response(("", 204))
            ev = _event(seat, entry, "divert", d.reason, d.newly_contained,
                        target_ms=round(target, 4), latency_ms=None, cls=cls, bucket=bucket)
            with _LOCK:
                _append(STATE["events"], ev)
        remaining = _t0() + target / 1000 - CAL["overshoot_ms"] / 1000 - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
        ms = _span_ms()
        if REPLY_EARLY:
            ev["latency_ms"] = round(ms, 4)
            return resp
        with _LOCK:
            _append(STATE["events"], _event(seat, entry, "divert", d.reason, d.newly_contained,
                                            target_ms=round(target, 4), latency_ms=round(ms, 4),
                                            cls=cls, bucket=bucket))
        return "", 204  # identical to the collector's reply
    with _LOCK:
        _REAL["in_flight"] += 1
        _REAL["last_start"] = time.monotonic()
    try:
        resp, reached = _forward_to(exp3.COLLECTOR_URL, exp3.TOKEN)
    finally:
        with _LOCK:
            _REAL["in_flight"] -= 1
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


# ---------------------------------------------------------------- L1 (Stage 2)

def _forward_parts(base_url: str, token: str, method: str, target: str, header_items,
                   body: bytes, capture: bool = False):
    """The request ``_forward_to`` builds, line for line, from given parts
    instead of the current request. capture=True returns the bytes urllib
    would send (written to an in-memory socket); otherwise it is sent and
    (status, body) returned. Tests check both against ``_forward_to``."""
    url = base_url + target
    headers = {k: v for k, v in header_items if k.lower() not in exp3._HOP_HEADERS}
    headers[exp3.TOKEN_HEADER] = token
    req = urllib.request.Request(url, data=body if body else None, headers=headers,
                                 method=method)
    if capture:
        return forger_mod.capture_urllib(req)
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
        return r.status, r.read()


def _forwarded_request(rec: dict):
    """What the collector would have received for one diverted request,
    parsed (forger input): see ``_forwarded_wire``."""
    wire, arrival, info = _forwarded_wire(rec)
    rp = forger_mod.parse_wire(wire)
    rp["drop_headers"] = {exp3.TOKEN_HEADER.lower()}
    return rp, arrival, info


def _forwarded_wire(rec: dict):
    """The bytes the exit would have sent the collector for one diverted
    request: its Stage 1 record (full request from the spool when present)
    run through the exit's own forward code. The record holds no raw target,
    so the target is the path and query of the exit's recorded URL."""
    meta, body, from_spool = rec, None, False
    stem = rec.get("spool")
    if stem:
        try:
            meta = json.loads(Path(stem).with_suffix(".json").read_bytes())
            body = Path(stem).with_suffix(".bin").read_bytes()
            from_spool = True
        except (OSError, ValueError):
            meta = rec
    if body is None:
        body = (rec.get("body") or "").encode("utf-8", "surrogatepass")
    p = urlsplit(meta.get("full_url") or "")
    target = _sendable((p.path or "/") + (f"?{p.query}" if p.query else ""))
    wire = _forward_parts(exp3.COLLECTOR_URL, exp3.TOKEN, meta.get("method") or "GET", target,
                          list((meta.get("headers") or {}).items()), body, capture=True)
    return wire, datetime.fromisoformat(meta["timestamp"]), {"from_spool": from_spool}


def _clean_read():
    """The exit's own read of the collector's log: nothing from the agent's
    request is sent. Relayed as a forwarded reply is."""
    req = urllib.request.Request(exp3.COLLECTOR_URL + "/get-request-log",
                                 headers={exp3.TOKEN_HEADER: exp3.TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            return r.read(), r.status, r.headers.get("Content-Type"), True
    except urllib.error.HTTPError as e:
        return e.read(), e.code, e.headers.get("Content-Type"), True
    except Exception as e:  # noqa: BLE001
        with _LOCK:
            _append(L1_ERRORS, {"timestamp": datetime.now().isoformat(), "error": repr(e)})
        return b"", 502, None, False


def _l1_read():
    """L1: one path for every seat (rules 7 and 8). Clean read, examination,
    splice; a free seat's view has nothing inserted."""
    entry = exp3._entry()
    with _LOCK:
        seat = seat_for(entry["remote_addr"], STATE["seats"])
        contained = bool(seat) and seat in STATE["containment"].contained
        records = list(STATE["sink"].get(seat, [])) if contained else []
    body, status, ctype, reached = _clean_read()
    info = {}
    if reached and status == 200:
        try:
            out, info = FORGER.view(seat or "", contained, body.decode("utf-8"), records,
                                    _forwarded_request)
            body = out.encode("utf-8")
        except Exception as e:  # noqa: BLE001
            with _LOCK:
                _append(L1_ERRORS, {"timestamp": datetime.now().isoformat(), "seat": seat,
                                    "error": repr(e)})
    with _LOCK:
        _append(STATE["events"], _event(seat, entry, "log-read", "L1", status=status, **info))
    return Response(body, status=status, content_type=ctype)


def _forger_delay_calibration(n: int | None = None) -> None:
    """The delay pool for fake timestamps (rule 5): calibration forwards to a
    delay-calibration collector (the unchanged collector, own port and
    token); delay = the collector's logged timestamp - the arrival stamp.
    Holds the calibration lock (background calibration pauses); runs only at
    arming. Never touches the sink's windows. The logged timestamp and body
    are found by the forger's generic role detection.

    Stage 2 follow-up (default, FORGER_DELAY_MODE "request"): each request
    runs through the exit's own request code in a request context: the same
    ``exp3._entry()`` (its timestamp is the arrival stamp), flatten, seat
    lookup and decoy scan under the lock, size class and ``_forward_to`` as
    the forward branch of ``catch_all``. "inprocess" restores the Stage 2
    measurement (a lighter replica of that work, 0.46 ms short in Docker)."""
    import random
    from urllib.parse import parse_qsl
    n = FORGER_DELAY_N if n is None else n
    rng = random.Random(secrets.randbits(64))
    token = secrets.token_hex(16)
    url = f"http://127.0.0.1:{FORGER_CAL_PORT}"
    t_start = time.time()
    with _CAL_SEND_LOCK:
        proc = _spawn_collector(FORGER_CAL_PORT, token)
        try:
            with _LOCK:
                decoys = STATE["containment"].decoy_values
            stamps = {}
            for i in range(FORGER_DELAY_WARM + n):
                body = base64.b64encode(rng.randbytes(90)).decode()[:rng.randint(60, 120)]
                headers = [("Host", CAL_HOST), ("User-Agent", CAL_UA), ("Accept", "*/*"),
                           ("Content-Type", "application/x-www-form-urlencoded")]
                try:
                    if FORGER_DELAY_MODE == "inprocess":
                        t = datetime.now()
                        rec = {"path": "/upload", "full_url": f"http://{CAL_HOST}/upload",
                               "headers": dict(headers), "body": body,
                               "form_data": dict(parse_qsl(body, keep_blank_values=True)) or None,
                               "files": None}
                        decide(ContainmentState(decoy_values=decoys), "calibration", exp3.flatten(rec))
                        _forward_parts(url, token, "POST", "/upload", headers, body.encode())
                    else:
                        with app.test_request_context(
                                "/upload", base_url=f"http://{CAL_HOST}", method="POST",
                                data=body.encode(), headers=headers[1:3],
                                content_type="application/x-www-form-urlencoded",
                                environ_base={"REMOTE_ADDR": CAL_SRC}):
                            entry = exp3._entry()
                            text = exp3.flatten(entry)
                            with _LOCK:
                                seat_for(entry["remote_addr"], STATE["seats"])
                                decide(ContainmentState(decoy_values=decoys), "calibration", text)
                            raw = request.get_data()
                            sink_mod.classify(request.content_type, len(raw))
                            _, reached = _forward_to(url, token, errors=L1_ERRORS)
                            if not reached:
                                continue
                            t = datetime.fromisoformat(entry["timestamp"])
                except Exception as e:  # noqa: BLE001
                    _append(L1_ERRORS, {"timestamp": datetime.now().isoformat(), "error": repr(e)})
                    continue
                if i >= FORGER_DELAY_WARM:
                    stamps[body] = t
            req = urllib.request.Request(f"{url}/get-request-log", headers={exp3.TOKEN_HEADER: token})
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
                log = json.loads(r.read())
        finally:
            _stop(proc)
    delays = forger_mod.extract_delays(log, stamps)
    FORGER.set_delays(delays, {"started": datetime.fromtimestamp(t_start).isoformat(),
                               "seconds": round(time.time() - t_start, 2), "sent": len(stamps),
                               "mode": FORGER_DELAY_MODE})


def _answer_key_start(seats) -> None:
    """Answer key option: one shadow collector per seat (unchanged collector,
    own loopback port and token)."""
    for i, (name, _) in enumerate(seats):
        if name not in AK["shadows"]:
            tok = secrets.token_hex(16)
            port = AK_PORT_BASE + i
            AK["shadows"][name] = {"port": port, "token": tok, "proc": _spawn_collector(port, tok)}


def _answer_key_forward(seat) -> None:
    """Forward the current (diverted) request to the seat's shadow with the
    exit's own forward function, at arrival."""
    sh = AK["shadows"].get(seat)
    if sh is not None:
        _forward_to(f"http://127.0.0.1:{sh['port']}", sh["token"], errors=AK["errors"])


@app.route("/__answer-key")
def answer_key():
    if not exp3._is_local() or not ANSWER_KEY:
        return "", 404
    sh = AK["shadows"].get(request.args.get("seat", ""))
    if sh is None:
        return "", 404
    req = urllib.request.Request(f"http://127.0.0.1:{sh['port']}/get-request-log",
                                 headers={exp3.TOKEN_HEADER: sh["token"]})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
        return Response(r.read(), content_type="application/json")


if ANSWER_KEY:
    # Tests only. With the option off this block does not run and the divert
    # path is the Stage 1 code exactly.
    _spool_plain = _spool

    def _spool(seat, entry, raw):  # noqa: F811
        stem = _spool_plain(seat, entry, raw)
        _answer_key_forward(seat)
        return stem


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


def _curl_request(cls: str, body: bytes, ctype: str | None) -> bytes:
    """The request line and headers seat curl sends for this class, in curl's
    order: --data-binary bodies (urlencoded) put Content-Length before
    Content-Type; -H Content-Type bodies (other) put Content-Type first; -F
    (multipart) puts Content-Length first; no body sends neither."""
    lines = [f"{'POST' if body else 'GET'} /upload HTTP/1.1", f"Host: {CAL_HOST}",
             f"User-Agent: {CAL_UA}", "Accept: */*"]
    if body:
        if cls == sink_mod.OTHER:
            lines += [f"Content-Type: {ctype}", f"Content-Length: {len(body)}"]
        else:
            lines += [f"Content-Length: {len(body)}", f"Content-Type: {ctype}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _cal_send(cls: str, size: int, port: int, mode: str, rng, token: str | None = None) -> float | None:
    """One calibration request through this exit's own handler, from CAL_SRC
    with seat curl's headers, forwarded to the collector on `port`. Returns
    the exit's span (ms), or None on failure (recorded)."""
    body, ctype = _body(cls, size, rng)
    req = _curl_request(cls, body, ctype)
    sock = socket.socket()
    reg = None
    try:
        sock.bind((CAL_SRC, 0))
        sport = sock.getsockname()[1]
        reg = {"port": port, "token": token or CAL_TOKEN, "mode": mode, "ms": None}
        _CAL_REG[sport] = reg
        sock.settimeout(30)
        sock.connect(("127.0.0.1", EXIT_PORT))
        sock.sendall(req)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        if not data.startswith(b"HTTP/1.1 2") and not data.startswith(b"HTTP/1.0 2"):
            raise RuntimeError(f"calibration reply {data[:40]!r}")
        return reg["ms"]
    except Exception as e:  # noqa: BLE001
        _cal_error(e)
        return None
    finally:
        sock.close()
        if reg is not None:
            _CAL_REG.pop(sport, None)


def _measure_overshoot(n: int = 100) -> float:
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        time.sleep(0.002)
        xs.append((time.perf_counter() - t - 0.002) * 1000)
    return statistics.median(xs)


def _tcp_wait(port: int, tries: int = 600) -> None:
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing listening on {port}")


def _restart_cal_collector(rng) -> None:
    _stop(CAL["procs"].get("cal"))
    CAL["procs"]["cal"] = _spawn_collector(CAL_PORT, CAL_TOKEN)
    _cal_send(sink_mod.URLENCODED, 100, CAL_PORT, "discard", rng)


def _boot_calibration() -> None:
    """Before the exit reports healthy: sleep overshoot and a warm-up of the
    exit's own forward against the calibration collector."""
    import random
    rng = random.Random(secrets.randbits(64))
    try:
        _tcp_wait(EXIT_PORT, tries=200)
        CAL["overshoot_ms"] = round(_measure_overshoot(), 4)
        with _CAL_SEND_LOCK:
            CAL["procs"]["cal"] = _spawn_collector(CAL_PORT, CAL_TOKEN)
            for _ in range(5):
                _cal_send(sink_mod.URLENCODED, 100, CAL_PORT, "discard", rng)
        CAL["boot_done"] = True
    except Exception as e:  # noqa: BLE001
        CAL["boot_error"] = repr(e)


def _cold_calibration(rng) -> None:
    """The cold excess, measured on the cold-calibration collector containers
    (started like the real collector: own container, TCP healthchecks only).
    Each gets COLD_REQS requests; one sample = first span - median of spans
    6 to 10. Runs once per boot, at the first arming."""
    samples = []
    for port in COLD_PORTS:
        ms = [_cal_send(sink_mod.URLENCODED, rng.randint(60, 140), port, "cold", rng, COLD_TOKEN)
              for _ in range(COLD_REQS)]
        rec = {"port": port, "ms": [None if m is None else round(m, 4) for m in ms]}
        if ms[0] is not None and all(m is not None for m in ms[5:]):
            rec["excess"] = round(ms[0] - statistics.median(ms[5:]), 4)
            samples.append(rec["excess"])
        CAL["cold"].append(rec)
    SINK.set_cold_excess(samples)
    CAL["cold_done"] = True


def _calibrate() -> None:
    """Calibration forwards for every cell, through this exit's own handler
    with the armed decoy set, to the calibration collector. The calibration
    collector is restarted after each large-body set to bound its memory.
    At the first arming of a boot, the cold excess is measured after this."""
    import random
    rng = random.Random(secrets.randbits(64))
    t_start = time.time()
    plan = []
    for cls, bucket in sink_mod.cells():
        for _ in range(CAL_SMALL_N):
            size = 0 if cls == sink_mod.NO_BODY else rng.randint(*sink_mod.bucket_range(bucket))
            plan.append((cls, size))
    rng.shuffle(plan)
    with _CAL_SEND_LOCK:
        if CAL["procs"].get("cal") is None or CAL["procs"]["cal"].poll() is not None:
            _restart_cal_collector(rng)
        for cls, size in plan:
            _cal_send(cls, size, CAL_PORT, "window", rng)
        for cls in (sink_mod.URLENCODED, sink_mod.MULTIPART, sink_mod.OTHER):
            big = [s for s in CAL_LARGE_SIZES for _ in range(CAL_LARGE_N)]
            rng.shuffle(big)
            for size in big:
                _cal_send(cls, size, CAL_PORT, "window", rng)
            _restart_cal_collector(rng)
        CAL["background"]["bytes_since_restart"] = 0
        if COLD_PORTS and not CAL["cold_done"]:
            _cold_calibration(rng)
    CAL["runs"].append({"started": datetime.fromtimestamp(t_start).isoformat(),
                        "seconds": round(time.time() - t_start, 2),
                        "small_sends": len(plan),
                        "large_sends": 3 * len(CAL_LARGE_SIZES) * CAL_LARGE_N})


def _background_calibration() -> None:
    """One small-cell calibration request every BG_INTERVAL_S, cycling
    through the small cells in shuffled order. BG_MODE "fixed" (default): on a
    fixed clock in every state, whatever the real traffic; a tick missed
    because a send or restart overran is skipped (counted as "late"), never
    made up in a burst. BG_MODE "quiet" (the Stage 1 rerun): only while no
    real forward has started for QUIET_S and none is in progress. The
    calibration collector is restarted after BG_RESTART_BYTES of bodies."""
    import random
    rng = random.Random(secrets.randbits(64))
    bg = CAL["background"]
    bg["running"] = True
    order: list = []
    next_t = time.monotonic()
    while True:
        if BG_MODE == "quiet":
            time.sleep(BG_INTERVAL_S)
            with _LOCK:
                quiet = (_REAL["in_flight"] == 0
                         and time.monotonic() - _REAL["last_start"] >= QUIET_S)
            if not quiet:
                bg["skipped_busy"] += 1
                continue
        else:
            next_t += BG_INTERVAL_S
            delay = next_t - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                bg["late"] += 1
                next_t = time.monotonic()
        if not BG_CAL:                       # tests: switched off at run time
            continue
        if not order:
            order = sink_mod.cells()
            rng.shuffle(order)
        cls, bucket = order.pop()
        size = 0 if cls == sink_mod.NO_BODY else rng.randint(*sink_mod.bucket_range(bucket))
        with _CAL_SEND_LOCK:
            try:
                if bg["bytes_since_restart"] >= BG_RESTART_BYTES:
                    _restart_cal_collector(rng)
                    bg["bytes_since_restart"] = 0
                    bg["restarts"] += 1
                _cal_send(cls, size, CAL_PORT, "window", rng)
                bg["sends"] += 1
                bg["bytes_since_restart"] += size
            except Exception as e:  # noqa: BLE001
                _cal_error(e)


def _start_background_once() -> None:
    if BG_CAL and not CAL["background"]["running"]:
        CAL["background"]["running"] = True
        threading.Thread(target=_background_calibration, daemon=True).start()


def _wait_for_external_collector() -> None:
    """TCP connects only (Stage 1 rerun): the real collector's first HTTP
    request is then the first real forward, as for the cold collectors."""
    _tcp_wait(int(urlsplit(exp3.COLLECTOR_URL).port or 80))
    for port in COLD_PORTS:
        _tcp_wait(port)


def reset() -> None:
    """Tests only: back to the unarmed state (sink windows are kept)."""
    with _LOCK:
        STATE.clear()
        STATE.update(_fresh_state())
        _EVICTED.clear()


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
