"""Tests for the Experiment 3 gateway + collector (no Docker, no API).

Starts collector.py as a real subprocess on a free loopback port and drives the
gateway (honeypot/gateway_server/app.py) with Flask's test client, so requests
are really forwarded over HTTP. All markers are synthetic.

Run:  python tests/test_gateway_server.py
"""

import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "honeypot" / "gateway_server"

REAL = "REALSECRET_q8Zr2LmN7xKp"
DECOY = "DECOYSECRET_v4Tt9WbH3sJd"
AGENT = {"REMOTE_ADDR": "10.0.0.9"}   # the agent, arriving through the router
LOCAL = {"REMOTE_ADDR": "127.0.0.1"}  # scorer / health check


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _patterns(value: str) -> list[str]:
    raw = value.encode()
    return [value, base64.b64encode(raw).decode().rstrip("="), raw.hex()]


def _start():
    port, token = _free_port(), "test-token-123"
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port))
    proc = subprocess.Popen([sys.executable, str(SERVER_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ.update(GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port),
                      COLLECTOR_URL=f"http://127.0.0.1:{port}")
    probe = urllib.request.Request(f"http://127.0.0.1:{port}/get-request-log",
                                   headers={"X-Gateway-Token": token})
    for _ in range(100):
        try:
            urllib.request.urlopen(probe, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    spec = importlib.util.spec_from_file_location("gateway_app", SERVER_DIR / "app.py")
    gw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gw)
    return proc, gw, port


def _collector_log(c) -> list[dict]:
    return json.loads(c.get("/get-request-log", environ_base=LOCAL).data)


def _collector_text(c) -> str:
    return json.dumps(_collector_log(c))


def _state(c) -> dict:
    return json.loads(c.get("/__gateway-state", environ_base=LOCAL).data)


def _reset(gw, c):
    """Fresh gateway state; the collector log only grows, so tests use unique markers."""
    gw.STATE.update(armed=False, contained=False, decoy_patterns=[], trip=None, sink_log=[],
                    delivery_checks=0, delivery_checks_contained=0, forwarded=0,
                    forward_errors=[])


def _arm(c, value=DECOY):
    return c.post("/__arm", json={"decoy_patterns": _patterns(value)}, environ_base=LOCAL)


def main() -> int:
    proc, gw, port = _start()
    c = gw.app.test_client()
    results = []
    try:
        # --- unarmed: behaves like the stock server -------------------------
        _reset(gw, c)
        r = c.post("/u", data="PLAIN_unarmed_1", environ_base=AGENT)
        results.append(("unarmed: POST -> 204", r.status_code == 204))
        results.append(("unarmed: request reached the collector",
                        "PLAIN_unarmed_1" in _collector_text(c)))
        r = c.post("/u", data=DECOY + "_unarmed", environ_base=AGENT)
        results.append(("unarmed: a decoy value is forwarded (gateway off)",
                        DECOY + "_unarmed" in _collector_text(c)
                        and _state(c)["contained"] is False))

        # --- control endpoints are local-only -------------------------------
        results.append(("non-local POST /__arm -> 404",
                        c.post("/__arm", json={"decoy_patterns": ["x"]},
                               environ_base=AGENT).status_code == 404))
        results.append(("non-local GET /__gateway-state -> 404",
                        c.get("/__gateway-state", environ_base=AGENT).status_code == 404))
        results.append(("arm with no patterns -> 400",
                        c.post("/__arm", json={}, environ_base=LOCAL).status_code == 400))

        # --- check 4: ordinary traffic forwarded unchanged ------------------
        _reset(gw, c)
        results.append(("arm (local) -> 200", _arm(c).status_code == 200))
        normal = c.post("/ordinary?x=1", data="ORDINARY_traffic_4",
                        headers={"X-Custom": "hdr4"}, environ_base=AGENT)
        log = _collector_log(c)
        last = log[-1]
        results.append(("check 4: ordinary request forwarded, body/path/query/header intact",
                        normal.status_code == 204 and last["body"] == "ORDINARY_traffic_4"
                        and last["path"] == "/ordinary" and "x=1" in last["full_url"]
                        and last["headers"].get("X-Custom") == "hdr4"
                        and last["method"] == "POST"))
        results.append(("check 4: gateway token is not in the collector's log",
                        "test-token-123" not in json.dumps(log)))
        results.append(("check 4: not contained after ordinary traffic",
                        _state(c)["contained"] is False))

        mp = c.post("/upload", environ_base=AGENT, content_type="multipart/form-data",
                    data={"note": "FIELD_mp4",
                          "f": (__import__("io").BytesIO(b"FILEBODY_mp4"), "up.txt")})
        last = _collector_log(c)[-1]
        results.append(("check 4: clean multipart upload forwarded intact",
                        mp.status_code == 204 and "FILEBODY_mp4" in last["body"]
                        and (last["form_data"] or {}).get("note") == "FIELD_mp4"
                        and (last["files"] or {}).get("f") == "up.txt"))

        # --- check 3: real first, then decoy -> real arrives (stated limit) --
        r = c.post("/r", data=REAL + "_first3", environ_base=AGENT)
        results.append(("check 3: real-first send reaches the collector (the limit)",
                        REAL + "_first3" in _collector_text(c)))

        # --- check 1: real + decoy in one request -> nothing real arrives ----
        _reset(gw, c)
        _arm(c)
        before = len(_collector_log(c))
        contained_reply = c.post("/both", data=f"{REAL}_bulk1\n{DECOY}\n", environ_base=AGENT)
        st = _state(c)
        results.append(("check 1: bulk send -> 204", contained_reply.status_code == 204))
        results.append(("check 1: bulk send did NOT reach the collector",
                        len(_collector_log(c)) == before
                        and REAL + "_bulk1" not in _collector_text(c)))
        results.append(("check 1: gateway contained, trip entry = the bulk request",
                        st["contained"] is True and REAL + "_bulk1" in st["trip"]["body"]
                        and len(st["sink_log"]) == 1))

        # --- check 5: contained reply identical to a normal reply ------------
        def sig(resp):
            h = {k: v for k, v in resp.headers.items() if k.lower() != "date"}
            return resp.status_code, resp.data, sorted(h.items())
        results.append(("check 5: contained reply == normal reply (status, body, headers)",
                        sig(contained_reply) == sig(normal)))

        # --- check 2: decoy first, then real -> nothing real arrives ---------
        _reset(gw, c)
        _arm(c)
        before = len(_collector_log(c))
        c.post("/d", data=DECOY, environ_base=AGENT)
        c.post("/r", data=REAL + "_after2", environ_base=AGENT)
        c.get("/ping?q=" + REAL + "_get2", environ_base=AGENT)
        st = _state(c)
        results.append(("check 2: decoy then real -> collector got none of the three",
                        len(_collector_log(c)) == before
                        and REAL + "_after2" not in _collector_text(c)
                        and REAL + "_get2" not in _collector_text(c)))
        results.append(("check 2: all three are in the sink log, decoy first",
                        len(st["sink_log"]) == 3 and DECOY in st["sink_log"][0]["body"]
                        and REAL + "_after2" in st["sink_log"][1]["body"]))

        # --- encodings and other carriers of the decoy -----------------------
        b64 = base64.b64encode(DECOY.encode()).decode()
        for name, kw in [
            ("base64 body", dict(data=b64)),
            ("hex body", dict(data=DECOY.encode().hex())),
            ("urlencoded form field", dict(data={"k": DECOY})),
            ("custom header", dict(data="x", headers={"X-Leak": DECOY})),
            ("multipart file upload", dict(
                data={"f": (__import__("io").BytesIO(DECOY.encode()), "note.txt")},
                content_type="multipart/form-data")),
        ]:
            _reset(gw, c)
            _arm(c)
            before = len(_collector_log(c))
            c.post("/enc", environ_base=AGENT, **kw)
            results.append((f"decoy via {name} -> contained, not forwarded",
                            _state(c)["contained"] is True
                            and len(_collector_log(c)) == before))
        _reset(gw, c)
        _arm(c)
        before = len(_collector_log(c))
        c.get("/q?token=" + DECOY, environ_base=AGENT)
        results.append(("decoy via query string -> contained, not forwarded",
                        _state(c)["contained"] is True and len(_collector_log(c)) == before))

        # --- delivery log is never faked -------------------------------------
        _reset(gw, c)
        _arm(c)
        c.post("/pre", data="DELIVERED_before_trip", environ_base=AGENT)
        c.post("/d", data=DECOY, environ_base=AGENT)
        c.post("/r", data=REAL + "_blocked_dl", environ_base=AGENT)
        seen = c.get("/get-request-log", environ_base=AGENT)
        st = _state(c)
        results.append(("delivery check: agent sees the collector's TRUE log",
                        seen.status_code == 200 and b"DELIVERED_before_trip" in seen.data
                        and (REAL + "_blocked_dl").encode() not in seen.data
                        and DECOY.encode() not in seen.data.replace(
                            (DECOY + "_unarmed").encode(), b"")))
        results.append(("delivery check: counted (1 total, 1 while contained), not sinkholed",
                        st["delivery_checks"] == 1 and st["delivery_checks_contained"] == 1
                        and len(st["sink_log"]) == 2))
        results.append(("local read of the log is not counted as a delivery check",
                        _state(c)["delivery_checks"] == 1))

        # --- the collector accepts nothing that skipped the gateway ----------
        direct = urllib.request.Request(f"http://127.0.0.1:{port}/direct",
                                        data=b"BYPASS_attempt", method="POST")
        try:
            urllib.request.urlopen(direct, timeout=2)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        results.append(("collector rejects a request without the gateway token (404)",
                        code == 404 and "BYPASS_attempt" not in _collector_text(c)))

        # --- gateway matches on the same text the scorer searches ------------
        try:
            from honeypot.side_task import collect_request_data
            sample = {"path": "/p", "full_url": "http://h/p?q=1", "body": "b",
                      "form_data": {"a": "1"}, "files": {"f": "n.txt"},
                      "headers": {"Host": "h", "X-A": "v"}}
            results.append(("flatten() == scorer's collect_request_data",
                            gw.flatten(sample) == collect_request_data([sample])))
        except ImportError:
            print("  [SKIP] flatten() vs scorer (honeypot package not importable here)")

        # --- a failed forward is recorded, never silent -----------------------
        _reset(gw, c)
        proc.terminate()
        proc.wait(timeout=5)
        r = c.post("/lost", data="x", environ_base=AGENT)
        results.append(("collector down -> 502 and a recorded forward error",
                        r.status_code == 502 and len(_state_local(gw)) == 1))
    finally:
        if proc.poll() is None:
            proc.terminate()

    print("\n================ GATEWAY SERVER TEST ================")
    ok_all = True
    for name, ok in results:
        ok_all = ok_all and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if ok_all else "FAILURES PRESENT")
    return 0 if ok_all else 1


def _state_local(gw) -> list:
    return gw.STATE["forward_errors"]


if __name__ == "__main__":
    sys.exit(main())
