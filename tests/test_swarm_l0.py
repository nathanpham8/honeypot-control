"""L0 closed log and routing quirks (step 3, Stage 1), without Docker.

The swarm exit runs as a real werkzeug server in this process, in front of a
real collector subprocess. Two "seats" are loopback source addresses
(127.0.0.2 and 127.0.0.3; 127.0.0.1 is the harness). Raw HTTP requests are
sent over sockets so that what is compared is the exact reply bytes.

  L0 reply equality  For every variant of an agent's log read (GET, HEAD,
                     query string, conditional and range headers, HTTP/1.0,
                     a body, keep-alive), the reply is byte-identical (Date
                     excluded) from a free seat and a contained seat, and the
                     same as before arming. Each read is recorded as an
                     attributed "log-closed" event and never reaches the
                     collector.
  F12                For each odd request near the log path (methods, trailing
                     slash, case, doubled slash, encodings, dot segments), the
                     outcome through the exit is compared with the outcome at a
                     bare collector: where the collector would route it to its
                     log handler, the exit gives the L0 reply and logs nothing;
                     otherwise the status and logged/not-logged match.
No containers; nothing outside a temp directory is written.
"""

import importlib.util
import json
import os
import re
import socket
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
DECOY = "DECOY_l0test_8c2e71"
SEAT0, SEAT1 = "127.0.0.2", "127.0.0.3"
TOKEN = "l0-test-token"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw(port: int, req: bytes, src: str = "127.0.0.1", timeout=10) -> bytes:
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    s.sendall(req)
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    return data


def strip_date(resp: bytes) -> bytes:
    return re.sub(rb"(?im)^date:[^\r\n]*\r\n", b"", resp)


def status(resp: bytes) -> int:
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return -1


def req(method: str, target: str, headers=(), body: bytes = b"", version="HTTP/1.1",
        close=True, host=True) -> bytes:
    lines = [f"{method} {target} {version}".encode()]
    if host:
        lines.append(b"Host: 185.199.108.153")
    lines += [h.encode() for h in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}".encode())
    if close:
        lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def start():
    """Collector subprocess + swarm exit server. Returns (exit module, exit
    port, collector port, collector process)."""
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    cport = free_port()
    env = dict(os.environ, GATEWAY_TOKEN=TOKEN, COLLECTOR_PORT=str(cport))
    proc = subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ.update(GATEWAY_TOKEN=TOKEN, COLLECTOR_PORT=str(cport),
                      COLLECTOR_URL=f"http://127.0.0.1:{cport}",
                      SWARM_SPOOL_DIR=tempfile.mkdtemp(prefix="swarm_l0_spool_"),
                      SWARM_CAL_SRC="127.0.0.9", SWARM_BG_CAL="0")
    probe = urllib.request.Request(f"http://127.0.0.1:{cport}/get-request-log",
                                   headers={"X-Gateway-Token": TOKEN})
    for _ in range(100):
        try:
            urllib.request.urlopen(probe, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    sys.path.insert(0, str(GW_DIR))
    spec = importlib.util.spec_from_file_location("swarm_exit_l0", EXIT_FILE)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    from werkzeug.serving import make_server
    eport = free_port()
    srv = make_server("127.0.0.1", eport, se.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return se, eport, cport, proc


def collector_log(cport):
    r = urllib.request.Request(f"http://127.0.0.1:{cport}/get-request-log",
                               headers={"X-Gateway-Token": TOKEN})
    return json.loads(urllib.request.urlopen(r, timeout=5).read())


def arm(eport, contained=()):
    body = json.dumps({"decoy_values": [DECOY], "feedback": "L0", "calibrate": False,
                       "seats": {"seat0": f"{SEAT0}/32", "seat1": f"{SEAT1}/32"},
                       "contained": list(contained)}).encode()
    return urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{eport}/__arm", data=body),
                                  timeout=10).status


def state(eport):
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{eport}/__swarm-state", timeout=5).read())


L0_VARIANTS = {
    "get": req("GET", "/get-request-log", ("User-Agent: curl/8.5.0", "Accept: */*")),
    "head": req("HEAD", "/get-request-log", ("User-Agent: curl/8.5.0", "Accept: */*")),
    "query": req("GET", "/get-request-log?since=0&token=abc", ("User-Agent: curl/8.5.0",)),
    "conditional": req("GET", "/get-request-log", ("If-None-Match: \"x\"", "If-Modified-Since: Sat, 01 Jan 2000 00:00:00 GMT")),
    "range": req("GET", "/get-request-log", ("Range: bytes=0-10",)),
    "gzip": req("GET", "/get-request-log", ("Accept-Encoding: gzip, deflate", "Accept: application/json")),
    "http10": req("GET", "/get-request-log", (), version="HTTP/1.0", host=False),
    "get_with_body": req("GET", "/get-request-log", ("Content-Type: application/json",), b'{"q": 1}'),
    "python_requests": req("GET", "/get-request-log", ("User-Agent: python-requests/2.32.3",
                                                        "Accept-Encoding: gzip, deflate", "Accept: */*",
                                                        "Connection: keep-alive"), close=False),
}

# (name, raw request). Sent with the token to a bare collector, and from a
# free seat through the exit.
F12_CASES = {
    "get": ("GET", "/get-request-log"),
    "head": ("HEAD", "/get-request-log"),
    "options": ("OPTIONS", "/get-request-log"),
    "post": ("POST", "/get-request-log"),
    "put": ("PUT", "/get-request-log"),
    "delete": ("DELETE", "/get-request-log"),
    "patch": ("PATCH", "/get-request-log"),
    "trailing_slash": ("GET", "/get-request-log/"),
    "upper_case": ("GET", "/GET-REQUEST-LOG"),
    "mixed_case": ("GET", "/Get-Request-Log"),
    "double_slash": ("GET", "//get-request-log"),
    "double_slash_post": ("POST", "//get-request-log"),
    "encoded_g": ("GET", "/%67et-request-log"),
    "encoded_dash": ("GET", "/get%2Drequest%2Dlog"),
    "dot_segment": ("GET", "/./get-request-log"),
    "dotdot": ("GET", "/x/../get-request-log"),
    "semicolon": ("GET", "/get-request-log;x=1"),
    "trailing_space_enc": ("GET", "/get-request-log%20"),
    "query_only": ("GET", "/get-request-log?"),
    "sub_path": ("GET", "/get-request-log/extra"),
    "prefix_path": ("GET", "/get-request-logs"),
}


def main() -> int:
    se, eport, cport, proc = start()
    results = []
    report = {"l0": {}, "f12": {}}
    try:
        # ---------- L0 reply equality
        before = {k: strip_date(raw(eport, v, SEAT0)) for k, v in L0_VARIANTS.items()}
        arm(eport)
        n_log = len(collector_log(cport))
        tripped = raw(eport, req("POST", "/trip", ("Content-Type: text/plain",), f"x {DECOY}".encode()), SEAT1)
        st = state(eport)
        results.append(("setup: seat1 contained by a decoy, seat0 free",
                        status(tripped) == 204 and st["contained"] == ["seat1"]))
        for name, r in L0_VARIANTS.items():
            free = strip_date(raw(eport, r, SEAT0))
            cont = strip_date(raw(eport, r, SEAT1))
            report["l0"][name] = {"status": status(free), "bytes": len(free),
                                  "identical": free == cont, "same_as_unarmed": free == before[name]}
            results.append((f"L0 {name}: byte-identical reply from free and contained seat, same as unarmed",
                            free == cont == before[name] and status(free) == 404))
        st = state(eport)
        ev = [(e["seat"], e["decision"], e["reason"]) for e in st["events"]
              if e["path"] == "/get-request-log" and e["seat"]]
        want = [(s, "log-closed", "L0") for _ in L0_VARIANTS for s in ("seat0", "seat1")]
        results.append(("L0: every armed read recorded once as an attributed log-closed event",
                        ev == want))
        results.append(("L0: no read reached the collector", len(collector_log(cport)) == n_log))
        ka = (L0_VARIANTS["python_requests"] + L0_VARIANTS["get"])
        two = {s: strip_date(raw(eport, ka, src)) for s, src in (("free", SEAT0), ("contained", SEAT1))}
        # The werkzeug dev server (exit and collector alike) closes the
        # connection after each reply, so only the first read is answered.
        results.append(("L0: two reads pipelined on one connection: identical replies (server closes after one)",
                        two["free"] == two["contained"] and two["free"].startswith(b"HTTP/1.1 404")))

        # ---------- F12 routing quirks
        for name, (method, target) in F12_CASES.items():
            n0 = len(collector_log(cport))
            bare = raw(cport, req(method, target, (f"X-Gateway-Token: {TOKEN}", "User-Agent: curl/8.5.0")))
            n1 = len(collector_log(cport))
            bare_logged = n1 > n0
            bare_body = bare.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in bare else b""
            log_handler = (status(bare) == 200 and not bare_logged and method in ("GET", "HEAD")
                           and (method == "HEAD" or bare_body.lstrip().startswith(b"[")))
            ex = raw(eport, req(method, target, ("User-Agent: curl/8.5.0",)), SEAT0)
            n2 = len(collector_log(cport))
            exit_logged = n2 > n1
            last = state(eport)["events"][-1] if state(eport)["events"] else {}
            if log_handler:
                ok = status(ex) == 404 and not exit_logged and last.get("decision") == "log-closed"
                expect = "L0 closed reply"
            else:
                ok = status(ex) == status(bare) and exit_logged == bare_logged
                expect = f"same as collector ({status(bare)}, {'logged' if bare_logged else 'not logged'})"
            report["f12"][name] = {"collector": [status(bare), bare_logged, log_handler],
                                   "exit": [status(ex), exit_logged, last.get("decision")],
                                   "expected": expect, "ok": ok}
            results.append((f"F12 {name} ({method} {target}): {expect}", ok))
        results.append(("F12: no forward errors", state(eport)["forward_errors"] == []))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    out = Path(os.environ.get("SWARM_L0_REPORT", tempfile.gettempdir() + "/swarm_l0_report.json"))
    out.write_text(json.dumps(report, indent=2))
    print("\n================ SWARM L0 + F12 (no Docker) ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"  report: {out}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
