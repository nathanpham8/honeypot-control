"""The swarm exit's own forward (step 3, Stage 1, fix 1), without Docker.

The swarm exit and the unchanged Experiment 3 gateway run as real werkzeug
servers in this process. Raw HTTP requests (one per request shape) are sent to
each, and both forward to a raw socket listener that records the exact bytes
it receives. Then:

  * every ordinary shape: the swarm exit's outgoing request is byte-identical
    to the Experiment 3 forward's;
  * every encoded-path shape (%20, %2F, %25, %3F, raw non-ASCII, ...): the
    swarm exit delivers (204) and its request line carries the client's raw
    target, with only bytes urllib cannot send percent-encoded. The Experiment
    3 outcome is recorded for comparison (it got 502 on %20 in Stage 0);
  * the same encoded shapes through the swarm exit to a real collector are
    logged with the path the exit itself saw.
No containers; nothing outside a temp directory is written.
"""

import importlib.util
import json
import os
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


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Listener:
    """Accepts connections one at a time; records each raw request; answers
    like the collector (204, text/html)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.got: list[bytes] = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            conn, _ = self.sock.accept()
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                n = 0
                for line in head.split(b"\r\n")[1:]:
                    k, _, v = line.partition(b":")
                    if k.strip().lower() == b"content-length":
                        n = int(v.strip())
                while len(rest) < n:
                    chunk = conn.recv(1 << 20)
                    if not chunk:
                        break
                    rest += chunk
                self.got.append(head + b"\r\n\r\n" + rest)
                conn.sendall(b"HTTP/1.1 204 NO CONTENT\r\nContent-Type: text/html; charset=utf-8\r\n"
                             b"Connection: close\r\n\r\n")


def _serve(app, port):
    from werkzeug.serving import make_server
    srv = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _raw(port: int, req: bytes, timeout=20) -> int:
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.sendall(req)
    data = b""
    while b"\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    try:
        return int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return -1


def _req(method: str, target: str | bytes, headers=(), body: bytes = b"", version="HTTP/1.1",
         host=True) -> bytes:
    t = target if isinstance(target, bytes) else target.encode()
    lines = [method.encode() + b" " + t + b" " + version.encode()]
    if host:
        lines.append(b"Host: 185.199.108.153")
    lines += [h.encode() if isinstance(h, str) else h for h in headers]
    if body and not any(str(h).lower().startswith("transfer-encoding") for h in headers):
        lines.append(f"Content-Length: {len(body)}".encode())
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


UA = ("User-Agent: curl/8.5.0", "Accept: */*")
B100 = b"x" * 100
ORDINARY = {
    "get_plain": _req("GET", "/shape/get_plain", UA),
    "get_query": _req("GET", "/shape/get_query?a=1&b=two", UA),
    "head": _req("HEAD", "/shape/head", UA),
    "options": _req("OPTIONS", "/shape/options", UA),
    "delete": _req("DELETE", "/shape/delete", UA),
    "post_default_ct": _req("POST", "/shape/post", UA + ("Content-Type: application/x-www-form-urlencoded",), B100),
    "post_no_ct": _req("POST", "/shape/post_no_ct", UA, B100),
    "post_octet": _req("POST", "/shape/octet", UA + ("Content-Type: application/octet-stream",), B100),
    "post_form": _req("POST", "/shape/form", UA + ("Content-Type: application/x-www-form-urlencoded",), b"a=1&b=two"),
    "post_json": _req("POST", "/shape/json", UA + ("Content-Type: application/json",), b'{"k": "v"}'),
    "post_multipart": _req("POST", "/shape/multipart", UA + ("Content-Type: multipart/form-data; boundary=XyZ",),
                           b'--XyZ\r\nContent-Disposition: form-data; name="file"; filename="b"\r\n'
                           b"Content-Type: application/octet-stream\r\n\r\n" + B100 +
                           b'\r\n--XyZ\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n--XyZ--\r\n'),
    "post_empty": _req("POST", "/shape/empty", UA + ("Content-Length: 0",)),
    "put": _req("PUT", "/shape/put", UA, B100),
    "patch": _req("PATCH", "/shape/patch", UA, B100),
    "invalid_utf8": _req("POST", "/shape/bad", UA, b"ok\xff\xfe\xfaend"),
    "unicode_body": _req("POST", "/shape/uni", UA + ("Content-Type: text/plain; charset=utf-8",),
                         "café 😀".encode()),
    "custom_headers": _req("GET", "/shape/custom", UA + ("X-Exfil: carried", "Authorization: Bearer abc", "Cookie: s=1")),
    "duplicate_headers": _req("GET", "/shape/dup", UA + ("X-Dup: 1", "X-Dup: 2")),
    "chunked": _req("POST", "/shape/chunked", UA + ("Transfer-Encoding: chunked",), b"64\r\n" + B100 + b"\r\n0\r\n\r\n"),
    "keep_alive_ua": _req("GET", "/shape/ua", ("User-Agent: python-requests/2.32", "Accept-Encoding: gzip, deflate",
                                               "Accept: */*", "Connection: keep-alive")),
    "query_and_body": _req("POST", "/shape/qb?k=v", UA, b"body"),
    "http10_no_host": _req("POST", "/shape/http10", ("Content-Length: 5",), b"hello", version="HTTP/1.0", host=False),
    "body_1m": _req("POST", "/shape/1m", UA + ("Content-Type: application/x-www-form-urlencoded",), b"Q" * (1 << 20)),
}
# target as sent -> target the forward must carry (only unsendable bytes encoded)
ENCODED = {
    "space_and_slash": ("/shape/encoded%20space%2Fslash", "/shape/encoded%20space%2Fslash"),
    "lower_hex": ("/shape/a%2fb%20c", "/shape/a%2fb%20c"),
    "percent_25": ("/shape/100%25done", "/shape/100%25done"),
    "question_3F": ("/shape/what%3Fnot-a-query", "/shape/what%3Fnot-a-query"),
    "plus_and_amp": ("/shape/a+b%26c?x=1%202&y=%2F", "/shape/a+b%26c?x=1%202&y=%2F"),
    # Raw non-ASCII bytes: werkzeug's dev server decodes the request line as
    # latin-1, so the exit (like a stock logging server) sees "/shape/cafÃ©".
    # The forward passes that string on, so the collector logs the same path
    # (checked against a real collector below).
    "raw_utf8": (b"/shape/caf\xc3\xa9", "/shape/caf%C3%83%C2%A9"),
    "encoded_utf8": ("/shape/caf%C3%A9", "/shape/caf%C3%A9"),
    "null_byte": ("/shape/nul%00x", "/shape/nul%00x"),
    "double_slash_inside": ("/shape//two", "/shape//two"),
    "trailing_qmark": ("/shape/q?", "/shape/q?"),
    "space_in_query": ("/shape/q?a=%20b", "/shape/q?a=%20b"),
}


def _first_line(b: bytes) -> bytes:
    return b.split(b"\r\n", 1)[0]


def main() -> int:
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    os.environ["SWARM_SPOOL_DIR"] = tempfile.mkdtemp(prefix="swarm_fwd_spool_")
    token = "fwd-test-token"
    os.environ["GATEWAY_TOKEN"] = token
    sys.path.insert(0, str(GW_DIR))
    spec = importlib.util.spec_from_file_location("swarm_exit_fwd", EXIT_FILE)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    exp3 = se.exp3
    lis = Listener()
    exp3.COLLECTOR_URL = f"http://127.0.0.1:{lis.port}"
    p_exit, p_exp3 = _free_port(), _free_port()
    _serve(se.app, p_exit)
    _serve(exp3.app, p_exp3)
    time.sleep(0.3)
    arm = json.dumps({"decoy_values": ["DECOY_never_sent_fwdtest"], "seats": {"seat0": "127.0.0.0/8"},
                      "feedback": "L0", "calibrate": False}).encode()
    urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{p_exit}/__arm", data=arm), timeout=10)

    results = []
    report = {"ordinary": {}, "encoded": {}}

    def send(port, req):
        n = len(lis.got)
        status = _raw(port, req)
        deadline = time.time() + 5
        while len(lis.got) == n and time.time() < deadline and status not in (-1, 502):
            time.sleep(0.01)
        return status, (lis.got[n] if len(lis.got) > n else None)

    for name, req in ORDINARY.items():
        s_exit, b_exit = send(p_exit, req)
        s_exp3, b_exp3 = send(p_exp3, req)
        same = b_exit is not None and b_exit == b_exp3
        report["ordinary"][name] = {"exit_status": s_exit, "exp3_status": s_exp3, "bytes_identical": same}
        results.append((f"ordinary {name}: delivered; outgoing bytes identical to the Experiment 3 forward",
                        s_exit == s_exp3 == 204 and same))

    for name, (sent, want) in ENCODED.items():
        req = _req("GET", sent, UA)
        s_exit, b_exit = send(p_exit, req)
        s_exp3, b_exp3 = send(p_exp3, req)
        line = _first_line(b_exit) if b_exit else b""
        ok = s_exit == 204 and line == f"GET {want} HTTP/1.1".encode()
        report["encoded"][name] = {"exit_status": s_exit, "exit_request_line": line.decode("latin-1"),
                                   "exp3_status": s_exp3,
                                   "exp3_request_line": _first_line(b_exp3).decode("latin-1") if b_exp3 else None}
        results.append((f"encoded {name}: delivered with the client's raw target", ok))

    # The same encoded shapes through the swarm exit to a real collector.
    cport = _free_port()
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(cport))
    proc = subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        exp3.COLLECTOR_URL = f"http://127.0.0.1:{cport}"
        probe = urllib.request.Request(f"{exp3.COLLECTOR_URL}/get-request-log", headers={"X-Gateway-Token": token})
        for _ in range(100):
            try:
                urllib.request.urlopen(probe, timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        se.reset()
        exp3.STATE["forward_errors"].clear()   # the Experiment 3 comparison's own 502s
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{p_exit}/__arm", data=arm), timeout=10)
        statuses = {name: _raw(p_exit, _req("GET", sent, UA)) for name, (sent, _) in ENCODED.items()}
        log = json.loads(urllib.request.urlopen(probe, timeout=5).read())
        from honeypot.swarm_gateway.ctl import full_state
        state = full_state(lambda path: json.loads(
            urllib.request.urlopen(f"http://127.0.0.1:{p_exit}{path}", timeout=5).read()))
        exit_paths = [e["path"] for e in state["forwarded"]]
        col_paths = [e["path"] for e in log]
        report["real_collector"] = {"statuses": statuses, "exit_paths": exit_paths, "collector_paths": col_paths}
        results.append(("real collector: every encoded shape delivered and logged",
                        all(s == 204 for s in statuses.values()) and len(log) == len(ENCODED)))
        results.append(("real collector: logged path equals the path the exit saw, for every shape",
                        exit_paths == col_paths))
        results.append(("real collector: no forward errors", state["forward_errors"] == []))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    exp3_502 = sorted(n for n, r in report["encoded"].items() if r["exp3_status"] != 204)
    report["exp3_failures_for_comparison"] = exp3_502
    out = Path(os.environ.get("SWARM_FWD_REPORT", tempfile.gettempdir() + "/swarm_forward_report.json"))
    out.write_text(json.dumps(report, indent=2))
    print("\n================ SWARM EXIT FORWARD (no Docker) ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"  (for comparison, Experiment 3 forward did not deliver: {exp3_502 or 'none'})")
    print(f"  report: {out}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
