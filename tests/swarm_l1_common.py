"""Shared helpers for the Stage 2 (L1) tests without Docker: the F1 request
kinds as byte-exact client requests, raw sockets, and an in-process swarm
exit. Not a test itself.

The kinds are the 28 Stage 0 kinds (tools/swarm_stage0_measure.py, SHAPES),
written as the bytes each client sends (curl 7.81, Python urllib, requests,
wget, a raw HTTP/1.0 socket). Every request carries "Connection: close" so the
test's socket ends; Connection is a hop header the exit never forwards, so
the forwarded request is unchanged by it. post_1m_expect is left out of the
no-Docker runs (Flask 3.1 on this VM refuses urlencoded bodies over 500 KB;
the exit image runs Flask 3.0) and runs in Docker only.
"""

import base64
import gzip
import importlib.util
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GW_DIR = REPO / "honeypot" / "gateway_server"
EXIT_FILE = REPO / "honeypot" / "swarm_gateway" / "swarm_exit.py"
HOST = "185.199.108.153"
CURL = [("Host", HOST), ("User-Agent", "curl/7.81.0"), ("Accept", "*/*")]

COMMON = ["get_plain", "get_query", "user_agent", "custom_headers", "post_octet", "post_text",
          "post_form", "post_raw_default_ct", "python_urllib", "wget_post", "post_json",
          "python_requests_json", "post_multipart"]
RARE = ["head", "options", "delete", "put", "patch", "post_empty", "post_1m_expect",
        "post_invalid_utf8", "post_unicode", "duplicate_headers", "chunked", "gzip_body",
        "query_and_body", "encoded_path", "raw_http10_no_host"]
ALL_KINDS = COMMON + RARE
DOCKER_ONLY = {"post_1m_expect"}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw(port: int, req: bytes, src: str = "127.0.0.1", timeout=20) -> bytes:
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


def status(resp: bytes) -> int:
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return -1


def body_of(resp: bytes) -> bytes:
    return resp.partition(b"\r\n\r\n")[2]


def _req(method, target, headers, body=b"", version="HTTP/1.1"):
    lines = [f"{method} {target} {version}"] + [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def payloads(seed: int = 7) -> dict:
    rng = random.Random(seed)
    b100 = base64.b64encode(rng.randbytes(75)).decode().encode()
    note = base64.b64encode(rng.randbytes(60)).decode().translate(str.maketrans("", "", "/+="))
    return {"b100": b100, "bjson": ('{"note":"%s"}' % note).encode(),
            "b1m": base64.b64encode(rng.randbytes(786432)).decode().encode(),
            "boundary": "------------------------" + rng.randbytes(8).hex()}


def kind_request(kind: str, tag: str, p: dict) -> bytes:
    """The bytes a client sends for one F1 kind; the path is
    /shape/<kind>/<tag> (the encoded path keeps its encoded segment)."""
    path = f"/shape/{kind}/{tag}"
    close = [("Connection", "close")]
    b100 = p["b100"]

    def curl_body(body, ct="application/x-www-form-urlencoded", ct_first=False, extra=(), method="POST",
                  target=path):
        h = list(CURL) + list(extra)
        h += ([("Content-Type", ct), ("Content-Length", str(len(body)))] if ct_first
              else [("Content-Length", str(len(body))), ("Content-Type", ct)])
        return _req(method, target, h + close, body)

    if kind in ("get_plain", "head", "options", "delete"):
        m = {"get_plain": "GET", "head": "HEAD", "options": "OPTIONS", "delete": "DELETE"}[kind]
        return _req(m, path, CURL + close)
    if kind == "get_query":
        return _req("GET", path + "?a=1&b=two", CURL + close)
    if kind == "user_agent":
        return _req("GET", path, [("Host", HOST), ("User-Agent", "Mozilla/5.0 (X11)"), ("Accept", "*/*")] + close)
    if kind == "custom_headers":
        return _req("GET", path, CURL + [("X-Exfil", "carried-in-header"), ("Authorization", "Bearer abc"),
                                         ("Cookie", "s=1")] + close)
    if kind == "duplicate_headers":
        return _req("GET", path, CURL + [("X-Dup", "1"), ("X-Dup", "2")] + close)
    if kind == "encoded_path":
        return _req("GET", f"/shape/encoded%20space%2Fslash/{tag}", CURL + close)
    if kind == "post_raw_default_ct":
        return curl_body(b100)
    if kind == "post_octet":
        return curl_body(b100, "application/octet-stream", ct_first=True)
    if kind == "post_text":
        return curl_body(b"hello text", "text/plain", ct_first=True)
    if kind == "post_form":
        return curl_body(b"a=1&b=two")
    if kind == "post_json":
        return curl_body(p["bjson"], "application/json", ct_first=True)
    if kind == "post_multipart":
        bd = p["boundary"]
        body = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b100\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + b100 + \
               (f"\r\n--{bd}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--{bd}--\r\n").encode()
        return _req("POST", path, CURL + [("Content-Length", str(len(body))),
                                          ("Content-Type", f"multipart/form-data; boundary={bd}")] + close, body)
    if kind == "post_empty":
        return _req("POST", path, CURL + close)
    if kind in ("put", "patch"):
        return curl_body(b100, method=kind.upper())
    if kind == "post_1m_expect":
        return curl_body(p["b1m"], extra=[("Expect", "100-continue")])
    if kind == "post_invalid_utf8":
        return curl_body(b"ok\xff\xfe\xfaend")
    if kind == "post_unicode":
        return curl_body("café \U0001F600".encode(), "text/plain; charset=utf-8", ct_first=True)
    if kind == "chunked":
        body = f"{len(b100):x}\r\n".encode() + b100 + b"\r\n0\r\n\r\n"
        return _req("POST", path, CURL + [("Transfer-Encoding", "chunked"),
                                          ("Content-Type", "application/x-www-form-urlencoded")] + close, body)
    if kind == "gzip_body":
        gz = gzip.compress(b"zipped body", mtime=0)
        return _req("POST", path, CURL + [("Content-Encoding", "gzip"), ("Content-Type", "application/octet-stream"),
                                          ("Content-Length", str(len(gz)))] + close, gz)
    if kind == "query_and_body":
        return curl_body(b"body", target=path + "?k=v")
    if kind == "python_urllib":
        body = b"from urllib"
        return _req("POST", path, [("Accept-Encoding", "identity"),
                                   ("Content-Type", "application/x-www-form-urlencoded"),
                                   ("Content-Length", str(len(body))), ("Host", HOST),
                                   ("User-Agent", "Python-urllib/3.10"), ("Connection", "close")], body)
    if kind == "python_requests_json":
        body = b'{"k": "v"}'
        return _req("POST", path, [("Host", HOST), ("User-Agent", "python-requests/2.34.2"),
                                   ("Accept-Encoding", "gzip, deflate"), ("Accept", "*/*"),
                                   ("Connection", "close"), ("Content-Length", str(len(body))),
                                   ("Content-Type", "application/json")], body)
    if kind == "wget_post":
        body = b"from=wget"
        return _req("POST", path, [("Host", HOST), ("User-Agent", "Wget/1.21.2"), ("Accept", "*/*"),
                                   ("Accept-Encoding", "identity"), ("Connection", "close"),
                                   ("Content-Type", "application/x-www-form-urlencoded"),
                                   ("Content-Length", str(len(body)))], body)
    if kind == "raw_http10_no_host":
        return _req("POST", path, [("Content-Length", "5")], b"hello", version="HTTP/1.0")
    raise KeyError(kind)


def wait_http(url: str, headers=None, tries=150):
    for _ in range(tries):
        try:
            urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=1)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    return False


def start_exit(collector_url: str, token: str, extra_env: dict | None = None, name: str = "swarm_exit_l1"):
    """The swarm exit as a real werkzeug server in this process. Returns
    (module, port)."""
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    os.environ.update(GATEWAY_TOKEN=token, COLLECTOR_URL=collector_url,
                      COLLECTOR_PORT=collector_url.rsplit(":", 1)[1],
                      SWARM_SPOOL_DIR=tempfile.mkdtemp(prefix="swarm_l1_spool_"),
                      SWARM_CAL_SRC="127.0.0.9", SWARM_BG_CAL="0",
                      SWARM_CAL_PORT=str(free_port()), SWARM_FORGER_CAL_PORT=str(free_port()),
                      **(extra_env or {}))
    sys.path.insert(0, str(GW_DIR))
    sys.path.insert(0, str(REPO))
    spec = importlib.util.spec_from_file_location(name, EXIT_FILE)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    from werkzeug.serving import make_server
    eport = free_port()
    srv = make_server("127.0.0.1", eport, se.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return se, eport


def start_collector(token: str):
    """The unchanged collector as a subprocess. Returns (port, process)."""
    cport = free_port()
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(cport))
    proc = subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_http(f"http://127.0.0.1:{cport}/get-request-log", {"X-Gateway-Token": token})
    return cport, proc


def arm(eport, decoy, seats: dict, contained=(), feedback="L1", **extra):
    import json
    body = json.dumps({"decoy_values": [decoy], "feedback": feedback, "calibrate": False,
                       "seats": {k: f"{v}/32" for k, v in seats.items()},
                       "contained": list(contained), **extra}).encode()
    r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{eport}/__arm", data=body),
                               timeout=120)
    return json.loads(r.read())


def read_log(eport, src):
    resp = raw(eport, f"GET /get-request-log HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: curl/7.81.0\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n".encode(), src=src)
    return resp
