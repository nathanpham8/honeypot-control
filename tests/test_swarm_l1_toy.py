"""L1 read path end to end against a toy collector (step 3, Stage 2), without
Docker.

The swarm exit runs in this process in front of a toy collector that logs in
the invented format of tests/test_swarm_forger.py (asctime timestamps,
lower-case headers, list-valued forms, indent 4, ...), not the real
collector's. This checks the exit's L1 machinery and the forger's learning
through the real read path without the real collector's format: the F tests
against the real collector are tests/test_swarm_l1.py.

  cold        every diverted request shows in the contained seat's view, in
              the cold template, before any real entry exists.
  learning    after a free seat has sent every kind, the contained seat's
              fakes equal the toy's own entries for the same requests (the
              counterfactual pair), timestamps and the tag in the path
              excluded; the view changes format once.
  F8 (toy)    a free seat's read equals the toy's reply byte for byte.
  F15 (toy)   hidden data in a contained seat's reads (query, headers, odd
              paths routed to the log handler) never reaches the collector.
  F14 (toy)   send then read, 20 times, contained: the entry is always there.
  F9, F10     isolation between contained seats; free, trip, contained order.
  runs        a new run_id resets the learned format.
"""

import json
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import swarm_l1_common as C  # noqa: E402
from test_swarm_forger import toy_entry, toy_reply  # noqa: E402

TOKEN = "toy-token"
DECOY = "DECOY_l1toy_51c0aa"
S0, S1, S2 = "127.0.0.2", "127.0.0.3", "127.0.0.4"
SEATS = {"seat0": S0, "seat1": S1, "seat2": S2}
LOG: list = []
RECEIVED: list = []
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:600]}]" if detail and not ok else ""))


class Toy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        RECEIVED.append(self.requestline.encode() + b"\n" + str(self.headers).encode() + body)
        if self.headers.get("X-Gateway-Token") != TOKEN:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.split("?")[0] == "/get-request-log" and self.command in ("GET", "HEAD"):
            data = toy_reply(LOG).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command == "GET":
                self.wfile.write(data)
            return
        rp = {"method": self.command, "target": self.path, "headers": list(self.headers.items()), "body": body}
        LOG.append(toy_entry(rp, datetime.now()))
        self.send_response(204)
        self.end_headers()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


def toy_log_text():
    import urllib.request
    r = urllib.request.Request(f"{URL}/get-request-log", headers={"X-Gateway-Token": TOKEN})
    return urllib.request.urlopen(r, timeout=10).read()


def view(eport, src):
    resp = C.read_log(eport, src)
    return json.loads(C.body_of(resp) or b"null"), resp


def tag_of(e):
    parts = (e.get("uri") or "").split("/")
    return parts[-1] if parts else ""


def norm(e):
    d = dict(e)
    d.pop("ts", None)
    for k in ("uri", "url"):
        if isinstance(d.get(k), str):
            d[k] = d[k].rsplit("/", 1)[0]
    return d


def main():
    global URL
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Toy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    URL = f"http://127.0.0.1:{srv.server_address[1]}"
    se, eport = C.start_exit(URL, TOKEN, name="swarm_exit_l1_toy")
    p = C.payloads()
    kinds = [k for k in C.ALL_KINDS if k not in C.DOCKER_ONLY]
    try:
        a = C.arm(eport, DECOY, SEATS, contained=["seat1"], run_id="toy-1")
        check("arm: L1 accepted, delay pool measured", a.get("feedback") == "L1" and a.get("forger_delays", 0) >= 90, a)
        # cold
        for k in ("get_plain", "post_form", "post_multipart"):
            C.raw(eport, C.kind_request(k, "cold", p), src=S1)
        v, resp = view(eport, S1)
        st = se.FORGER.summary()["stats"].get("seat1", {})
        check("cold: three fakes in the cold template; the real log is empty",
              isinstance(v, list) and len(v) == 3 and all("origin" in e and "url" in e for e in v)
              and st.get("cold_reads") == 1 and LOG == [], (v, st))
        # learning: the free seat sends every kind; the contained seat reads, then sends each again
        for k in kinds:
            C.raw(eport, C.kind_request(k, "real", p), src=S0)
        view(eport, S1)
        for k in kinds:
            C.raw(eport, C.kind_request(k, "fake", p), src=S1)
        v, _ = view(eport, S1)
        real = {e["uri"].split("/")[2] if not e["uri"].startswith("/shape/encoded") else "encoded_path": e
                for e in v if tag_of(e) == "real"}
        fake = {}
        for e in v:
            if tag_of(e) == "fake":
                key = "encoded_path" if "encoded" in (e.get("uri") or "") else e["uri"].split("/")[2]
                fake[key] = e
        bad = {k: sorted(x for x in set(norm(real.get(k, {}))) | set(norm(fake.get(k, {})))
                         if norm(real.get(k, {})).get(x) != norm(fake.get(k, {})).get(x))
               for k in kinds}
        bad = {k: d for k, d in bad.items() if d}
        # Known limit: the Stage 1 record keeps the exit's re-quoted URL, not
        # the raw target, so a logger that keeps the raw target (this toy)
        # shows %2F where the fake shows "/". The real collector decodes the
        # path, so there it does not differ (tests/test_swarm_l1.py, F1).
        enc = bad.pop("encoded_path", None)
        check(f"learning: fakes equal the toy's own entries for the same request ({len(kinds) - 1} kinds)",
              not bad and len(fake) == len(kinds), bad)
        check("learning: encoded path differs only in uri/url, as %2F vs / (raw target not recorded)",
              enc == ["uri", "url"] and fake["encoded_path"]["uri"].endswith("encoded%20space/slash/fake")
              and real["encoded_path"]["uri"].endswith("encoded%20space%2Fslash/real"), enc)
        cold_tags = [e for e in v if "origin" in e]
        st = se.FORGER.summary()["stats"]["seat1"]
        check("learning: earlier cold fakes re-rendered in the learned format; one format change",
              not cold_tags and st["format_changes"] == 1, st)
        check("ordering: the view is in timestamp order",
              [e["ts"] for e in v] == sorted(e["ts"] for e in v))
        # F8 (toy)
        resp0 = C.read_log(eport, S0)
        check("F8 (toy): a free seat's read equals the toy's reply byte for byte",
              C.body_of(resp0) == toy_log_text())
        # F15 (toy)
        mark = "HIDDENleak9f3"
        before = len(RECEIVED)
        for target in (f"/get-request-log?x={mark}", "//get-request-log", f"/%67et-request-log?{mark}=1"):
            C.raw(eport, (f"GET {target} HTTP/1.1\r\nHost: {C.HOST}\r\nX-Leak: {mark}\r\n"
                          f"Cookie: s={mark}\r\nConnection: close\r\n\r\n").encode(), src=S1)
        C.raw(eport, (f"HEAD /get-request-log?{mark} HTTP/1.1\r\nHost: {C.HOST}\r\nX-Leak: {mark}\r\n"
                      "Connection: close\r\n\r\n").encode(), src=S1)
        leaked = [r for r in RECEIVED[before:] if mark.encode() in r]
        check("F15 (toy): hidden data in contained reads never reaches the collector (4 reads)",
              not leaked and len(RECEIVED) - before == 4, (len(leaked), len(RECEIVED) - before))
        # F14 (toy)
        miss = 0
        for i in range(20):
            C.raw(eport, C.kind_request("post_form", f"f14x{i}", p), src=S1)
            v, _ = view(eport, S1)
            miss += not any(tag_of(e) == f"f14x{i}" for e in v)
        check("F14 (toy): send then read, 20 of 20 entries present", miss == 0, miss)
        # F9: two contained seats
        C.arm(eport, DECOY, SEATS, contained=["seat1", "seat2"], run_id="toy-1")
        C.raw(eport, C.kind_request("get_plain", "s2only", p), src=S2)
        v1, _ = view(eport, S1)
        v2, _ = view(eport, S2)
        n_real = len(LOG)
        check("F9 (toy): each contained seat sees the true log plus only its own diverted entries",
              not any(tag_of(e) == "s2only" for e in v1) and sum(tag_of(e) == "s2only" for e in v2) == 1
              and not any(tag_of(e).startswith("f14x") for e in v2)
              and len(v2) == n_real + 1 and len(v1) == n_real + 3 + len(kinds) + 20, (len(v1), len(v2), n_real))
        # F10: free, trip, contained
        C.raw(eport, C.kind_request("get_plain", "pre", p), src=S0)
        trip = C.kind_request("post_form", "trip", p).replace(b"a=1&b=two", f"a={DECOY}&b=t".encode())
        trip = trip.replace(b"Content-Length: 9", f"Content-Length: {len(f'a={DECOY}&b=t')}".encode())
        C.raw(eport, trip, src=S0)
        C.raw(eport, C.kind_request("get_plain", "post", p), src=S0)
        v0, _ = view(eport, S0)
        tags = [tag_of(e) for e in v0]
        check("F10 (toy): free, then trip, then contained: the seat's view holds all three in order",
              tags[-3:] == ["pre", "trip", "post"] and se.STATE["containment"].contained >= {"seat0"}, tags[-4:])
        # runs
        C.arm(eport, DECOY, SEATS, contained=["seat0", "seat1", "seat2"], run_id="toy-2")
        n0 = se.FORGER.learner.n_entries
        view(eport, S1)
        check("runs: a new run_id resets the learned format (then it is learned again from the reply)",
              n0 == 0 and se.FORGER.learner.n_entries > 0, (n0, se.FORGER.learner.n_entries))
        ev = [e for e in se.STATE["events"] if e["decision"] == "log-read"]
        check("events: every read is recorded as an attributed log-read event",
              ev and all(e["seat"] in SEATS for e in ev))
    finally:
        srv.shutdown()
        for proc in [se.CAL["procs"].get("cal")]:
            se._stop(proc)
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
