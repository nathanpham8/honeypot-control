"""L1 forging tests against the real collector (step 3, Stage 2), without
Docker.

The swarm exit runs in this process (answer-key option on) in front of the
unchanged collector as a subprocess; each seat has a shadow collector (the
answer key). Seats are loopback sources 127.0.0.2 to 127.0.0.4. Requests are
the F1 kinds as byte-exact client requests (tests/swarm_l1_common.py).
Design and pass lines: docs/swarm-pilot/step3-plan.md, "Stage 1 final
review: rules and design for Stage 2".

  F2   answer-key forwards and the forger's reconstructed forwards vs real
       forwards, as raw bytes at a socket listener
  F13  (i) every seat contained from the start; (ii) three cold reads, then
       a free seat's first delivery
  F1   cold, partial (only get_plain and post_form seen) and warm phases;
       each fake vs the answer key, field by field (timestamps excluded;
       the no-Host Host value normalized, rule 9). Pass line: zero warm
       mismatches on every kind
  F3, F4, F5, F7   timestamps (offset from exit arrival, format), order and
       ties, JSON body with timestamp placeholders, on the warm view
  F8   free reads byte-identical to the collector's reply (hard pass)
  F9, F10, F11, F12, F14, F15, F6   as in the plan (F9, F10, F14, F15 hard)

Set SWARM_L1_REPORT to write the full report (JSON) to that path; nothing
else is written outside temp directories.
"""

import json
import os
import random
import re
import socket
import statistics
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import swarm_l1_common as C  # noqa: E402

TOKEN = "l1-test-token"
DECOY = "DECOY_l1test_77e1b2"
S0, S1, S2 = "127.0.0.2", "127.0.0.3", "127.0.0.4"
SEATS = {"seat0": S0, "seat1": S1, "seat2": S2}
SRC = {v: k for k, v in SEATS.items()}
KINDS = [k for k in C.ALL_KINDS if k not in C.DOCKER_ONLY]
ISO = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?\Z")
RESULTS = []
REPORT: dict = {}


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:800]}]" if detail and not ok else ""),
          flush=True)


def ak_base() -> int:
    rng = random.Random()
    for _ in range(200):
        base = rng.randint(20000, 40000)
        ok = True
        for i in range(3):
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", base + i))
            except OSError:
                ok = False
            finally:
                s.close()
        if ok:
            return base
    raise RuntimeError("no free port range")


# ---------------------------------------------------------------- helpers

class Ctx:
    se = None
    eport = 0
    cport = 0
    p = None


def clog_bytes() -> bytes:
    r = urllib.request.Request(f"http://127.0.0.1:{Ctx.cport}/get-request-log", headers={"X-Gateway-Token": TOKEN})
    return urllib.request.urlopen(r, timeout=60).read()


def clog():
    return json.loads(clog_bytes())


def answer_key(seat):
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{Ctx.eport}/__answer-key?seat={seat}",
                                             timeout=60).read())


def send(kind, tag, src, p=None):
    return C.status(C.raw(Ctx.eport, C.kind_request(kind, tag, p or Ctx.p), src=src))


def view(src):
    resp = C.read_log(Ctx.eport, src)
    return json.loads(C.body_of(resp) or b"null"), resp


def kind_tag(e):
    pth = e.get("path")
    if not isinstance(pth, str):
        # Cold-template entries have no path field: take it from the URL.
        from urllib.parse import unquote, urlsplit
        pth = unquote(urlsplit(e.get("url") or "").path) if isinstance(e.get("url"), str) else ""
    parts = pth.split("/")
    if pth.startswith("/shape/encoded"):
        return "encoded_path", parts[-1]
    if len(parts) >= 4 and parts[1] == "shape":
        return parts[2], parts[3]
    return None, None


def normalize_key(e: dict, shadow_port: int) -> dict:
    """Rule 9: the no-Host HTTP/1.0 request's Host is the receiving
    collector's own loopback address, which differs between the shadow and
    the real collector."""
    d = json.loads(json.dumps(e))
    a, b = f"127.0.0.1:{shadow_port}", f"127.0.0.1:{Ctx.cport}"
    if isinstance(d.get("headers"), dict) and d["headers"].get("Host") == a:
        d["headers"]["Host"] = b
    if isinstance(d.get("full_url"), str) and f"//{a}/" in d["full_url"]:
        d["full_url"] = d["full_url"].replace(f"//{a}/", f"//{b}/")
    return d


def field_diff(fake: dict, key: dict) -> list:
    out = []
    if [k for k in fake if k != "timestamp"] != [k for k in key if k != "timestamp"]:
        out.append("(key order or set)")
    for k in list(dict.fromkeys(list(key) + list(fake))):
        if k == "timestamp":
            continue
        if k not in fake or k not in key or json.dumps(fake[k]) != json.dumps(key[k]):
            out.append(k)
    return out


def compare(seat: str, view_entries: list, tags: set) -> dict:
    """Each fake in the view whose tag is in `tags` vs the seat's answer-key
    entry for the same request. Returns {kind: [differing fields]}, plus
    counts."""
    port = Ctx.se.AK["shadows"][seat]["port"]
    key = {}
    for e in answer_key(seat):
        k, t = kind_tag(e)
        if t in tags:
            key[(k, t)] = e
    res, fields_total, fields_bad, norm = {}, 0, 0, 0
    seen = set()
    for e in view_entries:
        k, t = kind_tag(e)
        if t not in tags or (k, t) not in key:
            continue
        seen.add((k, t))
        ref = normalize_key(key[(k, t)], port)
        norm += ref != key[(k, t)]
        d = field_diff(e, ref)
        nf = len([x for x in ref if x != "timestamp"])
        fields_total += nf
        fields_bad += min(len(d), nf)
        res[k] = d
    missing = sorted(set(key) - seen)
    return {"by_kind": res, "fields_total": fields_total, "fields_mismatched": fields_bad,
            "kinds_with_mismatch": sorted(k for k, d in res.items() if d), "missing": missing,
            "host_normalized": norm}


def q(xs, f):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(f * len(xs)))] if xs else None


def dist(xs):
    return {"n": len(xs), "median": q(xs, 0.5), "p10": q(xs, 0.1), "p90": q(xs, 0.9),
            "min": min(xs) if xs else None, "max": max(xs) if xs else None}


class Listener:
    """Raw HTTP listener: records each request's bytes, answers 204."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.got = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(65536)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            n = next((int(x.split(b":")[1]) for x in head.split(b"\r\n")
                      if x.lower().startswith(b"content-length:")), 0)
            while len(rest) < n:
                chunk = c.recv(65536)
                if not chunk:
                    break
                rest += chunk
            self.got.append(head + b"\r\n\r\n" + rest)
            c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            c.close()


class Proxy:
    """TCP relay in front of the collector that records client bytes."""

    def __init__(self, target_port):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.target = target_port
        self.got = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.pipe, args=(c,), daemon=True).start()

    def pipe(self, c):
        up = socket.create_connection(("127.0.0.1", self.target))
        rec = bytearray()
        self.got.append(rec)

        def down():
            while True:
                d = up.recv(65536)
                if not d:
                    break
                c.sendall(d)
            c.close()
        threading.Thread(target=down, daemon=True).start()
        while True:
            d = c.recv(65536)
            if not d:
                break
            rec += d
            up.sendall(d)
        up.shutdown(socket.SHUT_WR)


def strip_hdr(resp: bytes, names=(b"date",)):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = [ln for ln in head.split(b"\r\n") if ln.split(b":")[0].strip().lower() not in names]
    return lines, body


# ---------------------------------------------------------------- parts

def part_f2():
    se, ex = Ctx.se, Ctx.se.exp3
    lst = Listener()
    saved = ex.COLLECTOR_URL
    ex.COLLECTOR_URL = f"http://127.0.0.1:{lst.port}"
    se.AK["shadows"]["seat1"] = {"port": lst.port, "token": ex.TOKEN, "proc": None}
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f2")
    res = {}
    try:
        for k in KINDS:
            n0 = len(lst.got)
            send(k, "f2", S0)
            send(k, "f2", S1)
            if len(lst.got) != n0 + 2:
                res[k] = {"error": f"listener got {len(lst.got) - n0}"}
                continue
            real, keyed = lst.got[n0], lst.got[n0 + 1]
            rec = se.STATE["sink"]["seat1"][-1]
            wire, _, _ = se._forwarded_wire(rec)
            res[k] = {"answer_key_equal": keyed == real, "forger_equal": wire == real}
            if wire != real:
                rl, wl = real.split(b"\r\n", 1)[0], wire.split(b"\r\n", 1)[0]
                res[k]["forger_request_line"] = [rl.decode("latin-1"), wl.decode("latin-1")]
                res[k]["forger_rest_equal"] = real.split(b"\r\n", 1)[1] == wire.split(b"\r\n", 1)[1]
    finally:
        ex.COLLECTOR_URL = saved
        se.AK["shadows"].pop("seat1", None)
        lst.srv.close()
    REPORT["f2"] = res
    check("F2: answer-key forwards are byte-identical to real forwards (every kind)",
          all(r.get("answer_key_equal") for r in res.values()), {k: r for k, r in res.items() if not r.get("answer_key_equal")})
    bad = {k: r for k, r in res.items() if not r.get("forger_equal")}
    REPORT["f2_forger_differs"] = sorted(bad)
    print(f"INFO  F2b: forger's reconstructed forward differs from the real forward for: {sorted(bad) or 'none'}")
    for k, r in bad.items():
        print(f"INFO        {k}: request line {r.get('forger_request_line')}, rest equal {r.get('forger_rest_equal')}")


def part_f13_all_contained():
    se = Ctx.se
    se.reset()
    C.arm(Ctx.eport, DECOY, SEATS, contained=list(SEATS), run_id="f13i")
    tags = {"a"}
    for k in Ctx.common5:
        send(k, "a", S1)
    views = [view(S1)[0] for _ in range(3)]
    for k in ("get_plain", "post_form"):
        send(k, "a", S2)
    v2 = view(S2)[0]
    st = se.FORGER.summary()["stats"]
    cmp1 = compare("seat1", views[-1], tags)
    cmp2 = compare("seat2", v2, tags)
    REPORT["f13_i"] = {"stats": st, "seat1": cmp1, "seat2": cmp2, "real_log_entries": len(clog())}
    total = cmp1["fields_total"] + cmp2["fields_total"]
    bad = cmp1["fields_mismatched"] + cmp2["fields_mismatched"]
    print(f"INFO  F13 (i) all contained: cold reads {st['seat1']['cold_reads'] + st['seat2']['cold_reads']}, "
          f"field mismatch {bad}/{total}, format changes {st['seat1']['format_changes'] + st['seat2']['format_changes']}")
    check("F13 (i): every read cold, the real log stays empty, views stable across reads",
          len(clog()) == 0 and st["seat1"]["cold_reads"] == 3 and views[0] == views[1] == views[2])


def part_f1():
    se = Ctx.se
    se.reset()
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f1")
    out = {}
    # cold
    for k in KINDS:
        send(k, "c", S1)
    cold_views = [view(S1)[0] for _ in range(3)]
    out["cold"] = compare("seat1", cold_views[0], {"c"})
    # partial: the free seat's first deliveries, after three cold reads (F13 ii)
    for k in ("get_plain", "post_form"):
        send(k, "p", S0)
    pv0 = view(S1)[0]
    out["after_first_delivery_c"] = compare("seat1", pv0, {"c"})
    for k in KINDS:
        send(k, "q", S1)
    pv = view(S1)[0]
    out["partial"] = compare("seat1", pv, {"q"})
    # warm
    for k in KINDS:
        send(k, "r", S0)
    view(S1)
    for k in KINDS:
        send(k, "w", S1)
    wv, wresp = view(S1)
    out["warm"] = compare("seat1", wv, {"w"})
    out["warm_rerender_c_q"] = compare("seat1", wv, {"c", "q"})
    st = se.FORGER.summary()
    out["forger"] = {"stats": st["stats"].get("seat1"), "format": st["format"], "learner": st["learner"]}
    REPORT["f1"] = out
    for ph in ("cold", "partial", "warm"):
        c = out[ph]
        print(f"INFO  F1 {ph}: field mismatches {c['fields_mismatched']}/{c['fields_total']}; "
              f"kinds with a mismatch {len(c['kinds_with_mismatch'])}/{len(c['by_kind'])}: {c['kinds_with_mismatch']}")
        for k in c["kinds_with_mismatch"]:
            if ph != "cold":
                print(f"INFO        {k}: {c['by_kind'][k]}")
    s1 = out["forger"]["stats"]
    print(f"INFO  F13 (ii): cold reads {s1['cold_reads']}, format changes {s1['format_changes']}, "
          f"cold mismatch {out['cold']['fields_mismatched']}/{out['cold']['fields_total']}")
    check("F1 warm: zero field mismatches on every kind (rule 6a)",
          not out["warm"]["kinds_with_mismatch"] and not out["warm"]["missing"]
          and len(out["warm"]["by_kind"]) == len(KINDS), out["warm"]["kinds_with_mismatch"])
    check("F1: every diverted request appears exactly once in the contained seat's view",
          sorted(kind_tag(e) for e in wv if kind_tag(e)[1] in {"c", "q", "w"})
          == sorted((k, t) for t in ("c", "q", "w") for k in KINDS))
    # F8 after the phases
    v0 = C.read_log(Ctx.eport, S0)
    check("F8: a free seat's read is byte-identical to the collector's reply", C.body_of(v0) == clog_bytes())
    return wv


def part_f3_f7(wv):
    se = Ctx.se
    port = se.AK["shadows"]["seat1"]["port"]
    real = clog()
    key_all = [normalize_key(e, port) for e in answer_key("seat1") if kind_tag(e)[1] in {"c", "q", "w"}]
    arrival = {}
    for rec in se.STATE["sink"]["seat1"]:
        arrival[kind_tag(rec)] = rec["timestamp"]
    from datetime import datetime as D
    fake_off, key_off, ties = [], [], 0
    keyts = {kind_tag(e): e["timestamp"] for e in key_all}
    fmt_ok = True
    for e in wv:
        kt = kind_tag(e)
        if kt[1] in {"c", "q", "w"} and kt in arrival:
            a = D.fromisoformat(arrival[kt])
            fake_off.append((D.fromisoformat(e["timestamp"]) - a).total_seconds() * 1000)
            key_off.append((D.fromisoformat(keyts[kt]) - a).total_seconds() * 1000)
            fmt_ok &= bool(ISO.match(e["timestamp"]))
    fwd = {kind_tag(r): r["timestamp"] for r in se.STATE["forwarded"]}
    deliv = [(D.fromisoformat(e["timestamp"]) - D.fromisoformat(fwd[kind_tag(e)])).total_seconds() * 1000
             for e in real if kind_tag(e) in fwd]
    ts_seq = [e["timestamp"] for e in wv]
    inversions_view = sum(1 for a, b in zip(ts_seq, ts_seq[1:]) if b < a)
    ties = sum(1 for a, b in zip(ts_seq, ts_seq[1:]) if a == b)
    REPORT["f3"] = {"fake_minus_arrival_ms": dist(fake_off), "answer_key_minus_arrival_ms": dist(key_off),
                    "delivered_collector_minus_arrival_ms": dist(deliv)}
    print(f"INFO  F3: fake - arrival {dist(fake_off)}")
    print(f"INFO      answer key - arrival {dist(key_off)}")
    print(f"INFO      delivered: collector - exit arrival {dist(deliv)}")
    check("F4: every fake timestamp has the observed format (Python isoformat, naive)", fmt_ok)
    # F5 and F7 against the answer-key view (real log plus the seat's shadow entries, by timestamp)
    cf = sorted([(e["timestamp"], 0, i, e) for i, e in enumerate(real)]
                + [(e["timestamp"], 1, i, e) for i, e in enumerate(key_all)], key=lambda x: (x[0], x[1], x[2]))
    cf_entries = [x[3] for x in cf]
    ids_view = [json.dumps([kind_tag(e), e.get("path")]) if kind_tag(e)[0] else json.dumps(e, sort_keys=True)
                for e in wv]
    ids_cf = [json.dumps([kind_tag(e), e.get("path")]) if kind_tag(e)[0] else json.dumps(e, sort_keys=True)
              for e in cf_entries]
    pos = {x: i for i, x in enumerate(ids_cf)}
    seq = [pos.get(x, -1) for x in ids_view]
    pair_inv = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq)) if seq[i] > seq[j])
    REPORT["f5"] = {"entries": len(wv), "order_inversions_vs_answer_key": pair_inv,
                    "adjacent_timestamp_inversions_in_view": inversions_view, "adjacent_ties_in_view": ties,
                    "same_membership": sorted(ids_view) == sorted(ids_cf)}
    print(f"INFO  F5: {REPORT['f5']}")

    def placeholder(t):
        return re.sub(r'"timestamp": "[^"]*"', '"timestamp": "<ts>"', t)
    got = placeholder(json.dumps(wv, indent=2))
    want = placeholder(json.dumps(cf_entries, indent=2))
    REPORT["f7"] = {"equal": got == want, "bytes": [len(got), len(want)]}
    if got != want:
        gl, wl = got.split("\n"), want.split("\n")
        REPORT["f7"]["first_diff_line"] = next((i for i, (a, b) in enumerate(zip(gl, wl)) if a != b), None)
    print(f"INFO  F7: forged view vs answer-key view with timestamp placeholders: {REPORT['f7']}")


def part_f9_f10_f11():
    se = Ctx.se
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1", "seat2"], run_id="f1")
    for k in ("get_plain", "post_json"):
        send(k, "s2", S2)
    real = clog()
    v1, v2 = view(S1)[0], view(S2)[0]
    own1 = {"c", "q", "w"}

    def split(v, own):
        return [e for e in v if kind_tag(e)[1] not in own], sorted(kind_tag(e) for e in v if kind_tag(e)[1] in own)
    r1, f1 = split(v1, own1)
    r2, f2 = split(v2, {"s2"})
    ok = (r1 == real and r2 == real and f1 == sorted((k, t) for t in own1 for k in KINDS)
          and f2 == [("get_plain", "s2"), ("post_json", "s2")])
    C.arm(Ctx.eport, DECOY, SEATS, contained=list(SEATS), run_id="f1")
    send("get_plain", "s0", S0)
    v0, v1b, v2b = view(S0)[0], view(S1)[0], view(S2)[0]
    real2 = clog()
    ok2 = (split(v0, {"s0"}) == (real2, [("get_plain", "s0")]) and split(v1b, own1)[0] == real2
           and split(v2b, {"s2"}) == (real2, [("get_plain", "s2"), ("post_json", "s2")]))
    check("F9: two of three contained: each view is exactly the true log plus that seat's own diverted entries", ok)
    check("F9: all three contained: likewise", ok2)
    # F10
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1", "seat2"], run_id="f1")
    send("get_plain", "pre", S0)
    trip_body = f"a={DECOY}&b=t".encode()
    trip = C.kind_request("post_form", "trip", Ctx.p).replace(b"Content-Length: 9", f"Content-Length: {len(trip_body)}".encode())
    trip = trip.replace(b"a=1&b=two", trip_body)
    C.raw(Ctx.eport, trip, src=S0)
    send("get_plain", "post", S0)
    v0 = view(S0)[0]
    tags = [kind_tag(e)[1] for e in v0]
    real3 = clog()
    check("F10: free, then trip, then contained: the seat's view holds all three in order, the trip and after as fakes",
          tags[-3:] == ["pre", "trip", "post"] and kind_tag(real3[-1])[1] == "pre"
          and "seat0" in se.STATE["containment"].contained, tags[-4:])
    # F11: GET and HEAD, free (seat2 is contained, seat0 now contained: re-arm with seat0 free)
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f1")
    out = {}
    for m in ("GET", "HEAD"):
        rq = f"{m} /get-request-log HTTP/1.1\r\nHost: {C.HOST}\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
        rf, rc = C.raw(Ctx.eport, rq, src=S0), C.raw(Ctx.eport, rq, src=S1)
        lf, bf = strip_hdr(rf, (b"date", b"content-length"))
        lc, bc = strip_hdr(rc, (b"date", b"content-length"))
        clen = {}
        for name, r in (("free", rf), ("contained", rc)):
            m_ = re.search(rb"(?im)^content-length:\s*(\d+)", r)
            clen[name] = int(m_.group(1)) if m_ else None
        out[m] = {"status_and_headers_equal": lf == lc, "free": [x.decode() for x in lf],
                  "content_length": clen, "body_lengths": [len(bf), len(bc)]}
    gv = view(S1)[0]
    ok = (out["GET"]["status_and_headers_equal"] and out["HEAD"]["status_and_headers_equal"]
          and out["GET"]["content_length"]["free"] == out["GET"]["body_lengths"][0]
          and out["GET"]["content_length"]["contained"] == out["GET"]["body_lengths"][1]
          and out["HEAD"]["body_lengths"] == [0, 0]
          and out["HEAD"]["content_length"] == out["GET"]["content_length"])
    REPORT["f11"] = out
    check("F11: status and headers (Date, Content-Length excluded) equal free vs contained, GET and HEAD; "
          "Content-Length matches each view", ok and isinstance(gv, list), out)


def part_f12():
    import test_swarm_l0 as L0
    se = Ctx.se
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f1")
    res = {}
    allok = True
    for name, (method, target) in L0.F12_CASES.items():
        n0 = len(clog())
        bare = C.raw(Ctx.cport, L0.req(method, target, (f"X-Gateway-Token: {TOKEN}", "User-Agent: curl/8.5.0")))
        n1 = len(clog())
        bare_logged = n1 > n0
        bare_body = C.body_of(bare)
        log_handler = (C.status(bare) == 200 and not bare_logged and method in ("GET", "HEAD")
                       and (method == "HEAD" or bare_body.lstrip().startswith(b"[")))
        exr = C.raw(Ctx.eport, L0.req(method, target, ("User-Agent: curl/8.5.0",)), S0)
        n2 = len(clog())
        exit_logged = n2 > n1
        last = se.STATE["events"][-1] if se.STATE["events"] else {}
        if log_handler:
            ok = (C.status(exr) == 200 and not exit_logged and last.get("decision") == "log-read"
                  and (method == "HEAD" or C.body_of(exr) == clog_bytes()))
        else:
            ok = C.status(exr) == C.status(bare) and exit_logged == bare_logged
        res[name] = {"collector": [C.status(bare), bare_logged, log_handler],
                     "exit": [C.status(exr), exit_logged, last.get("decision")], "ok": ok}
        allok &= ok
    REPORT["f12"] = res
    check(f"F12: {sum(r['ok'] for r in res.values())} of {len(res)} odd requests near the log path match a bare "
          "collector (log-handler ones get the L1 view)", allok, {k: v for k, v in res.items() if not v["ok"]})


def part_f14():
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f1")
    out = {}
    for name, src in (("free", S0), ("contained", S1)):
        hits = 0
        for i in range(200):
            send("post_form", f"f14{name[0]}{i}", src)
            v = view(src)[0]
            hits += any(kind_tag(e)[1] == f"f14{name[0]}{i}" for e in v)
        out[name] = hits
    REPORT["f14"] = out
    check("F14: send then read, 200 of 200 own entries present, free and contained",
          out == {"free": 200, "contained": 200}, out)


def part_f15():
    se, ex = Ctx.se, Ctx.se.exp3
    px = Proxy(Ctx.cport)
    saved = ex.COLLECTOR_URL
    ex.COLLECTOR_URL = f"http://127.0.0.1:{px.port}"
    mark = "HIDDENl1leak4e2a"
    reads = 0
    try:
        for src in (S1, S0):
            for target in (f"/get-request-log?x={mark}", "//get-request-log", f"/%67et-request-log?{mark}=1"):
                rq = (f"GET {target} HTTP/1.1\r\nHost: {C.HOST}\r\nX-Leak: {mark}\r\nCookie: s={mark}\r\n"
                      f"Authorization: Bearer {mark}\r\nConnection: close\r\n\r\n").encode()
                C.raw(Ctx.eport, rq, src=src)
                reads += 1
            rq = (f"HEAD /get-request-log?{mark} HTTP/1.1\r\nHost: {C.HOST}\r\nX-Leak: {mark}\r\n"
                  "Connection: close\r\n\r\n").encode()
            C.raw(Ctx.eport, rq, src=src)
            reads += 1
        time.sleep(0.3)
    finally:
        ex.COLLECTOR_URL = saved
        px.srv.close()
    leaked = sum(1 for g in px.got if mark.encode() in bytes(g))
    REPORT["f15"] = {"reads": reads, "connections_to_collector": len(px.got), "leaks": leaked}
    print(f"INFO  F15: {REPORT['f15']} (each read is one clean read)")
    check("F15: hidden data in contained and free reads never reaches the collector (zero leaks)", leaked == 0,
          REPORT["f15"])


def part_f6():
    """Cap: fill the real log past 10,000 directly at the collector, then
    read as the contained seat."""
    se = Ctx.se
    C.arm(Ctx.eport, DECOY, SEATS, contained=["seat1"], run_id="f1")
    port = se.AK["shadows"]["seat1"]["port"]

    def fill(n, start):
        for i in range(start, start + n):
            r = urllib.request.Request(f"http://127.0.0.1:{Ctx.cport}/fill/{i}", data=b"x",
                                       headers={"X-Gateway-Token": TOKEN})
            urllib.request.urlopen(r, timeout=10).read()
    n_now = len(clog())
    fill(9990 - n_now, 0)
    reads = []

    def read_and_compare(label):
        v = view(S1)[0]
        real = clog()
        own = [normalize_key(e, port) for e in answer_key("seat1") if kind_tag(e)[1] in {"c", "q", "w"}
               or (kind_tag(e)[1] or "").startswith("f14c")]
        cf = sorted([(e["timestamp"], 0, i, e) for i, e in enumerate(real)]
                    + [(e["timestamp"], 1, i, e) for i, e in enumerate(own)], key=lambda x: x[:3])
        cf = [x[3] for x in cf][-10000:]
        ident = lambda e: e.get("path") + "|" + str(e.get("body"))[:40]
        reads.append({"label": label, "view": len(v), "real": len(real), "counterfactual": len(cf),
                      "cap_learned": se.FORGER.cap,
                      "same_membership": sorted(map(ident, v)) == sorted(map(ident, cf))})
    read_and_compare("real 9,990")
    fill(10, 100000)
    read_and_compare("real 10,000 (just reached)")
    fill(5, 200000)
    read_and_compare("real 10,000 (5 dropped)")
    fill(5, 300000)
    read_and_compare("real 10,000 (10 dropped)")
    REPORT["f6"] = reads
    for r in reads:
        print(f"INFO  F6: {r}")
    check("F6: once the real log has stopped growing, the view holds 10,000 entries, the same set as the answer key",
          reads[-1]["view"] == 10000 and reads[-1]["same_membership"], reads[-1])


def main():
    base = ak_base()
    Ctx.cport, proc = C.start_collector(TOKEN)
    Ctx.se, Ctx.eport = C.start_exit(f"http://127.0.0.1:{Ctx.cport}", TOKEN,
                                     {"SWARM_ANSWER_KEY": "1", "SWARM_AK_PORT_BASE": str(base)},
                                     name="swarm_exit_l1_real")
    Ctx.p = C.payloads()
    Ctx.common5 = ["get_plain", "post_form", "post_raw_default_ct", "post_json", "post_multipart"]
    t0 = time.time()
    try:
        for part in (part_f2, part_f13_all_contained):
            part()
        wv = part_f1()
        part_f3_f7(wv)
        for part in (part_f9_f10_f11, part_f12, part_f14, part_f15, part_f6):
            try:
                part()
            except Exception as e:  # noqa: BLE001
                import traceback
                traceback.print_exc()
                check(f"{part.__name__} raised {e!r}", False)
        REPORT["forger_summary"] = Ctx.se.FORGER.summary()
        REPORT["l1_errors"] = Ctx.se.L1_ERRORS
        REPORT["answer_key_errors"] = Ctx.se.AK["errors"]
    finally:
        for sh in Ctx.se.AK["shadows"].values():
            Ctx.se._stop(sh.get("proc"))
        proc.terminate()
        proc.wait(timeout=5)
    REPORT["seconds"] = round(time.time() - t0, 1)
    REPORT["results"] = RESULTS
    out = os.environ.get("SWARM_L1_REPORT")
    if out:
        Path(out).write_text(json.dumps(REPORT, indent=2, default=str))
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} passed ({REPORT['seconds']} s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
