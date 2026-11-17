"""The L1 forger's machinery (step 3, Stage 2), without Docker or servers.

Nothing here touches the collector: format learning is tested against a toy
logger written in this file, in an invented format that differs from the
collector's in every learnable choice (timestamp format, header casing,
binary bodies, repeated form keys, empty values, files, content type and
length, path, layout). The forger must learn the toy's format from its
entries alone.

  formats     timestamp library: detection, rendering, parsing; Python's
              isoformat drops a zero microsecond field (rule 5).
  standards   urlencoded (WHATWG) and multipart (RFC 7578) parsing.
  capture     the in-memory forward capture equals what urllib sends to a real
              socket, byte for byte.
  splice      split and rebuild reproduce a reply byte for byte (F8's
              mechanism); "[]"; unknown layouts are refused.
  learning    after one toy entry of each kind, the forger renders new
              requests of those kinds exactly as the toy logs them
              (timestamps excluded); kinds not yet seen fall back to the cold
              template's rules.
  view        cold reads use the template; a free read is the reply byte for
              byte; fakes are inserted by timestamp; a fake keeps its
              timestamp across reads; the cap is learned only once the real
              log stops growing.
"""

import base64
import json
import socket
import sys
import threading
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from honeypot.swarm_gateway import swarm_forger as F  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))


# ---------------------------------------------------------------- toy logger

TOKEN = "X-Gateway-Token"


def toy_entry(rp: dict, dt: datetime) -> dict:
    """An invented logging style: asctime timestamps, lower-case header names,
    binary bodies as base64 data URLs, form values always lists, empty maps
    as {}, files as objects, media type only, content length as a string,
    raw path, a constant extra key."""
    hl = [(k.lower(), v) for k, v in rp["headers"] if k.lower() != TOKEN.lower()]
    hd = dict(hl)
    body = rp["body"]
    text = F.utf8_or_none(body)
    if text is None:
        text = "data:application/octet-stream;base64," + base64.b64encode(body).decode()
    ct = hd.get("content-type")
    mt = F.media_type(ct)
    form, uploads = {}, {}
    if body and mt == "application/x-www-form-urlencoded" and F.utf8_or_none(body) is not None:
        for k, v in F.parse_urlencoded(body):
            form.setdefault(k, []).append(v)
    if body and mt == "multipart/form-data":
        for p in F.parse_multipart(body, ct):
            if p["filename"] is None:
                form.setdefault(p["name"], []).append(p["content"].decode("utf-8", "replace"))
            else:
                uploads.setdefault(p["name"], {"filename": p["filename"], "content_type": p["content_type"]})
    path = rp["target"].split("?", 1)[0]
    return {
        "ts": dt.strftime("%Y-%m-%d %H:%M:%S") + f",{dt.microsecond // 1000:03d}",
        "verb": rp["method"],
        "uri": path,
        "url": "http://" + hd.get("host", "") + rp["target"],
        "request_headers": hd,
        "payload": text,
        "form": form,
        "uploads": uploads,
        "mime": mt or None,
        "size": hd.get("content-length"),
        "client": "10.9.8.7",
        "service": "toy-collector",
    }


def toy_reply(entries) -> str:
    return json.dumps(entries, indent=4, ensure_ascii=False)


def wire(method, target, headers, body=b""):
    lines = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
    return F.parse_wire(("\r\n".join(lines) + "\r\n\r\n").encode() + body)


CURL = [("Host", "185.199.108.153"), ("User-Agent", "curl/7.81.0"), ("Accept", "*/*")]


def kinds():
    mp_b = "------------------------abc123"
    mp = (f"--{mp_b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.txt\"\r\n"
          f"Content-Type: text/plain\r\n\r\nfile body\r\n--{mp_b}\r\nContent-Disposition: form-data; "
          f"name=\"note\"\r\n\r\nhello\r\n--{mp_b}--\r\n").encode()

    def post(path, ct, body, extra=()):
        h = [("Accept-Encoding", "identity"), ("Content-Length", str(len(body)))] + CURL + list(extra)
        if ct:
            h.append(("Content-Type", ct))
        return wire("POST", path, h + [("Connection", "close"), (TOKEN, "secret")], body)

    get_h = [("Accept-Encoding", "identity")] + CURL + [("Connection", "close"), (TOKEN, "secret")]
    return {
        "get": wire("GET", "/k/get?a=1", get_h),
        "form": post("/k/form", "application/x-www-form-urlencoded", b"a=1&b=two&a=3"),
        "json": post("/k/json", "application/json", b'{"k": "v"}'),
        "multipart": post("/k/mp", f"multipart/form-data; boundary={mp_b}", mp),
        "binary": post("/k/bin", "application/octet-stream", b"ok\xff\xfe\xfaend"),
        "unicode": post("/k/uni", "text/plain; charset=utf-8", "café ☃".encode()),
        "encoded": wire("GET", "/k/enc%20oded", get_h),
        "empty_post": post("/k/empty", None, b""),
    }


# ---------------------------------------------------------------- tests

def test_formats():
    dt = datetime(2026, 11, 17, 10, 0, 0, 0)
    check("formats: Python isoformat drops a zero microsecond field (rule 5)",
          F.ts_render("python_isoformat_naive", dt) == "2026-11-17T10:00:00")
    dt2 = dt.replace(microsecond=123456)
    ok = True
    for name in F.TS_ORDER:
        v = F.ts_render(name, dt2)
        back = F.ts_parse(name, v)
        ok &= F.ts_matches(name, v) and back is not None and abs((back - dt2).total_seconds()) < 1.0
    check("formats: every library format renders, matches its own pattern and parses back", ok)
    check("formats: detection picks Python isoformat for naive ISO values with or without the fraction",
          F.detect_ts_format(["2026-11-17T10:00:00.123456", "2026-11-17T10:00:01"]) == "python_isoformat_naive")
    check("formats: detection picks asctime and RFC 3339 Z",
          F.detect_ts_format(["2026-11-17 10:00:00,123"]) == "python_logging_asctime"
          and F.detect_ts_format(["2026-11-17T10:00:00.123Z"]) == "rfc3339_utc_ms_z")


def test_standards():
    check("standards: urlencoded (WHATWG): +, %, missing =, empty sequences, repeats",
          F.parse_urlencoded(b"a+b=c%20d&&x&a=1&a=2&%zz=%E2%82%AC")
          == [("a b", "c d"), ("x", ""), ("a", "1"), ("a", "2"), ("%zz", "€")])
    ks = kinds()
    parts = F.parse_multipart(ks["multipart"]["body"], dict(ks["multipart"]["headers"])["Content-Type"])
    check("standards: multipart (RFC 7578): fields, file names, part types",
          [(p["name"], p["filename"], p["content"], p["content_type"]) for p in parts]
          == [("file", "f.txt", b"file body", "text/plain"), ("note", None, b"hello", None)])
    check("standards: header parameters with quoted-pairs",
          F.header_params('form-data; name="a\\"b"; filename=x.txt') == {"name": 'a"b', "filename": "x.txt"})


def test_capture():
    got = {}

    def serve(srv):
        c, _ = srv.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += c.recv(65536)
        head, _, rest = data.partition(b"\r\n\r\n")
        n = next((int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")), 0)
        while len(rest) < n:
            rest += c.recv(65536)
        got["bytes"] = head + b"\r\n\r\n" + rest
        c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        c.close()

    ok = True
    for method, body, hdrs in (("POST", b"a=1", {"Host": "185.199.108.153", "User-Agent": "curl/7.81.0"}),
                               ("GET", None, {"Host": "185.199.108.153", "X-Dup": "1,2"}),
                               ("POST", b"", {}), ("HEAD", None, {"Accept": "*/*"})):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        t = threading.Thread(target=serve, args=(srv,))
        t.start()

        def mk():
            return urllib.request.Request(f"http://127.0.0.1:{port}/p%20q?x=1", data=body,
                                          headers=dict(hdrs, **{TOKEN: "tok"}), method=method)
        urllib.request.urlopen(mk(), timeout=10).read()
        t.join()
        srv.close()
        cap = F.capture_urllib(mk())
        ok &= cap == got["bytes"]
    check("capture: in-memory forward bytes equal what urllib sends to a real socket (4 shapes)", ok)


def test_splice():
    entries = [{"a": i, "b": "xé"} for i in range(5)]
    ok = True
    for ind in (2, 4):
        for ea in (True, False):
            text = json.dumps(entries, indent=ind, ensure_ascii=ea)
            sp = F.split_reply(text)
            ok &= sp is not None and sp[0] == ind and len(sp[1]) == 5
            ok &= F.join_reply([text[s:e] for s, e in sp[1]]) == text
    check("splice: split and rebuild reproduce indented replies byte for byte", ok)
    check("splice: empty log", F.split_reply("[]") == (None, []) and F.join_reply([]) == "[]")
    check("splice: a compact layout is refused, not reparsed", F.split_reply(json.dumps(entries)) is None)


def _learner_from(entries_texts):
    t = F.load_template()
    L = F.Learner(t)
    for e in entries_texts:
        text = toy_reply([e])
        sp = F.split_reply(text)
        L.note_layout(sp[0])
        seg = text[sp[1][0][0]:sp[1][0][1]]
        L.examine(json.loads(seg), seg, F._key_sep(seg))
    return L


def _diff(a: dict, b: dict, skip=("ts",)):
    return sorted(k for k in set(a) | set(b) if k not in skip and a.get(k) != b.get(k))


def test_learning():
    ks = kinds()
    dt = datetime(2026, 11, 17, 9, 0, 0, 500000)
    L = _learner_from([toy_entry(rp, dt) for rp in ks.values()])
    fmt = L.format()
    bad = {}
    for name, rp in ks.items():
        rp2 = dict(rp, target=rp["target"].replace("/k/", "/new/"))
        d = _diff(fmt.render(dict(rp2, drop_headers={TOKEN.lower()}), "x"), toy_entry(rp2, dt))
        if d:
            bad[name] = d
    check("learning: warm on every toy kind, new requests render exactly as the toy logs them", not bad, bad)
    check("learning: toy timestamp format and layout learned (asctime, indent 4, raw non-ASCII)",
          fmt.ts_format == "python_logging_asctime" and fmt.layout["indent"] == 4
          and fmt.layout["ensure_ascii"] is False and [k for k, _ in fmt.keys][0] == "ts", (fmt.ts_format, fmt.layout))
    ent = fmt.render(dict(ks["get"], drop_headers={TOKEN.lower()}), fmt.render_ts(dt))
    check("learning: the exit's token header is never shown", TOKEN.lower() not in ent["request_headers"])
    # Partly warm: only a GET seen. Unseen choices follow the template.
    Lp = _learner_from([toy_entry(ks["get"], dt)])
    fp = Lp.format()
    mp = fp.render(dict(ks["multipart"], drop_headers={TOKEN.lower()}), "x")
    check("learning: a kind not yet seen uses the template's rule (multipart files as content)",
          mp["uploads"] == {"file": "file body"} and fp.rules["files_value"] == "content", mp["uploads"])
    check("learning: an unseen encoded path is decoded by default; after one is seen it is raw",
          fp.render(dict(ks["encoded"], drop_headers=set()), "x")["uri"] == "/k/enc oded"
          and fmt.render(dict(ks["encoded"], drop_headers=set()), "x")["uri"] == "/k/enc%20oded")


def _rec(i):
    return {"spool": f"rec{i}"}


def test_view():
    ks = kinds()
    base = datetime(2026, 11, 17, 9, 0, 0)
    reqs = {f"rec{i}": (dict(rp, drop_headers={TOKEN.lower()}), base + timedelta(seconds=10 * i + 5), {})
            for i, rp in enumerate(ks.values())}

    def forwarded(rec):
        return reqs[rec["spool"]]

    fg = F.Forger(seed=1)
    fg.set_delays([2.0])
    out, info = fg.view("seat1", True, "[]", [_rec(0), _rec(1)], forwarded, now=base)
    cold = json.loads(out)
    check("view: cold read renders the template (httpbin keys, RFC 3339 Z)",
          info["cold"] and [sorted(e) for e in cold] == [sorted(k for k, _ in fg.template["keys"])] * 2
          and cold[0]["timestamp"].endswith("Z"), info)
    real = [toy_entry(rp, base + timedelta(seconds=10 * i)) for i, rp in enumerate(ks.values())]
    text = toy_reply(real)
    now = base + timedelta(minutes=5)
    out_free, _ = fg.view("seat0", False, text, [], forwarded, now=now)
    check("view: a free read is the reply byte for byte", out_free == text)
    out1, info1 = fg.view("seat1", True, text, [_rec(0), _rec(3)], forwarded, now=now)
    v1 = json.loads(out1)
    check("view: fakes inserted by timestamp, real entries unchanged",
          len(v1) == len(real) + 2 and v1[1]["uri"] == "/k/get" and v1[1]["ts"].endswith(",002")
          and v1[5]["uri"] == "/k/mp" and [e for e in v1 if e not in real] == [v1[1], v1[5]]
          and not info1["cold"], [e.get("uri") for e in v1])
    check("view: real entries keep their bytes in the view",
          all(toy_reply([e])[2:-2] in out1 for e in real))
    out2, _ = fg.view("seat1", True, text, [_rec(0), _rec(3)], forwarded, now=now)
    check("view: a fake keeps its timestamp and rendering across reads", out2 == out1)
    st = fg.summary()["stats"]["seat1"]
    check("view: format change counted once (cold template, then learned)",
          st["format_changes"] == 1 and st["cold_reads"] == 1, st)
    # Cap: only after the real log stops growing.
    fg2 = F.Forger(seed=2)
    fg2.set_delays([1.0])
    many = [toy_entry(ks["get"], base + timedelta(seconds=i)) for i in range(12)]
    fg2.view("s", True, toy_reply(many[:10]), [], forwarded, now=base)
    fg2.view("s", True, toy_reply(many[1:11]), [], forwarded, now=base)
    check("view: cap learned when the count stays and the first entry changes", fg2.cap == 10, fg2.cap)
    fg3 = F.Forger(seed=3)
    fg3.view("s", True, toy_reply(many[:10]), [], forwarded, now=base)
    fg3.view("s", True, toy_reply(many[:11]), [], forwarded, now=base)
    check("view: no cap while the log grows", fg3.cap is None)


def main():
    for t in (test_formats, test_standards, test_capture, test_splice, test_learning, test_view):
        try:
            t()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(f"{t.__name__} raised {e!r}", False)
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
