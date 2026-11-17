"""Realistic L1 forger for the swarm exit (step 3, Stage 2). Pure Python.

A contained seat's log read shows the collector's true log plus that seat's
own diverted requests, shown as delivered. This module writes those fake
entries. Rules (docs/swarm-pilot/step3-plan.md, "Stage 1 final review: rules
and design for Stage 2"):

  * It uses only (a) the contained seat's own diverted requests, (b) real log
    replies the exit fetched for contained seats' reads (format only; real
    entries pass through unchanged), (c) the exit's own forwarding rules, and
    (d) general knowledge of web standards. It never sees free seats' forward
    records, the board or collector code.
  * Fake entries are written at read time in the format known at that
    moment. With no real entry seen in this run (cold), the committed cold
    template (forger_cold_template.json, httpbin style) is used; once real
    entries are seen, every fake entry is rendered in the learned format.
  * Fake timestamps are exit arrival + a delay drawn from the exit's own
    calibration forwards, rendered in the observed timestamp format.
  * Entries are spliced into the real reply's text by timestamp; the log is
    never parsed and re-serialized. A free seat's read goes through the same
    split-and-rebuild with nothing inserted, which reproduces the reply byte
    for byte.

How the format is learned: each examined real entry is parsed; every key gets
a role (by key name, else by its value); for each role a fixed list of
candidate rules, written from web standards, is narrowed to those consistent
with the entry's own other fields (for example form fields against a standard
urlencoded or multipart parse of the logged body). A rule never observed, or
left ambiguous, follows the cold template when the template's rule is still a
candidate. Layout (indent, separators, escaping, nested key order) comes from
the reply text.
"""

import base64
import bisect
import hashlib
import http.client
import io
import json
import os
import random
import re
import secrets
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote_to_bytes, urlsplit
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(HERE, "forger_cold_template.json")
EXAMINE_BUDGET = 50          # real entries examined per read, newest first
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


# ------------------------------------------------------- web standards helpers

def utf8_or_none(b: bytes):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def media_type(ct) -> str:
    return (ct or "").split(";", 1)[0].strip().lower()


_PARAM = re.compile(r';\s*([^=;\s]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)')


def header_params(value: str) -> dict:
    """Parameters of a header value such as a Content-Type or a
    Content-Disposition (RFC 9110 quoted-string, with quoted-pairs)."""
    out = {}
    for m in _PARAM.finditer(value or ""):
        k, v = m.group(1).lower(), m.group(2).strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        out.setdefault(k, v)
    return out


def parse_urlencoded(b: bytes) -> list:
    """application/x-www-form-urlencoded (WHATWG URL standard): split on "&",
    skip empty sequences, split at the first "=", "+" is a space, percent-
    decode, then UTF-8 decode with replacement."""
    out = []
    for seq in b.split(b"&"):
        if not seq:
            continue
        name, _, value = seq.partition(b"=")
        name = unquote_to_bytes(name.replace(b"+", b" ")).decode("utf-8", "replace")
        value = unquote_to_bytes(value.replace(b"+", b" ")).decode("utf-8", "replace")
        out.append((name, value))
    return out


def parse_multipart(b: bytes, ct: str) -> list:
    """multipart/form-data (RFC 7578 / RFC 2046). Returns parts as dicts
    {name, filename (None if absent), content (bytes), content_type}."""
    boundary = header_params(ct).get("boundary")
    if not boundary:
        return []
    delim = b"--" + boundary.encode("latin-1", "replace")
    pieces = b.split(delim)
    parts = []
    for piece in pieces[1:]:
        if piece.startswith(b"--"):
            break
        if piece.startswith(b"\r\n"):
            piece = piece[2:]
        elif piece.startswith(b"\n"):
            piece = piece[1:]
        if piece.endswith(b"\r\n"):
            piece = piece[:-2]
        elif piece.endswith(b"\n"):
            piece = piece[:-1]
        head, sep, content = piece.partition(b"\r\n\r\n")
        if not sep:
            head, sep, content = piece.partition(b"\n\n")
        hdrs = {}
        for line in re.split(rb"\r?\n", head):
            k, colon, v = line.partition(b":")
            if colon:
                hdrs[k.strip().decode("latin-1").lower()] = v.strip().decode("utf-8", "replace")
        cd = hdrs.get("content-disposition", "")
        params = header_params(cd)
        if "name" not in params:
            continue
        parts.append({"name": params["name"], "filename": params.get("filename"),
                      "content": content, "content_type": hdrs.get("content-type")})
    return parts


def decoded_path(raw_path: str) -> str:
    """Percent-decoded path, UTF-8 with replacement (RFC 3986, PEP 3333)."""
    return unquote_to_bytes(raw_path).decode("utf-8", "replace")


def parse_wire(data: bytes) -> dict:
    """An HTTP/1.x request in wire form: method, target, version, headers in
    order, body."""
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    method, target, version = (lines[0].decode("latin-1").split(" ", 2) + ["", ""])[:3]
    headers = []
    for line in lines[1:]:
        k, colon, v = line.partition(b":")
        if colon:
            headers.append((k.decode("latin-1"), v.strip().decode("latin-1")))
    return {"method": method, "target": target, "version": version, "headers": headers, "body": body}


# ------------------------------------------------- the exit's own forward bytes

class _CapSock:
    """Stands in for the collector's socket: records what is sent and answers
    204, so urllib runs exactly as it does for a real forward."""

    def __init__(self):
        self.buf = bytearray()

    def sendall(self, data):
        self.buf += bytes(data)

    def makefile(self, *_a, **_k):
        return io.BytesIO(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    def settimeout(self, _t):
        pass

    def setsockopt(self, *_a):
        pass

    def close(self):
        pass


def capture_urllib(req) -> bytes:
    """The bytes urllib sends for this Request, written to an in-memory
    socket instead of the network (rule 2c: the exit's own forwarding rules)."""
    box = {}

    class Conn(http.client.HTTPConnection):
        def connect(self):
            self.sock = box["sock"] = _CapSock()

    class Handler(urllib.request.HTTPHandler):
        def http_open(self, r):
            return self.do_open(Conn, r)

    opener = urllib.request.build_opener(Handler)
    with opener.open(req, timeout=20) as r:
        r.read()
    return bytes(box["sock"].buf)


# ------------------------------------------------------------ timestamp formats

def _local_aware(dt: datetime) -> datetime:
    return dt.astimezone() if dt.tzinfo is None else dt


def _utc(dt: datetime) -> datetime:
    return _local_aware(dt).astimezone(timezone.utc)


def _naive_local(dt: datetime) -> datetime:
    return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt


_TS = [
    # name, pattern (strings) or None (numbers), render(naive local dt) -> value
    ("python_isoformat_naive", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?",
     lambda dt: dt.isoformat()),                     # Python drops a zero microsecond field
    ("python_isoformat_offset", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?[+-]\d{2}:\d{2}",
     lambda dt: _local_aware(dt).isoformat()),
    ("rfc3339_utc_ms_z", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
     lambda dt: _utc(dt).strftime("%Y-%m-%dT%H:%M:%S.") + f"{_utc(dt).microsecond // 1000:03d}Z"),
    ("rfc3339_utc_us_z", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
     lambda dt: _utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
    ("rfc3339_utc_s_z", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
     lambda dt: _utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ")),
    ("python_str_space", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{6})?",
     lambda dt: str(dt)),
    ("python_logging_asctime", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}",
     lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S") + f",{dt.microsecond // 1000:03d}"),
    ("apache_common_log", r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}",
     lambda dt: _local_aware(dt).strftime("%d/%b/%Y:%H:%M:%S %z")),
    ("epoch_s_float", None, lambda dt: _local_aware(dt).timestamp()),
    ("epoch_ms_int", None, lambda dt: int(_local_aware(dt).timestamp() * 1000)),
]
TS_FORMATS = {name: (re.compile(pat + r"\Z") if pat else None, fn) for name, pat, fn in _TS}
TS_ORDER = [name for name, _, _ in _TS]


def ts_matches(name: str, value) -> bool:
    pat, _ = TS_FORMATS[name]
    if pat is None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        return (name == "epoch_ms_int") == (isinstance(value, int) and value >= 10 ** 11)
    return isinstance(value, str) and bool(pat.match(value))


def ts_render(name: str, dt: datetime):
    return TS_FORMATS[name][1](dt)


def ts_parse(name: str, value) -> datetime | None:
    """Back to a naive local datetime (for ordering)."""
    try:
        if name in ("python_isoformat_naive", "python_str_space"):
            return datetime.fromisoformat(value)
        if name in ("python_isoformat_offset", "rfc3339_utc_ms_z", "rfc3339_utc_us_z", "rfc3339_utc_s_z"):
            return _naive_local(datetime.fromisoformat(value.replace("Z", "+00:00")))
        if name == "python_logging_asctime":
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S,%f")
        if name == "apache_common_log":
            return _naive_local(datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z"))
        if name == "epoch_s_float":
            return datetime.fromtimestamp(value)
        if name == "epoch_ms_int":
            return datetime.fromtimestamp(value / 1000)
    except (ValueError, TypeError, OverflowError):
        return None
    return None


def detect_ts_format(values) -> str | None:
    vals = list(values)
    if not vals:
        return None
    for name in TS_ORDER:
        if all(ts_matches(name, v) for v in vals):
            return name
    return None


# ------------------------------------------------------------- roles and rules

ROLE_NAMES = {
    "timestamp": ["timestamp", "time", "ts", "@timestamp", "date", "datetime", "loggedat", "receivedat", "when"],
    "method": ["method", "verb", "httpmethod", "requestmethod"],
    "path": ["path", "uri", "requesturi", "route", "pathname", "requestpath"],
    "url": ["fullurl", "url", "href", "requesturl", "absoluteurl"],
    "headers": ["headers", "requestheaders", "header", "httpheaders"],
    "body": ["body", "data", "rawbody", "payload", "content", "raw", "requestbody"],
    "form": ["formdata", "form", "postparams", "fields", "formfields"],
    "files": ["files", "uploads", "attachments", "filedata"],
    "content_type": ["contenttype", "mimetype", "mime", "ctype"],
    "content_length": ["contentlength", "length", "size", "bodylength"],
    "remote": ["remoteaddr", "ip", "clientip", "origin", "remoteip", "client", "sourceip", "addr"],
    "query_args": ["args", "query", "querystring", "queryparams", "params"],
    "json_body": ["json", "jsonbody"],
}
_SYN = {n: role for role, names in ROLE_NAMES.items() for n in names}
_IP = re.compile(r"\A(\d{1,3}\.){3}\d{1,3}\Z|\A[0-9a-fA-F:]+:[0-9a-fA-F:]*\Z")

CONTEXTS = ("urlencoded", "urlencoded_invalid_utf8", "multipart", "other", "no_body")
RULES = {
    "body_invalid_utf8": ["utf8_replace", "data_url_base64", "utf8_surrogateescape", "base64", "latin1"],
    "body_of_form_types": ["text", "empty"],
    **{f"form:{c}": ["parse", "empty"] for c in CONTEXTS},
    "form_empty": ["null", "empty_object", "empty_string"],
    "repeated_keys": ["first", "last", "list", "str_or_list"],
    **{f"files:{c}": ["parse", "empty"] for c in ("multipart", "other", "no_body")},
    "files_value": ["filename", "content", "object"],
    "files_empty": ["null", "empty_object"],
    "query_empty": ["null", "empty_object", "empty_string"],
    "json_body": ["parse_or_null"],
    "header_casing": ["title", "as_sent", "lower"],
    "path": ["decoded", "raw"],
    "url": ["raw_target", "requoted"],
    "content_type": ["header_value", "media_type"],
    "content_type_absent": ["null", "empty_string"],
    "content_length": ["int_header", "str_header", "body_bytes"],
    "content_length_absent": ["null", "zero"],
    "nested_order": ["as_received", "sorted"],
}
EMPTY = {"null": None, "empty_object": {}, "empty_string": "", "zero": 0}


def load_template(path: str = TEMPLATE_PATH) -> dict:
    with open(path) as f:
        t = json.load(f)
    r = t["rules"]
    rules = {
        "body_invalid_utf8": r["body_invalid_utf8"],
        "body_of_form_types": "empty" if r["body_of_form_types"] == "empty" else "text",
        **{f"form:{c}": r["form"][c] for c in CONTEXTS},
        "form_empty": r["form_empty"],
        "repeated_keys": r["repeated_keys"],
        **{f"files:{c}": r["files"][c] for c in ("multipart", "other", "no_body")},
        "files_value": r["files_value"],
        "files_empty": r["files_empty"],
        "query_empty": r["query_empty"],
        "json_body": r["json_body"],
        "header_casing": r["header_casing"],
        "path": r["path"],
        "url": r["url"],
        "content_type": r["content_type"],
        "content_type_absent": r["content_type_absent"],
        "content_length": r["content_length"],
        "content_length_absent": r["content_length_absent"],
        "nested_order": "sorted" if t["layout"]["sort_keys"] else "as_received",
    }
    for k, v in rules.items():
        assert v in RULES[k], (k, v)
    return {"name": t["name"], "keys": [tuple(x) for x in t["fields"]], "rules": rules,
            "ts_format": r["timestamp_format"], "layout": dict(t["layout"]),
            "remote": r["remote"]}


def pairs_value(pairs: list, repeated: str, empty: str):
    if not pairs:
        return EMPTY[empty] if not isinstance(EMPTY[empty], dict) else {}
    d: dict = {}
    if repeated == "first":
        for k, v in pairs:
            d.setdefault(k, v)
    elif repeated == "last":
        for k, v in pairs:
            d[k] = v
    elif repeated == "list":
        for k, v in pairs:
            d.setdefault(k, []).append(v)
    else:  # str_or_list
        counts = Counter(k for k, _ in pairs)
        for k, v in pairs:
            if counts[k] == 1:
                d[k] = v
            else:
                d.setdefault(k, []).append(v)
    return d


def _file_content(b: bytes) -> str:
    s = utf8_or_none(b)
    return s if s is not None else "data:application/octet-stream;base64," + base64.b64encode(b).decode()


def files_value(parts: list, value: str, empty: str):
    if not parts:
        return EMPTY[empty] if not isinstance(EMPTY[empty], dict) else {}
    d: dict = {}
    for p in parts:
        if value == "filename":
            v = p["filename"]
        elif value == "content":
            v = _file_content(p["content"])
        else:
            v = {"filename": p["filename"], "content_type": p["content_type"]}
        d.setdefault(p["name"], v)
    return d


def _is_empty(v) -> bool:
    return v is None or v == {} or v == "" or v == []


def _empty_name(v):
    if v is None:
        return "null"
    if v == {}:
        return "empty_object"
    if v == "":
        return "empty_string"
    return None


def _context(ct, body_empty: bool, invalid_utf8: bool) -> str:
    mt = media_type(ct)
    if body_empty:
        return "no_body"
    if mt == "application/x-www-form-urlencoded":
        return "urlencoded_invalid_utf8" if invalid_utf8 else "urlencoded"
    if mt == "multipart/form-data":
        return "multipart"
    return "other"


def _form_pairs(ctx: str, body: bytes, ct) -> list:
    if ctx == "multipart":
        return [(p["name"], p["content"].decode("utf-8", "replace"))
                for p in parse_multipart(body, ct) if p["filename"] is None]
    if ctx == "no_body":
        return []
    return parse_urlencoded(body)


def _role_by_value(v):
    if isinstance(v, dict) and any(str(k).lower() in ("host", "user-agent", "accept", "content-type")
                                   for k in v):
        return "headers"
    if isinstance(v, str):
        if any(ts_matches(n, v) for n in TS_ORDER if TS_FORMATS[n][0] is not None):
            return "timestamp"
        if v in METHODS:
            return "method"
        if v.startswith(("http://", "https://")):
            return "url"
        if v.startswith("/"):
            return "path"
        if _IP.match(v):
            return "remote"
    return None


_VALUE_TYPES = {"headers": (dict,), "method": (str,), "path": (str,), "url": (str,),
                "body": (str,), "content_type": (str, type(None)),
                "content_length": (int, str, type(None)), "remote": (str,)}


def assign_roles(entry: dict) -> list:
    out = []
    used = set()
    for k, v in entry.items():
        role = _SYN.get(re.sub(r"[^a-z0-9@]", "", str(k).lower()))
        if role is not None and role in _VALUE_TYPES and not isinstance(v, _VALUE_TYPES[role]):
            role = None
        if role is None:
            role = _role_by_value(v)
        if role is None or role in used:
            role = "unknown"
        used.add(role)
        out.append((k, role))
    return out


def extract_delays(entries: list, stamps: dict) -> list:
    """Delays (ms) of the exit's calibration forwards: logged timestamp -
    arrival. The timestamp and body fields are found by the generic role
    detection above, not by known key names; stamps maps each forward's body
    text to its arrival (naive local datetime)."""
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        roles = {role: k for k, role in assign_roles(e)}
        if "timestamp" not in roles or "body" not in roles:
            continue
        t = stamps.get(e[roles["body"]])
        if t is None:
            continue
        name = detect_ts_format([e[roles["timestamp"]]])
        dt = ts_parse(name, e[roles["timestamp"]]) if name else None
        if dt is not None:
            out.append((dt - t).total_seconds() * 1000)
    return out


class Fmt:
    """A complete format: keys with roles, chosen rules, timestamp format,
    layout and constants. Built from the template (cold) or a learner."""

    def __init__(self, keys, rules, ts_format, layout, *, consts=None, scheme="http",
                 remote="127.0.0.1", tz_offset_s=0, cold=False):
        self.keys, self.rules, self.ts_format = list(keys), dict(rules), ts_format
        self.layout = dict(layout)
        self.consts = dict(consts or {})
        self.scheme, self.remote, self.tz_offset_s, self.cold = scheme, remote, tz_offset_s, cold
        sig = json.dumps([self.keys, sorted(self.rules.items()), ts_format, sorted(self.layout.items()),
                          scheme, tz_offset_s, cold, sorted((k, repr(v)) for k, v in self.consts.items())])
        self.signature = hashlib.sha256(sig.encode()).hexdigest()[:12]
        self.ts_key = next((k for k, r in self.keys if r == "timestamp"), None)

    def render_ts(self, dt: datetime):
        return ts_render(self.ts_format, dt + timedelta(seconds=self.tz_offset_s))

    def parse_ts(self, value):
        dt = ts_parse(self.ts_format, value)
        return None if dt is None else dt - timedelta(seconds=self.tz_offset_s)

    def dump(self, entry: dict) -> str:
        """One entry as it appears inside the log's JSON array."""
        ind = self.layout.get("indent") or 2
        text = json.dumps([entry], indent=ind, ensure_ascii=bool(self.layout.get("ensure_ascii", True)),
                          separators=(",", self.layout.get("key_separator") or ": "),
                          sort_keys=bool(self.layout.get("sort_keys", False)))
        return text[2:-2]

    def render(self, rp: dict, ts_value) -> dict:
        """The fake entry for a forwarded request rp (from parse_wire, plus
        "drop_headers"), with the given timestamp value."""
        r = self.rules
        drop = rp.get("drop_headers") or set()
        casing = r["header_casing"]
        hdrs = []
        for k, v in rp["headers"]:
            if k.lower() in drop:
                continue
            name = k.title() if casing == "title" else k.lower() if casing == "lower" else k
            hdrs.append((name, v))
        hl = {k.lower(): v for k, v in rp["headers"] if k.lower() not in drop}
        body = rp["body"] or b""
        ct = hl.get("content-type")
        text = utf8_or_none(body)
        invalid = text is None
        ctx = _context(ct, not body, invalid)
        target = rp["target"]
        raw_path, _, query = target.partition("?")
        nested_sorted = r["nested_order"] == "sorted"

        def nest(d):
            return dict(sorted(d.items())) if nested_sorted and isinstance(d, dict) else d

        out = {}
        for key, role in self.keys:
            if role == "timestamp":
                v = ts_value
            elif role == "method":
                v = rp["method"]
            elif role == "path":
                v = decoded_path(raw_path) if r["path"] == "decoded" else raw_path
            elif role == "url":
                host = hl.get("host", "")
                tail = target if r["url"] == "raw_target" else (
                    quote(decoded_path(raw_path), safe="/:@!$&'()*+,;=~") + (f"?{query}" if query else ""))
                v = f"{self.scheme}://{host}{tail}"
            elif role == "headers":
                v = nest(dict(hdrs))
            elif role == "body":
                if media_type(ct) in ("application/x-www-form-urlencoded", "multipart/form-data") \
                        and r["body_of_form_types"] == "empty":
                    v = ""
                elif not invalid:
                    v = text
                else:
                    rule = r["body_invalid_utf8"]
                    v = (body.decode("utf-8", "replace") if rule == "utf8_replace"
                         else body.decode("utf-8", "surrogateescape") if rule == "utf8_surrogateescape"
                         else body.decode("latin-1") if rule == "latin1"
                         else base64.b64encode(body).decode() if rule == "base64"
                         else "data:application/octet-stream;base64," + base64.b64encode(body).decode())
            elif role == "form":
                if r[f"form:{ctx}"] == "parse":
                    v = nest(pairs_value(_form_pairs(ctx, body, ct), r["repeated_keys"], r["form_empty"]))
                else:
                    v = EMPTY[r["form_empty"]] if r["form_empty"] != "empty_object" else {}
            elif role == "files":
                fctx = ctx if ctx in ("multipart", "no_body") else "other"
                parts = [p for p in parse_multipart(body, ct) if p["filename"] is not None] \
                    if fctx == "multipart" and r[f"files:{fctx}"] == "parse" else []
                v = nest(files_value(parts, r["files_value"], r["files_empty"]))
            elif role == "content_type":
                if ct is None:
                    v = EMPTY[r["content_type_absent"]]
                else:
                    v = ct if r["content_type"] == "header_value" else media_type(ct)
            elif role == "content_length":
                cl = hl.get("content-length")
                if cl is None:
                    v = EMPTY[r["content_length_absent"]]
                elif r["content_length"] == "int_header":
                    v = int(cl) if cl.strip().isdigit() else cl
                elif r["content_length"] == "str_header":
                    v = cl
                else:
                    v = len(body)
            elif role == "remote":
                v = self.remote
            elif role == "query_args":
                v = nest(pairs_value(parse_urlencoded(query.encode("latin-1", "replace")),
                                     r["repeated_keys"], r["query_empty"]))
            elif role == "json_body":
                try:
                    v = json.loads(text) if text else None
                except ValueError:
                    v = None
            else:
                v = self.consts.get(key)
            out[key] = v
        return out


def template_fmt(t: dict, forward_source: str) -> Fmt:
    return Fmt(t["keys"], t["rules"], t["ts_format"], t["layout"], scheme="http",
               remote=forward_source, cold=True)


class Learner:
    """Evidence about the log format from examined real entries."""

    def __init__(self, template: dict, forward_source: str = "127.0.0.1"):
        self.t = template
        self.forward_source = forward_source
        self.n_entries = 0
        self.key_orders: Counter = Counter()
        self.last_keys = None
        self.ts_values: list = []
        self.cands: dict = {}                 # rule -> candidates with the most support
        self.support: dict = {}               # rule -> Counter(candidate -> consistent observations)
        self.observations: Counter = Counter()
        self.conflicts: Counter = Counter()
        self.unexplained: Counter = Counter()
        self.consts: dict = {}
        self.layout = {"indent": None, "key_separator": None, "ensure_ascii": None}
        self.scheme = None
        self.remote = None
        self.tz_offset_s = 0
        self._fmt = None

    # -- evidence
    def _observe(self, rule: str, consistent) -> None:
        """Count one observation for every candidate it is consistent with;
        the candidates kept are those consistent with the most observations,
        so one odd entry cannot flip a rule. Unexplained observations (no
        candidate fits) are counted and ignored."""
        new = set(consistent) & set(RULES[rule])
        if not new:
            self.unexplained[rule] += 1
            return
        sup = self.support.setdefault(rule, Counter())
        self.observations[rule] += 1
        for c in new:
            sup[c] += 1
        best = max(sup.values())
        self.cands[rule] = {c for c, n in sup.items() if n == best}
        if best < self.observations[rule]:
            self.conflicts[rule] = self.observations[rule] - best

    def choose(self, rule: str) -> str:
        default = self.t["rules"][rule]
        c = self.cands.get(rule)
        if c is None or default in c:
            return default
        return next(x for x in RULES[rule] if x in c)

    def examine(self, entry: dict, text: str, key_separator: str | None = None) -> None:
        if not isinstance(entry, dict) or not entry:
            return
        self._fmt = None
        self.n_entries += 1
        roles = assign_roles(entry)
        self.key_orders[tuple(roles)] += 1
        self.last_keys = roles
        by_role = {role: k for k, role in roles if role != "unknown"}
        for k, role in roles:
            if role == "unknown":
                v = entry[k]
                if k not in self.consts:
                    self.consts[k] = v
                elif self.consts[k] != v:
                    self.consts[k] = _Varies
        if key_separator:
            self.layout["key_separator"] = key_separator
        if re.search(r"[^\x00-\x7f]", text):
            self.layout["ensure_ascii"] = False
        elif re.search(r"\\u(00[89a-fA-F][0-9a-fA-F]|0[1-9a-fA-F][0-9a-fA-F]{2}|[1-9a-fA-F][0-9a-fA-F]{3})", text):
            self.layout["ensure_ascii"] = True
        if "timestamp" in by_role:
            self.ts_values.append(entry[by_role["timestamp"]])
            del self.ts_values[:-200]
        if "remote" in by_role:
            self.remote = entry[by_role["remote"]]
        url = entry.get(by_role["url"]) if "url" in by_role else None
        if isinstance(url, str) and "://" in url:
            self.scheme = url.split("://", 1)[0]

        headers = entry.get(by_role["headers"]) if "headers" in by_role else None
        headers = headers if isinstance(headers, dict) else {}
        hl = {str(k).lower(): v for k, v in headers.items()}
        names = [str(k) for k in headers]
        if names:
            # The exit's own forward (urllib) always sends title-cased names
            # (rule 2c), so a logged name in another case was changed by the
            # logger; title-cased names fit "title" and "as sent" alike.
            s = set()
            if all(n == n.title() for n in names):
                s |= {"title", "as_sent"}
            if all(n == n.lower() for n in names):
                s |= {"lower"}
            self._observe("header_casing", s or {"as_sent"})
        for d in [headers] + [entry.get(by_role[r]) for r in ("form", "files", "query_args") if r in by_role]:
            if isinstance(d, dict) and len(d) >= 2:
                ks = [str(k) for k in d]
                self._observe("nested_order", {"as_received", "sorted"} if ks == sorted(ks) else {"as_received"})

        ct = hl.get("content-type")
        if ct is None and "content_type" in by_role and isinstance(entry[by_role["content_type"]], str):
            ct = entry[by_role["content_type"]] or None
        if "content_type" in by_role:
            v = entry[by_role["content_type"]]
            if hl.get("content-type") is None:
                if _empty_name(v) in ("null", "empty_string"):
                    self._observe("content_type_absent", {_empty_name(v)})
            else:
                h = hl["content-type"]
                self._observe("content_type", {c for c, x in (("header_value", h), ("media_type", media_type(h)))
                                               if x == v})
        body = entry.get(by_role["body"]) if "body" in by_role else None
        if "content_length" in by_role:
            v = entry[by_role["content_length"]]
            h = hl.get("content-length")
            if h is None:
                if v is None:
                    self._observe("content_length_absent", {"null"})
                elif v == 0:
                    self._observe("content_length_absent", {"zero"})
            else:
                s = set()
                if str(h).strip().isdigit() and v == int(h):
                    s.add("int_header")
                if v == h:
                    s.add("str_header")
                if isinstance(body, str) and v == len(body.encode("utf-8", "surrogatepass")):
                    s.add("body_bytes")
                self._observe("content_length", s)
        if "path" in by_role and isinstance(url, str):
            raw = urlsplit(url).path
            pv = entry[by_role["path"]]
            s = {n for n, x in (("raw", raw), ("decoded", decoded_path(raw))) if x == pv}
            if s and s != {"raw", "decoded"}:
                self._observe("path", s)
        if not isinstance(body, str):
            return

        cl = hl.get("content-length")
        has_body = bool(body) or (cl not in (None, "0", ""))
        # The request's body bytes, recovered from the logged representation.
        raw_body = None
        if body.startswith("data:") and ";base64," in body[:80]:
            try:
                raw_body = base64.b64decode(body.split(";base64,", 1)[1], validate=True)
            except ValueError:
                raw_body = None
            if raw_body is not None and utf8_or_none(raw_body) is None:
                self._observe("body_invalid_utf8", {"data_url_base64"})
        if raw_body is None:
            raw_body = body.encode("utf-8", "surrogateescape")
        invalid = utf8_or_none(raw_body) is None or "\ufffd" in body
        if "\ufffd" in body:
            self._observe("body_invalid_utf8", {"utf8_replace"})
        elif re.search(r"[\udc80-\udcff]", body):
            self._observe("body_invalid_utf8", {"utf8_surrogateescape"})
        mt = media_type(ct)
        if mt in ("application/x-www-form-urlencoded", "multipart/form-data") and cl not in (None, "0", ""):
            self._observe("body_of_form_types", {"empty"} if body == "" else {"text"})
        ctx = _context(ct, not has_body, invalid)

        if "form" in by_role:
            fv = entry[by_role["form"]]
            pairs = _form_pairs(ctx, raw_body, ct) if body or ctx == "no_body" else None
            if pairs is not None:
                if _is_empty(fv):
                    if _empty_name(fv):
                        self._observe("form_empty", {_empty_name(fv)})
                    if pairs:
                        self._observe(f"form:{ctx}", {"empty"})
                elif isinstance(fv, dict):
                    reps = {rk for rk in RULES["repeated_keys"] if pairs_value(pairs, rk, "null") == fv}
                    if reps:
                        self._observe(f"form:{ctx}", {"parse"})
                        self._observe("repeated_keys", reps)
                    else:
                        self.unexplained[f"form:{ctx}"] += 1
        if "files" in by_role:
            fv = entry[by_role["files"]]
            fctx = ctx if ctx in ("multipart", "no_body") else "other"
            parts = [p for p in parse_multipart(raw_body, ct) if p["filename"] is not None] \
                if fctx == "multipart" else []
            if _is_empty(fv):
                if _empty_name(fv) in ("null", "empty_object"):
                    self._observe("files_empty", {_empty_name(fv)})
                if parts:
                    self._observe(f"files:{fctx}", {"empty"})
            elif isinstance(fv, dict) and parts:
                vals = {fv_ for fv_ in RULES["files_value"] if files_value(parts, fv_, "null") == fv}
                if vals:
                    self._observe(f"files:{fctx}", {"parse"})
                    self._observe("files_value", vals)
                else:
                    self.unexplained[f"files:{fctx}"] += 1

    def note_layout(self, indent: int | None) -> None:
        if indent:
            self.layout["indent"] = indent
            self._fmt = None

    def note_clock(self, newest_value, now: datetime) -> None:
        """Offset only if the newest real entry is over 60 s ahead of the
        exit's clock (naive timestamps are read as exit-local time)."""
        name = detect_ts_format(self.ts_values)
        if name is None:
            return
        dt = ts_parse(name, newest_value)
        if dt is None:
            return
        ahead = (dt - now).total_seconds()
        off = int(round(ahead / 900.0)) * 900 if ahead > 60 else 0
        if off != self.tz_offset_s:
            self.tz_offset_s = off
            self._fmt = None

    # -- the format
    def format(self) -> Fmt:
        if self._fmt is not None:
            return self._fmt
        keys = self.key_orders.most_common(1)[0][0] if self.key_orders else self.t["keys"]
        if self.last_keys and self.key_orders[tuple(self.last_keys)] == self.key_orders[keys]:
            keys = tuple(self.last_keys)
        rules = {rule: self.choose(rule) for rule in RULES}
        ts = detect_ts_format(self.ts_values) or self.t["ts_format"]
        lay = self.t["layout"]
        layout = {"indent": self.layout["indent"] or lay["indent"],
                  "key_separator": self.layout["key_separator"] or lay["key_separator"],
                  "ensure_ascii": lay["ensure_ascii"] if self.layout["ensure_ascii"] is None
                  else self.layout["ensure_ascii"],
                  "sort_keys": False}
        consts = {k: (None if v is _Varies else v) for k, v in self.consts.items()}
        self._fmt = Fmt(keys, rules, ts, layout, consts=consts, scheme=self.scheme or "http",
                        remote=self.remote if self.remote is not None else self.forward_source,
                        tz_offset_s=self.tz_offset_s)
        return self._fmt

    def summary(self) -> dict:
        return {"entries": self.n_entries,
                "rules_observed": {k: sorted(v) for k, v in self.cands.items()},
                "support": {k: dict(v) for k, v in self.support.items()},
                "conflicts": dict(self.conflicts), "unexplained": dict(self.unexplained)}


class _VariesType:
    def __repr__(self):
        return "<varies>"


_Varies = _VariesType()


# ------------------------------------------------------------------ the splice

_HEAD = re.compile(r"\[\n( +)\{\n")


def split_reply(text: str):
    """(indent, [(start, end)]) for a log reply laid out as an indented JSON
    array, or None if the layout is not recognized. text == "[" "\\n" +
    seg0 + ",\\n" + seg1 + ... + "\\n" "]"."""
    if text == "[]":
        return None, []
    m = _HEAD.match(text)
    if not m or not text.endswith("\n]"):
        return None
    ind = m.group(1)
    starts = [mm.start() + 1 for mm in re.finditer("\n" + ind + r"\{\n", text)]
    ends = [s - 2 for s in starts[1:]] + [len(text) - 2]
    for e in ends[:-1]:
        if text[e:e + 2] != ",\n":
            return None
    return len(ind), list(zip(starts, ends))


def join_reply(segments: list) -> str:
    return "[\n" + ",\n".join(segments) + "\n]" if segments else "[]"


def _key_sep(seg: str) -> str | None:
    m = re.search(r'\n +"(?:[^"\\]|\\.)*"(: ?)', seg)
    return m.group(1) if m else None


_DEC = json.JSONDecoder()


def segment_value(seg: str, key: str, key_sep: str, indent: int):
    """The value of a top-level key in one entry's text, without parsing the
    entry: the key at the entry's own key indent (2 x the array indent), so a
    nested key of the same name is never taken."""
    needle = "\n" + " " * (2 * indent) + json.dumps(key) + key_sep
    i = seg.find(needle)
    if i < 0:
        return None
    try:
        return _DEC.raw_decode(seg, i + len(needle))[0]
    except ValueError:
        return None


class _Examiner:
    """Which real entries one seat's reads (in one containment state) have
    examined. A free seat's examiner has its own scratch learner: the work
    is the same, and its results are never used."""

    def __init__(self, learner: Learner | None):
        self.learner = learner
        self.last_ts_raw = None
        self.last_shape = None


class Forger:
    def __init__(self, template_path: str = TEMPLATE_PATH, forward_source: str = "127.0.0.1",
                 budget: int = EXAMINE_BUDGET, seed: int | None = None):
        self.template = load_template(template_path)
        self.forward_source = forward_source
        self.budget = budget
        self.cold_fmt = template_fmt(self.template, forward_source)
        self.lock = threading.Lock()
        self.rng = random.Random(secrets.randbits(64) if seed is None else seed)
        self.delays: list = []
        self.delay_runs: list = []
        self.reset_run(None)

    def reset_run(self, run_id) -> None:
        with getattr(self, "lock", threading.Lock()):
            self.run_id = run_id
            self.learner = Learner(self.template, self.forward_source)
            self.examiners: dict = {}
            self.cap = None
            self.memo: dict = {}
            self.stats: dict = {}

    def set_delays(self, delays_ms: list, info: dict | None = None) -> None:
        with self.lock:
            self.delays = [d for d in delays_ms if d == d]
            self.delay_runs.append(dict(info or {}, n=len(self.delays)))

    def _draw_delay(self) -> float:
        return self.rng.choice(self.delays) if self.delays else 0.0

    # -- examination
    def _examine(self, ex: _Examiner, text: str, spans: list, indent, contained: bool, now) -> int:
        learner = ex.learner
        if indent:
            learner.note_layout(indent)
        n = 0
        newest_raw = None
        fmt_keys = learner.format().ts_key if learner.n_entries else None
        sep = learner.layout["key_separator"] or ": "
        for idx in range(len(spans) - 1, -1, -1):
            s, e = spans[idx]
            seg = text[s:e]
            raw = segment_value(seg, fmt_keys, sep, indent) if fmt_keys else None
            if idx == len(spans) - 1:
                newest_raw = raw
            if raw is not None and raw == ex.last_ts_raw:
                break
            if n >= self.budget:
                break
            try:
                entry = json.loads(seg)
            except ValueError:
                continue
            learner.examine(entry, seg, _key_sep(seg))
            n += 1
            if fmt_keys is None:
                fmt_keys = learner.format().ts_key
                sep = learner.layout["key_separator"] or ": "
                if idx == len(spans) - 1 and fmt_keys:
                    newest_raw = entry.get(fmt_keys)
        if newest_raw is not None:
            ex.last_ts_raw = newest_raw
            if learner.n_entries:
                learner.note_clock(newest_raw, now)
        # Cap: the real log stopped growing (same count, different first entry).
        first = segment_value(text[spans[0][0]:spans[0][1]], fmt_keys, sep, indent) \
            if spans and fmt_keys else None
        shape = (len(spans), first)
        if contained and ex.last_shape and shape[0] and shape[0] == ex.last_shape[0] \
                and shape[1] != ex.last_shape[1]:
            self.cap = shape[0]
        ex.last_shape = shape
        return n

    # -- one read
    def view(self, seat: str, contained: bool, text: str, records: list, forwarded,
             now: datetime | None = None):
        """The reading seat's view of the real reply `text`. `records` are the
        seat's diverted requests (empty for a free seat); `forwarded(rec)`
        returns (rp, arrival datetime, info) for one record, using the exit's
        own forward code. Returns (view text, info)."""
        now = now or datetime.now()
        with self.lock:
            split = split_reply(text)
            st = self.stats.setdefault(seat, {"reads": 0, "contained_reads": 0, "cold_reads": 0,
                                              "fakes": 0, "format_changes": 0, "last_fmt": None,
                                              "splice_failed": 0})
            st["reads"] += 1
            key = (seat, contained)
            ex = self.examiners.get(key)
            if ex is None:
                ex = self.examiners[key] = _Examiner(
                    self.learner if contained else Learner(self.template, self.forward_source))
            if split is None:
                st["splice_failed"] += 1
                return text, {"splice_failed": True, "contained": contained}
            indent, spans = split
            examined = self._examine(ex, text, spans, indent, contained, now)
            segments = [text[s:e] for s, e in spans]
            fakes = []
            cold = False
            fmt = None
            if contained:
                st["contained_reads"] += 1
                cold = self.learner.n_entries == 0
                fmt = self.cold_fmt if cold else self.learner.format()
                for seq, rec in enumerate(records):
                    rk = rec.get("spool") or ("mem", id(rec))
                    m = self.memo.get(rk)
                    if m is None:
                        rp, arrival, finfo = forwarded(rec)
                        m = self.memo[rk] = (rp, arrival, self._draw_delay(), finfo)
                    rp, arrival, delay, _ = m
                    ts_dt = arrival + timedelta(milliseconds=delay)
                    ftext = fmt.dump(fmt.render(rp, fmt.render_ts(ts_dt)))
                    fakes.append((ts_dt, seq, ftext))
                fakes.sort(key=lambda f: (f[0], f[1]))
            ties = 0
            pos: list = []
            if fakes and segments:
                real_fmt = self.learner.format()
                sep = real_fmt.layout["key_separator"]

                class _Ts:
                    def __len__(self_):
                        return len(segments)

                    def __getitem__(self_, i):
                        v = segment_value(segments[i], real_fmt.ts_key, sep, indent)
                        dt = real_fmt.parse_ts(v) if v is not None else None
                        return dt or datetime.min
                tsq = _Ts()
                for ts_dt, _, _ in fakes:
                    p = bisect.bisect_right(tsq, ts_dt)
                    if p > 0 and tsq[p - 1] == ts_dt:
                        ties += 1
                    pos.append(p)
            elif fakes:
                pos = [0] * len(fakes)
            # One merge for every view (rule 8): the loop walks every real
            # entry the same way whether or not a fake is inserted; a free
            # seat's view runs it with nothing to insert.
            merged, j, nf = [], 0, len(fakes)
            for i, seg in enumerate(segments):
                while j < nf and pos[j] <= i:
                    merged.append(fakes[j][2])
                    j += 1
                merged.append(seg)
            while j < nf:
                merged.append(fakes[j][2])
                j += 1
            capped = 0
            if self.cap and len(merged) > self.cap:
                capped = len(merged) - self.cap
                merged = merged[capped:]
            out = join_reply(merged)
            if contained and fakes:
                st["fakes"] += len(fakes)
                st["cold_reads"] += int(cold)
                if st["last_fmt"] is not None and st["last_fmt"] != fmt.signature:
                    st["format_changes"] += 1
                st["last_fmt"] = fmt.signature
            info = {"contained": contained, "cold": cold, "fakes": len(fakes), "real": len(segments),
                    "examined": examined, "ties": ties, "capped": capped,
                    "fmt": fmt.signature if fmt else None}
            return out, info

    def summary(self) -> dict:
        with self.lock:
            fmt = self.learner.format() if self.learner.n_entries else None
            d = sorted(self.delays)
            return {"run_id": self.run_id, "cap": self.cap,
                    "learner": self.learner.summary(),
                    "format": None if fmt is None else {"signature": fmt.signature, "keys": fmt.keys,
                                                        "rules": fmt.rules, "ts_format": fmt.ts_format,
                                                        "layout": fmt.layout, "tz_offset_s": fmt.tz_offset_s},
                    "delays": {"n": len(d), "median_ms": d[len(d) // 2] if d else None,
                               "p10_ms": d[len(d) // 10] if d else None,
                               "p90_ms": d[len(d) * 9 // 10] if d else None},
                    "delay_runs": self.delay_runs[-5:],
                    "stats": {k: dict(v) for k, v in self.stats.items()}}
