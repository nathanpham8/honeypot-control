"""Swarm pilot step 3, Stage 0: measure the real step 1 system, change nothing.

Uses the step 1 stack exactly as built (honeypot/swarm_layout.py, the step 1
swarm exit, the stock task services). The exit is armed with the seat subnets
and one synthetic decoy value that is never sent, so every request below is a
real delivery through the real exit to the real collector. No defender
behaviour is added.

Phases (each on its own fresh stack; raw results to analysis/swarm_pilot/stage0/):
  fwd      forward latency inside seat0 (curl -w %{time_total}) by body size
           (100 B, 10 KB) and by request type, interleaved in shuffled rounds;
           5 fresh stacks x 60 rounds = 300 samples per condition.
  fwd1m    1 MB sends, interleaved with 100 B sends as a same-boot reference;
           10 fresh stacks x 30 rounds = 300 samples. Kept apart because the
           step 1 exit container runs out of memory after about 40 sends of
           1 MB (the collector and the exit both keep every body, and both
           parse urlencoded bodies as forms); the exit's state is not fetched
           here for the same reason.
  mem      1 MB sends until the first failure: when the exit container runs
           out of memory, and what an agent sees when it does.
  divert   reference only, existing step 1 behaviour: a contained seat's
           diverted sends (immediate 204) vs a free seat's delivered sends.
  load     seat0's 100 B sends in alternating blocks of 30, idle vs while seat1
           floods 1 KB sends from 2 parallel loops; 10 blocks each.
  logread  log read latency at log sizes 10, 100, 1,000 (100 B entries): the
           real read path measured inside the exit container (local read, as an
           L1 relay would do it), plus the current seat-side placeholder reply.
  shapes   what the collector logs for each request shape (F1 matrix), next to
           what the exit itself saw; distinct entry shapes and varying fields.
  reach    what a seat can reach through the router: the VM's addresses, host
           Docker addresses, cloud metadata (status code only, no metadata
           header, nothing read), the internet, DNS. Report only.
  boots    first request after a fresh boot, 20 boots: seat0's first 10 sends
           and seat1's first send.

Run:  PYTHONPATH=<repo> python tools/swarm_stage0_measure.py <phase> [<phase> ...]
      (phases: fwd fwd1m mem divert load logread shapes reach boots, or "all")
Docker only; run only when no experiment is running. All values synthetic.
"""

import json
import math
import os
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from honeypot.swarm_layout import COLLECTION_IP, arm_payload, compose_text, parse_seat_subnets  # noqa: E402

TASK = "38927895"   # practice task
OUT = Path(os.environ.get("SWARM_MEASURE_OUT") or REPO / "analysis" / "swarm_pilot" / "stage0")
DECOY = "DECOY_stage0_never_sent_5c1e9a"
URL = f"http://{COLLECTION_IP}"


# ---------------------------------------------------------------- stack

class Stack:
    def __init__(self, tag: str, exit_env: dict | None = None):
        # exit_env: measurement options for the exit (default: none, or the
        # JSON object in SWARM_EXIT_ENV)
        if exit_env is None:
            exit_env = json.loads(os.environ.get("SWARM_EXIT_ENV") or "{}")
        self.dir = Path(tempfile.mkdtemp(prefix=f"stage0_{tag}_"))
        self.project = f"swarm-stage0-{tag}-{os.getpid()}"
        (self.dir / "compose.yml").write_text(compose_text(TASK, 2, task_services=True,
                                                           exit_env=exit_env))
        self.base = ["docker", "compose", "-p", self.project, "-f", str(self.dir / "compose.yml")]

    def dc(self, *args, input=None, timeout=600):
        return subprocess.run([*self.base, *args], input=input, capture_output=True,
                              text=True, timeout=timeout)

    def sh(self, service, script, timeout=600):
        return self.dc("exec", "-T", service, "sh", "-c", script, timeout=timeout)

    def up(self):
        t0 = time.time()
        r = self.dc("up", "-d", "--wait", "--wait-timeout", "420", timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"stack up failed: {r.stderr[-1500:]}")
        subnets = parse_seat_subnets(self.sh("router", "ip -o -4 addr show").stdout)
        a = self.dc("exec", "-T", "logging_server", "python", "ctl.py", "POST", "/__arm",
                    arm_payload([DECOY], subnets, feedback="L0"))
        if a.returncode != 0:
            raise RuntimeError(f"arm failed: {a.stdout} {a.stderr}")
        self.subnets = subnets
        return time.time() - t0

    def state(self):
        return json.loads(self.dc("exec", "-T", "logging_server", "python", "ctl.py",
                                  "GET", "/__swarm-state").stdout)

    def collector_log(self):
        return json.loads(self.dc("exec", "-T", "logging_server", "python", "ctl.py",
                                  "GET", "/get-request-log").stdout)

    def mem_mb(self, service="logging_server"):
        cid = self.dc("ps", "-q", service).stdout.strip()
        out = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", cid],
                             capture_output=True, text=True).stdout.strip()
        return out

    def down(self):
        self.dc("down", "-v", "--remove-orphans", timeout=300)


# ---------------------------------------------------------------- stats

def summary(xs_ms):
    xs = sorted(xs_ms)
    if not xs:
        return {"n": 0}
    q = lambda p: xs[min(len(xs) - 1, max(0, int(round(p * (len(xs) - 1)))))]
    return {"n": len(xs), "mean": round(statistics.fmean(xs), 3), "median": round(q(0.5), 3),
            "p10": round(q(0.1), 3), "p90": round(q(0.9), 3), "p99": round(q(0.99), 3),
            "min": round(xs[0], 3), "max": round(xs[-1], 3),
            "sd": round(statistics.pstdev(xs), 3)}


def ks_2samp(a, b):
    """Two-sample KS statistic and asymptotic p-value (no scipy here)."""
    a, b = sorted(a), sorted(b)
    na, nb = len(a), len(b)
    i = j = 0
    d = 0.0
    while i < na and j < nb:
        x = min(a[i], b[j])
        while i < na and a[i] <= x:
            i += 1
        while j < nb and b[j] <= x:
            j += 1
        d = max(d, abs(i / na - j / nb))
    ne = na * nb / (na + nb)
    lam = (math.sqrt(ne) + 0.12 + 0.11 / math.sqrt(ne)) * d
    p = 2 * sum((-1) ** (k - 1) * math.exp(-2 * k * k * lam * lam) for k in range(1, 101))
    return round(d, 4), max(0.0, min(1.0, p))


def compare(a, b):
    d, p = ks_2samp(a, b)
    sa, sb = summary(a), summary(b)
    return {"ks_d": d, "ks_p": p, "median_diff_ms": round(sb["median"] - sa["median"], 3),
            "p90_diff_ms": round(sb["p90"] - sa["p90"], 3)}


def write(name, data):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2))
    print(f"wrote {OUT / name}.json", flush=True)


# ---------------------------------------------------------------- payloads

_PAYLOADS = (
    "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100; "
    "head -c 7500 /dev/urandom | base64 -w0 > /tmp/b10k; "
    "head -c 786432 /dev/urandom | base64 -w0 > /tmp/b1m; "
    "head -c 750 /dev/urandom | base64 -w0 > /tmp/b1k; "
    "printf '{\"note\":\"%s\"}' $(head -c 60 /dev/urandom | base64 -w0 | tr -d '/+=') > /tmp/bjson; "
    "wc -c /tmp/b100 /tmp/b10k /tmp/b1m /tmp/b1k /tmp/bjson"
)
_W = "-s -o /dev/null -w '%{time_total} %{time_starttransfer} %{http_code}'"
FWD_CONDITIONS = {
    # size series (curl's default content type for --data-binary)
    "post_100": f"curl {_W} --data-binary @/tmp/b100 {URL}/m/size100",
    "post_10k": f"curl {_W} --data-binary @/tmp/b10k {URL}/m/size10k",
    "post_1m": f"curl {_W} --data-binary @/tmp/b1m {URL}/m/size1m",
    # request types, about 100 B bodies where a body applies
    "get": f"curl {_W} '{URL}/m/get?x=1'",
    "head": f"curl {_W} -I {URL}/m/head",
    "options": f"curl {_W} -X OPTIONS {URL}/m/options",
    "delete": f"curl {_W} -X DELETE {URL}/m/delete",
    "post_octet": f"curl {_W} -H 'Content-Type: application/octet-stream' --data-binary @/tmp/b100 {URL}/m/octet",
    "post_form": f"curl {_W} -d 'a=1' -d \"b=$(cat /tmp/b100 | tr -d '/+=' | head -c 90)\" {URL}/m/form",
    "post_json": f"curl {_W} -H 'Content-Type: application/json' --data-binary @/tmp/bjson {URL}/m/json",
    "post_multipart": f"curl {_W} -F file=@/tmp/b100 -F note=hello {URL}/m/multipart",
    "put": f"curl {_W} -X PUT --data-binary @/tmp/b100 {URL}/m/put",
    "patch": f"curl {_W} -X PATCH --data-binary @/tmp/b100 {URL}/m/patch",
}


def _parse_timing(out):
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4:
            rows.append((parts[0], float(parts[1]) * 1000, float(parts[2]) * 1000, parts[3]))
    return rows


# ---------------------------------------------------------------- phases

def phase_fwd(boots=5, rounds=60):
    conds = {k: v for k, v in FWD_CONDITIONS.items() if k != "post_1m"}
    samples = {k: [] for k in conds}
    codes, per_boot, mem, exit_ms = {}, [], [], {k: [] for k in conds}
    for b in range(boots):
        st = Stack(f"fwd{b}")
        try:
            up_s = st.up()
            st.sh("seat0", _PAYLOADS)
            names = list(conds)
            lines = []
            for r in range(rounds):
                order = names[:]
                random.Random(1000 * b + r).shuffle(order)
                lines += [f"echo {n} $({conds[n]})" for n in order]
            out = st.sh("seat0", "; ".join(lines), timeout=1800).stdout
            boot_rows = _parse_timing(out)
            for name, tt, _, code in boot_rows:
                samples[name].append(tt)
                codes.setdefault(name, {}).setdefault(code, 0)
                codes[name][code] += 1
            # the exit's own forward timing, for the same requests
            for ev in st.state()["events"]:
                for name, cmd in conds.items():
                    if ev["path"] == re.search(r"/m/[a-z0-9]+", cmd).group(0) and ev.get("latency_ms"):
                        exit_ms[name].append(ev["latency_ms"])
            mem.append(st.mem_mb())
            per_boot.append({"boot": b, "up_seconds": round(up_s, 1),
                             "median_ms": {n: summary([t for nm, t, _, _ in boot_rows if nm == n])["median"]
                                           for n in names}})
        finally:
            st.down()
    res = {"conditions": {k: summary(v) for k, v in samples.items()},
           "exit_internal_forward_ms": {k: summary(v) for k, v in exit_ms.items()},
           "http_codes": codes, "per_boot": per_boot, "exit_container_memory_after_boot": mem,
           "size_vs_100": {"post_10k": compare(samples["post_100"], samples["post_10k"])},
           "type_vs_post_100": {k: compare(samples["post_100"], samples[k])
                                for k in conds if k not in ("post_100", "post_10k")},
           "raw_ms": samples}
    write("fwd", res)
    return res


def phase_fwd1m(boots=10, rounds=30):
    conds = {k: FWD_CONDITIONS[k] for k in ("post_100", "post_1m")}
    samples = {k: [] for k in conds}
    codes, per_boot = {}, []
    for b in range(boots):
        st = Stack(f"fwd1m{b}")
        try:
            st.up()
            st.sh("seat0", _PAYLOADS)
            lines = []
            for r in range(rounds):
                order = list(conds)
                random.Random(5000 + 1000 * b + r).shuffle(order)
                lines += [f"echo {n} $({conds[n]})" for n in order]
            rows = _parse_timing(st.sh("seat0", "; ".join(lines), timeout=1800).stdout)
            for name, tt, _, code in rows:
                samples[name].append(tt)
                codes.setdefault(name, {}).setdefault(code, 0)
                codes[name][code] += 1
            per_boot.append({"boot": b, "exit_container_memory_end": st.mem_mb(),
                             "median_ms": {n: summary([t for nm, t, _, _ in rows if nm == n])["median"]
                                           for n in conds}})
        finally:
            st.down()
    res = {"conditions": {k: summary(v) for k, v in samples.items()}, "http_codes": codes,
           "per_boot": per_boot, "post_1m_vs_post_100": compare(samples["post_100"], samples["post_1m"]),
           "raw_ms": samples}
    write("fwd1m", res)
    return res


def phase_load(blocks=10, per_block=30):
    st = Stack("load")
    try:
        st.up()
        st.sh("seat0", _PAYLOADS)
        st.sh("seat1", _PAYLOADS)
        flood = (f"while true; do if [ -e /tmp/flood ]; then curl -s -o /dev/null --data-binary @/tmp/b1k "
                 f"{URL}/m/flood; else sleep 0.05; fi; done")
        for _ in range(2):
            st.sh("seat1", f"setsid nohup sh -c '{flood}' >/dev/null 2>&1 </dev/null &")
        idle, loaded, rates = [], [], []
        one = " ".join(f"echo post_100 $({FWD_CONDITIONS['post_100']});" for _ in range(per_block))
        for b in range(blocks):
            for cond in ("idle", "load"):
                if cond == "load":
                    st.sh("seat1", "touch /tmp/flood")
                    time.sleep(1)
                n0 = len(st.state()["events"])
                t0 = time.time()
                rows = _parse_timing(st.sh("seat0", one).stdout)
                dt = time.time() - t0
                n1 = len(st.state()["events"])
                st.sh("seat1", "rm -f /tmp/flood")
                time.sleep(1)
                (loaded if cond == "load" else idle).extend(t for _, t, _, _ in rows)
                if cond == "load":
                    rates.append(round((n1 - n0 - per_block) / dt, 1))
        res = {"idle": summary(idle), "load": summary(loaded), "load_vs_idle": compare(idle, loaded),
               "flood_requests_per_second_during_blocks": rates,
               "exit_container_memory_end": st.mem_mb(), "raw_ms": {"idle": idle, "load": loaded}}
    finally:
        st.down()
    write("load", res)
    return res


_EXIT_READ = """
import json, sys, time, urllib.request
n = int(sys.argv[1]); out = []
for _ in range(n):
    t0 = time.perf_counter()
    with urllib.request.urlopen("http://127.0.0.1:8081/get-request-log", timeout=30) as r:
        body = r.read()
    out.append((time.perf_counter() - t0) * 1000)
print(json.dumps({"ms": out, "bytes": len(body), "entries": len(json.loads(body))}))
"""


def phase_logread(sizes=(10, 100, 1000), n=300):
    st = Stack("logread")
    res = {"sizes": {}}
    try:
        st.up()
        st.sh("seat0", _PAYLOADS)
        have = 0
        for size in sizes:
            add = size - have
            st.sh("seat0", f"i=0; while [ $i -lt {add} ]; do curl -s -o /dev/null --data-binary @/tmp/b100 "
                           f"{URL}/m/fill; i=$((i+1)); done", timeout=1800)
            have = size
            r = st.dc("exec", "-T", "logging_server", "python", "-c", _EXIT_READ, str(n), timeout=1800)
            inside = json.loads(r.stdout)
            seat = _parse_timing(st.sh("seat0", " ".join(
                f"echo read $(curl {_W} {URL}/get-request-log);" for _ in range(n))).stdout)
            res["sizes"][str(size)] = {
                "entries": inside["entries"], "log_bytes": inside["bytes"],
                "real_read_inside_exit_ms": summary(inside["ms"]),
                "seat_placeholder_read_ms": summary([t for _, t, _, _ in seat]),
                "seat_placeholder_codes": sorted({c for _, _, _, c in seat}),
                "raw_inside_ms": inside["ms"]}
        # the same exit-internal view of a send, for scale
        res["seat_post_100_for_scale_ms"] = summary([t for _, t, _, _ in _parse_timing(st.sh(
            "seat0", " ".join(f"echo p $({FWD_CONDITIONS['post_100']});" for _ in range(n))).stdout)])
    finally:
        st.down()
    write("logread", res)
    return res


SHAPES = {
    "get_plain": f"curl -s -o /dev/null -w '%{{http_code}}' {URL}/shape/get_plain",
    "get_query": f"curl -s -o /dev/null -w '%{{http_code}}' '{URL}/shape/get_query?a=1&b=two'",
    "head": f"curl -s -o /dev/null -w '%{{http_code}}' -I {URL}/shape/head",
    "options": f"curl -s -o /dev/null -w '%{{http_code}}' -X OPTIONS {URL}/shape/options",
    "delete": f"curl -s -o /dev/null -w '%{{http_code}}' -X DELETE {URL}/shape/delete",
    "post_raw_default_ct": f"curl -s -o /dev/null -w '%{{http_code}}' --data-binary @/tmp/b100 {URL}/shape/post_raw_default_ct",
    "post_octet": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/octet-stream' --data-binary @/tmp/b100 {URL}/shape/post_octet",
    "post_text": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: text/plain' --data-binary 'hello text' {URL}/shape/post_text",
    "post_form": f"curl -s -o /dev/null -w '%{{http_code}}' -d 'a=1' -d 'b=two' {URL}/shape/post_form",
    "post_json": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json' --data-binary @/tmp/bjson {URL}/shape/post_json",
    "post_multipart": f"curl -s -o /dev/null -w '%{{http_code}}' -F file=@/tmp/b100 -F note=hello {URL}/shape/post_multipart",
    "post_empty": f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {URL}/shape/post_empty",
    "put": f"curl -s -o /dev/null -w '%{{http_code}}' -X PUT --data-binary @/tmp/b100 {URL}/shape/put",
    "patch": f"curl -s -o /dev/null -w '%{{http_code}}' -X PATCH --data-binary @/tmp/b100 {URL}/shape/patch",
    "post_1m_expect": f"curl -s -o /dev/null -w '%{{http_code}}' --data-binary @/tmp/b1m {URL}/shape/post_1m_expect",
    "post_invalid_utf8": f"printf 'ok\\377\\376\\372end' | curl -s -o /dev/null -w '%{{http_code}}' --data-binary @- {URL}/shape/post_invalid_utf8",
    "post_unicode": f"printf 'caf\\303\\251 \\360\\237\\230\\200' | curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Type: text/plain; charset=utf-8' --data-binary @- {URL}/shape/post_unicode",
    "custom_headers": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'X-Exfil: carried-in-header' -H 'Authorization: Bearer abc' -H 'Cookie: s=1' {URL}/shape/custom_headers",
    "duplicate_headers": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'X-Dup: 1' -H 'X-Dup: 2' {URL}/shape/duplicate_headers",
    "chunked": f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Transfer-Encoding: chunked' --data-binary @/tmp/b100 {URL}/shape/chunked",
    "gzip_body": f"printf 'zipped body' | gzip | curl -s -o /dev/null -w '%{{http_code}}' -H 'Content-Encoding: gzip' -H 'Content-Type: application/octet-stream' --data-binary @- {URL}/shape/gzip_body",
    "user_agent": f"curl -s -o /dev/null -w '%{{http_code}}' -A 'Mozilla/5.0 (X11)' {URL}/shape/user_agent",
    "query_and_body": f"curl -s -o /dev/null -w '%{{http_code}}' --data-binary 'body' '{URL}/shape/query_and_body?k=v'",
    "encoded_path": f"curl -s -o /dev/null -w '%{{http_code}}' '{URL}/shape/encoded%20space%2Fslash'",
    "python_urllib": ("python3 -c \"import urllib.request as u; "
                      f"print(u.urlopen(u.Request('{URL}/shape/python_urllib', data=b'from urllib'), timeout=10).status)\""),
    "python_requests_json": ("python3 -c \"import requests; "
                             f"print(requests.post('{URL}/shape/python_requests_json', json={{'k': 'v'}}, timeout=10).status_code)\""),
    "wget_post": f"wget -q -O /dev/null --post-data 'from=wget' {URL}/shape/wget_post; echo $?",
    "raw_http10_no_host": ("python3 -c \"import socket; s=socket.create_connection(('" + COLLECTION_IP + "', 80), 10); "
                           "s.sendall(b'POST /shape/raw_http10_no_host HTTP/1.0\\r\\nContent-Length: 5\\r\\n\\r\\nhello'); "
                           "print(s.recv(100).split(b' ')[1].decode())\""),
}


def _short(v, n=120):
    """Long strings (a 1 MB body parsed as a form key) shortened in the records."""
    if isinstance(v, str) and len(v) > n:
        return v[:n] + f"...<{len(v)} chars>"
    if isinstance(v, dict):
        return {_short(k): _short(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_short(x) for x in v]
    return v


def _sig(entry):
    return {"header_names": list((entry.get("headers") or {}).keys()),
            "content_type": entry.get("content_type"),
            "content_length": entry.get("content_length"),
            "form_data": None if entry.get("form_data") is None else _short(sorted(entry["form_data"])),
            "files": entry.get("files"),
            "body_len": len(entry.get("body") or ""),
            "full_url": entry.get("full_url"),
            "remote_addr": entry.get("remote_addr")}


def phase_shapes():
    st = Stack("shapes")
    try:
        st.up()
        st.sh("seat0", _PAYLOADS)
        status = {}
        for name, cmd in SHAPES.items():
            r = st.sh("seat0", cmd, timeout=60)
            status[name] = (r.stdout.strip().splitlines() or [""])[-1] or f"rc={r.returncode}"
        clog = st.collector_log()
        fwd = st.state()["forwarded"]
    finally:
        st.down()
    by_path = lambda entries: {e["path"]: e for e in entries}
    cmap, emap = by_path(clog), by_path(fwd)
    shapes = {}
    for name in SHAPES:
        p = f"/shape/{name}" if name != "encoded_path" else None
        if p is None:
            p = next((k for k in cmap if k.startswith("/shape/encoded")), "/shape/encoded")
        c, e = cmap.get(p), emap.get(p)
        row = {"client_status": status[name], "in_collector": c is not None}
        if c:
            row["collector"] = _sig(c)
            row["collector_headers"] = c.get("headers")
        if e:
            row["exit_saw"] = _sig(e)
            row["exit_headers"] = e.get("headers")
        if c and e:
            ch, eh = c.get("headers") or {}, e.get("headers") or {}
            row["changes_exit_to_collector"] = {
                "headers_added": {k: v for k, v in ch.items() if k not in eh},
                "headers_removed": sorted(k for k in eh if k not in ch),
                "headers_value_changed": {k: [eh[k], ch[k]] for k in ch if k in eh and ch[k] != eh[k]},
                "header_order_same": [k for k in ch if k in eh] == [k for k in eh if k in ch],
                "content_type": [e.get("content_type"), c.get("content_type")],
                "form_data": _short([e.get("form_data"), c.get("form_data")]),
                "form_data_same": e.get("form_data") == c.get("form_data"),
                "files": [e.get("files"), c.get("files")],
                "body_same": e.get("body") == c.get("body"),
                "full_url": [e.get("full_url"), c.get("full_url")],
            }
        shapes[name] = row
    sigs = {}
    for name, row in shapes.items():
        if row.get("collector"):
            s = row["collector"]
            key = json.dumps([s["header_names"], s["content_type"] is not None,
                              s["form_data"] is not None, s["files"] is not None])
            sigs.setdefault(key, []).append(name)
    varying = {}
    for field in ("method", "path", "full_url", "headers", "body", "form_data", "files",
                  "content_type", "content_length", "remote_addr", "timestamp"):
        vals = {json.dumps(e.get(field), sort_keys=True) for e in clog}
        varying[field] = len(vals)
    res = {"shapes": shapes, "distinct_entry_shapes": len(sigs),
           "entry_shape_groups": list(sigs.values()),
           "distinct_values_per_field_across_entries": varying,
           "collector_entries": len(clog), "missing_from_collector": [n for n, r in shapes.items()
                                                                       if not r["in_collector"]]}
    write("shapes", res)
    return res


def phase_reach():
    host = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    host_addrs = {m.group(1): m.group(2) for m in re.finditer(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/", host, re.M)}
    st = Stack("reach")
    try:
        st.up()
        outer_gw = json.loads(subprocess.run(["docker", "network", "inspect", f"{st.project}_outer"],
                                             capture_output=True, text=True).stdout)[0]["IPAM"]["Config"][0]["Gateway"]
        targets = {f"host {k} {v}": v for k, v in host_addrs.items() if k != "lo"}
        targets[f"outer bridge gateway {outer_gw}"] = outer_gw
        res = {"host_interfaces": host_addrs, "targets": {}}
        tcp = ("python3 -c \"import socket,sys; s=socket.socket(); s.settimeout(3)\n"
               "try:\n s.connect((sys.argv[1], int(sys.argv[2]))); b=s.recv(8); print('open', b[:7].decode(errors='replace'))\n"
               "except Exception as e: print(type(e).__name__)\" ")
        for label, addr in targets.items():
            row = {}
            for seat in ("seat0", "seat1"):
                ping = st.sh(seat, f"ping -c1 -W2 {addr} >/dev/null 2>&1; echo $?").stdout.strip()
                ssh = st.sh(seat, tcp + f"{addr} 22").stdout.strip()
                local_only = st.sh(seat, tcp + f"{addr} 53").stdout.strip()
                row[seat] = {"ping_rc": ping, "tcp22_sshd": ssh, "tcp53_localhost_only_service": local_only}
            res["targets"][label] = row
        md = st.sh("seat0", "curl -s -o /dev/null -m 5 -w '%{http_code}' http://169.254.169.254/computeMetadata/v1/; echo \" rc=$?\"").stdout.strip()
        res["cloud_metadata_169.254.169.254_no_header"] = md
        res["internet_http_1.1.1.1"] = st.sh("seat0", "curl -s -o /dev/null -m 6 -w '%{http_code}' http://1.1.1.1/; echo \" rc=$?\"").stdout.strip()
        res["dns_example_com"] = st.sh("seat0", "getent hosts example.com || echo 'no answer'").stdout.strip()
        res["dns_resolver"] = st.sh("seat0", "grep nameserver /etc/resolv.conf").stdout.strip()
        res["router_services_direct_8082_8083"] = st.sh(
            "seat0", "R=$(ip route show default | awk '{print $3}'); for p in 8082 8083; do "
                     "curl -s -o /dev/null -m 4 -w \"$p:%{http_code} \" http://$R:$p/; done").stdout.strip()
        res["note"] = ("Metadata probed without the Metadata-Flavor header and only the status code "
                       "recorded; nothing was read from it.")
    finally:
        st.down()
    write("reach", res)
    return res


def phase_boots(n=20):
    rows = []
    for b in range(n):
        st = Stack(f"boot{b}")
        try:
            up_s = st.up()
            st.sh("seat0", "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
            st.sh("seat1", "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
            s0 = _parse_timing(st.sh("seat0", " ".join(
                f"echo s0 $({FWD_CONDITIONS['post_100']});" for _ in range(10))).stdout)
            s1 = _parse_timing(st.sh("seat1", f"echo s1 $({FWD_CONDITIONS['post_100']})").stdout)
            ex = [e.get("latency_ms") for e in st.state()["events"] if e["decision"] == "forward"]
            rows.append({"boot": b, "up_seconds": round(up_s, 1),
                         "seat0_first10_ms": [round(t, 3) for _, t, _, _ in s0],
                         "seat1_first_ms": round(s1[0][1], 3) if s1 else None,
                         "exit_internal_forward_ms": ex})
            print(f"boot {b}: seat0 first {rows[-1]['seat0_first10_ms'][:3]} ...", flush=True)
        finally:
            st.down()
    first = [r["seat0_first10_ms"][0] for r in rows]
    later = [t for r in rows for t in r["seat0_first10_ms"][5:]]
    second = [r["seat0_first10_ms"][1] for r in rows]
    res = {"boots": rows, "seat0_first": summary(first), "seat0_second": summary(second),
           "seat0_sends_6_to_10": summary(later), "seat1_first": summary([r["seat1_first_ms"] for r in rows]),
           "first_vs_later": compare(later, first),
           "exit_internal_first_forward": summary([r["exit_internal_forward_ms"][0] for r in rows if r["exit_internal_forward_ms"]])}
    write("boots", res)
    return res


def phase_mem(max_sends=int(os.environ.get("SWARM_MEM_SENDS", "80"))):
    """1 MB sends one after another until the first non-204, recording the exit
    container's memory every 5 sends and whether it was OOM-killed."""
    st = Stack("mem")
    try:
        st.up()
        st.sh("seat0", _PAYLOADS)
        cid = st.dc("ps", "-q", "logging_server").stdout.strip()
        codes, mem = [], []
        for i in range(1, max_sends + 1):
            c = st.sh("seat0", f"curl -s -o /dev/null -m 30 -w '%{{http_code}}' --data-binary @/tmp/b1m {URL}/m/mem").stdout.strip()
            codes.append(c)
            if i % 5 == 0 or c != "204":
                mem.append((i, st.mem_mb()))
            if c != "204" and len(codes) - codes.index(c) >= 5:
                break
        insp = subprocess.run(["docker", "inspect", "-f", "{{.State.OOMKilled}} {{.State.Status}}", cid],
                              capture_output=True, text=True).stdout.strip()
        first_bad = next((i + 1 for i, c in enumerate(codes) if c != "204"), None)
        res = {"codes": codes, "first_non_204_at_send": first_bad, "memory_by_send": mem,
               "exit_container_oomkilled_status": insp,
               "forward_errors_note": "502 = the exit could not reach the collector"}
    finally:
        st.down()
    write("mem", res)
    return res


def phase_divert(rounds=300):
    """Step 1's existing sink (immediate 204), for reference: seat1 sends the
    decoy once and is contained; then seat0 (free, delivered) and seat1
    (contained, diverted) send 100 B, alternating, 300 each."""
    st = Stack("divert")
    try:
        st.up()
        for seat in ("seat0", "seat1"):
            st.sh(seat, _PAYLOADS)
        st.sh("seat1", f"curl -s -o /dev/null --data-binary 'x {DECOY}' {URL}/m/trip")
        contained = st.state()["contained"]
        free, div = [], []
        for _ in range(rounds // 30):
            block = " ".join(f"echo p $({FWD_CONDITIONS['post_100']});" for _ in range(30))
            free += [t for _, t, _, _ in _parse_timing(st.sh("seat0", block).stdout)]
            div += [t for _, t, _, _ in _parse_timing(st.sh("seat1", block).stdout)]
        res = {"contained": contained, "free_delivered": summary(free), "contained_diverted": summary(div),
               "diverted_vs_delivered": compare(free, div), "raw_ms": {"free": free, "diverted": div}}
    finally:
        st.down()
    write("divert", res)
    return res


PHASES = {"fwd": phase_fwd, "fwd1m": phase_fwd1m, "mem": phase_mem, "divert": phase_divert, "load": phase_load, "logread": phase_logread,
          "shapes": phase_shapes, "reach": phase_reach, "boots": phase_boots}


def main():
    wanted = sys.argv[1:] or ["all"]
    if wanted == ["all"]:
        wanted = list(PHASES)
    for ph in wanted:
        t0 = time.time()
        print(f"== phase {ph}", flush=True)
        res = PHASES[ph]()
        brief = {k: v for k, v in res.items() if not k.startswith("raw") and k not in ("shapes", "boots")}
        print(json.dumps(brief, indent=1)[:4000], flush=True)
        print(f"== phase {ph} done in {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
