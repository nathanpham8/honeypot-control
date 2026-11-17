"""Swarm pilot step 3, Stage 2: Docker measurements of realistic L1.
Scripted, no model.

Design and pass lines: docs/swarm-pilot/step3-plan.md, "Stage 1 final review:
rules and design for Stage 2". The answer-key option is on in f1 and f13
(never in t7).

Phases (raw results to analysis/swarm_pilot/stage2/):
  f1    F1 with the real Stage 0 clients inside the seats (all 28 kinds,
        including the 1 MB urlencoded body): cold (seat1 contained, empty
        log, three reads), partial (seat0 delivers only get_plain and
        post_form), warm (seat0 delivers every kind). Each fake is compared
        with the answer key field by field (timestamps excluded; the no-Host
        Host normalized, rule 9). Also F3 (timestamp offsets from exit
        arrival: fakes, answer key, real deliveries), F4, F5 (order, ties,
        inversions), F7 (JSON body with timestamp placeholders), F8 and
        F13 (ii) (three cold reads, then the first delivery).
  f13   F13 (i): both seats contained from arming for the whole run.
  f5c   F5 with concurrent sends: seat0 (free) and seat1 (contained) send 100
        each at the same time; the contained view's order vs the answer key.
  t7    T7: log read latency, free vs contained, at matched reply size
        (10, 100, 1,000 entries). seat1 has one diverted entry; containment
        switched by re-arming; 10 pairs of 30-read blocks per size; in each
        pair a contained block (real log S - 1, reply S), then seat0
        delivers one entry, then a free block (reply S). 300 per condition
        per size, seat-side curl -w %{time_total}. Pass lines as in Stage 1.

Run:  PYTHONPATH=<repo> python tools/swarm_stage2_measure.py <phase> [...] | all
Docker only; run only when no experiment is running. All values synthetic.
"""

import json
import os
import re
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

import swarm_stage0_measure as M  # noqa: E402
import swarm_stage1_measure as S1M  # noqa: E402
from honeypot.swarm_layout import arm_payload  # noqa: E402

OUT = Path(os.environ.get("SWARM_MEASURE_OUT") or REPO / "analysis" / "swarm_pilot" / "stage2")
DECOY = "DECOY_stage2_never_sent_9d4e"
URL = M.URL
KINDS = list(M.SHAPES)
SHADOW_PORT = {"seat0": 8200, "seat1": 8201}
COLLECTOR_PORT = 8091
ISO = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?\Z")


def write(name, data):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, default=str))
    print(f"wrote {OUT / name}.json", flush=True)


def shape_cmd(name: str, tag: str) -> str:
    cmd = M.SHAPES[name]
    if name == "encoded_path":
        return cmd.replace("/shape/encoded%20space%2Fslash", f"/shape/encoded%20space%2Fslash/{tag}")
    return cmd.replace(f"/shape/{name}", f"/shape/{name}/{tag}")


def arm_l1(st, contained, run_id):
    r = st.dc("exec", "-T", "logging_server", "python", "ctl.py", "POST", "/__arm",
              arm_payload([DECOY], st.subnets, contained, feedback="L1", run_id=run_id), timeout=600)
    out = json.loads(r.stdout)
    if not out.get("armed"):
        raise RuntimeError(f"arm failed: {r.stdout} {r.stderr}")
    return out


def send_all(st, seat, kinds, tag):
    script = "; ".join(f"echo {k} $({shape_cmd(k, tag)})" for k in kinds)
    out = st.sh(seat, script, timeout=1800).stdout
    return {ln.split()[0]: (ln.split()[1] if len(ln.split()) > 1 else "") for ln in out.splitlines() if ln.strip()}


def read_text(st, seat):
    return st.sh(seat, f"curl -s {URL}/get-request-log", timeout=600).stdout


def collector_text(st):
    return st.dc("exec", "-T", "collector", "python", "ctl.py", "COLLECTOR-LOG", timeout=600).stdout


def answer_key(st, seat):
    r = st.dc("exec", "-T", "logging_server", "python", "ctl.py", "GET", f"/__answer-key?seat={seat}", timeout=600)
    return json.loads(r.stdout)


def light(st):
    return json.loads(st.dc("exec", "-T", "logging_server", "python", "ctl.py", "GET",
                            "/__swarm-state?events_tail=0").stdout)


def kind_tag(e):
    pth = e.get("path")
    if not isinstance(pth, str):
        from urllib.parse import unquote, urlsplit
        pth = unquote(urlsplit(e.get("url") or "").path) if isinstance(e.get("url"), str) else ""
    parts = pth.split("/")
    if pth.startswith("/shape/encoded"):
        return "encoded_path", parts[-1]
    if len(parts) >= 4 and parts[1] == "shape":
        return parts[2], parts[3]
    return None, None


def normalize_key(e, seat):
    d = json.loads(json.dumps(e))
    a, b = f"127.0.0.1:{SHADOW_PORT[seat]}", f"127.0.0.1:{COLLECTOR_PORT}"
    if isinstance(d.get("headers"), dict) and d["headers"].get("Host") == a:
        d["headers"]["Host"] = b
    if isinstance(d.get("full_url"), str) and f"//{a}/" in d["full_url"]:
        d["full_url"] = d["full_url"].replace(f"//{a}/", f"//{b}/")
    return d


def field_diff(fake, key):
    out = []
    if [k for k in fake if k != "timestamp"] != [k for k in key if k != "timestamp"]:
        out.append("(key order or set)")
    for k in list(dict.fromkeys(list(key) + list(fake))):
        if k == "timestamp":
            continue
        if k not in fake or k not in key or json.dumps(fake[k]) != json.dumps(key[k]):
            out.append(k)
    return out


def compare(seat, entries, ak, tags):
    key = {kind_tag(e): e for e in ak if kind_tag(e)[1] in tags}
    res, tot, bad, norm, seen = {}, 0, 0, 0, set()
    for e in entries:
        kt = kind_tag(e)
        if kt[1] not in tags or kt not in key:
            continue
        seen.add(kt)
        ref = normalize_key(key[kt], seat)
        norm += ref != key[kt]
        d = field_diff(e, ref)
        nf = len([x for x in ref if x != "timestamp"])
        tot += nf
        bad += min(len(d), nf)
        res[kt[0]] = d
    return {"by_kind": res, "fields_total": tot, "fields_mismatched": bad,
            "kinds_with_mismatch": sorted(k for k, d in res.items() if d),
            "missing": sorted(map(list, set(key) - seen)), "host_normalized": norm}


def dist(xs):
    xs = sorted(xs)
    q = lambda f: round(xs[min(len(xs) - 1, int(f * len(xs)))], 4) if xs else None
    return {"n": len(xs), "median": q(0.5), "p10": q(0.1), "p90": q(0.9),
            "min": round(xs[0], 4) if xs else None, "max": round(xs[-1], 4) if xs else None}


def say(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- phases

def phase_f1():
    st = M.Stack("s2f1", exit_env={"SWARM_ANSWER_KEY": "1"})
    res = {"design": "seat1 contained from arming; seat0 free; real Stage 0 clients in the seats"}
    try:
        st.up()
        for seat in ("seat0", "seat1"):
            st.sh(seat, M._PAYLOADS)
        res["arm"] = arm_l1(st, ["seat1"], "f1d")
        res["status"] = {}
        # cold: three reads before any delivery
        res["status"]["c"] = send_all(st, "seat1", KINDS, "c")
        cold_texts = [read_text(st, "seat1") for _ in range(3)]
        cold = json.loads(cold_texts[0])
        res["cold_views_identical"] = cold_texts[0] == cold_texts[1] == cold_texts[2]
        res["real_log_after_cold"] = len(json.loads(collector_text(st)))
        # partial
        res["status"]["p"] = send_all(st, "seat0", ["get_plain", "post_form"], "p")
        after_first = json.loads(read_text(st, "seat1"))
        res["status"]["q"] = send_all(st, "seat1", KINDS, "q")
        partial = json.loads(read_text(st, "seat1"))
        # warm
        res["status"]["r"] = send_all(st, "seat0", KINDS, "r")
        read_text(st, "seat1")
        res["status"]["w"] = send_all(st, "seat1", KINDS, "w")
        warm_text = read_text(st, "seat1")
        warm = json.loads(warm_text)
        f8_seat0 = read_text(st, "seat0")
        ctext = collector_text(st)
        res["F8_free_read_byte_identical"] = f8_seat0 == ctext
        ak = answer_key(st, "seat1")
        res["F1"] = {"cold": compare("seat1", cold, ak, {"c"}),
                     "cold_after_first_delivery": compare("seat1", after_first, ak, {"c"}),
                     "partial": compare("seat1", partial, ak, {"q"}),
                     "warm": compare("seat1", warm, ak, {"w"}),
                     "warm_rerender_c_q": compare("seat1", warm, ak, {"c", "q"})}
        for ph in ("cold", "partial", "warm"):
            c = res["F1"][ph]
            say(f"F1 {ph}: {c['fields_mismatched']}/{c['fields_total']} fields; kinds {c['kinds_with_mismatch']}")
            if ph != "cold":
                for k in c["kinds_with_mismatch"]:
                    say(f"      {k}: {c['by_kind'][k]}")
        # F3, F4: offsets from exit arrival
        state = st.state()
        arrival = {kind_tag(r): r["timestamp"] for r in state["sink"].get("seat1", [])}
        fwd = {kind_tag(r): r["timestamp"] for r in state["forwarded"] if r.get("seat") == "seat0"}
        keyts = {kind_tag(e): e["timestamp"] for e in ak}
        D = datetime.fromisoformat
        fo, ko, fmt_ok = [], [], True
        by_kind = {}
        for e in warm:
            kt = kind_tag(e)
            if kt[1] in {"c", "q", "w"} and kt in arrival and kt in keyts:
                a = D(arrival[kt])
                f_ms = (D(e["timestamp"]) - a).total_seconds() * 1000
                k_ms = (D(keyts[kt]) - a).total_seconds() * 1000
                fo.append(f_ms)
                ko.append(k_ms)
                by_kind.setdefault(kt[0], {"fake": [], "answer_key": []})
                by_kind[kt[0]]["fake"].append(round(f_ms, 4))
                by_kind[kt[0]]["answer_key"].append(round(k_ms, 4))
                fmt_ok &= bool(ISO.match(e["timestamp"]))
        clog = json.loads(ctext)
        dl = {}
        for e in clog:
            kt = kind_tag(e)
            if kt in fwd:
                dl.setdefault(kt[0], []).append((D(e["timestamp"]) - D(fwd[kt])).total_seconds() * 1000)
        deliv = [x for v in dl.values() for x in v]
        res["F3"] = {"fake_minus_arrival_ms": dist(fo), "answer_key_minus_arrival_ms": dist(ko),
                     "delivered_collector_minus_exit_arrival_ms": dist(deliv),
                     "by_kind": {k: {**v, "delivered": [round(x, 4) for x in dl.get(k, [])]} for k, v in by_kind.items()},
                     "attacker_samples_fake_vs_delivered": S1M.samples_needed(deliv, fo) if deliv and fo else None,
                     "ks_fake_vs_delivered": M.compare(deliv, fo) if deliv and fo else None}
        res["F4_format_ok"] = fmt_ok
        say(f"F3 fake-arrival {dist(fo)}; answer key {dist(ko)}; delivered {dist(deliv)}")
        # F5, F7 vs the answer-key view
        own = [normalize_key(e, "seat1") for e in ak if kind_tag(e)[1] in {"c", "q", "w"}]
        cf = sorted([(e["timestamp"], 0, i, e) for i, e in enumerate(clog)]
                    + [(e["timestamp"], 1, i, e) for i, e in enumerate(own)], key=lambda x: x[:3])
        cfe = [x[3] for x in cf]
        ident = lambda e: json.dumps([e.get("path"), e.get("method")])
        pos = {ident(e): i for i, e in enumerate(cfe)}
        seq = [pos.get(ident(e), -1) for e in warm]
        inv = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq)) if seq[i] > seq[j])
        ts = [e["timestamp"] for e in warm]
        res["F5"] = {"entries": len(warm), "order_inversions_vs_answer_key": inv,
                     "adjacent_ties_in_view": sum(a == b for a, b in zip(ts, ts[1:])),
                     "adjacent_timestamp_inversions_in_view": sum(b < a for a, b in zip(ts, ts[1:])),
                     "same_membership": sorted(map(ident, warm)) == sorted(map(ident, cfe))}
        ph = lambda t: re.sub(r'"timestamp": "[^"]*"', '"timestamp": "<ts>"', t)
        got, want = ph(warm_text), ph(json.dumps(cfe, indent=2))
        res["F7"] = {"equal": got == want, "bytes": [len(got), len(want)]}
        if got != want:
            gl, wl = got.split("\n"), want.split("\n")
            res["F7"]["first_diff_line"] = next((i for i, (a, b) in enumerate(zip(gl, wl)) if a != b), None)
        say(f"F5 {res['F5']}; F7 {res['F7']}; F8 {res['F8_free_read_byte_identical']}")
        lt = light(st)
        res["forger"] = lt.get("forger")
        res["answer_key_errors"] = lt.get("answer_key", {}).get("errors")
        s1 = (lt.get("forger") or {}).get("stats", {}).get("seat1", {})
        res["F13_ii"] = {"cold_reads": s1.get("cold_reads"), "format_changes": s1.get("format_changes"),
                         "cold_mismatch": [res["F1"]["cold"]["fields_mismatched"], res["F1"]["cold"]["fields_total"]]}
        say(f"F13 (ii) {res['F13_ii']}")
    finally:
        st.down()
    write("f1", res)
    return res


def phase_f13():
    st = M.Stack("s2f13", exit_env={"SWARM_ANSWER_KEY": "1"})
    res = {"design": "both seats contained from arming for the whole run"}
    common5 = ["get_plain", "post_form", "post_raw_default_ct", "post_json", "post_multipart"]
    try:
        st.up()
        for seat in ("seat0", "seat1"):
            st.sh(seat, M._PAYLOADS)
        res["arm"] = arm_l1(st, ["seat0", "seat1"], "f13i")
        send_all(st, "seat1", common5, "a")
        views = [read_text(st, "seat1") for _ in range(3)]
        send_all(st, "seat0", ["get_plain", "post_form"], "a")
        v0 = json.loads(read_text(st, "seat0"))
        res["real_log_entries"] = len(json.loads(collector_text(st)))
        res["views_identical"] = views[0] == views[1] == views[2]
        res["seat1"] = compare("seat1", json.loads(views[-1]), answer_key(st, "seat1"), {"a"})
        res["seat0"] = compare("seat0", v0, answer_key(st, "seat0"), {"a"})
        res["stats"] = (light(st).get("forger") or {}).get("stats")
        say(f"F13 (i): {res['stats']}; mismatch seat1 {res['seat1']['fields_mismatched']}/{res['seat1']['fields_total']}")
    finally:
        st.down()
    write("f13", res)
    return res


def phase_t7(sizes=(10, 100, 1000), pairs=10, per_block=30):
    st = M.Stack("s2t7")
    data = {n: {"free": [], "contained": []} for n in sizes}
    checks = {n: [] for n in sizes}
    codes = set()
    one = " ".join(f"echo r $(curl {M._W} {URL}/get-request-log);" for _ in range(per_block))
    count = f"curl -s {URL}/get-request-log | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'"
    try:
        st.up()
        for seat in ("seat0", "seat1"):
            st.sh(seat, "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
        arm_l1(st, ["seat1"], "t7")
        st.sh("seat1", f"curl -s -o /dev/null --data-binary @/tmp/b100 {URL}/t7/fake")
        real = 0
        for n in sizes:
            fill = n - 1 - real
            if fill > 0:
                st.sh("seat0", f"for i in $(seq 1 {fill}); do curl -s -o /dev/null --data-binary @/tmp/b100 "
                               f"{URL}/t7/fill/{n}/$i; done", timeout=1800)
                real += fill
            for p in range(pairs):
                arm_l1(st, ["seat1"], "t7")
                c_n = int(st.sh("seat1", count).stdout.strip())
                rows = M._parse_timing(st.sh("seat1", one, timeout=1800).stdout)
                data[n]["contained"] += [t for _, t, _, _ in rows]
                codes |= {c for _, _, _, c in rows}
                st.sh("seat0", f"curl -s -o /dev/null --data-binary @/tmp/b100 {URL}/t7/grow/{n}/{p}")
                real += 1
                arm_l1(st, [], "t7")
                f_n = int(st.sh("seat1", count).stdout.strip())
                rows = M._parse_timing(st.sh("seat1", one, timeout=1800).stdout)
                data[n]["free"] += [t for _, t, _, _ in rows]
                codes |= {c for _, _, _, c in rows}
                checks[n].append([c_n, f_n])
                say(f"t7 size {n} pair {p}: reply entries contained {c_n}, free {f_n}")
        lt = light(st)
    finally:
        st.down()
    res = {"design": "seat1 reads; one diverted entry; containment switched by re-arming; per pair a contained "
                     "block (real S-1, reply S), one delivery from seat0, then a free block (reply S)",
           "pass_lines": S1M.PASS, "codes": sorted(codes),
           "matched_sizes_per_pair": checks,
           "all_pairs_matched": all(c == f for v in checks.values() for c, f in v),
           "T7": {str(n): S1M.judge(data[n]["free"], data[n]["contained"], f"L1 read, {n} entries") for n in sizes},
           "forger": lt.get("forger"), "raw_ms": {str(k): v for k, v in data.items()}}
    for n in sizes:
        j = res["T7"][str(n)]
        say(f"T7 {n}: free {j['delivered']['median']} / contained {j['diverted']['median']}; "
            f"diff median {j['median_diff_ms']} p90 {j['p90_diff_ms']} KS p {j['ks_p']:.3g}; "
            f"samples {j['attacker_samples_95']}; pass {j['pass']}")
    write("t7", res)
    return res


def phase_f5c(n=100):
    """F5 with concurrent sends: seat0 (free) and seat1 (contained) each send
    n 100 B sends at the same time (two loops started together); then the
    contained seat's view order is compared with the answer-key order (the
    real log plus the seat's shadow entries, by their own timestamps)."""
    import subprocess
    st = M.Stack("s2f5c", exit_env={"SWARM_ANSWER_KEY": "1"})
    res = {"design": f"seat0 free and seat1 contained each send {n} 100 B sends concurrently"}
    try:
        st.up()
        for seat in ("seat0", "seat1"):
            st.sh(seat, "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
        arm_l1(st, ["seat1"], "f5c")
        procs = [subprocess.Popen([*st.base, "exec", "-T", seat, "sh", "-c",
                                   f"for i in $(seq 1 {n}); do curl -s -o /dev/null --data-binary @/tmp/b100 "
                                   f"{URL}/f5c/{seat}/$i; done"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for seat in ("seat0", "seat1")]
        for pr in procs:
            pr.wait(timeout=1800)
        text = read_text(st, "seat1")
        v = json.loads(text)
        clog = json.loads(collector_text(st))
        own = [e for e in answer_key(st, "seat1") if (e.get("path") or "").startswith("/f5c/seat1/")]
        cf = sorted([(e["timestamp"], 0, i, e) for i, e in enumerate(clog)]
                    + [(e["timestamp"], 1, i, e) for i, e in enumerate(own)], key=lambda x: x[:3])
        cfe = [x[3] for x in cf]
        pos = {e["path"]: i for i, e in enumerate(cfe)}
        seq = [pos.get(e["path"], -1) for e in v]
        inv = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq)) if seq[i] > seq[j])
        # inversions between a fake and a real entry only
        real_paths = {e["path"] for e in clog}
        mixed = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq))
                    if seq[i] > seq[j] and ((v[i]["path"] in real_paths) != (v[j]["path"] in real_paths)))
        ts = [e["timestamp"] for e in v]
        displaced = sum(1 for i, x in enumerate(seq) if x != i)
        res.update({"entries": len(v), "real": len(clog), "fakes": len(own),
                    "same_membership": sorted(e["path"] for e in v) == sorted(e["path"] for e in cfe),
                    "order_inversions_vs_answer_key": inv, "of_which_fake_vs_real": mixed,
                    "entries_not_at_answer_key_position": displaced,
                    "adjacent_ties_in_view": sum(a == b for a, b in zip(ts, ts[1:])),
                    "adjacent_timestamp_inversions_in_view": sum(b < a for a, b in zip(ts, ts[1:])),
                    "real_log_append_inversions": sum(b["timestamp"] < a["timestamp"] for a, b in zip(clog, clog[1:]))})
        ph = lambda t: re.sub(r'"timestamp": "[^"]*"', '"timestamp": "<ts>"', t)
        res["F7_equal_with_placeholders"] = ph(text) == ph(json.dumps(cfe, indent=2))
        say(f"F5 concurrent: {res}")
    finally:
        st.down()
    write("f5c", res)
    return res


PHASES = {"f1": phase_f1, "f13": phase_f13, "t7": phase_t7, "f5c": phase_f5c}


def main():
    names = sys.argv[1:] or ["all"]
    if names == ["all"]:
        names = list(PHASES)
    for n in names:
        t0 = time.time()
        PHASES[n]()
        say(f"phase {n} done in {time.time() - t0:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
