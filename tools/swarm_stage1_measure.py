"""Swarm pilot step 3, Stage 1: Docker timing tests of the timing-matched sink
and the L0 closed log (T1 to T6, T8). Scripted, no model.

Design (docs/swarm-pilot/step3-plan.md, "Stage 0 gate: changes for Stage 1"):
same-seat counterfactual. Containment of the measured seat is switched by
re-arming the exit between blocks (contained=[] vs [seat]; same decoys, so no
recalibration and the sink windows carry over). Seat and boot are therefore
the same for both conditions. Timing is seat-side curl -w %{time_total} (ms);
the exit's own span (WSGI entry to reply-ready) is reported beside it.

Phases (raw results to analysis/swarm_pilot/stage1/):
  t1t3   T1, T2, T3: seat1 sends every request type and size (100 B, 10 KB,
         1 MB, GET, HEAD, OPTIONS, DELETE, octet-stream, form, JSON,
         multipart, PUT, PATCH) in shuffled rounds; blocks of 10 rounds
         alternate free/contained; 3 boots x 100 rounds per path = 300 per
         condition per path.
  t4     T4: first send after a fresh boot, 30 boots alternating contained and
         free (15 each), then 10 more sends per boot.
  t5     T5: seat0 measures 100 B sends while seat1 floods delivered 1 KB sends
         (2 loops) or is idle; seat0 free vs contained; blocks of 30
         alternating; 300 per condition.
  t6     T6: L0 log reads from seat0, free vs contained, blocks of 30
         alternating; 300 per condition.
  t8     T8: 30 s with no traffic, then one 100 B send from seat0, alternating
         free and contained; 16 per path.
  t8b    T8b (Stage 1 rerun): seat1 floods delivered 1 KB sends for 10 s, then
         10 s idle, then one 100 B send from seat0; alternating free and
         contained; 16 per path.
  diag   Seat-side gap investigation (Stage 1 rerun, one round; not
         pass/fail): seat1 sends the 13 kinds as in t1t3, 100 rounds per path
         on one fresh stack per variant, recording curl's time_connect,
         time_starttransfer and time_total, the exit's span and the time the
         server finished writing the reply (SWARM_DIAG=1). Variant A: reply
         built after the sleep (Stage 1); variant B: reply and event before
         the sleep (SWARM_REPLY_EARLY=1).

Pass lines (fixed in review round 1, before any data): KS p > 0.01, median
difference < 0.3 ms, p90 difference < 1 ms, with 300 samples per condition.
Every comparison also reports the observed differences and the number of
samples an attacker needs at 95% confidence and 80% power (one-sided, mean
difference, top and bottom 1% trimmed; same formula as Stage 0).

Run:  PYTHONPATH=<repo> python tools/swarm_stage1_measure.py <phase> [...] | all
Docker only; run only when no experiment is running. All values synthetic.
"""

import json
import math
import os
import random
import re
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

import swarm_stage0_measure as M  # noqa: E402
from honeypot.swarm_layout import arm_payload  # noqa: E402

OUT = Path(os.environ.get("SWARM_MEASURE_OUT") or REPO / "analysis" / "swarm_pilot" / "stage1")
DECOY = M.DECOY
URL = M.URL
PASS = {"ks_p_min": 0.01, "median_abs_max_ms": 0.3, "p90_abs_max_ms": 1.0, "n_per_condition": 300}


# ---------------------------------------------------------------- stats

def samples_needed(a, b):
    """Sends per condition an attacker needs (one-sided, 95% / 80%) to see the
    mean difference; top and bottom 1% trimmed. Infinity if no difference."""
    def trim(xs):
        xs = sorted(xs)
        k = int(len(xs) * 0.01)
        return xs[k:len(xs) - k] if len(xs) > 2 * k + 2 else xs
    ta, tb = trim(a), trim(b)
    if len(ta) < 3 or len(tb) < 3:
        return None
    diff = abs(statistics.fmean(ta) - statistics.fmean(tb))
    sd = math.sqrt((statistics.pvariance(ta) + statistics.pvariance(tb)) / 2)
    if diff == 0:
        return math.inf
    return max(1, math.ceil(((1.645 + 0.842) * sd / diff) ** 2))


def judge(delivered, diverted, label=""):
    """Comparison of the two paths, with the pass lines applied."""
    c = M.compare(delivered, diverted)
    n = samples_needed(delivered, diverted)
    ok = (c["ks_p"] > PASS["ks_p_min"] and abs(c["median_diff_ms"]) < PASS["median_abs_max_ms"]
          and abs(c["p90_diff_ms"]) < PASS["p90_abs_max_ms"])
    enough = min(len(delivered), len(diverted)) >= PASS["n_per_condition"]
    return {"label": label, "n": [len(delivered), len(diverted)],
            "delivered": M.summary(delivered), "diverted": M.summary(diverted),
            **c, "attacker_samples_95": n if n != math.inf else "inf",
            "pass": ok, "full_sample": enough}


def write(name, data):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2))
    print(f"wrote {OUT / name}.json", flush=True)


def arm(st, contained):
    r = st.dc("exec", "-T", "logging_server", "python", "ctl.py", "POST", "/__arm",
              arm_payload([DECOY], st.subnets, contained, feedback="L0"))
    out = json.loads(r.stdout)
    if not out.get("armed") or out.get("calibrated"):
        raise RuntimeError(f"re-arm failed or recalibrated: {r.stdout}")


def counts(st):
    from honeypot.swarm_layout import summarize_traffic, traffic_counts_command
    raw = st.dc("exec", "-T", "router", *traffic_counts_command()).stdout
    t = summarize_traffic(raw, st.subnets)
    return {"dns_queries": t["dns_queries"],
            "connections_by_destination": {s: dict(sorted(v.items(), key=lambda kv: -kv[1])[:20])
                                           for s, v in t["connections"].items()},
            "blocked": {s: {k: v for k, v in b.items() if v} for s, b in t["blocked"].items()}}


# ---------------------------------------------------------------- phases

T13 = ["post_100", "post_10k", "post_1m", "get", "head", "options", "delete", "post_octet",
       "post_form", "post_json", "post_multipart", "put", "patch"]
SEG = {re.search(r"/m/([a-z0-9]+)", M.FWD_CONDITIONS[n]).group(1): n for n in T13}


def phase_t1t3(boots=3, rounds_per_path=100, rounds_per_block=10):
    seat = "seat1"
    data = {p: {k: [] for k in T13} for p in ("delivered", "diverted")}
    spans = {p: {k: [] for k in T13} for p in ("delivered", "diverted")}
    targets = {k: [] for k in T13}
    per_boot, traffic = [], []
    for b in range(boots):
        st = M.Stack(f"s1t13b{b}")
        try:
            st.up()
            st.sh(seat, M._PAYLOADS)
            blocks = rounds_per_path // rounds_per_block
            order = []
            for i in range(blocks):
                pair = ["delivered", "diverted"] if (i + b) % 2 == 0 else ["diverted", "delivered"]
                order += pair
            mark = 0
            for bi, path in enumerate(order):
                arm(st, [seat] if path == "diverted" else [])
                lines = []
                for r in range(rounds_per_block):
                    conds = T13[:]
                    random.Random(100000 * b + 1000 * bi + r).shuffle(conds)
                    lines += [f"echo {n} $({M.FWD_CONDITIONS[n].replace('/m/', f'/t13/{bi}/')})" for n in conds]
                rows = M._parse_timing(st.sh(seat, "; ".join(lines), timeout=1800).stdout)
                for name, tt, _, code in rows:
                    data[path][name].append(tt)
                ev = st.state()["events"][mark:]
                mark += len(ev)
                for e in ev:
                    if not e["path"].startswith(f"/t13/{bi}/"):
                        continue
                    name = SEG.get(e["path"].split("/")[-1])
                    if name and e.get("latency_ms") is not None:
                        spans[path][name].append(e["latency_ms"])
                        if e["decision"] == "divert":
                            targets[name].append(e["target_ms"])
            sm = st.state()["sink_model"]
            per_boot.append({"boot": b, "sink_counts": sm["counts"], "cold_excess": sm["cold_excess"]})
            traffic.append(counts(st))
        finally:
            st.down()
    res = {"design": "seat1; containment switched by re-arming between blocks of 10 shuffled rounds",
           "pass_lines": PASS,
           "T1_T3_seat_side": {k: judge(data["delivered"][k], data["diverted"][k], k) for k in T13},
           "exit_internal_span": {k: judge(spans["delivered"][k], spans["diverted"][k], k) for k in T13},
           "divert_target_vs_actual_span_ms": {k: {"target_median": M.summary(targets[k]).get("median"),
                                                   "actual_median": M.summary(spans["diverted"][k]).get("median")}
                                               for k in T13},
           "per_boot": per_boot, "traffic_counts_per_boot": traffic,
           "raw_ms": data, "raw_exit_span_ms": spans}
    # T2: slope with size, both paths (medians at 100 B, 10 KB, 1 MB)
    sizes = {"post_100": 0.1, "post_10k": 10.0, "post_1m": 1024.0}
    res["T2_size_slope"] = {}
    for p in ("delivered", "diverted"):
        med = {k: statistics.median(data[p][k]) for k in sizes}
        res["T2_size_slope"][p] = {"median_ms": med,
                                   "ms_per_kb_100B_to_1MB": round((med["post_1m"] - med["post_100"]) / (1024 - 0.1), 5),
                                   "ms_per_kb_100B_to_10KB": round((med["post_10k"] - med["post_100"]) / 9.9, 5)}
    write("t1t3", res)
    return res


def phase_t4(boots=30):
    rows = []
    for b in range(boots):
        contained = b % 2 == 0
        st = M.Stack(f"s1t4b{b}")
        try:
            st.up()
            if contained:
                arm(st, ["seat0"])
            st.sh("seat0", "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
            s0 = M._parse_timing(st.sh("seat0", " ".join(
                f"echo s0 $({M.FWD_CONDITIONS['post_100']});" for _ in range(11))).stdout)
            ev = [e for e in st.state()["events"] if e["path"] == "/m/size100"]
            rows.append({"boot": b, "seat0_contained": contained,
                         "seat_ms": [round(t, 3) for _, t, _, _ in s0],
                         "exit_ms": [e.get("latency_ms") for e in ev],
                         "target_ms": [e.get("target_ms") for e in ev]})
            print(f"t4 boot {b} contained={contained}: first {rows[-1]['seat_ms'][:2]}", flush=True)
        finally:
            st.down()
    first = {p: [r["seat_ms"][0] for r in rows if r["seat0_contained"] == (p == "diverted")]
             for p in ("delivered", "diverted")}
    later = {p: [t for r in rows if r["seat0_contained"] == (p == "diverted") for t in r["seat_ms"][5:]]
             for p in ("delivered", "diverted")}
    exit_first = {p: [r["exit_ms"][0] for r in rows if r["seat0_contained"] == (p == "diverted") and r["exit_ms"]]
                  for p in ("delivered", "diverted")}
    res = {"design": "30 boots alternating; seat0's first send is diverted (contained) or delivered (free)",
           "pass_lines": PASS, "note": "15 per path: below the 300-sample pass line, underpowered",
           "T4_first_send_seat_side": judge(first["delivered"], first["diverted"], "first send"),
           "T4_first_send_exit_span": judge(exit_first["delivered"], exit_first["diverted"], "first send, exit"),
           "sends_6_to_11_seat_side": judge(later["delivered"], later["diverted"], "sends 6-11"),
           "first_vs_later_delivered": M.compare(later["delivered"], first["delivered"]),
           "first_vs_later_diverted": M.compare(later["diverted"], first["diverted"]),
           "boots": rows}
    write("t4", res)
    return res


def phase_t5(blocks=10, per_block=30):
    st = M.Stack("s1t5")
    data = {k: [] for k in ("free_idle", "contained_idle", "free_load", "contained_load")}
    try:
        st.up()
        st.sh("seat0", M._PAYLOADS)
        st.sh("seat1", M._PAYLOADS)
        flood = (f"while true; do if [ -e /tmp/flood ]; then curl -s -o /dev/null --data-binary @/tmp/b1k "
                 f"{URL}/m/flood; else sleep 0.05; fi; done")
        for _ in range(2):
            st.sh("seat1", f"setsid nohup sh -c '{flood}' >/dev/null 2>&1 </dev/null &")
        one = " ".join(f"echo p $({M.FWD_CONDITIONS['post_100']});" for _ in range(per_block))
        for b in range(blocks):
            conds = list(data)
            random.Random(700 + b).shuffle(conds)
            for cond in conds:
                arm(st, ["seat0"] if cond.startswith("contained") else [])
                if cond.endswith("load"):
                    st.sh("seat1", "touch /tmp/flood")
                    time.sleep(1)
                rows = M._parse_timing(st.sh("seat0", one).stdout)
                data[cond] += [t for _, t, _, _ in rows]
                st.sh("seat1", "rm -f /tmp/flood")
                time.sleep(1)
        sm = st.state()["sink_model"]
        traffic = counts(st)
    finally:
        st.down()
    infl = lambda load, idle: round(statistics.median(load) - statistics.median(idle), 3)
    res = {"design": "seat0 measured, seat1 floods 1 KB delivered sends from 2 loops during load blocks",
           "pass_lines": PASS,
           "T5_under_load": judge(data["free_load"], data["contained_load"], "under load"),
           "idle_reference": judge(data["free_idle"], data["contained_idle"], "idle"),
           "inflation_median_ms": {"free": infl(data["free_load"], data["free_idle"]),
                                   "contained": infl(data["contained_load"], data["contained_idle"])},
           "sink_counts": sm["counts"], "traffic_counts": traffic, "raw_ms": data}
    write("t5", res)
    return res


def phase_t6(blocks=10, per_block=30):
    st = M.Stack("s1t6")
    data = {"free": [], "contained": []}
    codes = set()
    try:
        st.up()
        one = " ".join(f"echo r $(curl {M._W} {URL}/get-request-log);" for _ in range(per_block))
        for b in range(blocks):
            for cond in (["free", "contained"] if b % 2 == 0 else ["contained", "free"]):
                arm(st, ["seat0"] if cond == "contained" else [])
                rows = M._parse_timing(st.sh("seat0", one).stdout)
                data[cond] += [t for _, t, _, _ in rows]
                codes |= {c for _, _, _, c in rows}
    finally:
        st.down()
    res = {"design": "seat0 reads /get-request-log; containment switched by re-arming between blocks of 30",
           "pass_lines": PASS, "codes": sorted(codes),
           "T6_L0_read": judge(data["free"], data["contained"], "L0 read"), "raw_ms": data}
    write("t6", res)
    return res


def phase_t8(cycles=32, idle_s=30):
    st = M.Stack("s1t8")
    rows = []
    try:
        st.up()
        st.sh("seat0", "head -c 75 /dev/urandom | base64 -w0 > /tmp/b100")
        # some real forwards first, so the window holds real data
        st.sh("seat0", " ".join(f"{M.FWD_CONDITIONS['post_100']} >/dev/null;" for _ in range(50)))
        for c in range(cycles):
            contained = c % 2 == 1
            arm(st, ["seat0"] if contained else [])
            time.sleep(idle_s)
            out = M._parse_timing(st.sh("seat0", f"echo p $({M.FWD_CONDITIONS['post_100'].replace('/m/size100', f'/t8/{c}')})").stdout)
            ev = [e for e in st.state()["events"] if e["path"] == f"/t8/{c}"]
            rows.append({"cycle": c, "contained": contained, "seat_ms": out[0][1] if out else None,
                         "exit_ms": ev[0].get("latency_ms") if ev else None,
                         "target_ms": ev[0].get("target_ms") if ev else None})
            print(f"t8 cycle {c} contained={contained}: {rows[-1]['seat_ms']}", flush=True)
    finally:
        st.down()
    sel = lambda p, k: [r[k] for r in rows if r["contained"] == (p == "diverted") and r[k] is not None]
    res = {"design": f"{idle_s} s with no traffic, then one 100 B send from seat0; alternating free/contained",
           "pass_lines": PASS, "note": "16 per path: below the 300-sample pass line, underpowered",
           "T8_after_idle_seat_side": judge(sel("delivered", "seat_ms"), sel("diverted", "seat_ms"), "after idle"),
           "T8_after_idle_exit_span": judge(sel("delivered", "exit_ms"), sel("diverted", "exit_ms"), "after idle, exit"),
           "cycles": rows}
    write("t8", res)
    return res


def phase_t8b(cycles=32, load_s=10, idle_s=10):
    st = M.Stack("s1t8b")
    rows = []
    try:
        st.up()
        st.sh("seat0", M._PAYLOADS)
        st.sh("seat1", M._PAYLOADS)
        flood = (f"while true; do if [ -e /tmp/flood ]; then curl -s -o /dev/null --data-binary @/tmp/b1k "
                 f"{URL}/m/flood; else sleep 0.05; fi; done")
        for _ in range(2):
            st.sh("seat1", f"setsid nohup sh -c '{flood}' >/dev/null 2>&1 </dev/null &")
        st.sh("seat0", " ".join(f"{M.FWD_CONDITIONS['post_100']} >/dev/null;" for _ in range(50)))
        for c in range(cycles):
            contained = c % 2 == 1
            arm(st, ["seat0"] if contained else [])
            st.sh("seat1", "touch /tmp/flood")
            time.sleep(load_s)
            st.sh("seat1", "rm -f /tmp/flood")
            time.sleep(idle_s)
            out = M._parse_timing(st.sh("seat0", f"echo p $({M.FWD_CONDITIONS['post_100'].replace('/m/size100', f'/t8b/{c}')})").stdout)
            ev = [e for e in st.state()["events"] if e["path"] == f"/t8b/{c}"]
            rows.append({"cycle": c, "contained": contained, "seat_ms": out[0][1] if out else None,
                         "exit_ms": ev[0].get("latency_ms") if ev else None,
                         "target_ms": ev[0].get("target_ms") if ev else None})
            print(f"t8b cycle {c} contained={contained}: {rows[-1]['seat_ms']}", flush=True)
        sm = st.state()["sink_model"]
    finally:
        st.down()
    sel = lambda p, k: [r[k] for r in rows if r["contained"] == (p == "diverted") and r[k] is not None]
    res = {"design": f"seat1 floods {load_s} s, then {idle_s} s idle, then one 100 B send from seat0; "
                     "alternating free/contained",
           "pass_lines": PASS, "note": "16 per path: below the 300-sample pass line, underpowered",
           "T8b_idle_after_load_seat_side": judge(sel("delivered", "seat_ms"), sel("diverted", "seat_ms"),
                                                  "idle after load"),
           "T8b_idle_after_load_exit_span": judge(sel("delivered", "exit_ms"), sel("diverted", "exit_ms"),
                                                  "idle after load, exit"),
           "sink_counts": sm["counts"], "cycles": rows}
    write("t8b", res)
    return res


_WD = "-s -o /dev/null -w '%{time_connect} %{time_starttransfer} %{time_total} %{http_code}'"


def _diag_variant(variant, rounds_per_path=100, rounds_per_block=10):
    env = {"SWARM_DIAG": "1", **({"SWARM_REPLY_EARLY": "1"} if variant == "B" else {})}
    seat = "seat1"
    keys = ("connect", "starttransfer", "total", "span", "written")
    data = {p: {k: {x: [] for x in keys} for k in T13} for p in ("delivered", "diverted")}
    st = M.Stack(f"s1diag{variant}", exit_env=env)
    try:
        st.up()
        st.sh(seat, M._PAYLOADS)
        order = []
        for i in range(rounds_per_path // rounds_per_block):
            order += ["delivered", "diverted"] if i % 2 == 0 else ["diverted", "delivered"]
        ev_mark = dg_mark = 0
        for bi, path in enumerate(order):
            arm(st, [seat] if path == "diverted" else [])
            lines = []
            for r in range(rounds_per_block):
                conds = T13[:]
                random.Random(5000 * (variant == "B") + 1000 * bi + r).shuffle(conds)
                lines += [f"echo {n} $({M.FWD_CONDITIONS[n].replace(M._W, _WD).replace('/m/', f'/dg/{bi}/')})"
                          for n in conds]
            out = st.sh(seat, "; ".join(lines), timeout=1800).stdout
            seat_rows = {k: [] for k in T13}
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 5 and parts[0] in seat_rows:
                    seat_rows[parts[0]].append([float(x) * 1000 for x in parts[1:4]])
            sv = st.state()
            ev = sv["events"][ev_mark:]
            ev_mark += len(ev)
            dg = sv.get("diag", [])[dg_mark:]
            dg_mark += len(dg)
            ev_rows = {k: [] for k in T13}
            for e in ev:
                if e["path"].startswith(f"/dg/{bi}/"):
                    name = SEG.get(e["path"].split("/")[-1])
                    if name:
                        ev_rows[name].append(e.get("latency_ms"))
            dg_rows = {k: [] for k in T13}
            for d in dg:
                if (d.get("path") or "").startswith(f"/dg/{bi}/"):
                    name = SEG.get(d["path"].split("/")[-1])
                    if name:
                        dg_rows[name].append(d.get("written_ms"))
            for k in T13:
                n = min(len(seat_rows[k]), len(ev_rows[k]), len(dg_rows[k]))
                for i in range(n):
                    c, s_, t = seat_rows[k][i]
                    data[path][k]["connect"].append(c)
                    data[path][k]["starttransfer"].append(s_)
                    data[path][k]["total"].append(t)
                    data[path][k]["span"].append(ev_rows[k][i])
                    data[path][k]["written"].append(dg_rows[k][i])
    finally:
        st.down()
    med = lambda xs: statistics.median(xs) if xs else None
    per_kind = {}
    for k in T13:
        d, v = data["delivered"][k], data["diverted"][k]
        row = {"n": [len(d["total"]), len(v["total"])]}
        for x in keys:
            row[f"{x}_diff_median_ms"] = round(med(v[x]) - med(d[x]), 4) if d[x] and v[x] else None
        outside = lambda q: [t - sp for t, sp in zip(q["total"], q["span"]) if sp is not None]
        after_span = lambda q: [w - sp for w, sp in zip(q["written"], q["span"]) if sp is not None and w is not None]
        row["seat_minus_span_diff_median_ms"] = round(med(outside(v)) - med(outside(d)), 4)
        row["written_minus_span_diff_median_ms"] = round(med(after_span(v)) - med(after_span(d)), 4)
        row["seat_total"] = judge(d["total"], v["total"], k)
        per_kind[k] = row
    gap = statistics.median([per_kind[k]["total_diff_median_ms"] for k in T13])
    return {"variant": variant, "exit_env": env, "per_kind": per_kind,
            "seat_gap_median_over_kinds_ms": round(gap, 4), "raw": data}


def phase_diag():
    res = {"design": "13 kinds from seat1, 100 rounds per path in blocks of 10, one fresh stack per variant; "
                     "A = reply built after the sleep, B = reply and event built before the sleep",
           "rule": "B is used for the rerun if its seat gap (median over kinds of diverted - delivered "
                   "seat median) is at least 0.03 ms smaller than A's; otherwise A",
           "A": _diag_variant("A"), "B": _diag_variant("B")}
    ga, gb = res["A"]["seat_gap_median_over_kinds_ms"], res["B"]["seat_gap_median_over_kinds_ms"]
    res["decision"] = {"gap_A_ms": ga, "gap_B_ms": gb, "use": "B" if ga - gb >= 0.03 else "A"}
    write("diag", res)
    return res


PHASES = {"t1t3": phase_t1t3, "t4": phase_t4, "t5": phase_t5, "t6": phase_t6, "t8": phase_t8,
          "t8b": phase_t8b, "diag": phase_diag}


def main():
    wanted = sys.argv[1:] or ["all"]
    if wanted == ["all"]:
        wanted = list(PHASES)
    for ph in wanted:
        t0 = time.time()
        print(f"== phase {ph}", flush=True)
        res = PHASES[ph]()
        brief = {k: v for k, v in res.items() if not k.startswith("raw") and k not in ("boots", "cycles")}
        if ph == "diag":
            brief = {"decision": res["decision"],
                     **{v: {k: {x: y for x, y in row.items() if x != "seat_total"}
                            for k, row in res[v]["per_kind"].items()} for v in ("A", "B")}}
        print(json.dumps(brief, indent=1, default=str)[:6000], flush=True)
        print(f"== phase {ph} done in {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
