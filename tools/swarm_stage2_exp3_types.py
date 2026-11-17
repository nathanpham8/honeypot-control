"""Counts of request types in Experiment 3 gateway records (step 3, Stage 2
rule 6c). Counts only: no bodies, paths, header values or credentials are
printed or written.

For every sample of the Experiment 3 gateway arms, the last scorer read of the
collector log (``get-request-log``) and of the gateway state (``sink_log``)
are taken from the eval's sandbox events. Each logged or diverted request is
classed by method, content-type class, body presence, query presence and body
size bucket, using the Stage 2 F1 type names where one fits.

Usage: python tools/swarm_stage2_exp3_types.py  (writes
analysis/swarm_pilot/stage2/exp3_request_types.json)
"""

import glob
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ARMS = {
    "deepseek": "logs/exp3/scouts_silent_gateway",
    "glm": "logs/exp3/scouts_silent_gateway_glm_b",
    "kimi": "logs/exp3/scouts_silent_gateway_kimi",
    "honest": "logs/exp3/scouts_silent_gateway_honest",
    "honest2": "logs/exp3/scouts_silent_gateway_honest2",
}


def ctype_class(ct):
    m = (ct or "").split(";", 1)[0].strip().lower()
    if not m:
        return "none"
    if m == "application/x-www-form-urlencoded":
        return "urlencoded"
    if m == "multipart/form-data":
        return "multipart"
    if m == "application/json":
        return "json"
    if m.startswith("text/"):
        return "text"
    if m == "application/octet-stream":
        return "octet"
    return "other"


def kind(e):
    """A coarse type, named after the F1 kinds where one fits."""
    method = (e.get("method") or "").upper()
    body = e.get("body") or ""
    cc = ctype_class(e.get("content_type"))
    query = "?" in (e.get("full_url") or "")
    if method == "GET":
        return "GET (with query)" if query else "GET"
    if method in ("HEAD", "OPTIONS", "DELETE", "PUT", "PATCH"):
        return method
    if method == "POST":
        if not body:
            return "POST empty"
        if cc == "urlencoded":
            return "POST urlencoded (form or curl default)"
        if cc == "multipart":
            return "POST multipart"
        if cc == "json":
            return "POST JSON"
        if cc in ("text", "octet", "other"):
            return f"POST plain ({cc})"
        return "POST no content type"
    return f"other method"


def size_bucket(e):
    n = e.get("content_length") or len(e.get("body") or "")
    for b, name in ((0, "0"), (1024, "<=1KB"), (65536, "<=64KB"), (1 << 20, "<=1MB")):
        if n <= b:
            return name
    return ">1MB"


def last_output(events, needle, attachments):
    """The JSON part of the last sandbox exec output whose command contains
    `needle`. Long outputs are stored as attachments; curl without -s puts its
    progress meter (stderr) in front of the JSON."""
    out = None
    for ev in events:
        if ev.get("event") == "sandbox" and needle in str(ev.get("cmd") or ""):
            out = ev.get("output")
    if out is None:
        return None
    m = re.fullmatch(r"attachment://([0-9a-f]+)", out.strip())
    if m:
        out = attachments.get(m.group(1), "")
    starts = [i for i in (out.find("\n["), out.find("\n{")) if i >= 0]
    if not out.lstrip().startswith(("[", "{")) and starts:
        out = out[min(starts) + 1:]
    return out


def main():
    res = {}
    for arm, d in ARMS.items():
        files = sorted(glob.glob(str(REPO / d / "*.eval")))
        kinds, sizes, src = Counter(), Counter(), Counter()
        samples = unreadable = 0
        for f in files:
            z = zipfile.ZipFile(f)
            for n in z.namelist():
                if not n.startswith("samples/"):
                    continue
                s = json.loads(z.read(n))
                samples += 1
                ev = s.get("events") or []
                entries = []
                try:
                    entries += [("collector", e) for e in json.loads(last_output(ev, "get-request-log", s.get("attachments") or {}) or "[]")]
                    gs = json.loads(last_output(ev, "__gateway-state", s.get("attachments") or {}) or "{}")
                    entries += [("sink", e) for e in (gs.get("sink_log") or [])]
                except (ValueError, TypeError):
                    # The eval keeps only a truncated copy of long command
                    # outputs, so the record cannot be parsed whole.
                    unreadable += 1
                    continue
                for where, e in entries:
                    kinds[kind(e)] += 1
                    sizes[size_bucket(e)] += 1
                    src[where] += 1
        res[arm] = {"eval_files": len(files), "samples": samples, "samples_with_truncated_records": unreadable,
                    "samples_counted": samples - unreadable,
                    "requests": sum(kinds.values()), "by_source": dict(src),
                    "by_kind": dict(kinds.most_common()), "by_size": dict(sizes.most_common())}
    tot = Counter()
    for arm in ("deepseek", "glm", "kimi"):
        tot.update(res[arm]["by_kind"])
    res["attacker_arms_total"] = {"requests": sum(tot.values()), "by_kind": dict(tot.most_common())}
    res["note"] = ("Inspect stores only a truncated copy of long sandbox outputs; a sample is counted "
                   "only if both its final collector log read and gateway state read parse whole.")
    out = REPO / "analysis/swarm_pilot/stage2/exp3_request_types.json"
    out.write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
