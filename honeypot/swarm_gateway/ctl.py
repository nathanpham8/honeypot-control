"""Harness-side control client for the swarm exit and collector, run inside
their containers (the image has no curl).

Through the exit (127.0.0.1:8081):
  python ctl.py GET  /__swarm-state          the light view (no forwarded, sink or trip
                                             records; last 100 events)
  python ctl.py DUMP [section ...]           every record of the full view, read page by
                                             page and printed one JSON line per record
                                             ({"section", "seat", "item"}); memory-safe
  python ctl.py STATE-FULL                   the light view plus every record, assembled
                                             in the pre-Stage-1-final shape (small states,
                                             tests only: holds everything in memory)
  python ctl.py GET  /__health
  python ctl.py GET  /get-request-log        (the collector's true log, small logs)
  python ctl.py POST /__arm '<json>'
Directly at the collector (127.0.0.1:$COLLECTOR_PORT, token from
$GATEWAY_TOKEN; run in the collector container):
  python ctl.py COLLECTOR-LOG                the true log (JSON)
  python ctl.py COLLECTOR-SUMMARY            entry count and size, streamed, without
                                             loading the log (safe for large logs)
Prints the response body; exits non-zero on an HTTP error or no answer.
"""

import json
import os
import sys
import urllib.error
import urllib.request


def _collector(path: str):
    port = os.environ.get("COLLECTOR_PORT", "8091")
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 headers={"X-Gateway-Token": os.environ.get("GATEWAY_TOKEN", "")})
    return urllib.request.urlopen(req, timeout=600)  # noqa: S310


def _summary() -> int:
    """Count entries by the collector's fixed layout (indent=2: each entry
    starts with a line of exactly two spaces and "{") without parsing it."""
    entries = size = 0
    tail = b""
    with _collector("/get-request-log") as r:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            data = tail + chunk
            entries += data.count(b"\n  {\n")
            tail = data[-8:]
    sys.stdout.write(json.dumps({"entries": entries, "log_bytes": size}))
    return 0


# ------------------------------------------------- paged state (Stage 1 final)

RECORD_SECTIONS = ("events", "forwarded", "sink", "trips", "forward_errors", "calibration_errors")


def iter_section(get_json, section: str, seat: str = "", page_size: int = 500, stats=None):
    """Yield every record of one section, page by page, up to the record
    count at the first read (a snapshot bound, so a read during traffic ends).
    get_json(path) -> dict. Records dropped by the exit's cap between pages
    are counted in stats["missed"]."""
    base = f"/__swarm-state?view=full&section={section}&page_size={page_size}"
    if section == "sink":
        base += f"&seat={seat}"
    first = get_json(base + "&page=0")
    bound = first["total"]
    page = first["first_available"] // page_size
    expected = first["first_available"]
    while page * page_size < bound:
        r = first if page == 0 else get_json(f"{base}&page={page}")
        start = max(page * page_size, r["first_available"])
        if stats is not None and start > expected:
            stats["missed"] = stats.get("missed", 0) + start - expected
        for i, item in enumerate(r["items"]):
            if start + i >= bound:
                return
            yield item
        expected = start + len(r["items"])
        page += 1


def iter_all(get_json, sections=RECORD_SECTIONS, page_size: int = 500):
    """(section, seat, record) for every record of the given sections."""
    light = get_json("/__swarm-state?events_tail=0")
    for section in sections:
        seats = sorted(light["totals"]["sink"]) if section == "sink" else [None]
        for seat in seats:
            for item in iter_section(get_json, section, seat or "", page_size):
                yield section, seat, item


def full_state(get_json, page_size: int = 500) -> dict:
    """The light view plus every record, in the shape /__swarm-state had
    before Stage 1 final (events, forwarded, sink {seat: [...]}, trips
    {seat: record}, forward_errors, calibration["errors"])."""
    view = get_json("/__swarm-state?events_tail=0")
    out = {"events": [], "forwarded": [], "sink": {}, "trips": {}, "forward_errors": [],
           "calibration_errors": []}
    for section, seat, item in iter_all(get_json, page_size=page_size):
        if section == "sink":
            out["sink"].setdefault(seat, []).append(item)
        elif section == "trips":
            item = dict(item)
            out["trips"][item.pop("seat")] = item
        else:
            out[section].append(item)
    view.update({k: out[k] for k in ("events", "forwarded", "sink", "trips", "forward_errors")})
    view["calibration"]["errors"] = out["calibration_errors"]
    view["view"] = "full (assembled)"
    return view


def _exit_json(path: str) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:8081{path}", timeout=600) as r:  # noqa: S310
        return json.loads(r.read())


def main() -> int:
    if sys.argv[1] == "DUMP":
        sections = tuple(sys.argv[2:]) or RECORD_SECTIONS
        for section, seat, item in iter_all(_exit_json, sections):
            sys.stdout.write(json.dumps({"section": section, "seat": seat, "item": item}) + "\n")
        return 0
    if sys.argv[1] == "STATE-FULL":
        sys.stdout.write(json.dumps(full_state(_exit_json)))
        return 0
    if sys.argv[1] == "COLLECTOR-SUMMARY":
        return _summary()
    if sys.argv[1] == "COLLECTOR-LOG":
        with _collector("/get-request-log") as r:
            sys.stdout.write(r.read().decode())
        return 0
    method, path = sys.argv[1], sys.argv[2]
    body = sys.argv[3].encode() if len(sys.argv) > 3 else None
    req = urllib.request.Request(f"http://127.0.0.1:8081{path}", data=body, method=method,
                                 headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:  # noqa: S310
            sys.stdout.write(r.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        sys.stdout.write(e.read().decode())
        return 1
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(repr(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
