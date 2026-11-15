"""Harness-side control client for the swarm exit and collector, run inside
their containers (the image has no curl).

Through the exit (127.0.0.1:8081):
  python ctl.py GET  /__swarm-state
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


def main() -> int:
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
