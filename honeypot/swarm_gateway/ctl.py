"""Harness-side control client for the swarm exit, run inside its container
(the image has no curl). Talks to 127.0.0.1:8081 only.

  python ctl.py GET  /__swarm-state
  python ctl.py GET  /get-request-log        (the collector's true log)
  python ctl.py POST /__arm '<json>'
Prints the response body; exits non-zero on an HTTP error or no answer.
"""

import sys
import urllib.error
import urllib.request


def main() -> int:
    method, path = sys.argv[1], sys.argv[2]
    body = sys.argv[3].encode() if len(sys.argv) > 3 else None
    req = urllib.request.Request(f"http://127.0.0.1:8081{path}", data=body, method=method,
                                 headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
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
