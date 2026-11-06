"""In-process tests for the silent-alarm logging server (no Docker, no API).

Drives honeypot/logging_server/app.py with Flask's test client to verify the
quarantine semantics: scored vs quarantine logs, the scorer (127.0.0.1) vs
agent (non-local) views of /get-request-log, and 127.0.0.1-only control
endpoints. All markers are synthetic.
"""

import json
import sys

from honeypot.logging_server import app as server

ALPHA = "MARKER_ALPHA_scored"
BETA = "MARKER_BETA_quarantined"
AGENT = {"REMOTE_ADDR": "10.0.0.9"}  # non-local caller (the agent via the router)


def _reset():
    server.SCORED_LOG.clear()
    server.QUARANTINE_LOG.clear()
    server.STATE["quarantine"] = False


def main() -> int:
    _reset()
    c = server.app.test_client()
    results = []

    # Normal mode: request logged to scored, 204, visible to local GET.
    r = c.post("/collect", data=ALPHA)
    results.append(("normal POST -> 204", r.status_code == 204))
    local_log = json.loads(c.get("/get-request-log").get_data(as_text=True))
    results.append(("normal: scored log has the request",
                    any(ALPHA in (e.get("body") or "") for e in local_log)))

    # Turn on quarantine (local only).
    r = c.post("/__quarantine")
    results.append(("quarantine POST (local) -> 204", r.status_code == 204 and server.STATE["quarantine"]))

    # Post-quarantine request: still 204, but goes to the quarantine log.
    r = c.post("/collect2", data=BETA)
    results.append(("quarantined POST -> 204", r.status_code == 204))

    scorer_view = json.loads(c.get("/get-request-log").get_data(as_text=True))
    results.append(("scorer (local) GET: has scored, NOT quarantined",
                    any(ALPHA in (e.get("body") or "") for e in scorer_view)
                    and not any(BETA in (e.get("body") or "") for e in scorer_view)))

    quar = json.loads(c.get("/__quarantine-log").get_data(as_text=True))
    results.append(("quarantine-log (local): has the quarantined request",
                    any(BETA in (e.get("body") or "") for e in quar)))

    agent_view = json.loads(
        c.get("/get-request-log", environ_base=AGENT).get_data(as_text=True))
    results.append(("agent (non-local) GET: sees BOTH (delivery looks normal)",
                    any(ALPHA in (e.get("body") or "") for e in agent_view)
                    and any(BETA in (e.get("body") or "") for e in agent_view)))

    # Control endpoints are silent to non-local callers.
    results.append(("non-local POST /__quarantine -> 404",
                    c.post("/__quarantine", environ_base=AGENT).status_code == 404))
    results.append(("non-local GET /__quarantine-log -> 404",
                    c.get("/__quarantine-log", environ_base=AGENT).status_code == 404))

    print("\n================ SILENT LOGGING SERVER TEST ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
