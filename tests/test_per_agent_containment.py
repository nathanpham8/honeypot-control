"""Tests for per-agent containment at a shared exit (no Docker, no API)."""

import sys

from honeypot.per_agent_containment import ContainmentState, decide

REAL_A, DECOY_A = "REAL_github_aaa111", "DECOY_github_bbb222"
DECOY_B = "DECOY_jwt_ccc333"


def main() -> int:
    r = []

    st = ContainmentState(decoy_values=(DECOY_A, DECOY_B))

    # A sends a real credential: forwarded, not contained.
    d = decide(st, "Agent A", f"POST body {REAL_A}")
    r.append(("real credential from A is forwarded",
              not d.divert and not d.newly_contained and d.reason == "forward"))

    # B sends a decoy: diverted, newly contained; A unaffected.
    d = decide(st, "Agent B", f"body {DECOY_B}")
    r.append(("decoy from B diverts and contains B",
              d.divert and d.newly_contained and d.reason == "decoy"
              and st.contained == {"Agent B"}))
    d = decide(st, "Agent A", f"body {REAL_A}")
    r.append(("A still flows after B is contained (per-agent, not global)",
              not d.divert and "Agent A" not in st.contained))

    # B's later traffic stays diverted but is not 'newly' contained again.
    d = decide(st, "Agent B", f"body {REAL_A}")
    r.append(("B's later real credential is diverted, not re-flagged",
              d.divert and not d.newly_contained and d.reason == "already-contained"))

    # A sends a decoy too: now both contained.
    d = decide(st, "Agent A", f"x {DECOY_A} y")
    r.append(("A sending a decoy contains A as well",
              d.divert and d.newly_contained and st.contained == {"Agent A", "Agent B"}))

    # Seeded containment from an earlier round: C starts contained.
    st2 = ContainmentState(decoy_values=(DECOY_A,))
    st2.seed_contained(["Agent C"])
    d = decide(st2, "Agent C", f"body {REAL_A}")
    r.append(("a position contained in an earlier round is diverted from its first send",
              d.divert and not d.newly_contained and d.reason == "already-contained"))
    d = decide(st2, "Agent D", f"body {REAL_A}")
    r.append(("a fresh position (D) is not contained by C's history",
              not d.divert))

    # Encoded decoy still catches.
    import base64
    enc = base64.b64encode(DECOY_A.encode()).decode().rstrip("=")
    d = decide(ContainmentState(decoy_values=(DECOY_A,)), "Agent A", f"blob {enc}")
    r.append(("base64-encoded decoy is caught", d.divert and d.newly_contained))

    # Missing identity: diverted, not attributed (harness fault, not a free pass).
    d = decide(ContainmentState(decoy_values=(DECOY_A,)), "", f"body {REAL_A}")
    r.append(("a request with no agent identity is diverted and unattributed",
              d.divert and not d.newly_contained and d.reason == "no-identity"))

    print("\n================ PER-AGENT CONTAINMENT TEST ================")
    ok_all = True
    for name, ok in r:
        ok_all = ok_all and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if ok_all else "FAILURES PRESENT")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
