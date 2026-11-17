"""Internet delay Part 2 option (no Docker): the compose option netem.

  * off by default: the compose file is identical to one built without the
    option;
  * "basharena" sets the router's NETEM to the recorded line and NETEM_PORTS
    to the collector, calibration, delay-calibration and cold-collector
    ports, and mounts the helper; 8081, 8082, 8083 and 8200+ are not delayed;
  * the router script applies netem only when NETEM is set, before it
    reports ready.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from honeypot import swarm_layout as L  # noqa: E402


def main():
    r = []
    kw = dict(token="t" * 32, host_addrs=["10.0.0.1"])
    base = L.compose_text("38927895", 2, **kw)
    r.append(("off by default: compose identical without the option and with netem=None",
              base == L.compose_text("38927895", 2, netem=None, **kw)))
    c = L.swarm_compose("38927895", 2, netem="basharena", **kw)
    env = c["services"]["router"]["environment"]
    ports = [int(p) for p in env["NETEM_PORTS"].split()]
    r.append(("basharena: the recorded netem line (5.84 ms, 0.29 ms, normal, rate, queue limit)",
              env["NETEM"] == "delay 5.84ms 0.29ms distribution normal rate 100gbit limit 100000"))
    r.append(("delayed ports: 8091, 8092, 8093, 8100 to 8109; not 8081, 8082, 8083, 8200+",
              ports == [8091, 8092, 8093] + list(range(8100, 8110))
              and not {8081, 8082, 8083} & set(ports) and all(p < 8200 for p in ports)))
    r.append(("helper mounted only with the option",
              any(v.endswith(":/swarm_netem.sh:ro") for v in c["services"]["router"]["volumes"])
              and "swarm_netem.sh" not in base))
    rs = (REPO / "honeypot" / "swarm_router.sh").read_text()
    r.append(("router applies netem only when NETEM is set, before reporting ready",
              'if [ -n "${NETEM:-}" ]; then' in rs and rs.index("swarm_netem.sh on") < rs.index("touch /tmp/router-ready")))
    ok = True
    for name, passed in r:
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
