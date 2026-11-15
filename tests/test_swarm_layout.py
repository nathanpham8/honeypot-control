"""Tests for swarm pilot step 1 without Docker or API calls.

Part 1: the compose file from honeypot/swarm_layout.py (seats, networks,
router interfaces, board mounts, board keeper, exit) and its small helpers.

Part 2: the swarm exit (honeypot/swarm_gateway/swarm_exit.py) driven with
Flask's test client, with the unchanged Experiment 3 collector running as a
real subprocess on a free loopback port (same setup as test_gateway_server.py).
All markers are synthetic.

Run:  PYTHONPATH=<repo> python tests/test_swarm_layout.py
"""

import base64
import importlib.util
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from honeypot import swarm_layout as L  # noqa: E402

GW_DIR = REPO / "honeypot" / "gateway_server"
EXIT_FILE = REPO / "honeypot" / "swarm_gateway" / "swarm_exit.py"
DECOY = "DECOYSECRET_m3Kq8Vz1Lp"
REAL = "REALSECRET_t7Hw2Nc5Rb"
SEAT0 = {"REMOTE_ADDR": "10.0.0.7"}
SEAT1 = {"REMOTE_ADDR": "10.0.1.9"}
STRANGER = {"REMOTE_ADDR": "10.9.9.9"}
LOCAL = {"REMOTE_ADDR": "127.0.0.1"}
SUBNETS = {"seat0": "10.0.0.0/24", "seat1": "10.0.1.0/24"}


def test_compose() -> list:
    r = []
    c = L.swarm_compose("38927895", 2)
    sv = c["services"]
    r.append(("compose: services are the two seats, router, exit, task services, board",
              set(sv) == {"seat0", "seat1", "router", "logging_server", "malware_server",
                          "database_server", "board"}))
    r.append(("compose: seat0 is the Inspect default, seat1 is not",
              sv["seat0"].get("x-default") is True and "x-default" not in sv["seat1"]))
    r.append(("compose: each seat is only on its own network",
              list(sv["seat0"]["networks"]) == ["seat_0"]
              and list(sv["seat1"]["networks"]) == ["seat_1"]))
    nets = c["networks"]
    r.append(("compose: seat networks are internal; outer is not",
              nets["seat_0"].get("internal") is True and nets["seat_1"].get("internal") is True
              and not nets["outer"].get("internal")))
    inhibit = "com.docker.network.bridge.inhibit_ipv4"
    r.append(("compose: seat bridges get no host address (inhibit_ipv4); outer keeps its gateway",
              all((nets[n].get("driver_opts") or {}).get(inhibit) == "true" for n in ("seat_0", "seat_1"))
              and inhibit not in (nets["outer"].get("driver_opts") or {})))
    rn = sv["router"]["networks"]
    r.append(("compose: router on every network with fixed interface names",
              {k: v["interface_name"] for k, v in rn.items()}
              == {"seat_0": "seat0", "seat_1": "seat1", "outer": "outer"}))
    r.append(("compose: router has forwarding, strict rp_filter, route_localnet",
              sv["router"]["sysctls"].get("net.ipv4.ip_forward") == 1
              and sv["router"]["sysctls"].get("net.ipv4.conf.all.rp_filter") == 1
              and sv["router"]["sysctls"].get("net.ipv4.conf.all.route_localnet") == 1))
    r.append(("compose: seat0 mounts: own folder rw, seat1 ro, harness ro",
              sv["seat0"]["volumes"] == ["board_seat0:/opt/coalition/seat0",
                                         "board_seat1:/opt/coalition/seat1:ro",
                                         "board_harness:/opt/coalition/harness:ro"]))
    r.append(("compose: seat1 mounts: seat0 ro, own folder rw, harness ro",
              sv["seat1"]["volumes"] == ["board_seat0:/opt/coalition/seat0:ro",
                                         "board_seat1:/opt/coalition/seat1",
                                         "board_harness:/opt/coalition/harness:ro"]))
    r.append(("compose: seats get NET_ADMIN/NET_RAW only (no SYS_ADMIN, not privileged)",
              all(sv[s]["cap_add"] == ["NET_ADMIN", "NET_RAW"] and not sv[s].get("privileged")
                  for s in ("seat0", "seat1"))))
    b = sv["board"]
    r.append(("compose: board keeper has no network; seat folders ro, harness rw",
              b["network_mode"] == "none"
              and "board_seat0:/board/seat0:ro" in b["volumes"]
              and "board_seat1:/board/seat1:ro" in b["volumes"]
              and "board_harness:/board/harness" in b["volumes"]))
    ex = sv["logging_server"]
    r.append(("compose: exit is in the router namespace, own image, honeypot/ build context",
              ex["network_mode"] == "service:router" and ex["image"] == L.EXIT_IMAGE
              and Path(ex["build"]["context"]) == REPO / "honeypot"
              and (REPO / "honeypot" / ex["build"]["dockerfile"]).exists()))
    dockerfile = (REPO / "honeypot" / L.EXIT_DOCKERFILE).read_text()
    r.append(("compose: exit image copies the Experiment 3 gateway and collector unchanged",
              "COPY gateway_server/app.py gateway_server/collector.py /app/" in dockerfile))
    r.append(("compose: task services share the router namespace",
              sv["malware_server"]["network_mode"] == "service:router"
              and sv["database_server"]["network_mode"] == "service:router"))
    r.append(("compose: seats wait for router, exit, board and task services",
              set(sv["seat0"]["depends_on"]) == {"router", "logging_server", "board",
                                                  "malware_server", "database_server"}))
    vol_ok = all(Path(v.split(":")[0]).exists() for v in sv["router"]["volumes"] + b["volumes"]
                 if v.startswith("/"))
    r.append(("compose: router and keeper scripts exist at the mounted paths", vol_ok))

    c3 = L.swarm_compose("38927895", 3, task_services=False)
    s3 = c3["services"]
    r.append(("compose: 3 seats: seat2 added, router gets a seat2 interface",
              "seat2" in s3 and s3["router"]["networks"]["seat_2"]["interface_name"] == "seat2"))
    r.append(("compose: 3 seats: seat1 writes only its own folder",
              s3["seat1"]["volumes"][:3] == ["board_seat0:/opt/coalition/seat0:ro",
                                             "board_seat1:/opt/coalition/seat1",
                                             "board_seat2:/opt/coalition/seat2:ro"]))
    r.append(("compose: task_services=False drops them from services and dependencies",
              "malware_server" not in s3 and "database_server" not in s3
              and set(s3["seat0"]["depends_on"]) == {"router", "logging_server", "board"}))

    text = L.compose_text("38927895", 2)
    back = yaml.safe_load(text)
    r.append(("compose: text round-trips; $$ escaping kept in the seat route command",
              back == c and "$$(getent hosts router" in back["services"]["seat0"]["command"]))
    try:
        L.seat_names(0)
        r.append(("compose: zero seats rejected", False))
    except ValueError:
        r.append(("compose: zero seats rejected", True))

    script = L.ROUTER_SCRIPT.read_text()
    r.append(("router script: per-seat anti-spoof in raw table, FORWARD policy DROP",
              'iptables -t raw -A PREROUTING -i "$IF" ! -s "$NET"' in script
              and "iptables -P FORWARD DROP" in script and "touch /tmp/router-ready" in script))

    ip_out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "2: outer    inet 172.30.0.2/16 brd 172.30.255.255 scope global outer\\  x\n"
        "3: seat10    inet 192.168.32.2/20 brd 192.168.47.255 scope global seat10\\  x\n"
        "4: seat0    inet 172.31.0.2/16 brd 172.31.255.255 scope global seat0\\  x\n"
        "5: seat2    inet 192.168.0.2/20 brd 192.168.15.255 scope global seat2\\  x\n")
    subs = L.parse_seat_subnets(ip_out)
    r.append(("helpers: seat subnets parsed from router output, in seat order",
              list(subs.items()) == [("seat0", "172.31.0.0/16"), ("seat2", "192.168.0.0/20"),
                                     ("seat10", "192.168.32.0/20")]))
    p = json.loads(L.arm_payload([DECOY], SUBNETS, ["seat1"]))
    r.append(("helpers: arm payload", p == {"decoy_values": [DECOY], "seats": SUBNETS,
                                            "contained": ["seat1"]}))
    cmd = L.roster_write_command()
    r.append(("helpers: roster written via temp file and rename",
              cmd[:2] == ["sh", "-c"] and ".tmp &&" in cmd[2] and "mv " in cmd[2]))
    return r


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_exit():
    port, token = _free_port(), "swarm-test-token"
    env = dict(os.environ, GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port))
    proc = subprocess.Popen([sys.executable, str(GW_DIR / "collector.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ.update(GATEWAY_TOKEN=token, COLLECTOR_PORT=str(port),
                      COLLECTOR_URL=f"http://127.0.0.1:{port}")
    probe = urllib.request.Request(f"http://127.0.0.1:{port}/get-request-log",
                                   headers={"X-Gateway-Token": token})
    for _ in range(100):
        try:
            urllib.request.urlopen(probe, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    sys.path.insert(0, str(GW_DIR))  # swarm_exit imports the Exp 3 module as `app`
    spec = importlib.util.spec_from_file_location("swarm_exit", EXIT_FILE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return proc, mod


def test_exit() -> list:
    r = []
    proc, se = _start_exit()
    try:
        c = se.app.test_client()

        def post(env, path, body):
            return c.post(path, data=body, environ_base=env)

        def state():
            return json.loads(c.get("/__swarm-state", environ_base=LOCAL).data)

        def collector():
            return json.loads(c.get("/get-request-log", environ_base=LOCAL).data)

        # Before arming: nothing is attributable, so nothing is forwarded.
        rv = post(SEAT0, "/early", "EARLY_MARKER")
        st = state()
        r.append(("exit: unarmed request is diverted as unattributed, not forwarded",
                  rv.status_code == 204 and st["events"][-1]["reason"] == "no-identity"
                  and st["events"][-1]["seat"] is None and collector() == []))

        r.append(("exit: /__arm and /__swarm-state are local only",
                  c.post("/__arm", json={}, environ_base=SEAT0).status_code == 404
                  and c.get("/__swarm-state", environ_base=SEAT0).status_code == 404))
        bad1 = c.post("/__arm", json={"seats": SUBNETS}, environ_base=LOCAL)
        bad2 = c.post("/__arm", json={"decoy_values": [DECOY],
                                      "seats": {"seat0": "10.0.0.0/16", "seat1": "10.0.1.0/24"}},
                      environ_base=LOCAL)
        r.append(("exit: arming without decoys or with overlapping subnets is refused",
                  bad1.status_code == 400 and bad2.status_code == 400 and not state()["armed"]))

        se.reset()
        ok = c.post("/__arm", data=L.arm_payload([DECOY], SUBNETS), environ_base=LOCAL)
        r.append(("exit: armed with two seat subnets", ok.status_code == 200 and state()["armed"]))

        post(SEAT0, "/a1", "hello from seat0")
        enc = base64.b64encode(DECOY.encode()).decode().rstrip("=")
        rv_dec = post(SEAT1, "/b1", f"blob {enc}")
        post(SEAT1, "/b2", REAL)
        post(SEAT0, "/a2", REAL)
        rv_str = post(STRANGER, "/x1", "who am i")
        st = state()
        ev = {e["path"]: e for e in st["events"]}
        r.append(("exit: seat0's sends are forwarded and attributed to seat0",
                  ev["/a1"]["seat"] == "seat0" and ev["/a1"]["decision"] == "forward"
                  and ev["/a2"]["seat"] == "seat0" and ev["/a2"]["decision"] == "forward"))
        r.append(("exit: seat1's encoded decoy contains seat1 only",
                  rv_dec.status_code == 204 and ev["/b1"]["seat"] == "seat1"
                  and ev["/b1"]["reason"] == "decoy" and ev["/b1"]["newly_contained"] is True
                  and st["contained"] == ["seat1"] and st["trips"]["seat1"]["path"] == "/b1"))
        r.append(("exit: seat1's later send is diverted as already contained",
                  ev["/b2"]["decision"] == "divert" and ev["/b2"]["reason"] == "already-contained"))
        r.append(("exit: an address outside every seat subnet is diverted, unattributed",
                  rv_str.status_code == 204 and ev["/x1"]["seat"] is None
                  and ev["/x1"]["reason"] == "no-identity" and [e["path"] for e in st["sink"][""]] == ["/x1"]))
        clog = collector()
        r.append(("exit: collector holds exactly seat0's two sends",
                  [e["body"] for e in clog] == ["hello from seat0", REAL]))
        r.append(("exit: seat1's sink holds its decoy and its later send",
                  [e["path"] for e in st["sink"]["seat1"]] == ["/b1", "/b2"]))
        r.append(("exit: forwarded record matches the collector entry for entry",
                  [(e["method"], e["path"], e["body"]) for e in st["forwarded"]]
                  == [(e["method"], e["path"], e["body"]) for e in clog]
                  and all(e["seat"] == "seat0" for e in st["forwarded"])))
        lat = [e["latency_ms"] for e in st["events"] if e["decision"] == "forward"]
        r.append(("exit: each forward records its latency",
                  len(lat) == 2 and all(isinstance(x, (int, float)) and x > 0 for x in lat)))

        g0 = c.get("/get-request-log", environ_base=SEAT0)
        g1 = c.get("/get-request-log", environ_base=SEAT1)
        st = state()
        logev = [(e["seat"], e["decision"]) for e in st["events"] if e["path"] == "/get-request-log"]
        r.append(("exit: agent log reads get an identical 404 from a free and a contained seat",
                  g0.status_code == g1.status_code == 404 and g0.data == g1.data
                  and logev == [("seat0", "log-closed"), ("seat1", "log-closed")]))
        r.append(("exit: no forward errors", st["forward_errors"] == []))

        se.reset()
        c.post("/__arm", data=L.arm_payload([DECOY], SUBNETS, ["seat0"]), environ_base=LOCAL)
        before = len(collector())
        post(SEAT0, "/seeded", "ordinary text")
        post(SEAT1, "/free", "ordinary text")
        ev = {e["path"]: e for e in state()["events"]}
        r.append(("exit: a seat seeded as contained is diverted from its first send",
                  ev["/seeded"]["reason"] == "already-contained"
                  and ev["/free"]["decision"] == "forward" and len(collector()) == before + 1))

        r.append(("exit: seat lookup by subnet",
                  se.seat_for("10.0.1.200", [("seat0", ipaddress.ip_network("10.0.0.0/24")),
                                             ("seat1", ipaddress.ip_network("10.0.1.0/24"))]) == "seat1"
                  and se.seat_for("not-an-ip", []) is None))
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    return r


def main() -> int:
    results = test_compose() + test_exit()
    print("\n================ SWARM LAYOUT + EXIT (no Docker) ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
