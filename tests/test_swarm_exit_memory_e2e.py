"""Docker test: a state read after 40,000 sends does not kill the swarm exit
(step 3, Stage 1 final). Scripted, no model, no API.

Background: in the Stage 1 rerun the cgroup OOM killer killed the exit process
in its 384 MB container after about 40,000 delivered sends, while the harness
read the full one-piece state reply (31 MB). Stage 1 final makes the light
view the default, pages the full records and raises the exit's memory limit
to 1 GB (docs/swarm-pilot/step3-plan.md, "Stage 1 rerun review").

On a fresh two-seat stack, armed with seat0 free:
  1. seat0 sends 40,000 delivered 1 KB urlencoded sends from 4 parallel curl
     loops (10,000 each);
  2. once 20,000 have been recorded, while the flood is still running: a
     default state read, then every page of every section (ctl.py DUMP);
  3. after the flood: the same reads again.
Pass:
  * every send got 204, and the exit recorded 40,000 forwards;
  * every read succeeds; the default reply holds no forwarded, sink or trip
    records; the paged read after the flood holds the kept records (10,000
    events and 10,000 forwarded, the cap) once each;
  * the exit container's main process is the same process throughout (same
    start time, no container restart) and its cgroup records no OOM kill;
  * the exit still forwards a send afterwards.
Reported: the container's peak and current memory, reply sizes, timings.

Run:  PYTHONPATH=<repo> python tests/test_swarm_exit_memory_e2e.py
      SWARM_MEM_REPORT=<path> sets where the JSON report goes; KEEP=1 leaves
      the stack up. Docker only; run only when no experiment is running.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from honeypot.swarm_layout import (  # noqa: E402
    COLLECTION_IP, EXIT_MEM, arm_payload, compose_text, parse_seat_subnets,
)

TASK = "38927895"   # practice task (tasks/pilot_practice.txt)
PROJECT = f"swarm-exit-mem-e2e-{os.getpid()}"
DECOY = "DECOY_memtest_3a91c07e"            # synthetic
URL = f"http://{COLLECTION_IP}"
N_LOOPS, PER_LOOP = 4, 10000
N_SENDS = N_LOOPS * PER_LOOP
CAP = 10000                                 # the exit's record cap (MAX_LOG_ENTRIES)


class Stack:
    def __init__(self, workdir: Path):
        self.compose = workdir / "compose.yml"
        self.compose.write_text(compose_text(TASK, 2, task_services=True))
        self.base = ["docker", "compose", "-p", PROJECT, "-f", str(self.compose)]

    def dc(self, *args, timeout=600):
        return subprocess.run([*self.base, *args], capture_output=True, text=True, timeout=timeout)

    def sh(self, service, script, timeout=600):
        return self.dc("exec", "-T", service, "sh", "-c", script, timeout=timeout)

    def popen(self, service, script):
        return subprocess.Popen([*self.base, "exec", "-T", service, "sh", "-c", script],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def ctl(self, *args, timeout=600):
        return self.dc("exec", "-T", "logging_server", "python", "ctl.py", *args, timeout=timeout)

    def exit_id(self) -> dict:
        """The exit container's identity and memory: main process start time
        and command, restart count, cgroup OOM-kill count, peak and current
        memory."""
        probe = ("import json\n"
                 "st = open('/proc/1/stat').read().rsplit(')', 1)[1].split()\n"
                 "cg = '/sys/fs/cgroup/'\n"
                 "ev = dict(l.split() for l in open(cg + 'memory.events'))\n"
                 "rd = lambda f: int(open(cg + f).read().split()[0])\n"
                 "print(json.dumps({'pid1_start': st[19], "
                 "'pid1_cmd': open('/proc/1/cmdline').read().replace(chr(0), ' ').strip(), "
                 "'oom_kill': int(ev.get('oom_kill', 0)), 'oom': int(ev.get('oom', 0)), "
                 "'peak_mb': round(rd('memory.peak') / 2**20, 1), "
                 "'current_mb': round(rd('memory.current') / 2**20, 1), "
                 "'max_mb': round(rd('memory.max') / 2**20, 1)}))\n")
        out = json.loads(self.dc("exec", "-T", "logging_server", "python", "-c", probe).stdout)
        cid = self.dc("ps", "-q", "logging_server").stdout.strip()
        ins = subprocess.run(["docker", "inspect", "-f",
                              "{{.RestartCount}} {{.State.OOMKilled}} {{.State.StartedAt}}", cid],
                             capture_output=True, text=True).stdout.split()
        out.update(restart_count=int(ins[0]), oom_killed=ins[1] == "true", started_at=ins[2])
        return out


def read_all(st: Stack) -> dict:
    """A default state read, then every page of every section."""
    t0 = time.time()
    d = st.ctl("GET", "/__swarm-state")
    t1 = time.time()
    dump = st.ctl("DUMP")
    t2 = time.time()
    out = {"default_rc": d.returncode, "default_bytes": len(d.stdout),
           "default_seconds": round(t1 - t0, 2), "dump_rc": dump.returncode,
           "dump_bytes": len(dump.stdout), "dump_seconds": round(t2 - t1, 2),
           "dump_stderr": dump.stderr[-300:]}
    try:
        view = json.loads(d.stdout)
        out["default_keys_ok"] = view.get("view") == "light" and not (
            {"forwarded", "sink", "trips"} & set(view))
        out["events_total"] = view["events_total"]
        out["forwarded_total"] = view["totals"]["forwarded"]
    except (ValueError, KeyError) as e:
        out["default_error"] = repr(e)
    counts = {}
    try:
        for line in dump.stdout.splitlines():
            sec = json.loads(line)["section"]
            counts[sec] = counts.get(sec, 0) + 1
    except ValueError as e:
        out["dump_error"] = repr(e)
    out["dump_counts"] = counts
    return out


def main() -> int:
    results = []
    report = {"design": f"seat0 free; {N_LOOPS} curl loops x {PER_LOOP} delivered 1 KB sends; "
                        "reads during (after 20,000 recorded) and after the flood",
              "exit_mem_limit": EXIT_MEM}
    workdir = Path(tempfile.mkdtemp(prefix="swarm_exit_mem_e2e_"))
    st = Stack(workdir)
    try:
        up = st.dc("up", "-d", "--build", "--wait", "--wait-timeout", "420")
        results.append(("stack up and healthy", up.returncode == 0, up.stderr[-800:]))
        if up.returncode != 0:
            raise RuntimeError("stack did not come up")
        subnets = parse_seat_subnets(st.sh("router", "ip -o -4 addr show").stdout)
        a = st.ctl("POST", "/__arm", arm_payload([DECOY], subnets, feedback="L0"))
        results.append(("exit armed, seat0 free", a.returncode == 0 and json.loads(a.stdout).get("armed"),
                        a.stdout[-300:]))
        id0 = st.exit_id()
        report["exit_before"] = id0
        results.append((f"exit container memory limit is {EXIT_MEM}", id0["max_mb"] == 1024.0, id0))

        st.sh("seat0", "head -c 1024 /dev/zero | tr '\\0' 'a' | sed 's/^/d=/' > /tmp/b1k")
        loop = (f"n=0; i=0; while [ $i -lt {PER_LOOP} ]; do "
                f"c=$(curl -s -m 20 -o /dev/null -w '%{{http_code}}' --data-binary @/tmp/b1k {URL}/mem/flood); "
                f"[ \"$c\" = 204 ] && n=$((n+1)); i=$((i+1)); done; echo $n")
        t_flood = time.time()
        procs = [st.popen("seat0", loop) for _ in range(N_LOOPS)]

        # reads while the flood is running
        during = None
        while time.time() - t_flood < 1800:
            v = st.ctl("GET", "/__swarm-state?events_tail=0")
            n = json.loads(v.stdout)["events_total"] if v.returncode == 0 else 0
            if n >= N_SENDS // 2:
                during = read_all(st)
                during["recorded_at_start"] = n
                during["flood_running"] = any(p.poll() is None for p in procs)
                break
            if all(p.poll() is not None for p in procs):
                break
            time.sleep(3)
        report["read_during_flood"] = during
        results.append(("read during the flood: default view light, every page read, flood still running",
                        bool(during) and during["default_rc"] == 0 and during.get("default_keys_ok")
                        and during["dump_rc"] == 0 and "dump_error" not in during
                        and during["dump_counts"].get("events", 0) >= CAP // 2
                        and during["flood_running"], during))

        ok_counts = [int((p.communicate(timeout=3600)[0] or "0").strip().splitlines()[-1] or 0) for p in procs]
        report["flood_seconds"] = round(time.time() - t_flood, 1)
        report["sends_204"] = sum(ok_counts)
        results.append((f"all {N_SENDS} sends got 204", sum(ok_counts) == N_SENDS, ok_counts))

        after = read_all(st)
        report["read_after_flood"] = after
        results.append(("read after the flood: default view light; exit recorded every forward",
                        after["default_rc"] == 0 and after.get("default_keys_ok")
                        and after.get("forwarded_total") == N_SENDS
                        and after.get("events_total") == N_SENDS, after))
        results.append(("read after the flood: every page read; kept records (cap 10,000) each once",
                        after["dump_rc"] == 0 and "dump_error" not in after
                        and after["dump_counts"].get("events") == CAP
                        and after["dump_counts"].get("forwarded") == CAP, after["dump_counts"]))

        id1 = st.exit_id()
        report["exit_after"] = id1
        same = (id1["pid1_start"] == id0["pid1_start"] and id1["pid1_cmd"] == id0["pid1_cmd"]
                and "swarm_exit.py" in id1["pid1_cmd"] and id1["restart_count"] == 0
                and id1["started_at"] == id0["started_at"])
        results.append(("exit process not restarted (same main process, no container restart)", same,
                        (id0, id1)))
        results.append(("exit container cgroup records no OOM kill",
                        id1["oom_kill"] == 0 and not id1["oom_killed"], id1))
        code = st.sh("seat0", f"curl -s -m 20 -o /dev/null -w '%{{http_code}}' --data-binary @/tmp/b1k "
                              f"{URL}/mem/after").stdout.strip()
        last = json.loads(st.ctl("GET", "/__swarm-state?events_tail=1").stdout)["events"]
        results.append(("exit still forwards a send afterwards",
                        code == "204" and last and last[-1]["path"] == "/mem/after"
                        and last[-1]["decision"] == "forward", (code, last)))
        report["peak_mb"] = id1["peak_mb"]
    except Exception as e:  # noqa: BLE001
        results.append(("no exception during the test", False, repr(e)))
    finally:
        if os.environ.get("KEEP") != "1":
            st.dc("down", "-v", "--remove-orphans", timeout=300)

    out = Path(os.environ.get("SWARM_MEM_REPORT", tempfile.gettempdir() + "/swarm_exit_memory_report.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    report["checks"] = [{"check": n, "pass": bool(ok)} for n, ok, _ in results]
    out.write_text(json.dumps(report, indent=2))
    print("\n================ SWARM EXIT MEMORY E2E (Stage 1 final) ================")
    all_ok = True
    for name, ok, detail in results:
        all_ok = all_ok and bool(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok or os.environ.get("VERBOSE") == "1":
            print(f"         detail: {str(detail)[:1500]}")
    print(f"  peak memory: {report.get('peak_mb')} MB of {EXIT_MEM}; report: {out}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
