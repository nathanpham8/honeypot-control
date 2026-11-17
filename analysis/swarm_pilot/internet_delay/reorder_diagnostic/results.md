Reordering diagnostic (internet delay Part 2, rule 4 check d). Throwaway
alpine:3.20 container with NET_ADMIN, the same helper (honeypot/swarm_netem.sh),
port 8091 delayed; counters from the container's /proc/net (deltas). Not a
stack; scripts in this folder (reorder.py mounted as /r.py).

| Workload | netem | RetransSegs | TCPOFOQueue | TCPSACKReorder | TCPLossProbes | TCPDSACKRecv |
|---|---|---|---|---|---|---|
| 30 sequential 1 MB requests | delay 5.84ms 0.29ms normal, rate 100gbit (recorded line) | 0 | 0 | 0 | 0 | 0 |
| 30 sequential 1 MB requests | same jitter, no rate | 7 | 156 | 104 | 0 | 7 |
| 30 sequential 1 MB requests | delay 5.84ms, no jitter | 0 | 0 | 0 | 0 | 0 |
| 4 x 10 concurrent 1 MB requests | recorded line | 39 | 0 | 0 | 39 | 39 |
| 4 x 10 concurrent 1 MB requests | off | 34 | 0 | 0 | 34 | 34 |
| 5 x 40 MB replies (server to client) | recorded line (4,074 packets, 0 dropped) | 0 | 1 | 3 | 0 | 0 |
| 5 x 40 MB replies | off | 0 | 0 | 0 | 0 | 0 |

The retransmits in the concurrent rows are tail-loss probes, one per
connection, equal with netem on and off. lo's rps_cpus is read-only in a
container.
