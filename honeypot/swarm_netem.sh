#!/bin/sh
# Emulated internet delay for the swarm exit's collector connections
# (step 3, internet delay Part 2). Run in the router container, whose network
# namespace the exit, the collector and the cold-calibration collectors
# share. Only used when the compose option netem is set (off by default).
#
#   NETEM        netem parameters, e.g.
#                "delay 5.84ms 0.29ms distribution normal rate 100gbit"
#   NETEM_PORTS  TCP ports whose traffic is delayed (both directions)
#
# Layout on lo: a prio qdisc with every priority mapped to band 1 (no delay);
# netem on band 3; u32 filters send TCP packets whose destination or source
# port is in NETEM_PORTS to band 3. Each direction of a loopback connection
# passes lo's queue once, so each gets one netem delay. With "rate" set,
# netem never schedules a packet before the last one queued, so packets are
# not reordered.
#
#   sh swarm_netem.sh on | off | status
set -eu
DEV=lo
case "${1:-status}" in
  on)
    [ -n "${NETEM:-}" ] && [ -n "${NETEM_PORTS:-}" ] || { echo "netem: NETEM and NETEM_PORTS required"; exit 1; }
    tc qdisc del dev "$DEV" root 2>/dev/null || true
    tc qdisc add dev "$DEV" root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    # shellcheck disable=SC2086
    tc qdisc add dev "$DEV" parent 1:3 handle 30: netem $NETEM
    for P in $NETEM_PORTS; do
      tc filter add dev "$DEV" parent 1: protocol ip prio 1 u32 \
        match ip protocol 6 0xff match ip dport "$P" 0xffff flowid 1:3
      tc filter add dev "$DEV" parent 1: protocol ip prio 1 u32 \
        match ip protocol 6 0xff match ip sport "$P" 0xffff flowid 1:3
    done
    echo "netem: on ($NETEM) for ports $NETEM_PORTS"
    ;;
  off)
    tc qdisc del dev "$DEV" root 2>/dev/null || true
    echo "netem: off"
    ;;
  status)
    tc -s qdisc show dev "$DEV"
    tc filter show dev "$DEV" | grep -c "flowid 1:3" || true
    ;;
  *) echo "usage: $0 on|off|status"; exit 2 ;;
esac
