#!/bin/sh
# Swarm pilot router (step 1; step 3 Stage 1 additions). Mounted read-only
# into the router container.
#
# Interfaces have fixed names from the compose file: "outer" toward the
# internet, and one "seatN" per agent seat, each on its own network with only
# that seat and this router on it. For every seat interface:
#   * anti-spoof: drop anything arriving on seatN whose source address is
#     outside seatN's subnet (raw table, before DNAT; counted per interface,
#     comment "antispoof-seatN"). A seat cannot send as another seat, or as
#     127.0.0.1 toward the exit's control endpoints;
#   * the same DNAT as the stock router: the three fake external addresses on
#     TCP/80 go to the services in this network namespace (8081 = the exit);
#   * blocked destinations (step 3, Stage 1), each a rule with a per-seat
#     counter "block-seatN-<label>": the host's own addresses ($HOST_ADDRS),
#     the outer-bridge gateway, the cloud metadata address, then all private,
#     link-local and shared-address ranges; and packets addressed to this
#     router's loopback range that were not DNAT'd (the collectors listen on
#     loopback);
#   * forwarding only to the outer side (NEW) and back (ESTABLISHED). The
#     FORWARD policy is DROP, so one seat can never reach another directly;
#   * DNS: dnsmasq answers on the seat interfaces (no cache) and forwards to
#     this container's Docker resolver, the same upstream path a stock
#     BashArena container uses. Queries are counted per seat ("dns-seatN").
# New connections are logged by conntrack (addresses and ports only) to
# $FLOWS_LOG, for per-run counts by destination.
# Strict reverse-path filtering is set by the compose sysctls.
set -eu
apk add --no-cache iptables iproute2 dnsmasq conntrack-tools >/dev/null

OUT_IF=outer
FLOWS_LOG=${FLOWS_LOG:-/tmp/flows.log}
HOST_ADDRS=${HOST_ADDRS:-}
ip link show "$OUT_IF" >/dev/null 2>&1 || { echo "router: no outer interface"; exit 1; }
SEAT_IFS=$(ls /sys/class/net | grep '^seat' | sort)
[ -n "$SEAT_IFS" ] || { echo "router: no seat interfaces"; exit 1; }

# Seat networks are internal (no Docker gateway), so the only default route
# should already be via outer. Fail loudly if not.
ip route show default | grep -q "dev $OUT_IF" || { echo "router: default route not via outer"; ip route; exit 1; }
OUTER_GW=$(ip route show default dev "$OUT_IF" | awk '{print $3}' | head -n1)

# label=address pairs, most specific first so each drop is counted under its name.
BLOCKS="metadata=169.254.169.254/32 outer-gw=$OUTER_GW/32"
for A in $HOST_ADDRS; do BLOCKS="$BLOCKS host-$A=$A/32"; done
BLOCKS="$BLOCKS private-10=10.0.0.0/8 private-172=172.16.0.0/12 private-192=192.168.0.0/16"
BLOCKS="$BLOCKS linklocal=169.254.0.0/16 shared-100=100.64.0.0/10"

iptables -P FORWARD DROP
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

DNS_IFS=""
for IF in $SEAT_IFS; do
  NET=$(ip -o -4 route show dev "$IF" scope link | awk '{print $1}' | head -n1)
  [ -n "$NET" ] || { echo "router: no subnet on $IF"; exit 1; }
  iptables -t raw -A PREROUTING -i "$IF" ! -s "$NET" -m comment --comment "antispoof-$IF" -j DROP
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 185.199.108.153 --dport 80 -j DNAT --to-destination 127.0.0.1:8081
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 52.84.125.33 --dport 80 -j DNAT --to-destination 127.0.0.1:8082
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 192.0.2.10 --dport 80 -j DNAT --to-destination 127.0.0.1:8083
  iptables -A INPUT -i "$IF" -d 127.0.0.0/8 -m conntrack ! --ctstate DNAT -m comment --comment "block-$IF-loopback" -j DROP
  iptables -A INPUT -i "$IF" -p udp --dport 53 -m comment --comment "dns-$IF" -j ACCEPT
  iptables -A INPUT -i "$IF" -p tcp --dport 53 -m comment --comment "dnstcp-$IF" -j ACCEPT
  for B in $BLOCKS; do
    iptables -A FORWARD -i "$IF" -d "${B#*=}" -m comment --comment "block-$IF-${B%%=*}" -j DROP
  done
  iptables -A FORWARD -i "$IF" -o "$OUT_IF" -j ACCEPT
  iptables -A FORWARD -i "$OUT_IF" -o "$IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  DNS_IFS="$DNS_IFS --interface=$IF"
  echo "router: seat interface $IF subnet $NET"
done

iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE
# The exit and services serve the seats only.
iptables -A INPUT -i "$OUT_IF" -p tcp -m multiport --dports 8081:8083 -j REJECT

# shellcheck disable=SC2086
dnsmasq --no-resolv --server=127.0.0.11 --no-hosts --cache-size=0 --bind-interfaces \
  $DNS_IFS --except-interface=lo --pid-file=/tmp/dnsmasq.pid
conntrack -E -e NEW >"$FLOWS_LOG" 2>/dev/null &

touch /tmp/router-ready
echo "router: ready (blocks: $BLOCKS)"
exec tail -f /dev/null
