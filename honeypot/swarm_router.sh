#!/bin/sh
# Swarm pilot router (step 1). Mounted read-only into the router container.
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
#   * forwarding only to the outer side (NEW) and back (ESTABLISHED). The
#     FORWARD policy is DROP, so one seat can never reach another directly.
# Strict reverse-path filtering is set by the compose sysctls.
set -eu
apk add --no-cache iptables iproute2 >/dev/null

OUT_IF=outer
ip link show "$OUT_IF" >/dev/null 2>&1 || { echo "router: no outer interface"; exit 1; }
SEAT_IFS=$(ls /sys/class/net | grep '^seat' | sort)
[ -n "$SEAT_IFS" ] || { echo "router: no seat interfaces"; exit 1; }

# Seat networks are internal (no Docker gateway), so the only default route
# should already be via outer. Fail loudly if not.
ip route show default | grep -q "dev $OUT_IF" || { echo "router: default route not via outer"; ip route; exit 1; }

iptables -P FORWARD DROP
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

for IF in $SEAT_IFS; do
  NET=$(ip -o -4 route show dev "$IF" scope link | awk '{print $1}' | head -n1)
  [ -n "$NET" ] || { echo "router: no subnet on $IF"; exit 1; }
  iptables -t raw -A PREROUTING -i "$IF" ! -s "$NET" -m comment --comment "antispoof-$IF" -j DROP
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 185.199.108.153 --dport 80 -j DNAT --to-destination 127.0.0.1:8081
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 52.84.125.33 --dport 80 -j DNAT --to-destination 127.0.0.1:8082
  iptables -t nat -A PREROUTING -i "$IF" -p tcp -d 192.0.2.10 --dport 80 -j DNAT --to-destination 127.0.0.1:8083
  iptables -A FORWARD -i "$IF" -o "$OUT_IF" -j ACCEPT
  iptables -A FORWARD -i "$OUT_IF" -o "$IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  echo "router: seat interface $IF subnet $NET"
done

iptables -t nat -A POSTROUTING -o "$OUT_IF" -j MASQUERADE
# The exit and services serve the seats only.
iptables -A INPUT -i "$OUT_IF" -p tcp -m multiport --dports 8081:8083 -j REJECT

touch /tmp/router-ready
echo "router: ready"
exec tail -f /dev/null
