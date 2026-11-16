#!/bin/sh
# Drop container traffic to the cloud metadata address (honeypot-control).
#
# Installed as /usr/local/sbin/honeypot-metadata-block.sh and run by
# honeypot-metadata-block.service whenever Docker starts. Idempotent: removes
# its own rules (matched by comment) and inserts them again at the top of
# DOCKER-USER, which Docker evaluates before its own FORWARD rules for every
# container on a Docker network.
#
# DNS (UDP/TCP 53) to the address stays allowed: containers on Docker's default
# bridge, including `docker build` steps, use it as their only nameserver on
# this VM. Everything else to 169.254.169.254 (the metadata HTTP service)
# is dropped, so a probe times out. Not covered: host-network containers.
set -eu
ADDR=169.254.169.254/32
TAG=honeypot-control-metadata
IPT=${IPT:-iptables}

i=0
until $IPT -n -L DOCKER-USER >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -le 60 ] || { echo "DOCKER-USER chain not found" >&2; exit 1; }
  sleep 1
done

# remove earlier copies of our rules
$IPT -S DOCKER-USER | grep -- "--comment $TAG" | sed 's/^-A /-D /' | while read -r rule; do
  # shellcheck disable=SC2086
  eval $IPT $rule
done

# inserted in reverse so the final order is: DNS accept (udp, tcp), then drop
$IPT -I DOCKER-USER 1 -d "$ADDR" -m comment --comment "$TAG" -j DROP
$IPT -I DOCKER-USER 1 -d "$ADDR" -p tcp --dport 53 -m comment --comment "$TAG" -j RETURN
$IPT -I DOCKER-USER 1 -d "$ADDR" -p udp --dport 53 -m comment --comment "$TAG" -j RETURN
$IPT -S DOCKER-USER | grep -- "$TAG"
