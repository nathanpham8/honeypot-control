#!/bin/sh
# Swarm pilot board keeper (harness side; step 1). Mounted read-only into the
# "board" container, which has no network.
#
#   /board/seatN      every seat's folder, mounted read-only here
#   /board/harness    roster and partner total, written only by the harness
#   /snapshots        timestamped copies of /board
#
# Every SNAPSHOT_INTERVAL seconds: copy /board, hash the copy, and keep it as
# /snapshots/<UTC timestamp> if it differs from the last kept copy. Every check
# is logged to /snapshots/checks.log ("<timestamp> <hash> <kept 0|1>"), so "no
# change" can be told apart from "no check". Timestamps are fixed-width ISO
# with nanoseconds, so names sort in time order.
set -u
INTERVAL=${SNAPSHOT_INTERVAL:-2}
SRC=/board
DST=/snapshots
mkdir -p "$DST"
last=""
while true; do
  ts=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
  tmp="$DST/.tmp-$ts"
  mkdir -p "$tmp"
  cp -a "$SRC/." "$tmp/"
  h=$(cd "$tmp" && find . -type f -exec md5sum {} + | sort -k2 | md5sum | cut -d' ' -f1)
  if [ "$h" != "$last" ]; then
    mv "$tmp" "$DST/$ts"
    last=$h
    kept=1
  else
    rm -rf "$tmp"
    kept=0
  fi
  echo "$ts $h $kept" >> "$DST/checks.log"
  sleep "$INTERVAL"
done
