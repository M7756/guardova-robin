#!/bin/bash
set -eu
# State and Tor notices stay in the container's bounded tmpfs; no source pages
# or credentials are written to the upstream investigation directory.
export ROBIN_TOR_LOG=/tmp/guardova-tor/notices.log
mkdir -p /tmp/guardova-tor
chmod 0700 /tmp/guardova-tor
: > "$ROBIN_TOR_LOG"
tor --DataDirectory /tmp/guardova-tor/state --SocksPort 127.0.0.1:9050 \
    --ControlPort 0 --Log "notice file $ROBIN_TOR_LOG" &
tor_pid=$!
python -m guardova_robin.worker "$@" &
worker_pid=$!
stop() {
    kill -TERM "$worker_pid" "$tor_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
    wait "$tor_pid" 2>/dev/null || true
}
trap stop INT TERM EXIT
# Exit if either child dies, so the container restarts instead of remaining
# permanently unready after a failed Tor process.
set +e
wait -n "$worker_pid" "$tor_pid"
status=$?
set -e
if ! kill -0 "$tor_pid" 2>/dev/null; then
    echo "Tor process exited; restarting collector." >&2
    exit 1
fi
exit "$status"
