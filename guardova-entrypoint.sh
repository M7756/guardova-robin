#!/bin/bash
set -eu

# Keep shutdown below Compose's 190-second stop window. The smaller override
# also permits real process-lifecycle checks without waiting three minutes.
stop_grace=${GUARDOVA_STOP_GRACE_SECONDS:-180}
if [[ ! "$stop_grace" =~ ^[1-9][0-9]{0,2}$ ]] || (( stop_grace > 180 )); then
    echo "supervisor_invalid_stop_grace" >&2
    exit 2
fi
tor_pid=
worker_pid=
stop_requested=0

# Consult Bash's own children rather than kill -0: a denied signal must never
# be mistaken for a process that has already exited. Stopped jobs count too.
child_active() {
    local child_pid=$1 active_pid
    [[ -n "$child_pid" ]] || return 1
    for active_pid in $(jobs -pr; jobs -ps); do
        [[ "$active_pid" != "$child_pid" ]] || return 0
    done
    return 1
}

children_active() {
    child_active "$worker_pid" || child_active "$tor_pid"
}

signal_child() {
    local child_name=$1 child_pid=$2 child_signal=$3
    child_active "$child_pid" || return 0
    if kill -"$child_signal" "$child_pid" 2>/dev/null; then
        return 0
    fi
    # The child may have exited between the job-table check and kill.
    child_active "$child_pid" || return 0
    echo "supervisor_signal_failed child=$child_name signal=$child_signal" >&2
    return 1
}

cleanup() {
    local failed=0 deadline
    signal_child worker "$worker_pid" TERM || failed=1
    signal_child tor "$tor_pid" TERM || failed=1
    deadline=$((SECONDS + stop_grace))
    # A permission failure cannot be cured by waiting out the TERM grace.
    while (( failed == 0 && SECONDS < deadline )) && children_active; do
        sleep 0.1 || :
    done
    if child_active "$worker_pid"; then
        echo "supervisor_force_kill child=worker" >&2
        signal_child worker "$worker_pid" KILL || failed=1
    fi
    if child_active "$tor_pid"; then
        echo "supervisor_force_kill child=tor" >&2
        signal_child tor "$tor_pid" KILL || failed=1
    fi
    deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )) && children_active; do
        sleep 0.1 || :
    done
    if children_active; then
        echo "supervisor_cleanup_timeout" >&2
        failed=1
    fi
    # wait is used only after the shell knows a child has exited, so cleanup
    # cannot hang even when the runtime denies both TERM and KILL.
    if [[ -n "$worker_pid" ]] && ! child_active "$worker_pid"; then
        wait "$worker_pid" 2>/dev/null || :
    fi
    if [[ -n "$tor_pid" ]] && ! child_active "$tor_pid"; then
        wait "$tor_pid" 2>/dev/null || :
    fi
    return "$failed"
}

on_exit() {
    local status=$?
    trap - EXIT
    trap '' INT TERM
    set +e
    cleanup || status=1
    exit "$status"
}

trap 'stop_requested=1' INT TERM
trap on_exit EXIT

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
# Exit if either child dies, so the container restarts instead of remaining
# permanently unready. Even an unexpected zero exit is a service failure.
while (( stop_requested == 0 )); do
    if ! child_active "$tor_pid"; then
        echo "supervisor_child_exited child=tor" >&2
        exit 1
    fi
    if ! child_active "$worker_pid"; then
        echo "supervisor_child_exited child=worker" >&2
        exit 1
    fi
    sleep 0.1 || :
done
exit 0
