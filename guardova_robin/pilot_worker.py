"""One real leased-job acceptance run against a private HTTPS pilot API.

The default uses the normal search engines. --seed-official instead supplies
one explicitly labelled official Tor Project onion URL to the search adapter;
the real Tor scraper, matching, evidence and HTTP completion stay unchanged.
Neither mode accepts arbitrary targets or stores a payload on disk.
"""

import argparse
from dataclasses import replace
from pathlib import Path
import signal
import subprocess
import time
from urllib.parse import urlsplit

from .collector import collect_watch
from .pilot import (BODY_BYTES, ONION_URL, PilotDeadline, _bootstrap_ready,
                    _collection_metadata, _emit)
from .worker import GuardovaClient, WorkerConfig, WorkerError, process_once

TOTAL_SECONDS = 360
BOOTSTRAP_SECONDS = 180
PUBLIC_TARGETS = frozenset({("domain", "torproject.org"), ("organization", "tor project")})


class ReplayClient(GuardovaClient):
    """Acknowledge completion twice over the real transport, with one payload."""

    def __init__(self, config, **kwargs):
        super().__init__(config, **kwargs)
        self.completion_requests = 0
        self.idempotent_replay = False

    def post(self, payload):
        if not isinstance(payload, dict) or payload.get("action") != "complete":
            return super().post(payload)
        self.completion_requests += 1
        response = super().post(payload)
        if response.get("ok") is not True:
            raise WorkerError("pilot_completion_rejected")
        self.completion_requests += 1
        replay = super().post(payload)
        if replay.get("ok") is not True:
            raise WorkerError("pilot_replay_rejected")
        self.idempotent_replay = True
        _emit("completion", requests=self.completion_requests, idempotent_replay=True)
        return replay


def _official_seed(_query):
    return {"results": [{"link": ONION_URL, "title": "", "engine": "pilot_official_seed"}],
            "stats": {"engines": [{"engine": "pilot_official_seed", "status": "ok",
                                     "results": 1, "http_status": None}]},
            "truncated": False}


def _collect_public(target, *, run_id, limits, seeded):
    if (target.kind, target.value) not in PUBLIC_TARGETS:
        raise WorkerError("pilot_target_refused")
    bounded = replace(limits, max_results=min(limits.max_results, 6),
                      max_pages=min(limits.max_pages, 2),
                      max_body_bytes=min(limits.max_body_bytes, BODY_BYTES),
                      max_run_seconds=min(limits.max_run_seconds, 120))
    result = collect_watch(target, run_id=run_id, limits=bounded,
                           search_fn=_official_seed if seeded else None)
    _emit("collection", source_mode="official_seed" if seeded else "default_search",
          **_collection_metadata(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run one bounded private-API acceptance job")
    parser.add_argument("--seed-official", action="store_true",
                        help="Seed only the official Tor Project onion; this does not test search coverage")
    args = parser.parse_args(argv)
    started, tor, previous = time.monotonic(), None, {}

    def stop_handler(*_):
        raise PilotDeadline()

    for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, stop_handler)
    signal.alarm(TOTAL_SECONDS)
    try:
        config = WorkerConfig.from_env()
        if urlsplit(config.origin).scheme != "https":
            raise WorkerError("pilot_requires_https")
        client = ReplayClient(config)
        directory = Path("/tmp/guardova-pilot-worker")
        directory.mkdir(mode=0o700, exist_ok=False)
        log_path = directory / "notices.log"
        log_path.touch(mode=0o600)
        tor = subprocess.Popen(
            ["tor", "--DataDirectory", str(directory / "state"),
             "--SocksPort", "127.0.0.1:9050", "--ControlPort", "0",
             "--Log", "notice file " + str(log_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _emit("started", total_seconds=TOTAL_SECONDS, bootstrap_seconds=BOOTSTRAP_SECONDS,
              source_mode="official_seed" if args.seed_official else "default_search")
        bootstrap_deadline = started + BOOTSTRAP_SECONDS
        while time.monotonic() < bootstrap_deadline:
            if tor.poll() is not None:
                raise WorkerError("tor_process_exited")
            if _bootstrap_ready(log_path):
                break
            time.sleep(1)
        else:
            raise WorkerError("tor_bootstrap_timeout")
        _emit("bootstrap", ok=True, elapsed_seconds=round(time.monotonic() - started, 2))
        observations = 0

        def collector(target, **kwargs):
            nonlocal observations
            result = _collect_public(target, seeded=args.seed_official, **kwargs)
            observations = len(result.findings)
            return result

        outcome = process_once(client, ready=lambda: _bootstrap_ready(log_path), collector=collector)
        accepted = (outcome == "completed" and client.idempotent_replay
                    and (not args.seed_official or observations > 0))
        _emit("finished", ok=accepted, outcome=outcome,
              completion_requests=client.completion_requests,
              observations=observations,
              idempotent_replay=client.idempotent_replay,
              elapsed_seconds=round(time.monotonic() - started, 2))
        return 0 if accepted else 1
    except PilotDeadline:
        _emit("finished", ok=False, code="pilot_deadline_or_stop")
        return 124
    except WorkerError as exc:
        _emit("finished", ok=False, code=str(exc))
        return 1
    except Exception:
        _emit("finished", ok=False, code="pilot_setup_error")
        return 1
    finally:
        if tor is not None and tor.poll() is None:
            tor.terminate()
            try:
                tor.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tor.kill()
                tor.wait(timeout=2)
        signal.alarm(0)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
