"""Finite, credential-free deployment probe using public Tor Project inputs.

Run only in the isolated Guardova image, overriding its worker entrypoint:
    python -m guardova_robin.pilot

No application endpoint is contacted. Output contains counters and fixed codes,
never exit IPs, remote page bodies, search titles, source URLs or findings.
"""

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from .collector import _default_scrape, collect_watch
from .models import CollectorLimits, WatchTarget


CHECK_URL = "https://check.torproject.org/api/ip"
# Published by the Tor Project at https://onion.torproject.org/.
ONION_URL = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
TOTAL_SECONDS = 480
BOOTSTRAP_SECONDS = 180
CHECK_SECONDS = 45
ONION_SECONDS = 90
COLLECTION_SECONDS = 120
BODY_BYTES = 262_144


class PilotDeadline(BaseException):
    """Bypass collector's ordinary network-error recovery at the hard deadline."""


def _emit(stage, **metadata):
    print(json.dumps({"stage": stage, **metadata}, sort_keys=True), flush=True)


def _check_tor():
    import requests
    import scrape

    session = requests.Session()
    session.trust_env = False
    session.proxies = dict(scrape.TOR_PROXIES)
    response = None
    try:
        response = session.get(CHECK_URL, stream=True, allow_redirects=False,
                               timeout=(15, 20))
        if response.status_code != 200:
            return {"ok": False, "code": "tor_check_http", "http_status": response.status_code}
        body = scrape.read_capped(response, 4097)
        if len(body) > 4096:
            return {"ok": False, "code": "tor_check_body_limit"}
        record = json.loads(body)
        # The response's IP field is deliberately never returned or logged.
        return {"ok": isinstance(record, dict) and record.get("IsTor") is True,
                "http_status": 200, "code": "tor_check_completed"}
    finally:
        if response is not None:
            response.close()
        session.close()


def _official_onion():
    _, page = _default_scrape({"link": ONION_URL}, {"max_body_bytes": BODY_BYTES})
    text = page.get("text", "")
    return {"ok": page.get("status") == "ok" and bool(text.strip()),
            "http_status": page.get("http_status"),
            "truncated": bool(page.get("truncated")),
            "text_sha256": hashlib.sha256(text.encode()).hexdigest() if text else None,
            "characters_inspected": len(text),
            "public_project_reference": "tor project" in text.casefold()}


def _probe_child(sender, operation):
    try:
        sender.send(_check_tor() if operation == "tor_check" else _official_onion())
    except Exception:
        sender.send({"ok": False, "code": "network_probe_error"})
    finally:
        sender.close()


def _bounded_probe(operation, seconds):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    child = context.Process(target=_probe_child, args=(sender, operation), daemon=True)
    child.start()
    sender.close()
    try:
        if not receiver.poll(seconds):
            return {"ok": False, "code": "network_probe_timeout"}
        try:
            return receiver.recv()
        except EOFError:
            return {"ok": False, "code": "network_probe_error"}
    finally:
        receiver.close()
        if child.is_alive():
            child.terminate()
        child.join(timeout=1)
        if child.is_alive():
            child.kill()
            child.join(timeout=1)


def _collection_metadata(run):
    coverage = run.coverage
    return {"status": run.status, "complete": coverage.complete,
            "search_status": coverage.search_status,
            "engines": coverage.search_engines,
            "results_received": coverage.results_received,
            "results_considered": coverage.results_considered,
            "pages_attempted": coverage.pages_attempted,
            "pages_read": coverage.pages_read, "pages_failed": coverage.pages_failed,
            "observations": len(run.findings), "limits_reached": coverage.limits_reached,
            "errors": coverage.errors}


def _bootstrap_ready(log_path):
    try:
        if "Bootstrapped 100%" not in log_path.read_text(errors="replace")[-200_000:]:
            return False
        with socket.create_connection(("127.0.0.1", 9050), timeout=0.5):
            return True
    except OSError:
        return False


def main():
    started = time.monotonic()
    tor = None
    previous = {}

    def deadline_handler(*_):
        raise PilotDeadline()

    for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, deadline_handler)
    signal.alarm(TOTAL_SECONDS)
    try:
        directory = Path("/tmp/guardova-pilot")
        directory.mkdir(mode=0o700, exist_ok=False)
        log_path = directory / "notices.log"
        log_path.touch(mode=0o600)
        tor = subprocess.Popen(
            ["tor", "--DataDirectory", str(directory / "state"),
             "--SocksPort", "127.0.0.1:9050", "--ControlPort", "0",
             "--Log", "notice file " + str(log_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _emit("started", uid=os.getuid(), total_seconds=TOTAL_SECONDS,
              bootstrap_seconds=BOOTSTRAP_SECONDS, target="torproject.org",
              max_results=6, max_pages=2, max_body_bytes=BODY_BYTES,
              collection_seconds=COLLECTION_SECONDS)
        bootstrap_deadline = started + BOOTSTRAP_SECONDS
        while time.monotonic() < bootstrap_deadline:
            if tor.poll() is not None:
                _emit("bootstrap", ok=False, code="tor_process_exited")
                return 1
            if _bootstrap_ready(log_path):
                break
            time.sleep(1)
        else:
            _emit("bootstrap", ok=False, code="tor_bootstrap_timeout")
            return 1
        _emit("bootstrap", ok=True, elapsed_seconds=round(time.monotonic() - started, 2))
        check = _bounded_probe("tor_check", CHECK_SECONDS)
        _emit("tor_check", **check)
        onion = _bounded_probe("official_onion", ONION_SECONDS)
        _emit("official_onion", **onion)
        run = collect_watch(
            WatchTarget("pilot-public-tor", "pilot-synthetic-tenant", "domain", "torproject.org"),
            run_id="pilot-public-tor-run",
            limits=CollectorLimits(max_results=6, max_pages=2,
                                   max_body_bytes=BODY_BYTES,
                                   max_run_seconds=COLLECTION_SECONDS))
        _emit("default_collection", **_collection_metadata(run))
        answered = any(engine.get("status") in ("ok", "empty")
                       for engine in run.coverage.search_engines)
        accepted = bool(check.get("ok") and onion.get("ok") and answered
                        and run.coverage.pages_read > 0)
        _emit("finished", ok=accepted, elapsed_seconds=round(time.monotonic() - started, 2))
        return 0 if accepted else 1
    except PilotDeadline:
        _emit("finished", ok=False, code="pilot_deadline_or_stop",
              elapsed_seconds=round(time.monotonic() - started, 2))
        return 124
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
