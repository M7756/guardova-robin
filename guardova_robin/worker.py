"""Lease-bound Guardova polling worker; no inbound port or model credentials.

The authenticated application assigns the tenant and target. Onion pages are
untrusted input handled solely by the collector. Neither a page nor a job can
choose the destination to which the worker sends its credential or evidence.
"""

import argparse
import json
import logging
import os
import re
import signal
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .collector import collect_watch
from .matching import normalize_target
from .models import CollectorLimits, WatchTarget, validate_identifier

LOGGER = logging.getLogger("guardova_robin")
MAX_HTTP_BYTES = 2_000_000
MAX_JOB_BYTES = 8192
HTTP_TIMEOUT = 20
INTERNAL_PATH = "/api/internal/darknet"
_CODE = re.compile(r"^[a-z_]{1,50}$")
_WIRE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class WorkerError(RuntimeError):
    """A fixed diagnostic code, never a URL, credential or response body."""

    def __init__(self, code):
        super().__init__(code if _CODE.fullmatch(str(code)) else "worker_error")


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


@dataclass(frozen=True)
class WorkerConfig:
    origin: str
    secret: str
    worker_id: str
    poll_seconds: float = 15

    def __post_init__(self):
        try:
            if not isinstance(self.origin, str):
                raise ValueError()
            parts = urlsplit(self.origin)
            if (parts.username is not None or parts.password is not None or parts.query or parts.fragment
                    or parts.path not in ("", "/") or not parts.hostname):
                raise ValueError()
            # HTTP exists only for a local test application. Remote credentials
            # always travel over certificate-validated HTTPS.
            if parts.scheme != "https" and not (
                    parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost")):
                raise ValueError()
            _ = parts.port
            if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in self.origin) or "\\" in self.origin:
                raise ValueError()
        except ValueError as exc:
            raise WorkerError("invalid_origin") from exc
        if (not isinstance(self.secret, str) or not 32 <= len(self.secret) <= 512
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in self.secret)):
            raise WorkerError("invalid_worker_secret")
        try:
            validate_identifier(self.worker_id, "worker_id")
            if not _WIRE_IDENTIFIER.fullmatch(self.worker_id):
                raise ValueError()
        except ValueError as exc:
            raise WorkerError("invalid_worker_id") from exc
        if (isinstance(self.poll_seconds, bool) or not isinstance(self.poll_seconds, (int, float))
                or not 1 <= self.poll_seconds <= 300):
            raise WorkerError("invalid_poll_interval")

    @property
    def endpoint(self):
        parts = urlsplit(self.origin)
        return urlunsplit((parts.scheme, parts.netloc, INTERNAL_PATH, "", ""))

    @classmethod
    def from_env(cls):
        secret_file = os.environ.get("DARKNET_WORKER_SECRET_FILE")
        if secret_file:
            try:
                secret = Path(secret_file).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError) as exc:
                raise WorkerError("worker_secret_unreadable") from exc
        else:
            secret = os.environ.get("DARKNET_WORKER_SECRET", "")
        try:
            poll = float(os.environ.get("GUARDOVA_POLL_SECONDS", "15"))
        except ValueError as exc:
            raise WorkerError("invalid_poll_interval") from exc
        return cls(os.environ.get("GUARDOVA_ORIGIN", ""), secret,
                   os.environ.get("GUARDOVA_WORKER_ID") or "robin-" + str(uuid.uuid4()), poll)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        # A reverse-proxy redirect must never forward the bearer to another
        # endpoint. Operators fix the configured origin instead.
        raise WorkerError("redirect_refused")


class GuardovaClient:
    def __init__(self, config, *, opener=None):
        self.config = config
        # Do not let ambient proxy settings send the worker credential through
        # an unexpected proxy. Onion traffic uses Robin's separate Tor client.
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    def post(self, payload):
        if not isinstance(payload, dict):
            raise WorkerError("invalid_request")
        try:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, RecursionError) as exc:
            raise WorkerError("invalid_request") from exc
        if len(body) > MAX_HTTP_BYTES:
            raise WorkerError("request_too_large")
        request = urllib.request.Request(self.config.endpoint, data=body, method="POST", headers={
            "Authorization": "Bearer " + self.config.secret,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Guardova-Robin/1.0",
        })
        try:
            with self.opener.open(request, timeout=HTTP_TIMEOUT) as response:
                if response.status != 200:
                    raise WorkerError("application_rejected")
                if response.headers.get_content_type() != "application/json":
                    raise WorkerError("invalid_content_type")
                cap = MAX_JOB_BYTES if payload.get("action") == "claim" else 1024
                data = response.read(cap + 1)
                if len(data) > cap:
                    raise WorkerError("response_too_large")
                value = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                if not isinstance(value, dict):
                    raise WorkerError("invalid_response")
                return value
        except WorkerError:
            raise
        except urllib.error.HTTPError as exc:
            raise WorkerError("authentication_failed" if exc.code in (401, 403)
                              else "application_rejected") from None
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            raise WorkerError("application_unreachable" if isinstance(exc, OSError)
                              else "invalid_response") from None


def parse_job(value):
    """Accept no executable command, fetch URL or callback from a claimed job."""
    if not isinstance(value, dict):
        raise WorkerError("invalid_job")
    try:
        if set(value) != {"id", "leaseToken", "watchId", "tenantId", "kind", "value", "limits"}:
            raise ValueError()
        job_id = validate_identifier(value["id"], "id")
        if any(not isinstance(value[key], str) or not _WIRE_IDENTIFIER.fullmatch(value[key])
               for key in ("id", "watchId", "tenantId")):
            raise ValueError()
        lease = value["leaseToken"]
        if not isinstance(lease, str) or not re.fullmatch(r"[a-f0-9]{64}", lease):
            raise ValueError()
        target = WatchTarget(value["watchId"], value["tenantId"], value["kind"], value["value"])
        if normalize_target(target) != target.value:
            raise ValueError()
        raw_limits = value["limits"]
        if not isinstance(raw_limits, dict) or set(raw_limits) != set(CollectorLimits.__dataclass_fields__):
            raise ValueError()
        limits = CollectorLimits(**raw_limits)
        # Reserve room within the five-minute lease for completion retries.
        if limits.max_run_seconds > 180 or limits.max_results > 100 or limits.max_pages > 25:
            raise ValueError()
        return job_id, lease, target, limits
    except (KeyError, ValueError, TypeError) as exc:
        raise WorkerError("invalid_job") from exc


def tor_ready():
    log_path = os.environ.get("ROBIN_TOR_LOG")
    if log_path:
        try:
            if "Bootstrapped 100%" not in Path(log_path).read_text(errors="replace")[-200_000:]:
                return False
        except OSError:
            return False
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=0.5):
            return True
    except OSError:
        return False


def process_once(client, *, collector=collect_watch, ready=tor_ready, stop=None):
    """Return idle/unready/completed; retries only the bound completion record."""
    if not ready():
        return "unready"
    reply = client.post({"action": "claim", "workerId": client.config.worker_id})
    if "job" not in reply:
        raise WorkerError("invalid_response")
    if reply["job"] is None:
        return "idle"
    job_id, lease, target, limits = parse_job(reply["job"])
    try:
        result = collector(target, run_id=job_id, limits=limits).to_dict()
        if (result.get("run_id") != job_id or result.get("tenant_id") != target.tenant_id
                or result.get("watch_id") != target.watch_id or result.get("schema_version") != "1.0"
                or result.get("target_kind") != target.kind or result.get("normalized_target") != target.value):
            raise WorkerError("result_binding_mismatch")
        findings = result.get("findings")
        if not isinstance(findings, list) or any(
                not isinstance(finding, dict) or finding.get("run_id") != job_id
                or finding.get("tenant_id") != target.tenant_id or finding.get("watch_id") != target.watch_id
                for finding in findings):
            raise WorkerError("result_binding_mismatch")
    except Exception:
        # No exception text or untrusted target is included in a diagnostic.
        client.post({"action": "fail", "jobId": job_id, "leaseToken": lease,
                     "code": "collection_error"})
        raise WorkerError("collection_error") from None
    payload = {"action": "complete", "jobId": job_id, "leaseToken": lease, "result": result}
    last_error = None
    for attempt in range(3):
        try:
            response = client.post(payload)
            if response.get("ok") is not True:
                raise WorkerError("invalid_response")
            return "completed"
        except WorkerError as exc:
            last_error = exc
            if str(exc) not in ("application_unreachable",):
                raise
            if attempt < 2:
                if stop is not None:
                    if stop.wait(2 ** attempt):
                        raise WorkerError("worker_stopping") from None
                else:
                    time.sleep(2 ** attempt)
    raise last_error


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the Guardova Robin polling worker")
    parser.add_argument("--once", action="store_true", help="Process at most one leased job")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        config = WorkerConfig.from_env()
    except WorkerError as exc:
        LOGGER.error("configuration: %s", exc)
        return 2
    client, stop = GuardovaClient(config), threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    while not stop.is_set():
        try:
            outcome = process_once(client, stop=stop)
            if outcome == "completed":
                LOGGER.info("collection completed")
            if args.once:
                return 0 if outcome != "unready" else 3
        except WorkerError as exc:
            LOGGER.warning("worker: %s", exc)
            if args.once:
                return 1
        if stop.wait(config.poll_seconds):
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
