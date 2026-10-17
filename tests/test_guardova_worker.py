"""Offline worker protocol tests, including loopback-only HTTP transport.

No test invokes Tor, upstream search engines, an external host, or a model.
Loopback tests skip if the operating system denies local server binding.
"""

import copy
import json
import os
import tempfile
import threading
import unittest
import urllib.error
from contextlib import contextmanager
from dataclasses import asdict
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from guardova_robin import CollectorLimits, WatchTarget, collect_watch
from guardova_robin.worker import (GuardovaClient, INTERNAL_PATH, MAX_HTTP_BYTES,
                                  MAX_JOB_BYTES, WorkerConfig, WorkerError,
                                  _NoRedirect, parse_job, process_once, tor_ready)

SECRET = "worker-secret-" + "s" * 40
LEASE = "a" * 64
URL = "http://" + "a" * 56 + ".onion/leak"


def config(origin="https://guardova.example"):
    return WorkerConfig(origin, SECRET, "worker-1")


def job(**changes):
    value = {"id": "job-1", "leaseToken": LEASE, "watchId": "watch-1", "tenantId": "tenant-1",
             "kind": "domain", "value": "example.com", "limits": asdict(CollectorLimits())}
    value.update(changes)
    return value


def collected():
    return collect_watch(WatchTarget("watch-1", "tenant-1", "domain", "example.com"), run_id="job-1",
                         search_fn=lambda q: {"results": [{"link": URL, "engine": "Fixture"}]},
                         scrape_fn=lambda item: (item["link"], {"status": "ok", "text": "example.com"})).to_dict()


class ClientStub:
    def __init__(self, replies):
        self.config = config()
        self.replies = list(replies)
        self.calls = []

    def post(self, payload):
        self.calls.append(copy.deepcopy(payload))
        reply = self.replies.pop(0) if self.replies else {"ok": True}
        if isinstance(reply, Exception):
            raise reply
        return copy.deepcopy(reply)


class Response:
    def __init__(self, body=b'{"ok":true}', status=200, content_type="application/json"):
        self.status = status
        self.body = body
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]


class WorkerConfigTests(unittest.TestCase):
    def test_endpoint_is_fixed_for_supported_origins(self):
        for origin in ("https://guardova.example", "https://guardova.example/", "https://guardova.example:8443",
                       "http://127.0.0.1:1234", "http://localhost:1234", "http://[::1]:1234"):
            self.assertTrue(config(origin).endpoint.endswith(INTERNAL_PATH))
        self.assertEqual(config().endpoint, "https://guardova.example" + INTERNAL_PATH)

    def test_invalid_origins_cannot_select_other_paths_or_leak_credentials(self):
        for origin in (None, 42, {}, [], "", "http://remote.example", "ftp://guardova.example",
                       "https://", "https://guardova.example/api", "https://a.example?x=1",
                       "https://a.example#frag", "https://user:password@a.example", "https://@a.example",
                       "https://a.example\\@evil.example", "https://a.example\n", "https://a.example\x00",
                       "https://a.example:99999"):
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(WorkerError, "^invalid_origin$"):
                    config(origin)

    def test_secret_worker_id_and_interval_match_wire_constraints(self):
        for secret in ("short", "s" * 513, "s" * 32 + "\n", "s" * 32 + "é"):
            with self.assertRaisesRegex(WorkerError, "^invalid_worker_secret$"):
                WorkerConfig("https://app.example", secret, "worker")
        for worker in ("", "space worker", "../worker", "é", "x" * 129):
            with self.assertRaisesRegex(WorkerError, "^invalid_worker_id$"):
                WorkerConfig("https://app.example", SECRET, worker)
        for interval in (0, 301, float("nan"), float("inf"), True, "15"):
            with self.assertRaisesRegex(WorkerError, "^invalid_poll_interval$"):
                WorkerConfig("https://app.example", SECRET, "worker", interval)

    def test_secret_file_is_preferred_and_bad_encoding_has_fixed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_file = Path(directory) / "worker-token"
            secret_file.write_text(SECRET + "\n")
            env = {"GUARDOVA_ORIGIN": "https://app.example", "DARKNET_WORKER_SECRET_FILE": str(secret_file),
                   "DARKNET_WORKER_SECRET": "ignored", "GUARDOVA_WORKER_ID": "worker-file"}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(WorkerConfig.from_env().secret, SECRET)
                secret_file.write_bytes(b"\xff\xff")
                with self.assertRaisesRegex(WorkerError, "^worker_secret_unreadable$"):
                    WorkerConfig.from_env()


class JobValidationTests(unittest.TestCase):
    def test_valid_job_preserves_run_lease_tenant_and_limits(self):
        job_id, lease, watch, limits = parse_job(job())
        self.assertEqual((job_id, lease, watch.watch_id, watch.tenant_id, watch.kind, watch.value),
                         ("job-1", LEASE, "watch-1", "tenant-1", "domain", "example.com"))
        self.assertEqual(asdict(limits), job()["limits"])

    def test_invalid_ids_leases_targets_and_extra_callbacks_are_rejected(self):
        invalid = [None, [], {}, job(id="../job"), job(tenantId="tenant 1"), job(watchId="watch/1"),
                   job(leaseToken="a" * 32), job(leaseToken="Z" * 64), job(leaseToken="a" * 63 + "_"),
                   job(kind="command"), job(value="https://example.com"), job(value="EXAMPLE.COM"),
                   job(callback="https://attacker.example/steal"), job(command="curl attacker"),
                   job(origin="https://attacker.example")]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaisesRegex(WorkerError, "^invalid_job$"):
                    parse_job(value)

    def test_limits_require_exact_keys_bounded_lease_duration_and_valid_numbers(self):
        base = job()["limits"]
        variants = [None, [], {}, {**base, "extra": 1}, {k: v for k, v in base.items() if k != "max_pages"}]
        for key, value in (("max_run_seconds", 181), ("max_run_seconds", float("nan")),
                           ("max_run_seconds", float("inf")), ("max_pages", 26),
                           ("max_results", 101), ("max_pages", True), ("max_body_bytes", -1)):
            variants.append({**base, key: value})
        for raw in variants:
            with self.subTest(limits=raw):
                with self.assertRaisesRegex(WorkerError, "^invalid_job$"):
                    parse_job(job(limits=raw))


class ProcessingTests(unittest.TestCase):
    def test_unready_does_not_claim_and_idle_does_not_collect(self):
        client, collector = ClientStub([]), mock.Mock()
        self.assertEqual(process_once(client, collector=collector, ready=lambda: False), "unready")
        self.assertEqual(client.calls, [])
        client = ClientStub([{"job": None}])
        self.assertEqual(process_once(client, collector=collector, ready=lambda: True), "idle")
        collector.assert_not_called()

    def test_claim_and_complete_use_same_bound_job_and_lease(self):
        client = ClientStub([{"job": job()}, {"ok": True}])
        collector = mock.Mock(return_value=SimpleNamespace(to_dict=collected))
        self.assertEqual(process_once(client, collector=collector, ready=lambda: True), "completed")
        self.assertEqual(client.calls[0], {"action": "claim", "workerId": "worker-1"})
        bound = collector.call_args
        self.assertEqual(bound.args[0].tenant_id, "tenant-1")
        self.assertEqual(bound.kwargs["run_id"], "job-1")
        completion = client.calls[1]
        self.assertEqual((completion["action"], completion["jobId"], completion["leaseToken"]),
                         ("complete", "job-1", LEASE))
        self.assertEqual(completion["result"]["run_id"], completion["jobId"])

    def test_collection_failure_sends_supported_fail_transition_without_exception_text(self):
        client = ClientStub([{"job": job()}, {"ok": True}])
        collector = mock.Mock(side_effect=RuntimeError("password=TOPSECRET"))
        with self.assertRaisesRegex(WorkerError, "^collection_error$"):
            process_once(client, collector=collector, ready=lambda: True)
        self.assertEqual(client.calls[1], {"action": "fail", "jobId": "job-1", "leaseToken": LEASE,
                                         "code": "collection_error"})
        self.assertNotIn("TOPSECRET", json.dumps(client.calls))

    def test_foreign_run_tenant_watch_kind_or_finding_never_reaches_completion(self):
        variants = []
        for key, value in (("run_id", "other"), ("tenant_id", "other"), ("watch_id", "other"),
                           ("schema_version", "2.0"), ("target_kind", "email"),
                           ("normalized_target", "other.example")):
            result = collected()
            result[key] = value
            variants.append(result)
        for key in ("run_id", "tenant_id", "watch_id"):
            result = collected()
            result["findings"][0][key] = "foreign"
            variants.append(result)
        for result in variants:
            client = ClientStub([{"job": job()}, {"ok": True}])
            collector = mock.Mock(return_value=SimpleNamespace(to_dict=lambda r=result: r))
            with self.assertRaisesRegex(WorkerError, "^collection_error$"):
                process_once(client, collector=collector, ready=lambda: True)
            self.assertEqual([p["action"] for p in client.calls], ["claim", "fail"])

    def test_completion_network_retry_reuses_identical_result_without_collecting_again(self):
        client = ClientStub([{"job": job()}, WorkerError("application_unreachable"), {"ok": True}])
        collector = mock.Mock(return_value=SimpleNamespace(to_dict=collected))
        stop = mock.Mock()
        stop.wait.return_value = False
        self.assertEqual(process_once(client, collector=collector, ready=lambda: True, stop=stop), "completed")
        collector.assert_called_once()
        self.assertEqual(client.calls[1], client.calls[2])
        stop.wait.assert_called_once_with(1)

    def test_uncertain_completion_has_three_identical_attempts_and_no_fail_transition(self):
        client = ClientStub([{"job": job()}] + [WorkerError("application_unreachable") for _ in range(3)])
        collector = mock.Mock(return_value=SimpleNamespace(to_dict=collected))
        stop = mock.Mock()
        stop.wait.return_value = False
        with self.assertRaisesRegex(WorkerError, "^application_unreachable$"):
            process_once(client, collector=collector, ready=lambda: True, stop=stop)
        self.assertEqual([p["action"] for p in client.calls], ["claim", "complete", "complete", "complete"])
        self.assertEqual(client.calls[1], client.calls[2])
        self.assertEqual(client.calls[2], client.calls[3])
        self.assertEqual(stop.wait.call_args_list, [mock.call(1), mock.call(2)])

    def test_authentication_and_rejected_completions_are_not_retried(self):
        for response in (WorkerError("authentication_failed"), WorkerError("application_rejected"), {"ok": False}):
            client = ClientStub([{"job": job()}, response])
            with self.assertRaises(WorkerError):
                process_once(client, collector=lambda *a, **k: SimpleNamespace(to_dict=collected), ready=lambda: True)
            self.assertEqual(len(client.calls), 2)

    def test_stop_interrupts_wait_without_recollecting_or_failing_uncertain_completion(self):
        client = ClientStub([{"job": job()}, WorkerError("application_unreachable")])
        stop = mock.Mock()
        stop.wait.return_value = True
        with self.assertRaisesRegex(WorkerError, "^worker_stopping$"):
            process_once(client, collector=lambda *a, **k: SimpleNamespace(to_dict=collected),
                         ready=lambda: True, stop=stop)
        self.assertEqual(len(client.calls), 2)

    def test_callback_injection_is_rejected_before_collection_or_evidence_send(self):
        client = ClientStub([{"job": job(callback="http://127.0.0.1/steal", origin="https://other.example")}])
        collector = mock.Mock()
        with self.assertRaisesRegex(WorkerError, "^invalid_job$"):
            process_once(client, collector=collector, ready=lambda: True)
        collector.assert_not_called()
        self.assertEqual([p["action"] for p in client.calls], ["claim"])


class TransportUnitTests(unittest.TestCase):
    def client(self, response):
        opener = mock.Mock()
        opener.open.return_value = response
        return GuardovaClient(config(), opener=opener), opener

    def test_transport_uses_only_configured_endpoint_and_authorization(self):
        client, opener = self.client(Response())
        self.assertEqual(client.post({"action": "complete", "callback": "https://other.example"}), {"ok": True})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, config().endpoint)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + SECRET)
        self.assertEqual(request.get_method(), "POST")

    def test_redirect_policy_refuses_every_status_without_creating_redirect_request(self):
        import urllib.request
        request = urllib.request.Request(config().endpoint, data=b"{}", headers={"Authorization": "Bearer " + SECRET})
        policy = _NoRedirect()
        for status in (301, 302, 303, 307, 308):
            with self.assertRaisesRegex(WorkerError, "^redirect_refused$"):
                policy.redirect_request(request, None, status, "redirect", {}, "https://attacker.example/steal")
        self.assertEqual(request.full_url, config().endpoint)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + SECRET)

    def test_request_cap_and_serialization_errors_prevent_open(self):
        client, opener = self.client(Response())
        for payload in ([], {"value": float("nan")}, {"value": object()}):
            with self.assertRaisesRegex(WorkerError, "^invalid_request$"):
                client.post(payload)
        with self.assertRaisesRegex(WorkerError, "^request_too_large$"):
            client.post({"action": "complete", "data": "x" * MAX_HTTP_BYTES})
        opener.open.assert_not_called()

    def test_claim_and_ack_responses_have_distinct_bounded_reads(self):
        for action, cap in (("claim", MAX_JOB_BYTES), ("complete", 1024), ("fail", 1024)):
            response = Response(body=b"x" * (cap + 1))
            client, _ = self.client(response)
            with self.assertRaisesRegex(WorkerError, "^response_too_large$"):
                client.post({"action": action})
            self.assertEqual(response.read_sizes, [cap + 1])

    def test_malformed_json_nonobject_duplicate_keys_nan_and_deep_json_are_fixed_errors(self):
        for body in (b"[]", b"not json", b'{"x":1,"x":2}', b'{"value":NaN}', b"\xff",
                     b"[" * 1500 + b"]" * 1500):
            client, _ = self.client(Response(body=body))
            with self.assertRaisesRegex(WorkerError, "^invalid_response$"):
                client.post({"action": "claim"})

    def test_network_and_http_errors_expose_no_secret_response_text(self):
        for error, expected in ((urllib.error.URLError("password=SECRET"), "application_unreachable"),
                                (urllib.error.HTTPError("https://secret.example", 401, "SECRET", {}, None), "authentication_failed"),
                                (urllib.error.HTTPError("https://secret.example", 409, "SECRET", {}, None), "application_rejected")):
            client, opener = self.client(Response())
            opener.open.side_effect = error
            with self.assertRaisesRegex(WorkerError, "^" + expected + "$"):
                client.post({"action": "claim"})


class LoopbackHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.calls.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                  "body": body})
        status, content_type, response, headers = self.server.responder(self.path, body)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


@contextmanager
def local_server(responder):
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LoopbackHandler)
    except OSError as exc:
        raise unittest.SkipTest("Operating system denied loopback test server") from exc
    server.calls = []
    server.responder = responder
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield server, "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def json_reply(payload):
    return 200, "application/json", json.dumps(payload).encode(), {}


class LocalHTTPTransportTests(unittest.TestCase):
    def test_real_post_transmits_bound_request_to_fixed_path(self):
        with local_server(lambda path, body: json_reply({"job": None})) as (server, origin):
            client = GuardovaClient(config(origin))
            self.assertEqual(process_once(client, ready=lambda: True), "idle")
            self.assertEqual(server.calls[0]["path"], INTERNAL_PATH)
            self.assertEqual(server.calls[0]["authorization"], "Bearer " + SECRET)
            self.assertEqual(json.loads(server.calls[0]["body"]), {"action": "claim", "workerId": "worker-1"})

    def test_real_redirect_never_sends_authorization_to_redirect_target(self):
        with local_server(lambda p, b: json_reply({"job": None})) as (sink, sink_origin):
            for status in (301, 302, 303, 307, 308):
                with local_server(lambda p, b, s=status: (s, "application/json", b"{}", {"Location": sink_origin + "/steal"})) as (server, origin):
                    with self.assertRaisesRegex(WorkerError, "^redirect_refused$"):
                        GuardovaClient(config(origin)).post({"action": "claim"})
                    self.assertEqual(len(server.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_ambient_proxy_cannot_receive_worker_credential(self):
        with local_server(lambda p, b: json_reply({"job": None})) as (proxy, proxy_origin):
            with local_server(lambda p, b: json_reply({"job": None})) as (server, origin):
                env = {"HTTP_PROXY": proxy_origin, "HTTPS_PROXY": proxy_origin, "ALL_PROXY": proxy_origin,
                       "http_proxy": proxy_origin, "https_proxy": proxy_origin, "all_proxy": proxy_origin,
                       "NO_PROXY": "", "no_proxy": ""}
                with mock.patch.dict(os.environ, env):
                    self.assertEqual(GuardovaClient(config(origin)).post({"action": "claim"}), {"job": None})
                self.assertEqual(len(server.calls), 1)
                self.assertEqual(proxy.calls, [])

    def test_real_oversized_or_nonjson_reply_is_refused(self):
        variants = [("application/json", b"x" * (MAX_JOB_BYTES + 1), "response_too_large"),
                    ("text/html", b"<html>password=SECRET</html>", "invalid_content_type"),
                    ("application/json", b'{"job":null,"job":{}}', "invalid_response")]
        for content_type, body, expected in variants:
            with local_server(lambda p, b, c=content_type, raw=body: (200, c, raw, {})) as (_, origin):
                with self.assertRaisesRegex(WorkerError, "^" + expected + "$"):
                    GuardovaClient(config(origin)).post({"action": "claim"})


class TorReadinessTests(unittest.TestCase):
    def test_incomplete_bootstrap_never_opens_socket(self):
        with mock.patch.dict(os.environ, {"ROBIN_TOR_LOG": "/tmp/fixture.log"}), \
                mock.patch("guardova_robin.worker.Path.read_text", return_value="Bootstrapped 80%"), \
                mock.patch("guardova_robin.worker.socket.create_connection") as connect:
            self.assertFalse(tor_ready())
            connect.assert_not_called()

    def test_completed_bootstrap_checks_only_local_socks_port(self):
        with mock.patch.dict(os.environ, {"ROBIN_TOR_LOG": "/tmp/fixture.log"}), \
                mock.patch("guardova_robin.worker.Path.read_text", return_value="Bootstrapped 100%"), \
                mock.patch("guardova_robin.worker.socket.create_connection") as connect:
            self.assertTrue(tor_ready())
            connect.assert_called_once_with(("127.0.0.1", 9050), timeout=0.5)


if __name__ == "__main__":
    unittest.main()
