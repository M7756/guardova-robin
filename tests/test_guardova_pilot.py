"""Offline acceptance-probe checks; no Tor daemon or remote request is started."""

import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

from guardova_robin import pilot
from guardova_robin.models import CollectionRun


class GuardovaPilotTests(unittest.TestCase):
    def test_tor_check_uses_tor_remote_dns_without_ambient_proxies_or_redirects(self):
        response = Mock(status_code=200)
        session = Mock()
        session.get.return_value = response
        with patch("requests.Session", return_value=session), patch("scrape.read_capped", return_value=b'{"IsTor":true,"IP":"PRIVATE_EXIT"}'):
            result = pilot._check_tor()
        self.assertEqual(result, {"ok": True, "http_status": 200, "code": "tor_check_completed"})
        self.assertFalse(session.trust_env)
        self.assertTrue(all(value == "socks5h://127.0.0.1:9050" for value in session.proxies.values()))
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertTrue(session.get.call_args.kwargs["stream"])
        self.assertNotIn("PRIVATE_EXIT", json.dumps(result))
        response.close.assert_called_once()
        session.close.assert_called_once()

    def test_check_rejects_a_non_tor_exit(self):
        with patch("requests.Session") as factory, patch("scrape.read_capped", return_value=b'{"IsTor":false,"IP":"PRIVATE_EXIT"}'):
            factory.return_value.get.return_value.status_code = 200
            result = pilot._check_tor()
        self.assertFalse(result["ok"])
        self.assertNotIn("IP", result)

    def test_check_rejects_body_over_cap_and_does_not_parse_it(self):
        with patch("requests.Session") as factory, patch("scrape.read_capped", return_value=b"X" * 4097):
            factory.return_value.get.return_value.status_code = 200
            self.assertEqual(pilot._check_tor(), {"ok": False, "code": "tor_check_body_limit"})

    def test_official_onion_prints_only_metadata(self):
        body = "Tor Project official public page with BODY_MARKER"
        page = {"status": "ok", "text": body, "http_status": 200, "truncated": True}
        with patch.object(pilot, "_default_scrape", return_value=(pilot.ONION_URL, page)) as scrape:
            result = pilot._official_onion()
        self.assertTrue(result["ok"])
        self.assertTrue(result["public_project_reference"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["characters_inspected"], len(body))
        self.assertNotIn("BODY_MARKER", json.dumps(result))
        self.assertNotIn(pilot.ONION_URL, json.dumps(result))
        self.assertEqual(scrape.call_args.args[1]["max_body_bytes"], 262_144)

    def test_collection_metadata_excludes_full_findings_and_source_outcomes(self):
        run = CollectionRun("run", "tenant", "watch", "domain", "torproject.org", "start")
        run.findings.append({"excerpt": "SECRET_BODY"})
        run.coverage.source_outcomes.append({"source_url": "SECRET_SOURCE"})
        metadata = pilot._collection_metadata(run)
        self.assertEqual(metadata["observations"], 1)
        self.assertNotIn("SECRET", json.dumps(metadata))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pilot._emit("default_collection", **metadata)
        self.assertEqual(json.loads(output.getvalue())["stage"], "default_collection")

    def test_bounded_probe_terminates_and_kills_a_stuck_child(self):
        receiver, sender, child = Mock(), Mock(), Mock()
        receiver.poll.return_value = False
        child.is_alive.return_value = True
        context = Mock()
        context.Pipe.return_value = (receiver, sender)
        context.Process.return_value = child
        with patch.object(pilot.multiprocessing, "get_context", return_value=context):
            result = pilot._bounded_probe("tor_check", 0.01)
        self.assertEqual(result, {"ok": False, "code": "network_probe_timeout"})
        receiver.poll.assert_called_once_with(0.01)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        receiver.close.assert_called_once()

    def test_deadline_cannot_be_swallowed_by_collector_exception_handler(self):
        self.assertFalse(issubclass(pilot.PilotDeadline, Exception))
        self.assertLess(pilot.BOOTSTRAP_SECONDS + pilot.CHECK_SECONDS + pilot.ONION_SECONDS + pilot.COLLECTION_SECONDS,
                        pilot.TOTAL_SECONDS)


if __name__ == "__main__":
    unittest.main()
