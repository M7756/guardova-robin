"""Offline pilot-worker contracts; live API/Tor acceptance remains separate."""

import unittest
from unittest.mock import Mock, patch

from guardova_robin import pilot_worker
from guardova_robin.models import CollectionRun, CollectorLimits, WatchTarget
from guardova_robin.worker import GuardovaClient, WorkerConfig, WorkerError


class PilotWorkerTests(unittest.TestCase):
    def setUp(self):
        self.config = WorkerConfig("https://pilot.invalid", "x" * 40, "pilot-worker")
        self.target = WatchTarget("watch", "tenant", "organization", "tor project")
        self.run = CollectionRun("run", "tenant", "watch", "organization", "tor project", "start")

    def test_completion_replays_identical_object_and_requires_real_ack_twice(self):
        client = pilot_worker.ReplayClient(self.config)
        payload = {"action": "complete", "result": {"not_logged": "BODY_MARKER"}}
        with patch.object(GuardovaClient, "post", return_value={"ok": True}) as transport, patch.object(pilot_worker, "_emit") as emit:
            self.assertEqual(client.post(payload), {"ok": True})
        self.assertEqual(transport.call_count, 2)
        self.assertTrue(all(call.args[0] is payload for call in transport.call_args_list))
        self.assertTrue(client.idempotent_replay)
        self.assertEqual(client.completion_requests, 2)
        self.assertNotIn("BODY_MARKER", str(emit.call_args))

    def test_rejected_first_ack_is_not_replayed_or_accepted(self):
        client = pilot_worker.ReplayClient(self.config)
        with patch.object(GuardovaClient, "post", return_value={"ok": False}) as transport:
            with self.assertRaisesRegex(WorkerError, "pilot_completion_rejected"):
                client.post({"action": "complete"})
        self.assertEqual(transport.call_count, 1)
        self.assertFalse(client.idempotent_replay)

    def test_rejected_replay_does_not_pass(self):
        client = pilot_worker.ReplayClient(self.config)
        with patch.object(GuardovaClient, "post", side_effect=[{"ok": True}, {"ok": False}]):
            with self.assertRaisesRegex(WorkerError, "pilot_replay_rejected"):
                client.post({"action": "complete"})
        self.assertFalse(client.idempotent_replay)

    def test_claim_is_sent_once_without_adding_fake_ack(self):
        client = pilot_worker.ReplayClient(self.config)
        with patch.object(GuardovaClient, "post", return_value={"job": None}) as transport:
            self.assertEqual(client.post({"action": "claim"}), {"job": None})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(client.completion_requests, 0)

    def test_unapproved_target_never_contacts_collector(self):
        for kind, value in (("domain", "customer.example"), ("organization", "tor project other"),
                            ("email", "public@torproject.org")):
            target = WatchTarget("watch", "tenant", kind, value)
            with patch.object(pilot_worker, "collect_watch") as collect:
                with self.assertRaisesRegex(WorkerError, "pilot_target_refused"):
                    pilot_worker._collect_public(target, run_id="run", limits=CollectorLimits(), seeded=True)
                collect.assert_not_called()

    def test_default_search_keeps_real_scraper_and_reduces_limits(self):
        limits = CollectorLimits(max_results=100, max_pages=25, max_body_bytes=2_000_000, max_run_seconds=180)
        with patch.object(pilot_worker, "collect_watch", return_value=self.run) as collect, patch.object(pilot_worker, "_emit"):
            pilot_worker._collect_public(self.target, run_id="run", limits=limits, seeded=False)
        options = collect.call_args.kwargs
        self.assertIsNone(options["search_fn"])
        self.assertNotIn("scrape_fn", options)
        self.assertEqual((options["limits"].max_results, options["limits"].max_pages,
                          options["limits"].max_body_bytes, options["limits"].max_run_seconds),
                         (6, 2, 262_144, 120))

    def test_seed_has_only_official_url_and_still_uses_real_scraper(self):
        target = WatchTarget("watch", "tenant", "domain", "torproject.org")
        limits = CollectorLimits(max_results=1, max_pages=1, max_body_bytes=4096, max_run_seconds=20)
        with patch.object(pilot_worker, "collect_watch", return_value=self.run) as collect, patch.object(pilot_worker, "_emit"):
            pilot_worker._collect_public(target, run_id="run", limits=limits, seeded=True)
        options = collect.call_args.kwargs
        self.assertIs(options["search_fn"], pilot_worker._official_seed)
        self.assertEqual(options["limits"], limits)
        self.assertNotIn("scrape_fn", options)
        seed = options["search_fn"]("ignored public query")
        self.assertEqual(len(seed["results"]), 1)
        self.assertEqual(seed["results"][0]["link"], pilot_worker.ONION_URL)
        self.assertEqual(seed["stats"]["engines"][0]["engine"], "pilot_official_seed")


if __name__ == "__main__":
    unittest.main()
