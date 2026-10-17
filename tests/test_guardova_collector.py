"""Offline tests: these fixtures never start Tor or access a remote service."""

import hashlib
import json
import threading
import time
import types
import unittest
from datetime import datetime
from unittest import mock

from guardova_robin import (CollectorLimits, WatchTarget, collect_watch,
                           find_matches, normalize_domain, normalize_target)
from guardova_robin.collector import _bounded_network, _default_search, _readable_body, _source_url

URL = "http://" + "a" * 56 + ".onion/leaks"
URL2 = "http://" + "b" * 56 + ".onion/post"


def target(kind="domain", value="example.com", tenant="tenant-a"):
    return WatchTarget("watch-1", tenant, kind, value)


def results(*urls):
    return {"results": [{"link": u, "title": "Untrusted title", "engine": "Fixture"} for u in urls],
            "stats": {"engines": [{"engine": "Fixture", "status": "ok", "results": len(urls)}]}}


def page(text, **extra):
    return lambda item: (item["link"], {"status": "ok", "text": text, "http_status": 200, **extra})


class MatchingTests(unittest.TestCase):
    def test_domain_requires_an_exact_host_boundary(self):
        text = "example.com, EXAMPLE.COM. https://example.com/a user@example.com"
        self.assertEqual([m.matched_text for m in find_matches(text, target())],
                         ["example.com", "EXAMPLE.COM", "example.com", "example.com"])
        for text in ("notexample.com", "example.com.evil", "sub.example.com", "example.com-bad", "example.com_foo"):
            self.assertEqual(find_matches(text, target()), [], text)

    def test_idn_and_punycode_are_equivalent_but_eszett_is_not_ss(self):
        watch = target(value="BÜCHER.de.")
        self.assertEqual(normalize_target(watch), "xn--bcher-kva.de")
        self.assertEqual(len(find_matches("bücher.de XN--BCHER-KVA.DE", watch)), 2)
        self.assertEqual(normalize_domain("faß.de"), "xn--fa-hia.de")
        self.assertEqual(find_matches("fass.de", target(value="faß.de")), [])
        self.assertEqual(len(find_matches("faß.de xn--fa-hia.de", target(value="faß.de"))), 2)

    def test_idna2008_keeps_greek_final_sigma_distinct(self):
        self.assertNotEqual(normalize_domain("ς.gr"), normalize_domain("σ.gr"))
        self.assertEqual(find_matches("ς.gr", target(value="σ.gr")), [])
        self.assertEqual(find_matches("σ.gr", target(value="ς.gr")), [])
        self.assertEqual(len(find_matches(normalize_domain("ς.gr"), target(value="ς.gr"))), 1)

    def test_unicode_separators_and_combining_marks_cannot_cut_domain_tokens(self):
        for text in ("example.com。evil", "例。example.com", "example.com．evil",
                     "例｡example.com", "a\u0327example.com", "example.com\u0327"):
            self.assertEqual(find_matches(text, target()), [], repr(text))
        self.assertEqual(len(find_matches("EXAMPLE。COM", target())), 1)
        self.assertEqual(len(find_matches("example.com。", target())), 1)

    def test_email_tokenization_uses_same_unicode_domain_boundaries(self):
        watch = target("email", "Admin@example.com")
        for text in ("Admin@example.com。evil", "Admin@例。example.com", "a\u0327Admin@example.com"):
            self.assertEqual(find_matches(text, watch), [], repr(text))
        self.assertEqual(len(find_matches("<Admin@EXAMPLE。COM>", watch)), 1)

    def test_unknown_or_private_unicode_cannot_create_a_suffix_reference(self):
        for marker in ("\u1c89", "\ue000", "\ufffd"):
            self.assertEqual(find_matches(marker + "example.com", target()), [])
            self.assertEqual(find_matches("example.com" + marker, target()), [])
            self.assertEqual(find_matches(marker + "Acme", target("organization", "Acme")), [])

    def test_match_limit_stops_streaming_before_remaining_tokens(self):
        from guardova_robin import matching
        with mock.patch.object(matching, "normalize_domain", wraps=normalize_domain) as normalize:
            matches = find_matches("example.com " * 10000, target(), limit=2)
        self.assertEqual(len(matches), 2)
        self.assertEqual(normalize.call_count, 3)  # target plus two observed tokens

    def test_email_matches_local_part_exactly_and_normalizes_host(self):
        watch = target("email", "Admin@bücher.de")
        text = "Admin@XN--BCHER-KVA.DE. Admin@bücher.de admin@bücher.de otherAdmin@bücher.de Admin@bücher.de.evil"
        matches = find_matches(text, watch)
        self.assertEqual(len(matches), 2)
        self.assertTrue(all(m.normalized_value == "Admin@xn--bcher-kva.de" for m in matches))

    def test_organization_casefold_and_whitespace_preserve_source_offsets(self):
        watch = target("organization", "Straße GmbH")
        text = "Prefix: STRASSE\n GmbH; suffix. SuperSTRASSE GmbH STRASSE GmbHaddon"
        matches = find_matches(text, watch)
        self.assertEqual(len(matches), 1)
        found = matches[0]
        self.assertEqual(text[found.start:found.end], "STRASSE\n GmbH")

    def test_invalid_watch_values_are_refused_before_search(self):
        search = mock.Mock()
        for kind, value in (("domain", "https://example.com"), ("domain", "*.example.com"),
                            ("domain", "127.0.0.1"), ("domain", "a..de"),
                            ("email", "a..b@example.com"), ("organization", "!")):
            with self.assertRaises(ValueError):
                collect_watch(target(kind, value), search_fn=search)
        search.assert_not_called()


class CollectorTests(unittest.TestCase):
    def collect(self, text="example.com", response=None, **kwargs):
        return collect_watch(target(), run_id="run-1",
                             search_fn=lambda query: response if response is not None else results(URL),
                             scrape_fn=page(text), **kwargs)

    def test_source_backed_reference_is_tenant_bound_and_json_serializable(self):
        run = self.collect("Observed example.com in source")
        self.assertEqual(run.status, "observed_reference")
        self.assertTrue(run.coverage.complete)
        finding = run.findings[0]
        self.assertEqual((finding.tenant_id, finding.watch_id, finding.run_id), ("tenant-a", "watch-1", "run-1"))
        self.assertEqual(finding.content_hash, hashlib.sha256(b"Observed example.com in source").hexdigest())
        self.assertEqual(finding.source_url, URL)
        self.assertEqual(finding.provenance["engine"], "Fixture")
        self.assertEqual(finding.status, "observed_reference")
        self.assertIn("not proof", finding.interpretation)
        self.assertIsNotNone(datetime.fromisoformat(finding.fetched_at.replace("Z", "+00:00")).tzinfo)
        self.assertEqual(json.loads(json.dumps(run.to_dict()))["schema_version"], "1.0")

    def test_excerpt_retains_only_watch_reference_not_adjacent_credentials(self):
        text = "Password=SuperSecret123! api_key=very-sensitive example.com user@other.com"
        run = self.collect(text)
        serialized = json.dumps(run.to_dict())
        self.assertEqual(run.findings[0].excerpt, "example.com")
        for secret in ("SuperSecret123", "very-sensitive", "user@other.com"):
            self.assertNotIn(secret, serialized)

    def test_page_title_cannot_confirm_a_reference(self):
        response = results(URL)
        response["results"][0]["title"] = "example.com breach"
        run = self.collect("Nothing relevant here", response=response)
        self.assertEqual(run.status, "no_matches")
        self.assertEqual(run.findings, [])

    def test_search_error_is_not_a_clean_run_and_does_not_copy_exception(self):
        def broken(query):
            raise RuntimeError("password=SECRET")
        run = collect_watch(target(), search_fn=broken, scrape_fn=page("example.com"))
        self.assertEqual(run.status, "error")
        self.assertFalse(run.coverage.complete)
        self.assertNotIn("SECRET", json.dumps(run.to_dict()))

    def test_inaccessible_search_is_distinct_from_successful_empty_search(self):
        broken = {"results": [], "stats": {"engines": [{"engine": "Fixture", "status": "failed"}]}}
        inaccessible = self.collect(response=broken)
        empty = self.collect(response=results())
        self.assertEqual(inaccessible.status, "inaccessible")
        self.assertFalse(inaccessible.coverage.complete)
        self.assertEqual(empty.status, "no_matches")
        self.assertTrue(empty.coverage.complete)

    def test_blocked_page_is_not_no_matches(self):
        run = collect_watch(target(), search_fn=lambda query: results(URL),
                            scrape_fn=lambda item: (item["link"], {"status": "blocked", "http_status": 403}))
        self.assertEqual(run.status, "inaccessible")
        self.assertEqual(run.coverage.pages_failed, 1)
        self.assertEqual(run.coverage.source_outcomes[0]["status"], "blocked")

    def test_partial_engine_failure_stays_partial_even_with_reference(self):
        response = results(URL)
        response["stats"]["engines"].append({"engine": "Offline", "status": "failed"})
        run = self.collect(response=response)
        self.assertEqual(run.status, "partial")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.coverage.search_status, "partial")

    def test_result_and_page_caps_are_reported(self):
        run = self.collect(response=results(URL, URL2), limits=CollectorLimits(max_results=1, max_pages=1))
        self.assertEqual(run.coverage.pages_attempted, 1)
        self.assertIn("max_results", run.coverage.limits_reached)
        self.assertEqual(run.coverage.results_skipped, 1)
        self.assertEqual(run.status, "partial")
        page_limited = self.collect(response=results(URL, URL2), limits=CollectorLimits(max_pages=1))
        self.assertIn("max_pages", page_limited.coverage.limits_reached)

    def test_body_cap_cannot_turn_uninspected_content_into_clean_status(self):
        text = "x" * 300 + " example.com"
        run = self.collect(text, limits=CollectorLimits(max_body_bytes=256))
        self.assertEqual(run.status, "partial")
        self.assertEqual(run.findings, [])
        self.assertTrue(run.coverage.source_outcomes[0]["truncated"])
        self.assertIn("max_body_bytes", run.coverage.limits_reached)

    def test_adapter_truncation_is_reported_and_prefix_hash_is_explicit(self):
        run = collect_watch(target(), search_fn=lambda query: results(URL),
                            scrape_fn=page("example.com", truncated=True))
        self.assertEqual(run.status, "partial")
        self.assertEqual(run.findings[0].hash_scope, "inspected_prefix")

    def test_match_cap_is_explicit(self):
        run = self.collect("example.com example.com", limits=CollectorLimits(max_matches_per_page=1))
        self.assertEqual(len(run.findings[0].matches), 1)
        self.assertIn("max_matches_per_page", run.coverage.limits_reached)

    def test_query_credentials_are_not_persisted_and_invalid_urls_are_not_fetched(self):
        run = self.collect(response=results(URL + "?token=TOPSECRET#foo"))
        self.assertEqual(run.findings[0].source_url, URL)
        self.assertTrue(run.findings[0].provenance["source_url_query_omitted"])
        self.assertNotIn("TOPSECRET", json.dumps(run.to_dict()))
        fetch = mock.Mock()
        for invalid in ("http://example.com/page", "http://user:secret@" + "a" * 56 + ".onion/page",
                        "http://valid.onion\\@example.com", "file:///tmp/data"):
            run = collect_watch(target(), search_fn=lambda q: results(invalid), scrape_fn=fetch)
            self.assertEqual(run.status, "partial")
        fetch.assert_not_called()

    def test_fetch_response_cannot_bind_another_sources_text(self):
        run = collect_watch(target(), search_fn=lambda query: results(URL),
                            scrape_fn=lambda item: (URL2, {"status": "ok", "text": "example.com"}))
        self.assertEqual(run.findings, [])
        self.assertEqual(run.status, "inaccessible")

    def test_redirected_source_keeps_requested_provenance_and_actual_source(self):
        run = collect_watch(target(), search_fn=lambda query: results(URL),
                            scrape_fn=page("example.com", final_url=URL2 + "?key=SECRET"))
        finding = run.findings[0]
        self.assertEqual(finding.source_url, URL2)
        self.assertEqual(finding.provenance["requested_source_url"], URL)
        self.assertEqual(finding.provenance["source_url_hash"], hashlib.sha256((URL2 + "?key=SECRET").encode()).hexdigest())
        self.assertNotIn("SECRET", json.dumps(run.to_dict()))

    def test_source_identity_is_canonical_before_hash_and_dedup(self):
        bare = "HTTP://" + "A" * 56 + ".onion"
        canonical = "http://" + "a" * 56 + ".onion/"
        fetch = mock.Mock(side_effect=page("example.com", final_url=bare + "#section"))
        run = collect_watch(target(), search_fn=lambda q: results(bare, canonical), scrape_fn=fetch)
        self.assertEqual(fetch.call_count, 1)
        finding = run.findings[0]
        self.assertEqual(finding.source_url, canonical)
        self.assertEqual(finding.provenance["source_url_hash"], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertFalse(finding.provenance["source_url_query_omitted"])

    def test_normalization_does_not_persist_huge_whitespace_in_match(self):
        watch = target("organization", "Example GmbH")
        run = collect_watch(watch, search_fn=lambda q: results(URL),
                            scrape_fn=page("Example" + " " * 10000 + "GmbH"))
        self.assertEqual(run.findings[0].matches[0].matched_text, "Example GmbH")
        self.assertLess(len(json.dumps(run.to_dict())), 4000)

    def test_engine_body_limit_is_explicit_even_if_no_engine_replied(self):
        response = {"results": [], "stats": {"engines": [{"engine": "Fixture", "status": "failed", "limit": "max_body_bytes"}]}}
        run = self.collect(response=response)
        self.assertEqual(run.status, "inaccessible")
        self.assertIn("max_body_bytes", run.coverage.limits_reached)

    def test_duplicate_sources_are_read_once(self):
        fetch = mock.Mock(side_effect=page("example.com"))
        run = collect_watch(target(), search_fn=lambda q: results(URL, URL + "#section"), scrape_fn=fetch)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(len(run.findings), 1)

    def test_tenant_specific_finding_ids_cannot_collide(self):
        first = self.collect()
        other = collect_watch(target(tenant="tenant-b"), run_id="run-1",
                              search_fn=lambda q: results(URL), scrape_fn=page("example.com"))
        self.assertNotEqual(first.findings[0].finding_id, other.findings[0].finding_id)

    def test_total_deadline_rejects_adapter_output_after_timeout(self):
        with mock.patch("guardova_robin.collector.time.monotonic", side_effect=[0.0, 0.0, 2.0]):
            run = self.collect(limits=CollectorLimits(max_run_seconds=1))
        self.assertEqual(run.status, "timeout")
        self.assertEqual(run.findings, [])
        self.assertIn("max_run_seconds", run.coverage.limits_reached)

    def test_total_deadline_covers_matching_and_cannot_report_clean_completion(self):
        now = [0.0]
        def slow_match(*args):
            now[0] = 2.0
            return []
        with mock.patch("guardova_robin.collector.time.monotonic", side_effect=lambda: now[0]), \
                mock.patch("guardova_robin.collector.find_matches", side_effect=slow_match):
            run = self.collect(limits=CollectorLimits(max_run_seconds=1))
        self.assertEqual(run.status, "timeout")
        self.assertFalse(run.coverage.complete)
        self.assertIn("max_run_seconds", run.coverage.limits_reached)

    def test_default_network_timeout_terminates_child(self):
        context = mock.Mock()
        receiver, sender, process = mock.Mock(), mock.Mock(), mock.Mock()
        context.Pipe.return_value = (receiver, sender)
        context.Process.return_value = process
        receiver.poll.return_value = False
        process.is_alive.side_effect = [True, False]
        with mock.patch("guardova_robin.collector.multiprocessing.get_context", return_value=context):
            with self.assertRaises(TimeoutError):
                _bounded_network("search", "example.com", CollectorLimits(), 0.01)
        process.terminate.assert_called_once()
        process.join.assert_called_once()
        receiver.close.assert_called_once()

    def test_limit_validation_rejects_unbounded_or_nonfinite_values(self):
        for kwargs in ({"max_pages": 0}, {"max_results": 501}, {"max_body_bytes": -1},
                       {"max_run_seconds": float("nan")}, {"max_run_seconds": float("inf")},
                       {"max_run_seconds": 901}, {"max_pages": True}):
            with self.assertRaises(ValueError):
                CollectorLimits(**kwargs)


class DefaultAdapterTests(unittest.TestCase):
    def test_readable_html_keeps_references_in_all_structural_elements(self):
        html = """<html><nav>example.com</nav><aside>example.com</aside>
        <header>example.com</header><footer>example.com</footer>
        <script>notexample.com</script><style>style.example.com</style></html>"""
        text = _readable_body(html, "text/html; charset=utf-8")
        self.assertEqual(len(find_matches(text, target())), 4)
        self.assertNotIn("notexample.com", text)
        self.assertNotIn("style.example.com", text)

    def test_plain_text_angle_bracket_address_is_not_parsed_as_markup(self):
        text = _readable_body("Contact <Admin@example.com>", "text/plain; charset=utf-8")
        self.assertEqual(text, "Contact <Admin@example.com>")
        self.assertEqual(len(find_matches(text, target("email", "Admin@example.com"))), 1)

    def test_inline_html_keeps_contiguous_reference_and_block_boundaries(self):
        text = _readable_body("<p>Contact Admin<span>@</span>example.com</p><p>example.com</p>", "text/html")
        self.assertEqual(len(find_matches(text, target("email", "Admin@example.com"))), 1)
        self.assertEqual(len(find_matches(text, target())), 2)

    def test_bounded_search_returns_completed_engine_results_before_slow_engine(self):
        release, finished = threading.Event(), threading.Event()
        def fetch(endpoint, query):
            if endpoint == "slow":
                try:
                    release.wait(timeout=2)
                    return {"engine": endpoint, "status": "empty", "links": []}
                finally:
                    finished.set()
            return {"engine": endpoint, "status": "ok", "links": [{"link": URL, "title": "Source"}]}
        search = types.SimpleNamespace(read_capped=lambda r, c: b"", encode_query=lambda q: q,
                                       DEFAULT_SEARCH_ENGINES=["slow", "fast"], _engine_name=lambda e: e,
                                       fetch_search_results_detailed=fetch, is_abuse_material=lambda r: False)
        started = time.monotonic()
        try:
            with mock.patch.dict("sys.modules", {"search": search}):
                response = _default_search("example.com", {"max_body_bytes": 1024, "max_results": 10,
                                                           "max_run_seconds": 1, "_search_seconds": 0.08})
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(response["results"][0]["engine"], "fast")
            slow = next(e for e in response["stats"]["engines"] if e["engine"] == "slow")
            self.assertEqual(slow["status"], "failed")
            self.assertEqual(slow["error"], "timeout")
            run = collect_watch(target(), search_fn=lambda q: response, scrape_fn=page("example.com"))
            self.assertEqual(run.status, "partial")
            self.assertEqual(len(run.findings), 1)
            self.assertIn("search_phase_seconds", run.coverage.limits_reached)
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=1))


if __name__ == "__main__":
    unittest.main()
