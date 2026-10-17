"""Bounded Tor collection with explicit coverage and no model dependency.

Only default network adapters run in a child process; the parent kills that
process when the run deadline expires. Injected offline adapters run directly
and must return promptly; they are checked against the same deadline before
their output can be accepted. Page text is inspected in memory and discarded.
"""

import hashlib
import multiprocessing
import time
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit

from .matching import find_matches, minimized_excerpt, normalize_target
from .models import (CollectionRun, CollectorLimits, Finding, WatchTarget,
                     validate_identifier)


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_url(value):
    """Only unambiguous HTTP onion addresses; never store URL credentials."""
    if (not isinstance(value, str) or not value or len(value) > 2048
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)
            or "\\" in value):
        raise ValueError("invalid_source_url")
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        port = parts.port
        if (parts.scheme not in ("http", "https") or parts.username is not None
                or parts.password is not None or not host.lower().endswith(".onion")
                or any(not (ch.isascii() and (ch.isalnum() or ch in ".-")) for ch in host)):
            raise ValueError("invalid_source_url")
        authority = host.lower() + (":" + str(port) if port else "")
        # Query parameters may carry account tokens. Never persist them. They
        # remain in the in-memory fetch URL, while this evidence URL is safe.
        return urlunsplit((parts.scheme, authority, parts.path or "/", "", ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid_source_url") from exc


def _source_identity(value):
    """Canonical fetch identity: preserve query privately, omit fragments."""
    safe = urlsplit(_source_url(value))
    return urlunsplit((safe.scheme, safe.netloc, safe.path, urlsplit(value).query, ""))


def _safe_engine(record):
    statuses = {"ok", "empty", "failed"}
    safe = {"engine": str(record.get("engine", "unknown"))[:120],
            "status": record.get("status") if record.get("status") in statuses else "failed",
            "results": _nonnegative(record.get("results")),
            "http_status": _http_status(record.get("http_status"))}
    if record.get("error") == "search_body_limit" or record.get("limit") == "max_body_bytes":
        safe["limit"] = "max_body_bytes"
    if record.get("error") in ("search_phase_timeout", "timeout"):
        safe["error"] = "timeout"
    return safe


def _http_status(value):
    return value if isinstance(value, int) and 100 <= value <= 599 else None


def _nonnegative(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _default_search(query, limits):
    """Reuse Robin's engine parser and Tor transport, preserving engine names."""
    import search

    # Upstream read_capped silently clips; asking for one extra byte lets this
    # adapter refuse an incomplete engine page rather than report it as empty.
    original_read = search.read_capped

    def checked_read(response, ignored_cap):
        body = original_read(response, limits["max_body_bytes"] + 1)
        if len(body) > limits["max_body_bytes"]:
            raise ValueError("search_body_limit")
        return body

    search.read_capped = checked_read
    encoded = search.encode_query(query)
    results, engines, total, excluded = [], [], 0, 0
    endpoints = list(search.DEFAULT_SEARCH_ENGINES)
    records = {}
    phase_budget = limits.get("_search_seconds", limits["max_run_seconds"] * 0.5)
    executor = ThreadPoolExecutor(max_workers=5)
    futures = {executor.submit(search.fetch_search_results_detailed, endpoint, encoded): endpoint
               for endpoint in endpoints}
    try:
        # Consume completed futures in completion order. A slow first engine
        # must not hide all the pages already discovered by another engine.
        for future in as_completed(futures, timeout=phase_budget):
            endpoint = futures[future]
            try:
                records[endpoint] = future.result()
            except Exception:
                records[endpoint] = {"engine": search._engine_name(endpoint), "status": "failed"}
    except FuturesTimeout:
        pass
    finally:
        for future, endpoint in futures.items():
            if endpoint in records:
                continue
            if future.done() and not future.cancelled():
                try:
                    records[endpoint] = future.result()
                    continue
                except Exception:
                    pass
            future.cancel()
            records[endpoint] = {"engine": search._engine_name(endpoint), "status": "failed",
                                 "error": "search_phase_timeout"}
        # This adapter runs inside a disposable child process. Returning now
        # delivers completed results; the parent terminates still-busy threads
        # after receipt rather than waiting for stalled sockets to finish.
        executor.shutdown(wait=False, cancel_futures=True)
        if all(future.done() for future in futures):
            search.read_capped = original_read
    for endpoint in endpoints:
        record = records[endpoint]
        engine = _safe_engine(record)
        engines.append(engine)
        for result in record.get("links", []):
            if search.is_abuse_material(result):
                excluded += 1
                continue
            total += 1
            if len(results) < limits["max_results"] + 1:
                    results.append({"link": result.get("link"), "title": "",
                                "engine": engine["engine"]})
    return {"results": results, "truncated": total > len(results),
            "stats": {"engines": engines, "results_raw": total,
                      "results_excluded_abuse": excluded}}


class _ReadableHTML(HTMLParser):
    _BOUNDARIES = frozenset({"address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt",
                             "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3",
                             "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre",
                             "section", "table", "td", "th", "tr", "ul"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.ignored += 1
        elif not self.ignored and tag in self._BOUNDARIES:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.ignored:
            self.ignored -= 1
        elif not self.ignored and tag in self._BOUNDARIES:
            self.parts.append(" ")

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def _readable_body(decoded, content_type):
    if content_type.split(";", 1)[0].strip().lower() == "text/plain":
        return decoded
    # Research-oriented boilerplate removal can erase evidence in menus,
    # sidebars and footers. Keep every readable text node, excluding scripts
    # and styles. Plain text bypasses markup parsing altogether.
    parser = _ReadableHTML()
    parser.feed(decoded)
    parser.close()
    return "".join(parser.parts)


def _default_scrape(item, limits):
    """Use Robin's Tor and extraction primitives with observable body limits."""
    import scrape

    url = item["link"]
    response = None
    try:
        response, final_url = scrape.get_over_tor(
            scrape._get_session(), url, allow_clearweb=False,
            headers={"User-Agent": scrape.USER_AGENTS[0]}, timeout=scrape.TOR_TIMEOUT)
        status = response.status_code
        if status in scrape.BLOCKED_STATUS_CODES:
            return url, {"status": "blocked", "http_status": status}
        if status != 200:
            return url, {"status": "error", "http_status": status}
        content_type = (response.headers.get("Content-Type") or "").lower()
        if content_type and not any(t in content_type for t in scrape.ALLOWED_CONTENT_TYPES):
            return url, {"status": "unsupported_content_type", "http_status": status}
        body = scrape.read_capped(response, limits["max_body_bytes"] + 1)
        truncated = len(body) > limits["max_body_bytes"]
        decoded = scrape.decode_capped(response, body[:limits["max_body_bytes"]])
        readable = _readable_body(decoded, content_type)
        text = " ".join(scrape.scrub_untrusted_text(readable).split())
        return url, {"status": "ok", "text": text, "http_status": status,
                     "truncated": truncated, "final_url": final_url}
    except Exception:
        # Exception strings can include URLs, tokens or remote body fragments.
        # Persist a fixed failure code and retain no arbitrary exception data.
        return url, {"status": "error"}
    finally:
        if response is not None:
            response.close()


def _network_worker(connection, operation, argument, limits):
    try:
        value = (_default_search(argument, limits) if operation == "search"
                 else _default_scrape(argument, limits))
        connection.send((True, value))
    except Exception:
        connection.send((False, "adapter_error"))
    finally:
        connection.close()


def _bounded_network(operation, argument, limits, remaining):
    """Cancellation ends network reads and upstream executor threads as well."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    worker_limits = dict(limits.__dict__)
    if operation == "search":
        worker_limits["_search_seconds"] = max(0, remaining * 0.5)
    process = context.Process(target=_network_worker,
                              args=(sender, operation, argument, worker_limits), daemon=True)
    process.start()
    sender.close()
    try:
        if not receiver.poll(max(0, remaining)):
            raise TimeoutError("run_deadline")
        try:
            ok, value = receiver.recv()
        except EOFError as exc:
            raise RuntimeError("adapter_error") from exc
        if not ok:
            raise RuntimeError("adapter_error")
        return value
    finally:
        receiver.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=0.25)
        if process.is_alive():
            process.kill()
            process.join(timeout=0.25)


def collect_watch(target: WatchTarget, *, run_id: Optional[str] = None,
                  limits: Optional[CollectorLimits] = None,
                  search_fn: Optional[Callable] = None,
                  scrape_fn: Optional[Callable] = None) -> CollectionRun:
    """Collect source-backed references for exactly one tenant's watch item.

    search_fn(query) returns {results: [{link, title, engine?}], stats: {engines: []}}.
    scrape_fn({link, title}) returns (url, {status, text, truncated?, http_status?}).
    Adapters are injected for offline tests. They must return already extracted
    page text, never include the search title in that text, and expose any prior
    truncation through ``truncated``. No LLM selects, suppresses or confirms hits.
    """
    if not isinstance(target, WatchTarget):
        raise TypeError("target must be a WatchTarget")
    limits = limits or CollectorLimits()
    if not isinstance(limits, CollectorLimits):
        raise TypeError("limits must be CollectorLimits")
    normalized = normalize_target(target)
    run_id = validate_identifier(run_id or str(uuid.uuid4()), "run_id")
    run = CollectionRun(run_id, target.tenant_id, target.watch_id, target.kind,
                        normalized, _utc_now())
    coverage = run.coverage
    deadline = time.monotonic() + limits.max_run_seconds

    def limit_reached(name):
        if name not in coverage.limits_reached:
            coverage.limits_reached.append(name)

    def call(operation, argument, adapter):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("run_deadline")
        value = (adapter(argument) if adapter is not None
                 else _bounded_network(operation, argument, limits, remaining))
        if time.monotonic() >= deadline:
            raise TimeoutError("run_deadline")
        return value

    try:
        response = call("search", normalized, search_fn)
        if not isinstance(response, dict) or not isinstance(response.get("results"), (list, tuple)):
            raise ValueError("invalid_search_response")
        stats = response.get("stats") or {}
        if not isinstance(stats, dict):
            raise ValueError("invalid_search_stats")
        engines = stats.get("engines", [])
        coverage.search_engines = [_safe_engine(e) for e in engines[:100] if isinstance(e, dict)]
        if any(e.get("limit") == "max_body_bytes" for e in coverage.search_engines):
            limit_reached("max_body_bytes")
        if any(e.get("error") == "timeout" for e in coverage.search_engines):
            limit_reached("search_phase_seconds")
        failed_engines = any(e["status"] == "failed" for e in coverage.search_engines)
        answered = any(e["status"] in ("ok", "empty") for e in coverage.search_engines)
        if failed_engines:
            coverage.errors.append({"stage": "search", "code": "engine_failure"})
        coverage.search_status = "partial" if failed_engines and answered else "ok"
        results = response["results"]
        coverage.results_received = max(len(results), _nonnegative(stats.get("results_raw")))
        if not results and failed_engines and not answered:
            coverage.search_status = "inaccessible"
            run.status = "inaccessible"
            return run
        if response.get("truncated") or len(results) > limits.max_results:
            limit_reached("max_results")
        if _nonnegative(stats.get("results_excluded_abuse")):
            coverage.errors.append({"stage": "search", "code": "unsafe_results_excluded"})
        selected, seen = [], set()
        for item in results[:limits.max_results]:
            coverage.results_considered += 1
            if not isinstance(item, dict):
                coverage.errors.append({"stage": "search", "code": "invalid_result"})
                continue
            try:
                safe_url = _source_url(item.get("link"))
            except ValueError:
                coverage.errors.append({"stage": "search", "code": "invalid_source_url"})
                continue
            # Keep the complete URL solely in memory for fetch and identity;
            # stored URLs omit query parameters so credentials never leak.
            identity = _source_identity(item["link"])
            if identity in seen:
                continue
            seen.add(identity)
            selected.append((item, safe_url, identity))
        if len(selected) > limits.max_pages:
            limit_reached("max_pages")
        coverage.results_skipped = max(0, coverage.results_received - min(len(selected), limits.max_pages))
        for item, safe_url, identity in selected[:limits.max_pages]:
            coverage.pages_attempted += 1
            try:
                value = call("scrape", {"link": identity, "title": ""}, scrape_fn)
                if isinstance(value, tuple) and len(value) == 2:
                    fetched_url, page = value
                    if fetched_url != identity:
                        raise ValueError("source_binding_mismatch")
                else:
                    raise ValueError("invalid_scrape_response")
                if not isinstance(page, dict):
                    raise ValueError("invalid_scrape_record")
                final_url = _source_identity(page.get("final_url") or identity)
                final_safe_url = _source_url(final_url)
                fetched_at = _utc_now()
                page_status = page.get("status")
                http_status = _http_status(page.get("http_status"))
                if page_status != "ok":
                    coverage.pages_failed += 1
                    outcome = page_status if page_status in ("blocked", "error", "refused_not_onion", "unsupported_content_type") else "error"
                    coverage.source_outcomes.append({"source_url": safe_url, "status": outcome,
                                                     "fetched_at": fetched_at, "http_status": http_status})
                    continue
                text = page.get("text")
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("empty_page")
                encoded = text.encode("utf-8")
                truncated = bool(page.get("truncated")) or len(encoded) > limits.max_body_bytes
                if truncated:
                    limit_reached("max_body_bytes")
                    text = encoded[:limits.max_body_bytes].decode("utf-8", errors="ignore")
                # Controls are discarded, never interpreted as terminal/HTML
                # instructions. Offsets/hash refer to this inspected text.
                text = " ".join("".join(ch for ch in text if ch in "\t\n" or ord(ch) >= 32 and ord(ch) != 127).split())
                text = unicodedata.normalize("NFC", text)
                if time.monotonic() >= deadline:
                    raise TimeoutError("run_deadline")
                matches = find_matches(text, target, limits.max_matches_per_page + 1)
                if time.monotonic() >= deadline:
                    raise TimeoutError("run_deadline")
                coverage.pages_read += 1
                if len(matches) > limits.max_matches_per_page:
                    limit_reached("max_matches_per_page")
                    matches = matches[:limits.max_matches_per_page]
                coverage.source_outcomes.append({"source_url": safe_url,
                                                 "status": "observed_reference" if matches else "no_matches",
                                                 "fetched_at": fetched_at, "truncated": truncated, "http_status": http_status})
                if not matches:
                    coverage.pages_without_matches += 1
                    continue
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                evidence_id = hashlib.sha256((target.tenant_id + "\0" + target.watch_id + "\0" + run_id
                                              + "\0" + identity + "\0" + digest).encode("utf-8")).hexdigest()
                provenance = {"query": normalized, "engine": str(item.get("engine") or "unspecified")[:120],
                              "discovery": "search_result", "requested_source_url": safe_url,
                              "source_url_hash": hashlib.sha256(final_url.encode("utf-8")).hexdigest(),
                              "source_url_query_omitted": "?" in final_url}
                run.findings.append(Finding(evidence_id, target.tenant_id, target.watch_id, run_id,
                                            final_safe_url, provenance, fetched_at, digest,
                                            "inspected_prefix" if truncated else "inspected_text",
                                            minimized_excerpt(matches, limits.max_excerpt_chars), matches))
            except TimeoutError:
                coverage.pages_failed += 1
                coverage.source_outcomes.append({"source_url": safe_url, "status": "timeout"})
                raise
            except Exception:
                coverage.pages_failed += 1
                coverage.source_outcomes.append({"source_url": safe_url, "status": "error"})
                coverage.errors.append({"stage": "scrape", "code": "adapter_or_page_error"})
        if time.monotonic() >= deadline:
            raise TimeoutError("run_deadline")
        coverage.complete = not (coverage.errors or coverage.pages_failed or coverage.limits_reached)
        if not coverage.complete:
            run.status = "inaccessible" if coverage.pages_attempted and not coverage.pages_read and not coverage.limits_reached else "partial"
        else:
            run.status = "observed_reference" if run.findings else "no_matches"
    except TimeoutError:
        limit_reached("max_run_seconds")
        run.status = "partial" if run.findings else "timeout"
    except Exception:
        coverage.search_status = "error" if coverage.search_status == "not_started" else coverage.search_status
        coverage.errors.append({"stage": "search", "code": "adapter_or_response_error"})
        run.status = "error"
    finally:
        run.completed_at = _utc_now()
    return run
