# Guardova collector

This development branch adds a defensive monitoring collector to Robin. The
upstream application, its MIT license and its existing UI/MCP entrypoints remain
in the repository. The Guardova image installs only the search/scrape runtime;
it does not start Streamlit, MCP or a model provider.

Upstream baseline: `apurvsinghgautam/robin` commit
`b5d4f5f509fac39d65d3a28fd1d78b56efbeeaf4`. The public source is
<https://github.com/apurvsinghgautam/robin>. Keep `LICENSE` with copied code; the
Guardova image includes it as `/app/LICENSE.robin`.

## Collection

`guardova_robin.collect_watch(WatchTarget(...))` searches the configured Robin
engines and fetches selected text over Tor. Domain, email and company-name
references are matched deterministically. Domain names use IDNA2008/UTS46
nontransitional normalization; exact hosts are distinct from subdomains.
Mailbox local parts preserve case. Company-name matching uses Unicode casefold
and word boundaries. Neither an LLM nor a search title can confirm a reference.

The result is a versioned JSON record bound to its run, company and watch item.
It contains UTC observation times, sanitized source URLs, source fingerprints,
SHA-256 of the inspected normalized text, an explicit whole-text/prefix scope,
and excerpts containing only matched identifiers. Adjacent credentials, full
page bodies and URL query values are not persisted. Different query-bearing
source identities retain different fingerprints. Control characters and
instructions in source pages are data, never commands.

The collector reports `observed_reference`, `no_matches`, `partial`,
`inaccessible`, `error` or `timeout`. A reference is not proof of a breach; a
clean search is limited to the configured engines and pages it inspected.
Truncation, inaccessible engines and limits cannot become a clean no-match.
The search phase has half the remaining run budget so finished engines can
contribute even when others are unavailable. Child processes are terminated at
the overall deadline.

## Guardova worker

`python -m guardova_robin.worker` polls one fixed application origin. It has no
inbound port, database credentials, model API key or shell-command interface.
It claims a job from `POST /api/internal/darknet`, collects it, and submits the
result with its exact lease. A changed company/watch/run binding is refused.
Redirects are refused so the bearer cannot be forwarded to another site.
Transport failures retry the same completion object; Guardova acknowledges
identical completions without creating duplicate findings. Expired/cancelled
leases are rejected by Guardova and eventually retried by its durable queue.

Application requests use certificate-validated HTTPS directly; page requests
use Robin's Tor client. HTTP application origins are accepted only on loopback
for isolated tests. Ambient HTTP proxy environment settings are ignored.

The app and worker must agree on `DARKNET_WORKER_SECRET`, a random printable
secret of at least 32 characters. Configure the app through its private server
environment. The worker supports `DARKNET_WORKER_SECRET_FILE` and
`DARKNET_WORKER_SECRET`. Never put either value in source, a browser setting,
logs or the Compose file.

## Container

`Dockerfile.guardova` and `compose.guardova.yml` run the collector and Tor as UID
10001, with a read-only root filesystem, a 64 MiB temporary filesystem, dropped
capabilities, no host/database mounts and no published ports. Both children are
supervised: a failed Tor process terminates the container so restart policy can
recover. The default limits are 384 MiB memory, one CPU and 96 processes.

Prepare the secret outside the repository with permission for container UID
10001 to read it. Compose file-based secrets retain host-file ownership; merely
setting an operator-owned file to mode 0600 is insufficient. On a Linux host,
an administrator can provision a dedicated secret file owned by UID/GID 10001
with mode 0400. Configure the same value independently in the app's protected
environment. Do not broaden file readability to solve a mount error.

Set these non-secret deployment inputs:

```sh
export GUARDOVA_ORIGIN=https://guardova.app
export DARKNET_WORKER_SECRET_PATH=/absolute/private/path/to/worker-token
docker compose -f compose.guardova.yml build
docker compose -f compose.guardova.yml run --rm --entrypoint python robin -c \
  "from pathlib import Path; p=Path('/run/secrets/worker_token'); assert 32 <= len(p.read_text().strip()) <= 512"
docker compose -f compose.guardova.yml up -d
```

Do this only after the matching Guardova database migration and application
version have been deployed. The worker waits for Tor bootstrap before claiming
a job. No token or database configuration is generated automatically by this
repository. UTC clocks must be synchronized: Guardova allows five seconds of
clock skew when accepting observations. The app document `docs/darknet-robin.md`
describes migration, lease/capacity limits, retention and rollback.

## Verification

Install `requirements-guardova.txt` in an isolated Python environment, then run:

```sh
python -m unittest tests.test_guardova_collector tests.test_guardova_worker -v
```

The fixtures do not contact Tor or external services. Transport tests start
only loopback HTTP servers; they test bearer handling, redirect refusal, body
limits and errors. Collector tests cover exact boundaries, IDNs, Unicode,
minimized evidence, source identity, partial engine failures and deadlines.
The broader upstream suites require the original upstream development/model
dependencies; these are deliberately absent from the minimal collector image.

The matching app has separate tests for authentication, owner checks,
cross-language result validation, PostgreSQL row security and durable leases.
Live Tor collection, container execution and concurrent multi-connection
database behavior require separate deployment acceptance; passing offline
fixtures does not establish source availability or whole-darknet coverage.
