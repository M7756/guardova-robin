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
supervised: any unexpected Tor or worker exit, including exit code zero, ends
the container with a failure so its restart policy can recover. An explicit
TERM or INT requests a planned shutdown and returns zero after both children
have exited and been reaped. Shutdown allows at most 180 seconds after TERM,
then sends KILL and waits at most five more seconds. Signal permission errors
are reported and cause a nonzero exit; cleanup never waits indefinitely. The
bounded `GUARDOVA_STOP_GRACE_SECONDS` override accepts integers from 1 to 180
for lifecycle tests; its default is 180, within Compose's 190-second stop window.
The default limits are 384 MiB memory, one CPU and 96 processes.

The Debian 13 VPS exposed a Podman/crun AppArmor stacking issue: with
`no-new-privileges`, the `containers-default-0.62.2` signal rule did not match
the peer label `containers-default-0.62.2//&crun`. The same issue is documented
in the [container runtime upstream tracker](https://github.com/podman-container-tools/container-libs/issues/805).
The validated per-command workaround selects the installed Debian runc binary:
use `podman --runtime /usr/bin/runc run` for each isolated container invocation.
Its signal smoke test retained `containers-default-0.62.2 (enforce)`,
`NoNewPrivs: 1`, zero effective capabilities, and successful TERM/KILL child
cleanup. Keep the read-only filesystem, capability drop, no-new-privileges and
resource limits on these commands. No global runtime or AppArmor policy change
is required. The final image also passed the live lifecycle checks below.

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
python -m unittest tests.test_guardova_collector tests.test_guardova_worker \
  tests.test_guardova_pilot tests.test_guardova_pilot_worker \
  tests.test_guardova_entrypoint -v
```

The fixtures do not contact Tor or external services. Transport tests start
only loopback HTTP servers; they test bearer handling, redirect refusal, body
limits and errors. Collector tests cover exact boundaries, IDNs, Unicode,
minimized evidence, source identity, partial engine failures and deadlines.
Seven entrypoint tests use disposable fake Tor/worker processes to check planned
TERM/INT, unexpected child exits, forced KILL after a bounded grace, rejected
grace values, and visible bounded failure when signals are denied. They require
no network or collector dependencies. By default they exercise the repository
script; set `GUARDOVA_TEST_ENTRYPOINT=/usr/local/bin/guardova-entrypoint` to test
the installed image file through a read-only test mount. On Linux, executable
fixture scripts need a separate disposable exec-enabled tmpfs at
`/test-fixtures`, with `TMPDIR=/test-fixtures`; retain the normal noexec `/tmp`.
That extra fixture mount belongs only to the offline test container. The
production image and service configuration do not require it.

On 17 October 2026, final image
`309038abaec901112594269b4455231e4086fb40d7bc10c6702c6e62725c8961`
passed all 86 tests on the VPS in 7.118 seconds. Its actual default entrypoint
was also checked with real Tor at 100% bootstrap and the private HTTPS pilot
configuration: `podman stop --time 190` returned exit 0; deliberately killing
the exact Tor child or worker child with SIGKILL each returned exit 1. All
three containers ended with `Pid: 0`, `OOMKilled: false`, and no
`supervisor_signal_failed` or `supervisor_cleanup_timeout` diagnostic. These
were isolated acceptance runs; production activation remains outstanding.

The broader upstream suites require the original upstream development/model
dependencies; these are deliberately absent from the minimal collector image.

The matching app has separate tests for authentication, owner checks,
cross-language result validation, PostgreSQL row security and durable leases.
Live Tor collection, container execution and concurrent multi-connection
database behavior require separate deployment acceptance; passing offline
fixtures does not establish source availability or whole-darknet coverage.

## Isolated live acceptance probe

`python -m guardova_robin.pilot` starts its own temporary Tor client, waits up to
180 seconds for bootstrap, checks the Tor Project's HTTPS `api/ip` endpoint,
fetches the Tor Project's official v3 onion site, then exercises the unchanged
default collector against the public domain `torproject.org`. The full probe
has a 480-second deadline; collection has 120 seconds, six results, two fetched
pages and a 256 KiB per-body cap. It does not contact Guardova, claim jobs or
require any application secret. It prints only fixed codes, HTTP statuses,
hashes and counters; the exit IP, page bodies, source URLs and findings are not
logged. Tor notices and network state remain only in the disposable tmpfs.

The authoritative onion address is published at
<https://onion.torproject.org/>. The Tor Check response must report
`IsTor: true`; an unavailable Tor Check service is a failed acceptance check,
not proof that Tor itself is disconnected. See <https://status.torproject.org/>
when diagnosing that case. Even a successful probe does not establish the
availability of all upstream search engines.

Build once and run this standalone container without Compose secrets or
published ports:

```sh
docker build -f Dockerfile.guardova -t guardova-robin:pilot .
docker run --name guardova-robin-pilot --rm --init --read-only \
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --memory 384m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --entrypoint python guardova-robin:pilot -m guardova_robin.pilot
```

On the validated Podman VPS, replace the `docker run` prefix above with
`podman --runtime /usr/bin/runc run`, preserving every remaining protection and
limit. Apply the same explicit runtime selection to private-API and lifecycle
acceptance containers.

Run it separately from production deployment; do not use a production worker
token. Observe peak memory, `/tmp` space and container exit status during the
probe. An interrupted operator session can stop only this named container with
`docker stop --time 10 guardova-robin-pilot`. For success, the probe requires
Tor Check, the official onion, at least one answering default search engine and
one page actually read by the default collector. Partial search coverage stays
visible even on success. A missing search result can therefore make this probe
fail while its separately reported transport checks pass.

For the separate private-API acceptance, run
`python -m guardova_robin.pilot_worker` in the isolated image with the normal
worker configuration. It requires HTTPS with certificate verification; a
private pilot CA can be supplied as a read-only public certificate mount via
`SSL_CERT_FILE`. The worker token remains in its separate protected secret
file. This probe starts Tor, waits at most 180 seconds for bootstrap, claims
one real job, and submits the same completion object twice over the real API.
Both replies must acknowledge success. No payload is written to disk. Its
overall deadline is 360 seconds; collection is reduced to at most six results,
two pages, 256 KiB per body and 120 seconds. Only the public targets domain
`torproject.org` and organization `tor project` are accepted.

For a positive evidence test, `python -m guardova_robin.pilot_worker
--seed-official` supplies only the official Tor Project onion as a declared
`pilot_official_seed` start source. Fetching still uses the normal bounded Tor
scraper, followed by real text matching, evidence hashing and API submission.
That mode passes only after at least one real reference and two accepted
completion requests. It tests ingestion and completion, independently of search
engine availability; it must never be reported as successful search discovery.
Without the flag, the normal search engines are used and their partial or
inaccessible status remains visible. The pilot API must use only an isolated
database and synthetic tenant/accounts. No production app or database settings
are changed by either probe.
