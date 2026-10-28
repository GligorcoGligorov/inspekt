# Inspekt

**An email threat-analysis service in Go that explains every verdict and
measures its own accuracy.** Inspekt parses raw email as hostile input,
extracts links (including ones hidden in QR-code images), verifies SPF,
DKIM and DMARC itself, and scores the message with small, independent
rules; every point of the score comes with evidence an analyst can read.
Behind the API sits a crash-safe Redis Streams pipeline (at-least-once,
watchdog, dead-letter queue, backpressure) with results in MariaDB,
Prometheus metrics and a Grafana dashboard. An optional LLM gives a second
opinion only on messages the rules cannot decide, and can only add points.
Detection is measured on public corpora with a held-out split, and CI fails
if it regresses.

| Headline | Result |
|---|---|
| Precision / recall / FPR, 6,202 public emails (rules `0.6.1`, scoring identical to `0.6.0`) | **0.9551 / 0.3943 / 0.0092** |
| Same, on the 20 % holdout never used for design | 0.9581 / 0.3922 / 0.0088 |
| Holdout recall since the first public-corpus run | 0.1985 → **0.3922**, no new false positives |
| Full Docker stack throughput, MacBook Air M3 | **868.1–1,019.6 scans/s** across load runs; end-to-end p95 64.2 ms at 32 clients (rules `0.4.0`) |
| Analysis of a typical message | 7,062–21,809 ns (single core, rules `0.6.0`) |

Honest reading: it is precise (about 19 in 20 flags are right) but catches
about **one phishing email in three**; most of what it misses has nothing
structurally wrong. [Details](#detection-quality) and
[`docs/EVAL.md`](docs/EVAL.md) have every number, including the ones that
are not flattering.

![Demo page: a phishing email with every signal and its evidence](docs/img/demo.png)

*The demo page at `/`: drop an `.eml`, get the verdict and the evidence.*

![Grafana dashboard during a load test](docs/img/grafana.png)

*The Grafana dashboard during a load test (see [Observability](#observability)).*

```
$ inspekt scan testdata/phish_lookalike.eml
testdata/phish_lookalike.eml
  verdict: malicious (score 100)
  from:    alerts@micros0ft-support.com
  subject: Unusual sign-in activity
  links: 1  attachments: 0
  [high   +35] dmarc_fail: [dmarc=fail]
  [high   +35] link_text_mismatch: [shows "https://account.microsoft.com/security", goes to login-micros0ft.com]
  [high   +30] display_name_spoof: [display name shows security@microsoft.com, real sender is alerts@micros0ft-support.com]
  [high   +30] lookalike_sender: [micros0ft-support.com imitates microsoft.com (embedded)]
  [high   +30] brand_display_name: [display name "Microsoft account team <security@microsoft.com>" claims microsoft.com, sender domain is micros0ft-support.com]
  [high   +30] lookalike_link: [login-micros0ft.com imitates microsoft.com (embedded)]
  ...
```

## How I built this

I built Inspekt over one weekend with AI as the implementation partner: Claude (chat) for planning and the initial skeleton, and [Claude Code](https://claude.com/claude-code) for the implementation. I chose the problem and the target, a scan pipeline for email security, and directed the work step by step.

The decisions were mine: the order of the steps, the LLM provider and what data may leave the system, that public corpora are never sent to an LLM, that the LLM stays off unless explicitly enabled, and that every number is reported as measured. The implementation followed fixed rules. Every step ends with green tests and its own commit, and CI must pass before the next step. Bugs are fixed in separate commits with a test that fails on the old code. Detection weights change only on evaluation data, decided on the dev split and confirmed once on the holdout.

I tested the running system myself (API, queue, Grafana, the demo page and the Groq integration). `docs/NOTES.md` explains each step in plain language with interview questions; it is what I use to study the design. The commit history shows the order of work, including the bugs the evaluation and load tests found.

## Quick start

```bash
make test          # Go + Python tests
make scan          # scan the sample messages
make run           # HTTP API on :8080, scans analysed inline (no Redis needed)
open http://localhost:8080   # demo page: drop an .eml, see verdict, score and evidence
curl --data-binary @testdata/phish_lookalike.eml localhost:8080/v1/scans

make e2e           # full stack in Docker (API, Redis, worker, MariaDB) + end-to-end checks
make test-db       # store tests against a throwaway MariaDB container
make eval-sample   # precision / recall on the 7 hand-made samples
make eval          # download the public corpora (pinned) and evaluate on 6,202 emails
```

With the full stack (`docker compose up --build`), a scan is queued and
fetched by id. The MariaDB password defaults to a **dev-only** value
(`inspekt-dev`, public in this repo); anywhere else, copy `.env.example` to
`.env` and set `INSPEKT_DB_PASSWORD`.

```bash
$ curl -si --data-binary @testdata/phish_lookalike.eml localhost:8080/v1/scans
HTTP/1.1 202 Accepted
Location: /v1/scans/8f3c…
{"id":"8f3c…","status":"queued"}

$ curl -s localhost:8080/v1/scans/8f3c… | jq '.status, .report.verdict, .received_at'
"done"
"malicious"
"2026-10-24T09:00:00.123Z"
```

Results land in MariaDB with one row per signal, so detection questions are
plain SQL:

```sql
-- Which signals fire on mail we called clean? (false-positive drivers)
SELECT signal_id, COUNT(*) FROM signals JOIN scans ON scans.id = signals.scan_id
WHERE verdict = 'clean' AND received_at > NOW() - INTERVAL 7 DAY
GROUP BY signal_id ORDER BY 2 DESC;
```

## Architecture

### Pipeline

```mermaid
flowchart LR
  C[client] -- "POST /v1/scans" --> API[inspekt-api]
  API -- "202 + id<br/>(id = SHA-256 of message)" --> C
  API -- "WATCH/MULTI: raw + status + XADD" --> S[(Redis Stream<br/>scans)]
  S -- "XREADGROUP<br/>consumer group" --> W[inspekt-worker<br/>N goroutines]
  W -- "1. save result" --> DB[(MariaDB<br/>scans, signals)]
  W -- "2. status + XACK<br/>in one MULTI" --> H[(scan:id hash)]
  C -- "GET /v1/scans/id" --> API
  API -- "done" --> DB
  API -- "queued / failed" --> H
  WD[watchdog<br/>XAUTOCLAIM idle > 60 s] -.-> S
  W -- "after 3 attempts" --> D[(scans:dead)]
```

- **Idempotent:** the same message posted twice is one scan.
- **At-least-once:** the result is saved to MariaDB first (an idempotent
  upsert), then the entry is acknowledged in the same Redis transaction that
  marks it done. A worker that dies mid-scan leaves the entry pending; the
  watchdog hands it to a live worker after 60 s.
- **Poison messages** (e.g. a parser panic) are dead-lettered with the reason
  after 3 attempts; unparseable input fails at once without retries.
- **Backpressure:** Redis runs with `maxmemory 64mb` and `noeviction`; when
  full, the API answers `503` with `Retry-After` instead of losing queued scans.
- **Graceful shutdown:** on SIGTERM the worker stops reading, then finishes and
  acknowledges what it is analysing.
- `/readyz` checks Redis and MariaDB. Prometheus metrics come from the API
  (`:8080/metrics`) and from every worker (`:9090/metrics`); see
  [Observability](#observability).

### Analysis

```mermaid
flowchart LR
  A[raw .eml] --> P[email.Parse<br/>size / part / depth limits]
  P --> X[extract.Links<br/>text, HTML anchors, forms]
  P --> Q[qr.Scan<br/>QR codes in images,<br/>bounded]
  X --> E[analyze.Engine]
  Q -- "links (source qr_code)" --> E
  E --> C1[auth] & C2[sender] & C3[lookalike] & C4[links] & C5[attachments] & C6[lure]
  C1 & C2 & C3 & C4 & C5 & C6 --> M[merge signals<br/>score → verdict]
  M --> R[JSON report]
```

| Package | Responsibility |
|---|---|
| `internal/email` | Hostile-input MIME parser (stdlib only), limits, attachment hashing |
| `internal/extract` | Links with visible anchor text, form actions (fuzz-tested) |
| `internal/qr` | QR codes in image attachments → links, with image count / size / pixel / time limits |
| `internal/auth` | Native SPF / DKIM / DMARC verification behind an injectable DNS `Resolver` |
| `internal/analyze` | Independent checks, signal merging, scoring, verdict |
| `internal/api` | HTTP API (async with a queue, inline without), metrics, and the demo page at `/` (one embedded HTML file, strict CSP) |
| `internal/queue` | Redis Streams producer, worker pool, watchdog, dead-letter queue |
| `internal/store` | `Store` interface; MariaDB (upsert, signals table, migrations under a named lock) and in-memory |
| `internal/pipeline` | What a worker does with a job: analyse, then save |
| `internal/llm` | Optional grey-zone reviewer: data minimisation, OpenAI-compatible client, per-minute and daily budget, 429 pause |
| `internal/campaign` | Campaign indicators, union-find clustering with a giant-cluster guard |
| `internal/config` | `INSPEKT_*` environment shared by CLI, API and worker |
| `internal/metrics` | Prometheus metrics shared by API and worker; queue gauges read from Redis at scrape time |
| `deploy/` | Prometheus scrape config, Grafana datasource and dashboard (provisioned) |
| `migrations/` | Numbered SQL files, embedded in the binaries and applied at startup |
| `cmd/` | `inspekt` (CLI), `inspekt-api`, `inspekt-worker`, `inspekt-load` (load generator), `inspekt-campaigns` (offline campaign measurement) |
| `eval/` | Corpus fetch (pinned), held-out split, precision / recall / FPR, analysis, CI gates |

## Detection quality

Measured with `make eval` on public corpora. Sources, checksums, every
intermediate result and the full analysis are in
[`docs/EVAL.md`](docs/EVAL.md).

| Corpus | Ham | Phish | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| Public: SpamAssassin ham 2002–03 + Nazario phishing 2019–25 | 4,150 | 2,049 (+3 unparseable) | 0.9551 | 0.3943 | 0.5582 | 0.0092 |
| — dev split (80 %) | 3,357 | 1,641 | 0.9543 | 0.3949 | | 0.0092 |
| — holdout split (20 %) | 793 | 408 | 0.9581 | 0.3922 | | 0.0088 |
| CI subset (holdout, fixed) | 100 | 100 | 0.9762 | 0.41 | | 0.01 |
| Sample (`testdata/`) | 4 | 5 | 1.00 | 0.80 | | 0.00 |

**What this says.** The rules are precise (about 19 in 20 flags are right,
under 1 % of legitimate mail is flagged) but catch **about one phishing
message in three**. The largest group of misses linked to legitimate
infrastructure attackers abuse (IPFS gateways, object storage, serverless
hosting) or claimed a brand in the sender name. Checks designed on the dev
split and each measured once on the holdout (`abused_hosting_link`,
`brand_display_name`, reading only visible text, `hidden_text_salting`)
raised holdout recall from 0.1985 to 0.3922 with no new false positives.
Most remaining misses have nothing structurally wrong.

**How it was measured.** A fixed 80/20 dev/holdout split by hash of the file
path; changes were chosen on dev and kept only if holdout agreed. Two weights
changed on that evidence (`html_form_in_email` 30 → 10, which cut false
positives by two thirds; `missing_from` 20 → 30). The ham is 20 years older
than the phishing, which makes authentication signals look perfect; no
weight was raised because of that. The evaluation's first run also found a
crash in HTML link extraction on non-ASCII input (now fixed and fuzz-tested).

**Gates.** CI fails if detection regresses: the 7 hand-made samples
(`--min-recall 0.8 --max-fpr 0`; the one miss, `bec_reply_to.eml`, is a
documented gap for the grey-zone LLM) and a fixed 200-message holdout subset
of the public corpora (`--min-recall 0.41 --max-fpr 0.01`), rebuilt in CI
from the pinned downloads because the SpamAssassin texts may not be
redistributed. Both gates sit exactly at today's numbers, and parse errors
fail them too.

## Performance

Details, raw numbers and method in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
MacBook Air 13" M3 (2024), 8 GB RAM.

| Measure | Result |
|---|---|
| Parse a typical message | 3,401–9,121 ns (119.7–176.3 MB/s) |
| Analyse a typical message | 7,062–21,809 ns (rules `0.6.0`; 6,654–17,220 on `0.4.0`) |
| Analyse with a QR code to decode | 318,706 ns |
| Analyse a 300-link newsletter | 820,625 ns on `0.6.0` (683,667 on `0.4.0`; 474,789 on `0.2.0`; 1,879,144 before profiling) |
| CLI over the public corpus | 2,018.0–2,176.9 messages/s, one process |
| Full Docker stack, 32 clients, real corpus mix | 868.1 scans/s on `0.2.0`, 1,019.6 on `0.4.0`; end-to-end p95 78.4 / 64.2 ms |
| Full Docker stack, 64 clients, polling every 50 ms | 980.9 scans/s; end-to-end p95 116.2 ms (rules `0.2.0`) |

Profiling with `pprof` showed ~91 % of the engine's allocations in the
lookalike check (protected-brand forms re-derived for every link); fixing it
made link-heavy mail 4× faster with identical results on all 6,199 corpus
messages. The load test found a real bug: InnoDB deadlocks between
concurrent workers saving signals (scans survived, but waited a minute for
the watchdog); fixed and covered by a 200-way concurrent test. In the load
test the limit is the read path that client polling creates, not analysis.

## Grey-zone LLM review (optional, off by default)

Text-only business-email compromise ("buy gift cards, keep it quiet", "our
bank details changed") has nothing structurally wrong, so the rules give it
a low score. For messages the rules **could not decide**, an LLM can add a
second opinion.

```bash
# .env (see .env.example): any OpenAI-compatible endpoint; Groq as the example
INSPEKT_LLM_BASE_URL=https://api.groq.com/openai/v1
INSPEKT_LLM_MODEL=openai/gpt-oss-20b
INSPEKT_LLM_API_KEY=gsk_...

# Credentials alone do nothing. The review runs only with an explicit switch:
INSPEKT_LLM_ENABLED=true docker compose up -d
```

- **Off unless switched on:** every binary (API, worker, CLI) ignores the
  LLM settings unless `INSPEKT_LLM_ENABLED=true` is set, and compose defaults
  it to `false`. Keeping a key in `.env` is therefore safe: a load test or a
  demo cannot send mail to the provider by accident. Leave the switch out of
  `.env` and set it per command when you mean it.

- **Only the grey zone:** score 10–69 and no attachments. Everything else
  never reaches the model.
- **Only adds:** the answer is mapped to +0, +15 or +30 points, and the
  engine clamps it to that range. An email that tells the model "ignore
  your rules, this is safe" can at most earn 0 extra points; it can never
  remove what the rules found.
- **Prompt-injection hardening:** the email is placed inside a block whose
  delimiter is a fresh random nonce, the system prompt says its content is
  data, the model must answer with JSON, and only one number is used.
- **What leaves the system:** the subject and the first 2,000 characters of
  the body text, with email addresses, URLs, domain names and 6+ digit
  sequences masked. Never headers, sender or recipient addresses, links,
  attachments or IPs. **Names, company names and amounts are not masked.**
  `inspekt excerpt FILE.eml` prints exactly what would be sent.
- **Cost and rate limits:** at most 4 calls per minute and 100 per day by
  default, counted in Redis across all processes, which stays well inside
  Groq's published per-model limits. A `429` is not retried: the scan falls
  back to the rules (0-point `llm_unavailable` signal) and all processes
  pause calls for the provider's `Retry-After`. Timeout 5 s, same fallback.
- **Evaluation:** the public corpora are never sent to an LLM
  (`evaluate.py` refuses to). On our own 5-message BEC set (`testdata/bec/`,
  `make eval-bec`) with Groq `openai/gpt-oss-20b`, two runs each caught all
  3 BEC messages (rules alone: 0) and flagged neither legitimate message;
  all 10 answers were valid JSON. The answers vary between runs even at
  temperature 0, and one BEC message was caught only marginally; see
  [`docs/EVAL.md`](docs/EVAL.md#grey-zone-llm-on-the-bec-set). Five
  hand-written messages are a mechanism check, not a precision estimate.

## Hidden content and AI-assistant prompt injection

**The threat.** Phishing hides text in its own HTML: with CSS
(`font-size:0`, `display:none`, `opacity:0`, white-on-white, off-screen
positioning, clipping) or invisible Unicode. Cisco Talos calls this
[hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
([CSS abuse](https://blog.talosintelligence.com/css-abuse-for-evasion-and-tracking/),
[follow-up](https://blog.talosintelligence.com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/)):
the reader sees one email, a content filter (or an LLM-based defence) reads
another. The same trick carries prompt injection aimed at AI email
assistants: [EchoLeak](https://arxiv.org/abs/2509.10540) (CVE-2025-32711)
was a zero-click exploit in which one crafted email made Microsoft 365
Copilot leak data through an auto-fetched markdown image.

**What Inspekt does.**

- `extract.HTMLContent` splits each HTML body into the text a reader sees
  and the text that is hidden, with the reason (inline styles, simple
  `<style>` rules, the `hidden` attribute, colour matching a declared
  background), plus invisible characters and HTML comments. It streams the
  HTML (no DOM), has hard limits, and is fuzz-tested in CI.
- Content checks (lure wording, brand mentions) read **only the visible
  text**, so salting can neither dilute nor fake them.
- Every report has a `hidden` section, and the demo page shows it under
  "Hidden from the reader": exactly what was in the email that a person
  could not see, rendered as plain text.
- `hidden_text_salting` (+20, never decisive alone): at least as much
  hidden as visible text, beyond a short preheader.
- `ai_prompt_injection` (**informational, 0 points**): text written for an
  AI assistant (instruction overrides, an assistant told to forward,
  reveal or conceal, markdown-image exfiltration) in hidden text, comments,
  or visible text that addresses an assistant by name. Shown as
  "AI-assistant prompt injection (informational)" in the report and on the
  demo page; it never changes a score or verdict.

**Measured** (design on the dev split, one holdout measurement each; all
in [`docs/EVAL.md`](docs/EVAL.md)):

| | Result |
|---|---|
| Corpus phishing with hidden text | **284 of 2,049 (13.9 %)**; ham: 2 of 4,150 |
| Reading only visible text | holdout recall 0.3775 → 0.3824, FPR unchanged |
| `hidden_text_salting` | holdout recall 0.3824 → 0.3922, FPR unchanged (0.88 %) |
| `hidden_brand_mismatch` | **dropped**: on dev, 7 of 8 hits were Microsoft Word markup in comments; 0 gain at a conservative weight |
| `ai_prompt_injection` | **informational only (0 points, rules `0.6.1`)**: it cannot be measured on the public corpora, which predate the threat (0 of 2,049 phishing emails contain it). **Smoke test, not a measurement:** on the synthetic `testdata/injection/` set it reports 5 of 5 injection emails and 0 of 4 legitimate ones. Adding it changed no verdict or score on any of the 6,199 corpus messages. |

**Limits.** Not a CSS engine: descendant selectors, external stylesheets,
computed layout and text inside images count as visible. White text is
hidden only against a background the email declares; image and gradient
backgrounds are "unknown". A short preheader before the body never counts
(legitimate newsletters use them, and `testdata/` has two). The 2002 ham is
mostly plain text, so the false-positive cost on modern HTML mail is not
measured. The AI-injection signal is informational until it can be
measured on modern labelled mail (real injection attempts and real
legitimate mail that talks about AI); only then would it earn points.

## Campaigns (v0.7, correlation only; branch `feat/campaigns`)

Scans that come from the same attack are grouped into **campaigns**, the way
a threat-intel platform correlates detections. This is a correlation layer
only: it never changes a score or a verdict (the evaluation numbers above
are identical with and without it).

**Design.**

- For each finished scan, `internal/campaign` extracts indicators and
  stores them in `scan_indicators` (migration 002) **in the same
  transaction** as the result, so a redelivered message never duplicates
  them.
  - **Strong** (one shared value links two emails): attachment SHA-256, and
    the full URL (scheme://host/path, query dropped) of links to URL
    shorteners and abusable hosting, where the bare host is shared by
    everyone.
  - **Weak** (two emails need shared values of **two different kinds**):
    the link's registrable domain (full Public Suffix List; huge benign
    platforms and the recipient's own domain skipped), the first public IP
    in the `Received` "from" clauses, and a fingerprint of the normalised
    subject (lowercase, `re:`/`fw:` removed, digit runs → `#`).
- On read, union-find groups all scans of the window transitively. Missed
  phishing therefore joins its caught siblings; `min_verdict` then filters
  campaigns by their highest member.
- Guards: a value shared by more than max(20, 5 % of the window) scans is
  ignored; a cluster above 500 scans is returned marked **oversized**
  ("likely shared infrastructure") and counted separately
  (`INSPEKT_CAMPAIGN_MAX_SHARED`, `_MAX_SHARE`, `_MAX_SIZE`).
- The campaign id is a short hash of the smallest scan id, so it is stable.

```bash
$ curl -s 'localhost:8080/v1/campaigns?since=24h&min_size=2&min_verdict=suspicious' | jq '.campaigns[0]'
# abridged, from a local run with three related test emails
{
  "id": "f6448aa1f93c",
  "size": 3,
  "first_seen": "…",
  "last_seen": "…",
  "verdicts": {"suspicious": 3},
  "max_verdict": "suspicious",
  "indicators": [
    {"kind": "link_host", "value": "evil-login.xyz", "scans": 3},
    {"kind": "subject_fp", "value": "a52950d42f9e", "scans": 3}
  ],
  "subjects": ["Your mailbox is full (141 messages held)", "..."],
  "scan_ids": ["3c0e…", "…"]
}
```

`since` accepts `90m`, `24h` or `7d` (capped at 30 days); the response also
reports the window, the guard limit, the values it dropped and the number
of oversized clusters. Prometheus: `inspekt_campaign_query_duration_seconds`,
`inspekt_campaigns_returned`. The demo page shows a Campaigns panel under
each result.

**Measured** (`python3 eval/campaigns.py --split dev`, then `--split holdout`
once; details in [`docs/EVAL.md`](docs/EVAL.md)):

| | dev | holdout |
|---|---|---|
| Campaigns (2+ emails) / 100 % phishing | 395 / 179 | 77 / 22 |
| Missed phishing that shares a campaign with caught phishing | 82 of 993 (8.26 %) | 9 of 248 (3.63 %) |
| Legitimate mail sharing a campaign with phishing | **0 of 3,357 (0.00 %)** | **0 of 793 (0.00 %)** |
| Oversized clusters | 0 | 0 |

The largest phishing campaigns are real attacks (billing-problem lures,
fake DocuSign receipts, "shared document via OneDrive"); the largest
clusters overall are legitimate mailing-list threads, correctly grouped and
hidden by the default `min_verdict=suspicious`.

**How it got here.** The first design (any single shared indicator links)
built one component of 3,257 of 4,998 dev emails, chained by mailing-list
relay IPs, public suffixes such as `co.za` counted as domains, and generic
or recipient domains; 71.64 % of dev ham "shared a campaign" with
phishing. The redesign above was decided from that diagnosis before
measuring again; both rounds are in `docs/EVAL.md`.

**Limitations.**

- **The 0 % is flattered by the corpus:** 2002 ham and 2019–2025 phishing
  can hardly share a subject pattern plus a host or IP. Modern legitimate
  mail on the same email service providers as phishing is the real test.
- The stricter rule misses campaigns whose emails share only one weak
  indicator (for example only a link domain).
- **Compute-on-read** reads and clusters the whole window per request, and
  weak-indicator pairs grow with the square of each value's (guard-capped)
  carrier count: fine up to roughly 100k scans per window. Beyond that,
  materialise clusters (update them as each scan is saved) or run a
  streaming job.
- The corpora have no real time window, so each split was clustered as one.

## Observability

```bash
docker compose --profile observability up -d --build   # adds Prometheus and Grafana
open http://localhost:3000                             # dashboard "Inspekt" (anonymous read-only)
```

The dashboard screenshot at the top was taken during a load run (8
clients, real corpus mix plus samples, polling every 50 ms) on the MacBook
Air. The p99 queue-wait rise at its right edge coincides with restarting
Grafana and rendering the screenshot on the same laptop.

| Metric | Type | From | What it answers |
|---|---|---|---|
| `inspekt_verdicts_total{verdict}` | counter | worker (API inline) | How much mail, and what share is flagged? |
| `inspekt_queue_wait_seconds` | histogram | worker | How long a client waits: API acceptance → result saved |
| `inspekt_check_duration_seconds{check}` | histogram | worker (API inline) | Which check costs time (QR decoding dominates on image mail) |
| `inspekt_scan_duration_seconds` | histogram | worker (API inline) | Parse + analysis time per message |
| `inspekt_worker_outcomes_total{outcome}` | counter | worker | done / failed / retry / dead per delivery |
| `inspekt_signals_total{signal}` | counter | worker (API inline) | Which rules fire most (false-positive drivers) |
| `inspekt_queue_lag`, `_pending`, `_dead_letters` | gauge | API (read from Redis at scrape) | Backlog, stuck work, poison messages |
| `inspekt_scans_enqueued_total`, `inspekt_scan_failures_total` | counter | API | Accepted and rejected submissions |

Plus the Go runtime and process metrics (memory, goroutines). A Redis outage
removes only the queue gauges from `/metrics`; everything else keeps being
served. A test fails if the dashboard queries a metric the code does not
define.

## Design decisions

- **Every input is hostile.** The parser caps size, MIME parts and nesting;
  images are checked against pixel limits *from their header* before any
  pixel is decoded (a 67-byte PNG claiming 50000×50000 is rejected in
  microseconds); decoding is time- and concurrency-bounded; the parser and
  the HTML link extractor are fuzz-tested in CI.
- **Explainability over a black box.** Checks emit signals with evidence;
  duplicate signals merge so ten copies of one bad link count once.
- **Forged headers are not evidence.** `Authentication-Results` is trusted only
  from configured authserv-ids, and `INSPEKT_AUTH_MODE=verify` ignores it
  entirely: Inspekt checks SPF, DKIM and DMARC (with alignment) itself. All DNS
  goes through an interface, so tests use a fake DNS.
- **An outage never looks like an attack.** DNS failures become `temperror`
  and an informational `auth_unverified` signal worth 0 points.
- **A crash can cause a repeat, never a loss.** Results are saved before the
  queue entry is acknowledged; saving is an idempotent upsert keyed by the
  message hash, so a redelivered scan overwrites instead of duplicating.
- **Configuration is a claim until a test proves it.** `noeviction` looked
  right, but Redis 7 does not memory-check unflagged Lua scripts; the enqueue
  now uses `WATCH`/`MULTI`, and the end-to-end test fills Redis on purpose.
- **Wording rules carry little weight** (max 10 points). LLM-written phishing
  defeats keyword lists, so structural signals decide verdicts.
- **Weights change only with an eval run**, decided on the dev split and
  confirmed on the holdout.

## Known limitations

- **Recall is moderate (0.38)**: much modern phishing has nothing structurally wrong;
  see [What I'd do next](#what-id-do-next).
- **The grey-zone LLM is measured only on 5 synthetic messages**, by
  design (the public corpora must not be sent to a provider). Its answers
  vary between runs even at temperature 0. Its grey zone starts at score 10:
  a BEC email with no technical signal at all (score 0) is never reviewed.
- The public ham predates SPF, DKIM, DMARC and URL shorteners, so their
  false-positive cost is not measured. `dmarc_fail` scores 35 regardless of
  the domain's policy: 39 of 51 DMARC-failing phishing messages came from
  `p=none` domains, and down-weighting would miss 35 of them, but the cost on
  legitimately forwarded mail is unmeasured.
- Click-tracking redirectors in legitimate newsletters still trigger
  `link_text_mismatch` (the main remaining false-positive class).
- Registrable domains use a small built-in suffix table instead of the full
  Public Suffix List.
- `verify` auth mode takes the client IP and HELO from the **topmost**
  `Received` header and assumes our own MTA wrote it; deploy directly behind
  that MTA. It is wrong for archived mail (rotated DKIM keys), so evaluations
  run in `headers` mode. DMARC `pct=` is ignored.
- Queue state lives in Redis for 24 h; results in MariaDB have no retention
  policy yet. A transiently failed scan is retried only when the watchdog
  reclaims it (about 60 s). Worker restarts leave idle consumer names in the
  group. Migrations only move forward, and MariaDB cannot roll back DDL.
- Redis checks `maxmemory` before each write, so one write can overshoot it by
  up to a full message (25 MiB); the container limit (160 MiB) leaves room.
- HTML and archive attachments are flagged by type, not opened. QR codes are
  read from PNG, JPEG and GIF attachments only (not `data:` URIs, PDFs or
  Office files), one per image, within the limits (10 images, 5 MiB,
  4000×4000 px, 2 s each); skipped images give a 0-point `qr_not_scanned`
  signal.

## What I'd do next

In order of expected impact on the measured weaknesses:

1. **A modern ham corpus** for the abused-hosting check: the 2002 ham cannot
   contain IPFS or serverless links, so its false-positive cost on today's
   mail is unmeasured.
2. **Open-redirect unwrapping**: run the link checks on the destination inside
   `google.com/url?q=`, `doubleclick.net` and ESP click links, without fetching.
3. **The same modern ham corpus** (with DMARC, shorteners, forwarding) to measure
   the false-positive cost of authentication signals and settle the `p=none` risk.
4. **Alerts** on the existing metrics: dead letters above 0, pending growing,
   queue-wait p95 over a budget, a signal's share of clean mail jumping.
5. **Measure the grey-zone LLM on more (and real, consented) BEC data**,
   then set its point mapping and thresholds from that, not from 5 samples.
6. **Webhooks or long polling** for results instead of client polling, which
   the load test showed is the throughput limit.
7. URL reputation feeds, the full Public Suffix List, a retention policy for
   results.

## Documentation

- [`docs/EVAL.md`](docs/EVAL.md): corpora, method, every result, analysis, decisions
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md): micro-benchmarks, profiling, load test
- [`docs/NOTES.md`](docs/NOTES.md): each step explained simply, with interview questions

## License

MIT. The evaluation corpora are not included; `eval/fetch_corpora.sh` downloads
them from their sources (Nazario corpus: CC BY 4.0, José Nazario).
