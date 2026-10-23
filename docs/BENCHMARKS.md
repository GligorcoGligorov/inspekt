# Benchmarks

**Machine:** MacBook Air 13" M3 (Mac15,12, 2024), 8 cores, 8 GB RAM,
macOS 14.5, Go 1.27.2. The Docker runs use Docker Desktop 27.5.1, whose VM
reports 8 CPUs and 3.83 GiB, with the compose limits in
`docker-compose.yml` (API and worker 256 MiB, Redis 160 MiB, MariaDB
256 MiB). Numbers are from single runs and vary by a few percent between
runs; nothing is rounded up.

## Micro-benchmarks (`go test -bench`)

```bash
go test -run='^$' -bench=. -benchtime=2s ./internal/analyze
```

Inputs are the samples in `testdata/` plus `newsletter_300_links`, a
synthetic HTML newsletter with 300 links to 20 hosts (the shape that makes
link extraction and the lookalike check work hardest).

| Message | Parse (ns/op) | Analyze (ns/op) | Analyze allocs/op |
|---|---|---|---|
| bec_reply_to (text only) | 3,401 | 6,265 | 59 |
| malware_attachment | 9,121 | 6,752 | 59 |
| ip_link_mailbox | 4,791 | 8,428 | 84 |
| phish_lookalike | 5,894 | 11,073 | 156 |
| clean_newsletter (4 links) | 5,870 | 12,783 | 111 |
| support_ticket_reply_to | 7,085 | 15,009 | 120 |
| newsletter_300_links | 12,250 | 474,789 | 5,395 |
| qr_phish (QR decode) | 8,121 | 327,596 | 214 |

Parsing runs at 119.7–176.3 MB/s on the sample messages (1,938.2 MB/s on the
synthetic newsletter, which is one large text part).

Two costs stand out, both expected: decoding a QR code (~0.3 ms, bounded by
the limits in `internal/qr`) and messages with hundreds of links.

## Profiling (`pprof`)

```bash
go test -run='^$' -bench='Analyze/newsletter_300_links' -cpuprofile cpu.out -memprofile mem.out ./internal/analyze
go tool pprof -sample_index=alloc_objects -top analyze.test mem.out
```

The CPU profile of this single-goroutine benchmark was mostly the Go
scheduler and GC idling, so the allocation profile was the useful one:
**~91 % of all allocations came from the lookalike check**: the homoglyph
`strings.Replacer` (35 %), `strings.Split` in `RegistrableDomain` (20 %),
`net.ParseIP` (20 %) and `levenshtein` (17 %). Cause: for every link, it
re-derived the registrable domain, label and skeleton of all 15 protected
brands, and the link's own skeleton 15 times.

Fix (`96247c7`): brand forms derived once per engine, each host checked
once per message, edit distance skipped when the lengths alone rule out a
typo, `net.ParseIP` only for strings that can be IP literals. Behaviour is
unchanged: the public-corpus evaluation gives identical verdicts, scores
and signals for all 6,199 scanned messages.

| Analyze | Before | After |
|---|---|---|
| newsletter_300_links | 1,879,144 ns, 57,824 allocs | 474,789 ns, 5,395 allocs |
| clean_newsletter | 56,827 ns, 1,873 allocs | 12,783 ns, 111 allocs |
| support_ticket_reply_to | 44,434 ns, 1,165 allocs | 15,009 ns, 120 allocs |

## Load test (full Docker stack)

```bash
docker compose up -d --build
go run ./cmd/inspekt-load -n 5000 -c 32 -files 'testdata/*.eml'
```

`cmd/inspekt-load` posts messages with C concurrent clients (each made
unique with an `X-Inspekt-Load` header so idempotency does not collapse
them), then polls `GET /v1/scans/{id}` until the result is readable. It
measures the real path: API → Redis Stream → worker (4 goroutines) →
MariaDB → API. End-to-end latency is quantised by the polling interval.

| Run | Messages | Clients | Poll | Throughput | Accept p95 | End-to-end p50 / p95 / p99 |
|---|---|---|---|---|---|---|
| A: samples (7 files) | 5,000 | 32 | 10 ms | 980.2 scans/s | 6.0 ms | 25.1 / 76.9 / 127.0 ms |
| B: corpus mix (2,903 files) | 5,000 | 32 | 10 ms | 868.1 scans/s | 6.3 ms | 28.3 / 78.4 / 149.7 ms |
| C: corpus mix | 10,000 | 64 | 10 ms | 672.1 scans/s | 6.4 ms | 81.5 / 181.2 / 345.6 ms |
| C′: corpus mix | 10,000 | 64 | 50 ms | 980.9 scans/s | 10.1 ms | 56.9 / 116.2 / 134.0 ms |

"Corpus mix" is SpamAssassin `easy_ham` plus Nazario `phishing-2024`
(real messages, sizes and structures). No message was rejected or failed in
these runs.

**Where the limit is.** During run B the busiest containers were the API
(peak 128.58 % CPU) and MariaDB (130.05 %); the worker peaked at 68.86 % of
one core and Redis at 32.56 %. At 64 clients, polling every 10 ms means up to 6,400 result lookups
per second, each a MariaDB read, and throughput fell to 672.1/s. Polling
every 50 ms (C′) brought it to 980.9/s. So in these runs the bottleneck
is the *read path the load generator creates*, not analysis: the pipeline
sustained 868.1–980.9 scans/s on this laptop. A real client would use a
webhook or long polling instead of tight polling.

Peak memory during run B: API 14.75 MiB, worker 14.33 MiB, Redis 40.34 MiB,
MariaDB 114.7 MiB.

### The bug the load test found

The first load runs reported 80.7 and 83.2 scans/s, with 4 and 1 scans
not finished within the 60 s timeout (the stragglers set the wall time). The worker logs showed InnoDB deadlocks (Error 1213) when
concurrent workers saved signals: `DELETE FROM signals` for a new scan
took gap locks that collided with other workers' inserts. Nothing was lost
(the watchdog retried them after 60 s, as designed), but latency was
terrible. Fixed in `fb3f414` (no DELETE for new scans, retry on 1213/1205)
with a 200-way concurrent-save test that failed on the old code. The
numbers above are after the fix.
