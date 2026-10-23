# Notes

Plain-language explanations of each step, plus interview questions to practise.

---

## Step 1: The `url_shortener` check

### What it does

A short link (`https://bit.ly/3xYzAb`) hides where it really goes. Our other
link checks look at the destination host (lookalike domain? IP address?
text says one site, link goes to another?), and a shortener blinds all of
them: they only see `bit.ly`. So a short link in an email is a small
warning sign of its own: `url_shortener`, **+10 points**.

### Details worth knowing

- It compares the **registrable domain** (`RegistrableDomain`), not the raw
  host, so `www.bit.ly` matches but `notbit.ly` does not. A test checks both,
  and fails if someone "simplifies" it to compare the raw host.
- **Low weight on purpose.** Legitimate mail uses shorteners all the time:
  every Twitter/X notification is full of `t.co` links. 10 points can never
  make a verdict on its own (the threshold is 30); it only tips a message
  that already has other signals.
- Ten short links in one email count **once** (the engine merges signals
  with the same ID), so a newsletter with many `bit.ly` links is not pushed
  over the line by repetition. There is a test for that too.
- It lives inside `LinkCheck` because it is a property of a link, like
  `ip_literal_url`.

### Interview questions

1. **"Why not follow the short link to see where it goes?"**
   That would be more accurate, but it means our scanner makes outbound
   HTTP requests to attacker-controlled URLs: it confirms to the attacker
   that the email was opened (many links are unique per victim), can be
   served a harmless page while real users get the phishing page, and costs
   time per message. If I added it, it would run in a sandboxed worker with
   strict timeouts, no cookies, and only HEAD requests that follow
   redirects without loading content.

2. **"Why only 10 points?"**
   Because the false-positive cost is real: legitimate senders use
   shorteners heavily. A weight should match how much a signal separates
   phishing from legitimate mail, and I would confirm the number with the
   public-corpus evaluation (precision of `url_shortener` alone) rather than
   by feel.

3. **"How would you keep the shortener list up to date?"**
   Move it from code to configuration (a file or the database) so it can
   change without a deploy, seed it from public lists of shortener
   domains, and log every link domain the scanner sees so new shorteners
   show up in the data.

---

## Step 2: Verifying SPF, DKIM and DMARC ourselves

### The problem

Before this step, Inspekt only read the `Authentication-Results` header,
where a mail server writes "spf=pass; dkim=pass; dmarc=pass". But a header
is just text, and **anyone can write any header**. A phisher can add
`dmarc=pass` to their own message. `TrustedAuthServIDs` helped (only believe
the header our own server wrote), but we still depended on another program
being correct and configured.

Now Inspekt can do the checks itself (`INSPEKT_AUTH_MODE=verify`).

### The three checks in one sentence each

- **SPF**: "Is this IP address allowed to send mail for this domain?"
  The domain publishes a list of allowed IPs in DNS
  (`v=spf1 ip4:192.0.2.10 -all`), and we compare it with the IP that
  actually connected.
- **DKIM**: "Was this message signed by the domain, and has nobody changed
  it since?" The sender signs some headers and the body with a private key;
  we fetch the public key from DNS (`selector._domainkey.domain`) and check
  the signature.
- **DMARC**: "Does SPF or DKIM pass *for the same domain the user sees in
  From*?" This is the part people forget. SPF and DKIM can both pass for
  `attacker.example` while From says `paypal.com`. DMARC requires
  **alignment**: the domain that passed must match the From domain (exactly
  in strict mode, the same organisation in relaxed mode). The domain owner
  also publishes a policy: `none`, `quarantine` or `reject`.

### How the code is built

- `internal/auth` does the checks. All DNS goes through a small
  `Resolver` interface. In production that is Go's `net.DefaultResolver`; in
  tests it is `authtest.DNS`, a map in memory. So the tests run without any
  network and are fast and repeatable. They sign real messages with a test
  ed25519 key and publish the public key in the fake DNS.
- **Where does the IP come from?** SPF needs the IP that connected to us.
  The email itself does not contain it, but our own mail server writes it
  into the **topmost** `Received` header. We read only that one, because
  every `Received` header below it could have been written by the attacker.
  This is an assumption about deployment, and it is written in the README.
- `AuthCheck` uses the same signal names and points in both modes
  (`dmarc_fail` = 35 and so on), so evaluation numbers stay comparable.
- **A DNS outage must never look like an attack.** If DNS times out, the
  result is `temperror`, which scores 0 points and adds an `auth_unverified`
  info signal so the analyst knows the check did not run. A test proves this
  (and fails if someone changes temperror into fail).
- Hostile-input limits: at most 5 DKIM signatures are checked per message
  (each costs a DNS query and a crypto operation, and the attacker decides how
  many there are), and all DNS work for one message has a 5-second timeout.
  The SPF library also enforces the RFC limit of 10 DNS lookups.

### Why `headers` is still the default

Old emails in public datasets were signed with DKIM keys that have since been
removed from DNS, and SPF records change over time. Verified today, lots of
legitimate old mail would fail, and our false-positive rate would look
terrible for the wrong reason. So: `verify` for live mail, `headers` for
evaluating old corpora.

### Interview questions

1. **"SPF and DKIM both pass, but the email is still phishing. How?"**
   They passed for the attacker's own domain. SPF checks the envelope sender
   (Return-Path), DKIM checks the `d=` domain, and neither has to match the
   From address the user sees. DMARC alignment closes that gap, but only if
   the impersonated domain publishes DMARC with `p=quarantine` or `reject`.
   Lookalike domains (`micros0ft-support.com`) pass all three for
   themselves, which is why Inspekt also has the lookalike check.

2. **"Why does your verifier need the topmost Received header, and what
   could go wrong?"**
   SPF needs the connecting IP, and only our own MTA saw the connection. It
   records the IP in the Received header it adds at the top. If Inspekt were
   fed mail that did not come through our MTA, the top header would be the
   attacker's and they could choose any IP. So I documented the assumption
   (run directly behind our MTA). In production, the MTA could pass the IP
   as metadata instead of making us parse headers.

3. **"Your DNS resolver times out. What happens to the verdict?"**
   Nothing gets worse: timeouts become `temperror`, which adds 0 points,
   plus an informational `auth_unverified` signal for the analyst. Treating
   an outage as `fail` would flag every message during the outage, and an
   attacker who can slow our DNS could cause that on purpose. There is a
   test for exactly this case. I would also add a metric for temperrors so
   an outage is visible on a dashboard.

---

## Step 3: The async pipeline (Redis Streams)

### The idea

Before, the API analysed each email while the client waited. That breaks
under load: a burst of 1,000 emails means 1,000 slow requests, and if the
server restarts, those emails are gone. Now the API only **stores and
queues** the email and answers right away (`202 Accepted` + an id). Separate
**worker** processes take emails from the queue and analyse them. The client
asks for the result later with `GET /v1/scans/{id}`.

### The pieces

- **Redis Stream `scans`**: an append-only log of "please scan id X".
  The raw email itself sits in a separate key (`scan:raw:{id}`, 24 h TTL).
- **Consumer group `workers`**: Redis gives each entry to exactly one
  worker and remembers which entries were handed out but not yet finished
  (the **pending list**). This is what a plain Redis list cannot do.
- **id = SHA-256 of the email**, so sending the same email twice gives the
  same id and only one scan (**idempotency**).
- **XACK only after the result is saved**, in the same transaction. If a
  worker crashes halfway, the entry is still pending, nothing is lost
  (**at-least-once delivery**).
- **Watchdog**: every 30 s it looks for entries pending longer than 60 s
  (their worker probably died) and takes them over with `XAUTOCLAIM`.
- **Dead-letter stream `scans:dead`**: every attempt is counted. After 3
  failed attempts the entry moves there with the reason, so one "poison"
  email (say, one that makes the parser panic) cannot loop forever. An email
  that simply is not an email fails at once: retrying cannot fix it.
- **Graceful shutdown**: on SIGTERM a worker stops taking new work but
  finishes and saves what it is doing.

### The maxmemory bug we found (and why it matters)

Redis runs with `maxmemory 64mb` and `noeviction`: when full, it should
refuse new writes, and the API turns that into `503 Retry-After`, so clients
slow down instead of us losing data. Testing it by hand showed Redis
happily storing 16 MB with a 2 MB limit.

The cause: the enqueue was a **Lua script**, and Redis 7 does not apply the
memory check to scripts without flags. The fix uses `WATCH` + `MULTI/EXEC`
(an optimistic transaction) instead: every write inside it is a normal
command that Redis memory-checks, and if one is refused the whole
transaction is aborted. It is still atomic, and the end-to-end test now
fills Redis on purpose and expects `503` with `Retry-After`.

Lesson: a config setting is a claim until a test proves it.

### How it is tested

- Unit tests use **miniredis** (an in-memory fake Redis): crash recovery,
  retries, dead-lettering, idempotency and graceful shutdown run in about
  two seconds, with no Docker.
- `make e2e` (also a CI job) starts the real stack with docker compose and
  checks the real thing: real Redis, real worker, a Redis restart, and the
  full-memory case above.

### Interview questions

1. **"Why Redis Streams and not a Redis list or RabbitMQ?"**
   With a list (`LPUSH`/`BRPOP`), an item is removed when a worker takes it.
   If that worker crashes, the email is lost. Streams with a consumer group
   keep a pending list of unacknowledged entries, support several
   independent consumer groups, and keep history for replay. RabbitMQ would
   also work (acks, dead-letter exchanges), but it is one more system to run
   and monitor. At this volume Redis is enough, and we already need it for
   the result cache. Past roughly that point, I would look at RabbitMQ or Kafka.

2. **"Your worker crashes after saving the result but before XACK. What
   happens?"**
   That window cannot happen here: the save and the XACK are in one
   `MULTI/EXEC` transaction, so both happen or neither does. In general,
   with at-least-once delivery you must assume an entry can be processed
   twice, so processing must be **idempotent**. Here it is: the id is the
   hash of the email, and re-analysing the same email gives the same result
   and overwrites the same key.

3. **"What happens when Redis is full?"**
   It refuses writes (`noeviction`), and the API answers `503` with
   `Retry-After`, which is backpressure: the client retries later and
   nothing already queued is evicted. Eviction policies like `allkeys-lru`
   would silently delete queued emails. Then I would tell the story of the
   Lua-script bug above: the setting looked right, but only a test that
   fills Redis on purpose showed it was not enforced.

---

## Step 4: QR codes in image attachments

### The problem

"Quishing": the phishing link is not text in the email but a **QR code in
a picture**. Our link checks never saw it, because there was no link to see.
And the victim scans it with a phone, outside the company's protected
laptop browser. `qr_phish.eml` was the sample we could not catch.

### What we do now

- For every attachment, we first ask "is this an image?" by **reading its
  bytes** (`image.DecodeConfig`), not by trusting the Content-Type or file
  name, which the attacker writes.
- We decode the image and look for a QR code (`gozxing`, a Go port of the
  ZXing library). If it contains a web address, it becomes a normal link
  with `source: qr_code`. Payloads like `evil.example/pay` (no `https://`)
  count too, because phones open them as web addresses.
- Because it joins the same link list, **every existing check runs on it
  automatically**: lookalike domain, IP address, URL shortener. We did not
  write new checks for QR links, we just fed them in.
- New signal `qr_code_link` (+20): a QR code pointing outside the sender's
  own domain. A restaurant emailing a QR code to its own menu does not get it.

Result: `qr_phish.eml` is now suspicious (score 50: `qr_code_link` +
`lookalike_link`), recall on the samples went from 0.60 to 0.80, and the
CI gate was raised to 0.80 so it cannot quietly drop back.

### The limits (images are hostile input)

| Limit | Default | Why |
|---|---|---|
| images per message | 10 | 1,000 tiny images would cost 1,000 decodes |
| bytes per image | 5 MiB | bounds reading and decompression work |
| width / height | 4000 px | stops **decompression bombs** (below) |
| time per image | 2 s | a pathological image cannot stall a worker |
| decodes at once | 2 per process | bounds memory, even for timed-out decodes |

A **decompression bomb** is a tiny file that claims to be huge. Our test
builds a 67-byte PNG whose header says 50000×50000 pixels. Decoding it would
mean allocating ~10 GB. We read **only the header** first and reject it
before any pixel is decoded. The test also checks this takes under 100 ms.

The timeout has a catch worth knowing: **Go cannot kill a goroutine**. When
a decode times out, we stop waiting, but the decode keeps running until it
ends. That is why a decode keeps its "slot" until it really finishes: at
most 2 decodes exist at any time, finished or abandoned, so memory stays
bounded.

We measured it: 4 large (3990×3990 colour) QR images at once pushed the
worker to **255.9 of 256 MiB**. Go's garbage collector does not know about
the container's limit. Setting `GOMEMLIMIT=200MiB` tells it, and the same
test peaked at ~207 MiB with no OOM kill.

### Interview questions

1. **"Why read the image header before decoding?"**
   Because the decoder allocates memory for the size the header *claims*.
   A 67-byte file can claim 50000×50000 pixels: decoding first and checking
   later means the damage (gigabytes of allocation, or an OOM kill of the
   worker) is already done. Checking the header costs microseconds. Same
   idea as zip bombs: check the declared size before expanding.

2. **"Your per-image timeout fires. Is the work actually stopped?"**
   No. In Go you cannot kill a goroutine from outside; the decode keeps
   running until it finishes. So the timeout protects the *caller's*
   latency, not the CPU. To bound the real cost I cap pixel dimensions and
   cap concurrent decodes per process, and a timed-out decode keeps its slot
   until it ends. For a hard stop you would decode in a separate process you
   can kill (more isolation, more overhead).

3. **"How would an attacker evade your QR check?"**
   Put the QR code where we do not look (inside a PDF, in an HTML `data:`
   image, split across two images, or drawn with HTML table cells), make
   it hard to decode (distortion, low contrast), or exceed our limits on
   purpose (11 images, huge dimensions). Exceeding a limit produces a
   0-point `qr_not_scanned` signal, so the analyst sees it. Once evaluation
   data exists, that signal could carry a few points, because legitimate
   mail rarely trips these limits.

---

## Step 5: Results in MariaDB

### Why

Until now a finished scan lived in Redis for 24 hours and then was gone.
Redis is memory (we gave it 64 MB), and a queue is not a database. Results
need to be kept, and questions about them need answers: "how many malicious
emails this week?", "which signal causes the most false positives?". That
is a job for a relational database. MariaDB is in Hornetsecurity's stack.

### The schema (`migrations/001_init.sql`)

- `scans`: one row per distinct email (`id` = SHA-256 of the message, the
  same id as in the queue): `received_at` (when the API accepted it),
  `scanned_at`, `verdict`, `score`, `engine` (rule-set version),
  `from_domain`, and the full `report` as JSON.
- `signals`: one row per signal per scan (`scan_id`, `signal_id`, `score`).
  The same data is also inside the JSON report, stored twice on purpose:
  the JSON is for showing one scan, the table is for **counting across
  scans** with an index (`idx_signals_signal`) instead of parsing millions
  of JSON documents.
- Indexes follow the questions we expect: by time, by verdict and time, by
  sender domain and time.

### How it fits the queue

The worker now: analyses → **saves to MariaDB** → marks done in Redis and
XACKs. The order matters. If the worker dies after saving but before XACK,
the message is processed again. That is fine, because saving is an
**upsert** (`INSERT ... ON DUPLICATE KEY UPDATE`) and the signals are
deleted and re-inserted in the same transaction, so a second save
overwrites instead of duplicating. That is "at-least-once delivery +
idempotent processing", which together behave like "exactly once" for the
data.

If MariaDB is down, the save fails, the message is **not** acknowledged,
and it is retried later. A result is never marked done unless it is saved.

`GET /v1/scans/{id}` asks MariaDB first (finished results, kept forever),
then Redis (still queued, or failed). The e2e test proves results survive
Redis being wiped with `FLUSHALL`.

### Migrations without a migration tool

The SQL files are embedded into the Go binaries (`go:embed`), and both the
API and the worker apply missing ones at startup, recording them in
`schema_migrations`. They start at the same time, so two processes could
both try to create the same table. `GET_LOCK('inspekt_migrate')` (a MariaDB
named lock) makes them take turns. A test starts three migrators at once.
Removing the lock makes that test fail with "Table 'scans' already exists".

One caveat: MariaDB cannot roll back `CREATE TABLE`/`ALTER TABLE`. A
migration that fails halfway leaves part of it applied, so keep one
change per file.

### Tests

The same **contract test** runs against both `Store` implementations
(in-memory, used by the fast API tests, and MariaDB), so they cannot
behave differently. The MariaDB part needs a real server: CI starts one as
a service container; locally `make test-db` starts a throwaway one.

### Interview questions

1. **"Why save to MariaDB before acknowledging in Redis, and what if the
   worker crashes in between?"**
   If we acknowledged first and then crashed, the message would be gone and
   the result never saved: data loss. Saving first means a crash can only
   cause a **repeat**, never a loss. Repeats are harmless because the save
   is an idempotent upsert keyed by the message hash. I prefer a duplicate
   I can absorb to a loss I can't detect.

2. **"Why store signals in their own table when they are already in the
   JSON report?"**
   Different questions. The JSON answers "show me this scan". The table
   answers "how often did X fire on clean mail this week?", which needs an
   index, not a JSON scan over every row. It is deliberate denormalisation:
   the report is the source of truth, and the signals table is rebuilt from
   it inside the same transaction on every save, so they cannot drift.

3. **"Two instances start at the same moment and both run migrations. What
   happens?"**
   Without coordination, both see "001 not applied" and both run
   `CREATE TABLE`; one fails. I take a MariaDB named lock (`GET_LOCK`) on a
   single connection, so the second instance waits, then sees 001 already
   recorded and does nothing. A test runs three migrators concurrently, and
   fails if the lock is removed. In a bigger setup I would run migrations as
   a separate deploy step instead of at startup.

---

## Step 7: Evaluation on public corpora

### What we did

We ran the scanner over **6,202 real emails**: 4,150 legitimate ones
(SpamAssassin public corpus, 2002–2003) and 2,052 phishing ones (José
Nazario's corpus, 2019–2025). The downloads are pinned by SHA-256 so the
numbers are reproducible. Everything is in `docs/EVAL.md`.

### What we found, in order

1. **A crash.** A quarter of the messages "failed to parse". Really, 56
   phishing emails made the HTML link extractor **panic**, and each panic
   killed a batch of 200. Cause: we searched a `strings.ToLower` copy of
   the HTML but cut the original with those positions, and `ToLower` can
   change byte length (invalid UTF-8, letters like `İ`). Lesson: the first
   value of a real-data evaluation is often finding bugs, not numbers. It
   is fixed, with a regression test and a fuzz test in CI.
2. **The honest baseline:** precision 0.75, recall 0.165, false-positive
   rate 2.7 %. We catch about one phishing email in six.
3. **Why false positives:** one rule, `html_form_in_email`, caused 69 % of
   them. Newsletters have search and subscribe forms. It was right only
   5 % of the time it fired.
4. **Why misses:** most missed phishing has *nothing structurally wrong*.
   The links go to real services attackers abuse: IPFS, Google,
   Cloudflare R2, Firebase, click-tracking redirects. No lookalike domain,
   no IP address, authentication passes. Weights cannot fix "no signal".

### How we tuned (and how we avoided fooling ourselves)

- **Held-out split:** every message is put in *dev* (80 %) or *holdout*
  (20 %) by a hash of its file name. Fixed forever, same on every machine.
  We **only look at dev** to decide a change, then check it on holdout. If
  a change only helps dev, it fitted the examples we stared at, and we
  revert it.
- **One change at a time**, with before/after numbers for each:
  - `html_form_in_email` 30 → 10: false-positive rate 2.7 % → 0.9 %
    (holdout agrees), recall unchanged.
  - `missing_from` 20 → 30 (an unparseable From header, 96 % phishing on
    dev): holdout recall 0.174 → 0.199, no new false positives.
- **What we did *not* change:** SPF/DKIM/DMARC signals look 100 % precise
  here, but only because the 2002 ham predates SPF and DMARC. Raising them
  would be "learning" the age of the emails, not phishing.

Final: precision 0.91, recall 0.19, FPR 0.9 %. Precise but low recall,
which is the normal shape for explainable rules, and we say so in the README.

### The p=none decision

76 % of the DMARC-failing phishing came from domains with `p=none`.
Attackers pick those domains because receivers don't enforce. Counting
them less would miss 35 of 39. Decision: keep the weight; the remaining
risk (forwarding breaks DMARC on real mail) is written down to measure
with modern ham.

### The CI gate

100 legitimate + 100 phishing emails from the **holdout** split, chosen by
a fixed hash. They are downloaded in CI rather than committed, because
the SpamAssassin emails are not ours to redistribute. The gate is set to
exactly today's numbers, so any change that loses a detection or adds a
false positive fails CI until someone updates the gate and EVAL.md on purpose.

### Interview questions

1. **"Your recall is 19 %. Isn't that bad?"**
   It is low, and I report it as it is. What matters is *why*: most misses
   use legitimate hosting with nothing structurally wrong, which no
   structural rule can see. The engine is precise (91 %, under 1 % false
   positives), which is what a first layer should be: cheap, explainable,
   rarely wrong. The evaluation tells me what to build next (an
   abusable-hosting signal, open-redirect unwrapping, URL reputation, the
   grey-zone LLM), and each will be measured the same way. I would rather
   show 19 % I can explain than 95 % from a model fitted to the test set.

2. **"How do you know your weight changes didn't just overfit the corpus?"**
   A fixed 80/20 split by hash of the file name, decided before tuning. I
   only looked at dev to choose changes, made one change at a time, and
   kept a change only if holdout improved too. Both changes held on
   holdout. I also refused changes the data seemed to support but that
   came from corpus bias: the ham is from 2002, so authentication signals
   cannot fire on it.

3. **"What was the most useful result of the evaluation?"**
   The crash. A quarter of the corpus silently disappeared from the
   metrics because one panic killed a batch, and the first numbers looked
   plausible. Two lessons: count what you *didn't* measure (we report
   parse errors and gate on them), and evaluate on real, messy data early,
   because hand-made samples never contain invalid UTF-8 in HTML.

---

## Step 9: Benchmarks, profiling, load test

### Three kinds of measurement, three different questions

- **Micro-benchmarks** (`go test -bench`, `make bench`): how fast is one
  function on one input? Parsing an email takes about 3–9 microseconds; analysing
  it 6–15 µs; decoding a QR code ~0.33 ms. Good for comparing before/after a
  code change, useless for "how many emails per second can the system do".
- **Profiling** (`pprof`): *where* does the time or memory go?
- **Load test** (`cmd/inspekt-load`, `make load`): the whole system (API,
  Redis, worker, MariaDB) under many concurrent clients. How many scans per
  second, and how long does a client wait (p50/p95/p99)?

### What profiling found

The CPU profile was useless for this benchmark (mostly the Go runtime
idling), but the **allocation** profile was clear: about 91 % of all memory
allocations came from the lookalike check. For every link it recomputed
the same things about our 15 protected brands. A 300-link newsletter meant
4,500 repeats. Computing them once (and each host once per email) made
link-heavy mail **4× faster** and cut allocations by 90 %.

How we know it did not change behaviour: we re-ran the 6,202-email
evaluation and compared every message. All 6,199 scanned messages had the
same verdict, score and signals. A performance change should be provably
boring.

### What the load test found

1. **A bug.** The first runs showed ~80 scans/s and a few scans taking over
   a minute. The worker logs said: InnoDB **deadlock**. Two workers saving
   different scans at the same time locked each other, because
   `DELETE FROM signals WHERE scan_id = ?` for a scan that has no signals
   yet still takes "gap locks" in InnoDB. Our design meant nothing was lost
   (the watchdog retried after 60 s), but users would wait a minute. Fix:
   skip the DELETE for new scans (the upsert tells us whether the row is
   new), and retry the transaction on a deadlock, which InnoDB documents as
   normal. A new test runs 200 saves at once and failed before the fix.
2. **The real numbers:** ~870–980 scans/s, p95 under 80 ms at 32 clients.
3. **The limit is not where you'd guess.** At 64 clients the throughput
   dropped, and the busiest containers were the API and MariaDB, not the
   worker. The load generator polls for results every 10 ms, and each poll is
   a database read. Polling every 50 ms instead gave ~980 scans/s again. So
   the bottleneck was the *measurement's own read traffic*. A real system
   would push results (webhook) instead of being polled.

Rule we followed: never round a number up, write down the machine
(MacBook Air M3, 8 GB), and keep the raw numbers in `docs/BENCHMARKS.md`.

### Interview questions

1. **"What's the difference between your benchmark and your load test
   numbers?"**
   The benchmark says one core analyses a typical email in ~10 µs, so in
   theory 100,000 per second. The load test says the whole system does
   ~900 per second. The gap is everything around the analysis: HTTP, a
   Redis write and stream read, a MariaDB transaction per scan, the
   result lookups, and Docker networking on a laptop. If I want more
   throughput, the profile says not to optimise the analysis but the I/O:
   batch the database writes, push results instead of being polled.

2. **"You found a deadlock. Why didn't you just retry and move on?"**
   Retrying alone would hide the cause and still waste work under load. The
   cause was a DELETE of rows that didn't exist taking gap locks, done for
   every new scan. Removing it fixes the common case; retry stays as the
   safety net because InnoDB can still pick a deadlock victim in rare
   cases. I wrote a test that reproduces it (200 concurrent saves) first, saw
   it fail with the same error as production, then fixed it.

3. **"How do you know your optimisation didn't break detection?"**
   Same input, same output: I ran the full evaluation before and after and
   compared every one of the 6,199 messages: verdicts, scores and signals
   were identical. Benchmarks show it's faster; the evaluation shows it's
   still correct. A speed-up that changes results is a behaviour change and
   needs its own justification.

---

## Step 8: Prometheus metrics and a Grafana dashboard

### The idea

Logs tell you what happened to *one* email. Metrics tell you how the
*system* is doing right now: how many scans per second, how long clients
wait, whether anything is stuck. Prometheus asks every service for its
numbers every 5 seconds (it "scrapes" `/metrics`) and stores them; Grafana
draws them.

### What we measure, and where

The important design question was **where each number comes from**:

- In async mode the **worker** does the analysis, so the analysis metrics
  (scans by verdict, time per check, which signals fire, queue wait,
  outcomes) come from the worker. Each worker has its own `/metrics` on
  port 9090. Prometheus finds every worker through DNS, so starting 3
  workers needs no config change.
- **Queue depth** (lag, pending, dead letters) is read from Redis at the
  moment Prometheus asks. If each process counted it itself, two API
  replicas would disagree; Redis is the single source of truth.
- Counters vs histograms: a **counter** only goes up (scans done); Grafana
  turns it into "per second" with `rate()`. A **histogram** puts each
  duration in a bucket, so Grafana can compute p50/p95/p99 across all
  workers. An average would hide the slow requests that p99 shows.

### Two details worth knowing

1. **One broken source must not hide everything.** By default, if any
   metric fails to collect (say Redis is down), the Prometheus Go library
   answers 500 for the *whole* `/metrics` page, and all graphs go blank
   exactly during the outage you need them for. We serve with
   `ContinueOnError`, and a test checks that with Redis down the other
   metrics are still there.
2. **The dashboard is tested.** A test reads the dashboard JSON and fails
   if a panel queries a metric the code does not define. Without it,
   renaming a metric silently empties a panel and nobody notices until
   they need it.

Also: `GOMEMLIMIT` from step 4 shows on the dashboard as the worker's
memory staying flat under load.

### Interview questions

1. **"Why histograms and not just an average latency?"**
   An average hides the users who wait. If 99 scans take 10 ms and one
   takes 2 s, the average is ~30 ms and looks fine. A histogram lets me
   graph p95 and p99, and it can be **aggregated across workers**
   (summing bucket counts is valid, averaging percentiles is not). The cost
   is choosing bucket boundaries up front; I picked exponential buckets
   around the latencies the benchmarks measured.

2. **"What would you alert on?"**
   Symptoms users feel, not causes: queue-wait p95 above a budget (users
   wait), dead letters above 0 (a message we could not scan), pending
   growing for minutes (workers dying or stuck), lag growing (too few
   workers). And one detection alert: a signal's share of clean mail
   jumping, which means a rule started firing on legitimate mail.

3. **"Your /metrics reads Redis on every scrape. Is that a problem?"**
   It is 3 cheap Redis commands every 5 seconds per API replica: nothing.
   The benefit is that the numbers are correct whatever the number of
   processes. If scrapes ever got expensive, I would move it to one
   exporter process or cache the result for a few seconds. And if Redis is
   down, only those three gauges disappear: no data, rather than a
   misleading zero.
