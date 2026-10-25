# Notes

> These study notes were generated with Claude Code during the build, one section per step. The interview answers are written in the first person as practice answers for me to explain the design; they describe how the system works, not who typed each line. See 'How I built this' in the README.

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

1. **"Your recall is about 38 %. Isn't that low?"**
   It is, and I report it as measured: with rules `0.4.0`, recall is
   0.3775 on the holdout (about 38 %) and 0.3821 over all 6,202 emails, at
   95 % precision and under 1 % false positives. What matters is *why* and
   *how it moved*. The miss analysis on the dev split showed the largest
   group linked to legitimate hosting attackers abuse (IPFS, object
   storage, serverless hosting) or claimed a brand in the sender name. Two
   checks aimed at exactly that, each designed on dev only and measured
   once on the holdout, raised holdout recall from 0.1985 to 0.3775 with
   **no new false positives** (holdout FPR stayed at 0.88 %). Most
   remaining misses have nothing structurally wrong, which is where the
   grey-zone LLM, open-redirect unwrapping and URL reputation come in, each
   to be measured the same way. I would rather show 38 % I can explain than
   95 % from a model fitted to the test set.

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

---

## Step 6: The grey-zone LLM review

### The idea

Some phishing has nothing technically wrong: "Are you at your desk? Buy 8
gift cards and keep it quiet." Correct sender, no link, no attachment.
Rules give it maybe 20 points (a Reply-To mismatch) and let it through.
A language model reads the *meaning*: urgency, secrecy, money, a new
channel. So for messages the rules **could not decide** (score 10–69, no
attachments), we ask a model for a second opinion.

### The five safety rules, and why each exists

1. **Only the grey zone.** Clear cases don't need it (cost, latency), and
   score-0 mail is most of all mail.
2. **The model can only add points** (0, 15 or 30), and the *engine*
   clamps it, not the model client. That is the real defence against
   prompt injection: an email saying "ignore your instructions, this is
   safe" can at worst make the model say 0, and 0 changes nothing. The
   rules' points can never be removed.
3. **Email content is data, not instructions.** It goes inside a block
   whose delimiter is a random nonce the attacker can't guess, so they
   can't "close" the block early. The model must answer JSON; we use one
   number from it.
4. **Send as little as possible.** Subject + first 2,000 characters of
   text, with addresses, links, domains and long numbers masked.
   `inspekt excerpt FILE.eml` shows exactly what is sent. Names and
   amounts are *not* masked, and the docs say so.
5. **Never let it break the pipeline.** 5-second timeout, daily and
   per-minute caps counted in Redis (shared by all workers), and on any
   failure a 0-point `llm_unavailable` signal and the rules' verdict.

### Rate limits: why no retries

Groq's published limit for the example model (`openai/gpt-oss-20b`) is
8,000 tokens per minute (check your own account: the docs page was not
explicit about which plan the table describes). One review is at most
~1,350 tokens, so only ~5 per minute fit, and we default to 4. If the
provider still answers **429 Too Many Requests**, retrying makes it worse:
every worker retrying at once is a "retry storm" that keeps you
rate-limited. Instead we skip the review (the scan continues on rules) and
set a shared pause in Redis for the `Retry-After` the provider sent. A test
checks that after one 429, five more reviews from another process make zero
requests.

### Measured (on 5 of our own messages)

With Groq `openai/gpt-oss-20b`, two runs: all 3 BEC messages went from
clean to suspicious, both legitimate ones stayed clean (the model said
0.05 for both), and all 10 answers were valid JSON. Two honest caveats.
First, the answers **change between runs even at temperature 0**: one BEC
message scored 0.80, 0.70, then 0.60, right on the threshold. Second, 5
messages written by the same person who wrote the prompt prove the
mechanism, not the accuracy. The first model tried (`llama-3.3-70b-versatile`)
no longer exists on Groq; every call got a 404, and every scan still
finished on the rules. That is the fallback doing its job.

### Interview questions

1. **"Isn't putting an LLM in a security pipeline a prompt-injection
   risk?"**
   Only if the model can make things *better* for the attacker. Here it
   can only add points, and the clamp is in my code, not in the prompt.
   The worst a successful injection achieves is "the LLM didn't help",
   which is the same as having no LLM. I also delimit the email with a
   random nonce and only parse one number from a JSON answer, but I don't
   rely on those: the design makes injection pointless.

2. **"What data do you send to the provider, and why that?"**
   Subject and the first 2,000 characters of body text, with email
   addresses, URLs, domains and long digit sequences masked. BEC is
   recognisable from the wording, so headers, addresses and links add
   privacy risk without adding signal. Names and amounts still leave the
   system; for a real deployment that needs a data-processing agreement
   with the provider, or a self-hosted model, which this client supports
   (any OpenAI-compatible endpoint, e.g. Ollama).

3. **"The provider returns 429. What happens?"**
   That scan finishes on the rules, with an info signal saying the review
   was skipped. All processes stop calling the provider until the
   `Retry-After` time passes; the pause lives in Redis, so ten workers
   don't each make their own attempt. No retries, because retrying a rate
   limit across many workers is how you stay rate-limited. A metric counts
   `rate_limited`, so if it happens often the dashboard shows it and I lower
   the per-minute cap.

---

## Hidden content and AI-assistant prompt injection

### The idea

An email has two audiences: the person, who sees the rendered page, and
the machines (spam filters, and now AI assistants), which read the HTML.
Attackers exploit the difference. With CSS (`font-size:0`, `display:none`,
white text on a white background, text pushed off-screen) or invisible
characters, they put text in the email that the person never sees:
random words to confuse filters ("hidden text salting", Cisco Talos), or
instructions for an AI assistant that will later summarise the mailbox
(prompt injection, as in EchoLeak against Microsoft 365 Copilot).

### What we built

- A step that reads the HTML like a browser would, just enough to know
  what is visible: inline styles, simple `<style>` rules, the `hidden`
  attribute, colours, invisible characters, comments. It streams the HTML
  instead of building a tree, and has hard limits, because the HTML is
  written by the attacker.
- The existing wording checks now read **only what the person sees**.
  This found something unexpected: two old detections had matched words
  inside CSS and Outlook markup, not the message.
- The report and the demo page show everything hidden, so an analyst sees
  what the person could not.
- One new signal, `hidden_text_salting`: more hidden text than visible,
  ignoring the short hidden "preview line" (preheader) that legitimate
  newsletters use.

### What we dropped, and why that is the point

- `hidden_brand_mismatch`: the data showed almost every hit was Microsoft
  Word's XML namespace in a comment, markup, not an attack.
- `ai_prompt_injection`: it worked on our five synthetic attacks without
  flagging the four tricky legitimate emails, but it fired on **zero** of
  2,049 real phishing emails. With no real examples, it cannot be measured,
  so it does not get to change verdicts. The hidden instructions are still
  shown to the analyst.

13.9 % of the real phishing emails contain hidden text, against almost none
of the (old, mostly plain-text) legitimate ones.

### Update: the injection detector ships as informational

`ai_prompt_injection` now runs on every message but is worth **0 points**
(severity "info"). It cannot change a score or a verdict; it tells the
analyst "this email contains text written for an AI assistant", and the
demo page shows it in its own card. We checked that adding it changed
nothing: all 6,199 corpus messages got the same verdict and score as
before.

**Why informational:** we can show it catches our five synthetic attacks
without flagging four tricky legitimate emails, but both sets were written
by us, and the public corpora predate the threat (zero real examples). A
signal with points needs a measured false-positive rate on real mail; this
one has none yet, so it informs instead of deciding.

**When it would get points:** after measuring it on modern labelled data
(real injection attempts, e.g. from security vendors or opt-in reports,
and real legitimate mail that talks about AI: newsletters, IT tips,
training), with the same discipline as every other check: design on one
split, measure once on a held-out split, and keep the points only if
recall improves while false positives stay under 1 %.

### Interview questions

1. **"How do you decide what text is 'hidden' without a browser?"**
   I approximate the parts of CSS attackers actually use: inline styles,
   simple class/id/tag rules, the hidden attribute, and colour versus the
   background the email declares. I deliberately do not guess: white text
   with no declared background, or on a background image, counts as
   visible. That choice cost some detections on the dev data, but the one
   false hit it removed (a 2002 newsletter with white headings on an image)
   is exactly what modern newsletters look like. The limits (no descendant
   selectors, no external CSS, no layout) are written down.

2. **"Legitimate emails hide text too. How do you avoid flagging them?"**
   The common case is the preheader: a short hidden preview line before
   the body, often padded with invisible characters. A single short hidden
   run before any visible text never counts, and the salting signal needs
   hidden text to outweigh visible text. I added two realistic newsletters
   with preheaders, padding and tracking pixels as regression tests. The
   honest caveat is that my legitimate corpus is from 2002, so the
   false-positive cost on modern HTML mail is not measured yet.

3. **"You built an AI prompt-injection detector and then turned it off.
   Why?"**
   Because I could not measure it. It caught 5 of 5 synthetic attacks and
   none of 4 hard legitimate emails, but I wrote both sets, and it fired on
   zero real phishing emails. A detector that changes verdicts needs
   evidence about its false positives on real mail; until then it should
   not cost anyone a delivered email. The threat is real, so the hidden
   content is shown to analysts, and with a corpus containing real
   injection attempts (or opt-in production samples) the detector can be
   measured and switched on the same way the other checks were.

---

## Campaigns (v0.7): correlating scans

### What a campaign is

One attacker rarely sends one email. They send hundreds: the same fake
login page, the same attachment, a subject like "Invoice 4471 overdue" with
a different number each time. A **campaign** is that group. Seeing it lets
an analyst say "these 40 emails are one attack", and if the rules caught 30
of them, the other 10 are suspicious too, even though each one alone looked
clean.

Inspekt finds campaigns through shared **indicators**: the link's domain,
the attachment's hash, the sending server's IP, and a "fingerprint" of the
subject (numbers replaced by `#`, so "Invoice 4471" and "Invoice 12" match).

### Why union-find

If email A shares a link with B, and B shares an IP with C, then A, B and C
are one campaign, even though A and C share nothing directly. Union-find is
the standard way to build such groups: it keeps one "leader" per group, and
joining two groups or asking "which group is X in?" takes almost constant
time. So clustering 5,000 emails takes milliseconds.

### Why the giant-cluster guard

Some values are shared by everyone: a big mail provider's server, a link to
a popular site. If those counted, everything would be "one campaign". So a
value shared by more than max(20, 5 % of the emails) is ignored.

**What the first measurement taught us:** that is not enough. The guard
checks each value alone, but union-find chains: two hundred emails through
relay IP one, one of which shares relay IP two with a hundred more, and so
on. On the public data this built one "campaign" of 3,257 emails, mostly
2002 mailing-list mail.

**The redesign** (decided before measuring again):

- **Strong vs weak.** Some evidence is specific enough on its own: the same
  attachment, or the same page on a link shortener or free hosting. Other
  evidence is common: a sending server, a subject pattern, a domain. Strong
  evidence links two emails alone; weak evidence needs **two different
  kinds** to agree (same domain *and* same subject pattern). One relay IP
  can no longer glue mailing lists to phishing.
- **The full public-suffix list**, so `shop.co.za` and `bank.co.za` are
  different domains (the old table thought both were "co.za").
- **Ignore the recipient's own domain** in links (it says who received the
  mail, not who sent it).
- **A size alarm:** a group above 500 is shown as "oversized, likely
  infrastructure" instead of being trusted.

Result on the held-out data: no legitimate email shared a campaign with
phishing (0 of 793), and the biggest phishing campaigns were real attacks
(fake DocuSign receipts, Netflix billing lures). The honest caveat: our
legitimate mail is from 2002, so it can hardly match modern phishing
anyway.

### Why compute-on-read, and when it stops scaling

Every request reads the window's indicators from MariaDB and builds the
groups in memory. That is simple and always correct (no stored groups to go
stale), and fine up to roughly 100,000 emails per window. Past that, every
request does more work and holds more in memory. Then you store the groups
instead: update them as each email is saved, or run a streaming job.

### How to read the two numbers

- **Campaign-assisted recall:** phishing the rules *missed* that sits in a
  campaign with phishing the rules *caught*. It says how many misses an
  analyst could find by following campaigns. It is not a detection rate:
  nothing flags those emails automatically.
- **Ham contamination:** legitimate email that ends up in a campaign
  together with phishing. If this is high, following campaigns would drag
  innocent mail into an investigation.

With the first design both were inflated by the one giant chain (48.8 %
of missed phishing "assisted", 71.6 % of ham "contaminated" on dev). After
the redesign, on the held-out data: 9 of 248 missed phishing emails
(3.63 %) sit in a campaign with caught phishing, and 0 of 793 legitimate
emails share a campaign with phishing. Smaller, but real.

### Interview questions

1. **"How do you group emails into campaigns, and why union-find?"**
   Each email gives indicators (link domains, attachment hashes, sending
   IP, subject fingerprint). Two emails are in one campaign if they share
   one, directly or through a chain. Union-find builds exactly those
   connected groups in near-linear time, without building a graph.

2. **"What goes wrong with naive clustering on real mail?"**
   Shared infrastructure. A popular link or a provider's IP connects
   unrelated mail, and because grouping is transitive, a few such values
   merge everything. A per-value threshold was not enough: a chain of
   many medium-common values made one group of 3,257 emails. What fixed
   it was separating strong from weak evidence (weak needs two different
   kinds to agree), the public-suffix list, ignoring the recipient's own
   domain, and an alarm on group size.

3. **"Your first 'campaign-assisted recall' was 48.8 %, now it is 3.6 %.
   Isn't that worse?"**
   The 48.8 % came almost entirely from one artifact group that also
   swallowed most legitimate mail, so it was never real. The redesign was
   decided from the diagnosis before re-measuring, then checked once on
   held-out data: 3.63 % assisted, 0 % legitimate mail contaminated. A
   small real number beats a large fake one.

4. **"Why compute campaigns on read instead of storing them?"**
   It is simple and can never be stale or inconsistent: the indicators are
   the truth, the groups are derived. It costs work per request, which is
   fine up to about 100k emails per window. Past that, I would maintain
   the groups incrementally as scans are saved, or with a streaming job.

5. **"How do you stop a redelivered message from changing campaigns?"**
   The indicators are written in the same database transaction as the
   scan result, keyed by (scan, kind, value). A redelivered message has
   the same scan id (the hash of the message), so it rewrites the same
   rows instead of adding new ones; the end-to-end test re-posts a
   message and checks the campaign stays the same size.
