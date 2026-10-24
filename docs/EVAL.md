# Evaluation on public corpora

All numbers on this page come from `make eval` runs on the corpora below, on
an Apple M3. Sections 0–3 ran `inspekt-rules/0.1.0` with the weights stated
in each; the two kept changes were released as `inspekt-rules/0.2.0`, which
reproduces section 4 exactly. Nothing is rounded up. A message counts
as flagged at verdict `suspicious` or higher.

## Corpora

| Label | Source | Files | Messages | Licence |
|---|---|---|---|---|
| ham | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | `20030228_easy_ham.tar.bz2`, `20030228_easy_ham_2.tar.bz2`, `20030228_hard_ham.tar.bz2` | 2,500 + 1,400 + 250 = **4,150** | "Copyright for the text in the messages remains with the original senders" (corpus readme) |
| phish | [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | `phishing-2019` … `phishing-2025` | 243 + 158 + 101 + 247 + 419 + 403 + 481 = **2,052** | CC BY 4.0 (`LICENSE.txt`, José Nazario) |

`eval/fetch_corpora.sh` downloads them into `data/` (gitignored), checks
every file against `eval/corpora.sha256`, unpacks the ham and splits the
phishing mboxes into one `.eml` per message (`eval/split_mbox.py`, which
keeps each message's bytes exactly as stored). Pinned checksums (SHA-256):

```
2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438  20030228_easy_ham.tar.bz2
b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38  20030228_easy_ham_2.tar.bz2
ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9  20030228_hard_ham.tar.bz2
cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e  phishing-2019
99e20bf25f5e8556d37103f2c8140cd75181a62d3df91df8acf9d9aece9f08bb  phishing-2020
636707cff42245d1482e4ae8a2c03369717a5e06bf9d1a0f4ec5dcd846661cee  phishing-2021
a6291e2cb990204766fce425423949b403cce4ae6a660fc8d08812e40a063fa7  phishing-2022
5007f1c1dc91b15e93e988afa3a1cf402e15c88f765d3057be8bfec50dae1fe8  phishing-2023
60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99  phishing-2024
f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f  phishing-2025
```

Some Nazario files are still updated upstream (`phishing-2025` changed in
February 2026). If one changes again, the fetch fails on the checksum
instead of silently changing the numbers; re-pin deliberately.

Not used: `private-phishing4.mbox` (its name suggests it was not meant for
publication) and the 2005–2007 phishing mboxes (to keep the phishing side
recent).

### Biases to keep in mind

- **Era mismatch.** The ham is from 2002–2003; the phishing from 2019–2025.
  Old ham has no SPF/DKIM/DMARC results (none of the 4,150 has a DMARC
  result) and no URL shorteners. Any signal tied to modern mail
  infrastructure looks perfectly precise here because it *cannot* fire on
  this ham. Precision numbers for `spf_*`, `dkim_fail`, `dmarc_fail` and
  `url_shortener` are therefore not evidence, and no weight was raised
  because of them.
- **One inbox.** The Nazario corpus is one person's inbox (`monkey.org`),
  hand-labelled, not a representative sample of phishing.
- **Spam is not phishing.** The SpamAssassin *spam* folders are not used:
  spam is a different problem, and labelling it as phishing would be wrong.

## Method

- `python3 eval/evaluate.py --ham data/ham --phish data/phish --out eval/report`
  runs the CLI over every message (headers mode: `Authentication-Results`
  from any authserv-id is believed, as the corpus has no "own MTA").
- **Fixed held-out split:** each message is assigned to *dev* (80 %) or
  *holdout* (20 %) by a SHA-256 of its path (`eval/metrics.py:split_of`).
  Every analysis below that led to a change looked at **dev only**
  (`python3 eval/explain.py eval/report.json`); holdout was only used to
  check the change afterwards.

## Results

### 0. First run: invalid (a crash, now fixed)

| Messages scanned | Parse errors | Precision | Recall | FPR |
|---|---|---|---|---|
| 4,711 of 6,202 | 1,491 | 0.7500 | 0.1695 | 0.0100 |

1,491 messages "failed to parse". Running them one by one showed only 3
real parse failures: 56 phishing messages crashed the scanner with a panic
in HTML link extraction (offsets from `strings.ToLower` used on the original
string; non-ASCII changes the byte length), and each crash took down the
rest of its 200-message batch. Fixed in `859c0b6`, with a regression test
and a new fuzz test in CI. These numbers are kept only as a record.

### 1. Baseline (after the crash fix, no tuning)

| Split | Messages | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---|---|---|---|---|---|---|---|
| all | 6,199 | 338 | 113 | 4,037 | 1,711 | 0.7494 | 0.1650 | 0.0272 |
| dev | 4,998 | 267 | 93 | 3,264 | 1,374 | 0.7417 | 0.1627 | 0.0277 |
| holdout | 1,201 | 71 | 20 | 773 | 337 | 0.7802 | 0.1740 | 0.0252 |

3 parse errors (all phishing; genuinely malformed headers such as a header
line starting with `=`). Throughput 2,169.7 messages/s (CLI, one process,
batches of 200, including process start-up).

### 2. Why it looks like this (dev split)

**False positives (93 on dev).** 64 of them are `html_form_in_email` alone
(30 points = exactly the threshold). That signal fires on 75 dev messages,
only 4 of them phishing: **5.3 % precision**. Nearly all are `hard_ham`
commercial newsletters with search or subscribe forms. Next is
`link_text_mismatch` alone (15): newsletters whose visible link says
`Walmart.com` but goes through a click-tracking redirector
(`clickthru.online.com`). Modern ESPs do the same, so this is a real,
remaining false-positive class (the signal is still 84 % precise).

**Missed phishing (1,374 on dev).**

| Score of the missed message | Count |
|---|---|
| 0–9 | 1,007 |
| 10–19 | 228 |
| 20–29 | 139 |

743 missed messages carry **no signal at all**. Of those, 94 % contain
links, but to legitimate infrastructure that attackers rent or abuse: IPFS
gateways (`ipfs.io` 42, `dweb.link` 14, `cloudflare-ipfs.com` 10),
Google (`google.com` 41, `googleapis.com` 27), Cloudflare R2 (`r2.dev`: 25),
Glitch (`glitch.me`: 18), Firebase (`web.app`: 9), and click-tracking or
open redirects (`sendgrid.net` 20, `doubleclick.net` 16). Counts are messages per
link domain; one message can count under two. No lookalike
domain, no IP literal, authentication passes or is absent: every
structural rule is satisfied. 78 % carry an `Authentication-Results`
header. Only 3 % have neither links nor attachments (pure-text BEC-style).

The rest of the misses carry weak signals only: `return_path_mismatch`
(5 points, 11 % precise), `spf_softfail` (8), `url_shortener` (10),
`credential_lure` (10, capped by design), and 38 with only `missing_from`
(an unparseable From header, then worth 20).

### 3. Changes (one at a time, dev first, then holdout)

**Change 1: `html_form_in_email` 30 → 10.** Reason: 5.3 % precision, the
cause of 69 % of dev false positives. At 10 it can still tip a borderline
message but never decides one alone.

| Split | Precision | Recall | FPR | FP | TP |
|---|---|---|---|---|---|
| dev before | 0.7417 | 0.1627 | 0.0277 | 93 | 267 |
| dev after | 0.9017 | 0.1621 | 0.0086 | 29 | 266 |
| holdout before | 0.7802 | 0.1740 | 0.0252 | 20 | 71 |
| holdout after | 0.9103 | 0.1740 | 0.0088 | 7 | 71 |

The holdout confirms it: false positives drop by two thirds, recall is
unchanged (one dev detection lost).

**Change 2: `missing_from` 20 → 30.** Reason: an unparseable From header
(`"Tax" <>`, `info@secure.com` with no closing `>`, a trailing `.`) fired on
46 dev messages, 44 of them phishing (96 %), and 38 missed phishing messages
had nothing else. This is not an era artefact (2002 mail had valid From
headers too), and since 2024 Gmail and Yahoo require RFC 5322-valid From
headers from bulk senders.

| Split | Precision | Recall | FPR | FP | TP |
|---|---|---|---|---|---|
| dev before | 0.9017 | 0.1621 | 0.0086 | 29 | 266 |
| dev after | 0.9083 | 0.1871 | 0.0092 | 31 | 307 |
| holdout before | 0.9103 | 0.1740 | 0.0088 | 7 | 71 |
| holdout after | 0.9205 | 0.1985 | 0.0088 | 7 | 81 |

The holdout confirms it: +10 detections, no new false positives (dev: +41
detections, +2 false positives).

No further weight was changed. Everything else the dev data "suggested"
was either an era artefact (authentication signals) or too small to trust.

### 4. Current numbers

| Split | Messages | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| all | 6,199 | 388 | 38 | 4,112 | 1,661 | 0.9108 | 0.1894 | 0.3135 | 0.0092 |
| dev | 4,998 | 307 | 31 | 3,326 | 1,334 | 0.9083 | 0.1871 | | 0.0092 |
| holdout | 1,201 | 81 | 7 | 786 | 327 | 0.9205 | 0.1985 | | 0.0088 |

3 parse errors. Throughput varies between runs of the same corpus on the
same machine: 2,018.0 to 2,176.9 messages/s over the four runs above (CLI,
one process, batches of 200, including process start-up).

**Read this honestly:** the rule engine is precise (about 9 in 10 flags are
right, under 1 % of legitimate mail is flagged) but it **catches about one
phishing message in five**. That is the expected shape of a structural,
explainable rule set facing phishing that lives on legitimate hosting.

## The `p=none` decision

Question (from step 2): should `dmarc_fail` count less when the sender's
domain publishes `p=none`?

Data: 51 phishing messages have `dmarc_fail`; the receiving MTA wrote the
published policy into the header. **39 of them (76 %) are `p=none`**, 6
`quarantine`, 6 `reject`. Scoring `dmarc_fail` at 0 for `p=none` would turn
**35 of those 39 detections into misses**. On the ham side the corpus has
**no DMARC results at all**, so the false-positive cost of `dmarc_fail`
cannot be measured here.

**Decision: keep `dmarc_fail` at 35 regardless of policy.** `p=none` is the
domain owner saying "do not enforce", not evidence that the mail is
legitimate, and attackers favour `p=none` domains exactly because receivers
let failures through. Open risk: legitimate forwarding and mailing lists
break DMARC; that needs measuring on a modern ham corpus (and handling via
ARC or known forwarders) before this weight can be called right.

## CI gate on a fixed subset

`eval/make_subset.py` selects **100 ham + 100 phishing from the holdout
split**, ordered by a fixed hash, so the gate measures mail that no tuning
decision looked at. The SpamAssassin texts may not be redistributed, so
the subset is not committed: CI runs the pinned fetch (cached by checksum)
and rebuilds it. Current subset result: precision 0.9412, recall 0.16, FPR
0.01 (TP 16, FP 1, TN 99, FN 84), 0 parse errors. The gate is set to exactly
that (`--min-recall 0.16 --max-fpr 0.01 --max-parse-errors 0`): losing a
detection or adding a false positive fails CI, so such a change has to
update the gate and this page on purpose.

## What would move recall (not done yet)

In order of expected impact, from the missed-phishing analysis:

1. **Abusable-hosting signal**: links to IPFS gateways, `r2.dev`,
   `glitch.me`, `web.app` / `firebaseapp.com`, `workers.dev`, `pages.dev`
   and similar free hosting, especially when combined with credential
   wording or a brand name in the path.
2. **Open-redirect unwrapping**: follow the target inside
   `google.com/url?q=`, `doubleclick.net`, `sendgrid.net` click links
   *without fetching them* (the destination is in the URL) and run the link
   checks on the destination.
3. **URL reputation feeds** (e.g. PhishTank / OpenPhish) as an external
   signal.
4. **The grey-zone LLM (step 6)** for the text-only and "nothing
   structurally wrong" cases.

Each of these must be measured the same way before it is kept.

## Grey-zone LLM on the BEC set

**Scope, stated plainly:** the LLM stage is evaluated **only on our own
synthetic samples**, never on the public corpora. The SpamAssassin texts
are not ours to send to a third party, and `eval/evaluate.py` refuses to
run when `INSPEKT_LLM_*` is set and any message comes from `data/`. Five
hand-written messages say very little about a model's real precision or
recall; they show the mechanism works and catch regressions, nothing more.

The set (`testdata/bec/labels.csv`), all scoring in the grey zone (20 or 25)
with no attachments, so all would be reviewed:

| File | Label | What it is |
|---|---|---|
| `bec_reply_to.eml` | phish | CEO impersonation, confidential payment, Reply-To elsewhere |
| `bec/bec_gift_cards.eml` | phish | gift cards, urgency, secrecy, Reply-To to a personal mailbox |
| `bec/bec_vendor_bank_change.eml` | phish | supplier's "new bank account", do not call, Reply-To elsewhere |
| `bec/legit_ceo_meeting.eml` | ham | the real CEO moving a meeting; replies go to his office |
| `bec/legit_invoice_reminder.eml` | ham | a real invoice reminder; "details have not changed" |

| Run | Model | Date (UTC) | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|---|---|
| Rules only | none (`inspekt-rules/0.2.0`) | 2026-10-23 | 0.0 | 0.0 | 0.0 | 0 / 0 / 2 / 3 |
| Rules + LLM, run 1 | Groq `openai/gpt-oss-20b` | 2026-10-23 18:45 | 1.0 | 1.0 | 0.0 | 3 / 0 / 2 / 0 |
| Rules + LLM, run 2 | Groq `openai/gpt-oss-20b` | 2026-10-23 18:46 | 1.0 | 1.0 | 0.0 | 3 / 0 / 2 / 0 |

Command: `set -a; source .env; set +a; INSPEKT_LLM_ENABLED=true
INSPEKT_LLM_PER_MINUTE=10 make eval-bec`. The per-minute cap was raised from
the default 4 for these runs only, because one CLI process reviews all 5
messages within seconds (5 calls, roughly 6K tokens, well inside Groq's
per-minute limits for this model). Prompt, temperature (0), `max_tokens`
(400) and point mapping are the shipped defaults; nothing was tuned to
these samples.

Per message (likelihood as returned by the model, then the resulting
verdict and score):

| Message | Label | Rules only | Run 1 | Run 2 |
|---|---|---|---|---|
| `bec_reply_to.eml` | phish | clean, 20 | 0.70 → suspicious, 35 | 0.60 → suspicious, 35 |
| `bec_gift_cards.eml` | phish | clean, 20 | 0.90 → suspicious, 50 | 0.95 → suspicious, 50 |
| `bec_vendor_bank_change.eml` | phish | clean, 20 | 0.90 → suspicious, 50 | 0.80 → suspicious, 50 |
| `legit_ceo_meeting.eml` | ham | clean, 20 | 0.05 → clean, 20 | 0.05 → clean, 20 |
| `legit_invoice_reminder.eml` | ham | clean, 25 | 0.05 → clean, 25 | 0.05 → clean, 25 |

**JSON validity:** all 10 answers were valid JSON with a number in range:
no `llm_unavailable` signal, nothing truncated. The reasoning model's
answers fit in `max_tokens` 400, so no reasoning-effort or token-limit
change was needed. The model's reasons were on topic (e.g. "Changed bank
details; No verification or confirmation", "No financial request; No
urgency or secrecy").

**What to take from it, and what not:**

- On these 5 hand-written messages the stage does what it is for: all 3 BEC
  messages move from clean to suspicious, neither legitimate message is
  flagged, and the model gave both legitimate messages 0.05.
- **Answers vary between runs even at temperature 0.** `bec_reply_to.eml`
  got 0.80 in a preliminary run, then 0.70, then 0.60, and 0.60 is exactly
  the +15 threshold: its 35 points clear the verdict line by 5. It was caught
  every time, but marginally; a slightly lower answer would leave it clean.
  `bec_vendor_bank_change.eml` moved from 0.90 to 0.80, the edge of +30.
- 5 messages, written by the same person who wrote the prompt, say nothing
  reliable about precision or recall in production.

History: a first attempt with `llama-3.3-70b-versatile` returned HTTP 404
("does not exist or you do not have access to it") for every call; the
fallback worked (all 5 scans completed on the rules with `llm_unavailable`).
A preliminary run with `openai/gpt-oss-20b` at 18:44 gave the same
verdicts (likelihoods 0.80 / 0.90 / 0.90 for the BEC messages); it did not
yet record 0-point reviews, which is why the two runs above were made after
adding the `llm_no_bec` info signal (a review that finds no BEC is now
visible to the analyst, still worth 0 points).

Known limits of the stage: answers vary from run to run (above); its grey zone starts at score 10, so BEC with no
technical signal at all is never reviewed; names, company names and
amounts are sent unmasked; the points mapping (≥ 0.8 → +30, ≥ 0.6 → +15) is a
starting point to be set from data once real runs exist.

## Recall work, 2026-10-24 (dev for design, holdout measured once)

Rules: design and analysis use **only the dev split**
(`evaluate.py --split dev`, which does not even compute holdout numbers);
each check's design is frozen before **one** holdout measurement
(`--split holdout`). A check is kept only if holdout recall improves and
holdout FPR stays at or below 1 %. One check per commit.

Starting point (`inspekt-rules/0.2.0`):

| Split | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|
| dev | 0.9083 | 0.1871 | 0.0092 | 307 / 31 / 3,326 / 1,334 |
| holdout | 0.9205 | 0.1985 | 0.0088 | 81 / 7 / 786 / 327 |

### Check 1: `abused_hosting_link` (+30), kept → `inspekt-rules/0.3.0`

**Design (dev only).** Of 1,334 missed dev phishing messages, 309 (23 %)
link to abusable hosting: IPFS gateways (134), object storage such as
`r2.dev`, `storage.googleapis.com`, `blob.core.windows.net`, S3 (100),
serverless/static hosting such as `pages.dev`, `workers.dev`, `web.app`,
`glitch.me` (74), form/site builders (5). The host list follows known abuse
categories rather than only the hosts seen in the misses. Hosting alone is
not evidence (plenty of legitimate mail links to cloud storage), so the
check also requires credential wording in the subject or body, or a
protected brand named in the text or in the link; 265 of the 309 met that.
Two refinements came from dev data before freezing: a 2002 newsletter
linked to `freshmeat.net/projects/ipfs/`, so a bare `/ipfs/` path no longer
counts (only a real IPFS content id does); and brand words may carry digits
(`office365`, `microsoft365`) but not letters (`officer`).

| Split | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|
| dev before | 0.9083 | 0.1871 | 0.0092 | 307 / 31 / 3,326 / 1,334 |
| dev after | 0.9489 | 0.3510 | 0.0092 | 576 / 31 / 3,326 / 1,065 |
| holdout before | 0.9205 | 0.1985 | 0.0088 | 81 / 7 / 786 / 327 |
| **holdout after** | **0.9500** | **0.3260** | **0.0088** | 133 / 7 / 786 / 275 |

Kept: holdout recall +0.1275, no new false positive. Caveat, as before: the
2002 ham predates every one of these services, so this corpus **cannot
measure** the check's false-positive cost on modern mail (a SharePoint-like
newsletter on `web.app` that says "account" would fire). The credential or
brand condition is the mitigation; a modern ham corpus is the real test.

All data after check 1: precision 0.9491, recall 0.3460, F1 0.5072, FPR
0.0092 (709 / 38 / 4,112 / 1,340). CI subset (holdout): precision 0.9677,
recall 0.30, FPR 0.01; its gate is raised to `--min-recall 0.30`.

### Check 2: `brand_display_name` (+30), kept → `inspekt-rules/0.4.0`

**Design (dev only).** Five variants of "a protected brand is named but
neither the sender nor any link belongs to it" were compared on the dev
messages the rules still missed:

| Variant (dev) | Missed phish it covers | Clean ham it touches |
|---|---|---|
| A: brand anywhere in subject/body, links present, none to the brand | 241 | 325 |
| B: brand in the subject | 50 | 50 |
| C: brand anywhere in the From display name | 53 | 2 |
| D: brand in subject or display name + credential wording | 62 | 11 |
| E: brand in subject or display name, links present | 78 | 45 |
| **C′: display name *starts with* the brand** | **53** | **0** |

Tech mailing lists name Microsoft, Apple and Google constantly, so any
"brand in the text" rule is unusable here (A: 325 ham). C was precise; its
2 ham hits were a newsletter called "Lockergnome Apple Core": a publication
*about* a brand, not a sender claiming to *be* it. C′ encodes that
distinction (phishing names the sender as the brand: "DocuSign", "DHL
Express", "Netflix Support"). "office" and "live" are not treated as brand
names at the start of a display name ("Office Manager", "Live Events"):
ordinary words, decided from domain knowledge, not from the data (they
covered 2 dev phish).

| Split | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|
| dev before | 0.9489 | 0.3510 | 0.0092 | 576 / 31 / 3,326 / 1,065 |
| dev after | 0.9530 | 0.3833 | 0.0092 | 629 / 31 / 3,326 / 1,012 |
| holdout before | 0.9500 | 0.3260 | 0.0088 | 133 / 7 / 786 / 275 |
| **holdout after** | **0.9565** | **0.3775** | **0.0088** | 154 / 7 / 786 / 254 |

Kept: holdout recall +0.0515, no new false positive. Remaining risk: brands
that legitimately send from other domains (agencies, payment processors);
none appear in this corpus, so that cost is unmeasured.

All data after check 2: precision 0.9537, recall 0.3821, F1 0.5456, FPR
0.0092 (783 / 38 / 4,112 / 1,266). CI subset (holdout): precision 0.9750,
recall 0.39, FPR 0.01; gate raised to `--min-recall 0.39`.

### Check 3 (credential forms in HTML attachments): not built

**Dev data.** No missed dev phishing message has an HTML-like attachment
(`.html`, `.htm`, `.shtml`, `.xhtml`, `.svg`, or an HTML / SVG content
type). All 81 dev phishing messages with one are already flagged by the
existing `html_attachment` signal (30 points); 59 of them contain a password
input. A form check would add evidence, not recall, so it was not built and
the holdout was not consulted for it.

### Where the recall work ends (rules `0.4.0`)

| Split | Precision | Recall | FPR |
|---|---|---|---|
| dev, start of the day | 0.9083 | 0.1871 | 0.0092 |
| dev, after checks 1 and 2 | 0.9530 | 0.3833 | 0.0092 |
| holdout, start of the day | 0.9205 | 0.1985 | 0.0088 |
| **holdout, after checks 1 and 2** | **0.9565** | **0.3775** | **0.0088** |

Holdout FPR stayed at 0.88 % (7 of 793), under the 1 % limit; holdout
recall nearly doubled. The holdout was measured exactly twice, once per
check, after each design was frozen.

## Hidden content and AI-assistant prompt injection (2026-10-24)

Same discipline: designs use the dev split only; each change is measured
once on the holdout after it is frozen; a signal is kept only if holdout
recall improves and holdout FPR stays at or below 1 %.

### Step 1: content checks read only visible text → `inspekt-rules/0.5.0`

New `extract.HTMLContent` splits HTML into the text a reader sees and the
text hidden by CSS, the `hidden` attribute, or invisible characters (see
the README for what it understands and what it does not). `credential_lure`
and `abused_hosting_link` now read subject + plain text + *visible* HTML
text, instead of the raw HTML.

Dev, message by message against `0.4.0`: 5 phishing messages gained
`credential_lure` (their wording had been split by tags, e.g.
`verify your <b>account</b>`); 2 lost `abused_hosting_link`, and in both the
old match was markup, not content: `outlook` in a CSS selector
(`body[data-outlook-cycle]`) and Outlook's conditional-comment XML
(`<o:OfficeDocumentSettings>`). One of those two fell below the threshold.

| Split | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|
| dev before (`0.4.0`) | 0.9530 | 0.3833 | 0.0092 | 629 / 31 / 3,326 / 1,012 |
| dev after | 0.9530 | 0.3827 | 0.0092 | 628 / 31 / 3,326 / 1,013 |
| holdout before | 0.9565 | 0.3775 | 0.0088 | 154 / 7 / 786 / 254 |
| **holdout after** | **0.9571** | **0.3824** | **0.0088** | 156 / 7 / 786 / 252 |

Kept (this was a required change, not an optional signal): holdout +2
detections, no new false positive; on dev, −1, from a match on markup.
All data: precision 0.9538, recall 0.3826, FPR 0.0092. CI subset unchanged
(recall 0.39, FPR 0.01).

### Step 2: `hidden_text_salting` (+20), kept → `inspekt-rules/0.6.0`

**How common is hidden text?** On the dev split (final extractor): **229
of 1,641 phishing messages (14 %)** contain hidden text, against **2 of
3,357 ham**. That gap is partly the era again: most of the 2002 ham is
plain text, so it barely has HTML to hide anything in. Modern newsletters
routinely hide preview lines (preheaders), which is why the legitimate
samples in `testdata/` exist and a short preheader never counts.

**Design (dev only).** Candidate rules over the hidden text of dev messages
the rules still missed: hidden letters ≥ 100 (62 missed phish, 1 ham);
≥ 3 interleaved runs (23, 1); hidden ≥ visible (46, 0); many invisible
characters (6, 0). The one ham hit exposed an extractor assumption, not
salting: WinXPnews has white headings on cells with a background *image*
(`<td background=…>`), and the extractor assumed a white page background
when none was declared. Both were changed before freezing: white text
counts as hidden only against a background the email itself declares,
and an image or gradient background makes the colour unknown. That cost
49 dev phishing messages their "hidden" status (229 instead of 286) in
exchange for not guessing.

Frozen rule: hidden text beyond a short preheader (a single hidden run
before any visible text, ≤ 300 letters, is ignored), at least 50 hidden
letters/digits, and **at least as much hidden as visible text**. +20: it
never decides alone (threshold 30). On dev it was predicted to add 20
detections and added exactly 20, so the extractor refinement in the same
commit changed nothing else on dev.

| Split | Precision | Recall | FPR | TP / FP / TN / FN |
|---|---|---|---|---|
| dev before | 0.9530 | 0.3827 | 0.0092 | 628 / 31 / 3,326 / 1,013 |
| dev after | 0.9543 | 0.3949 | 0.0092 | 648 / 31 / 3,326 / 993 |
| holdout before | 0.9571 | 0.3824 | 0.0088 | 156 / 7 / 786 / 252 |
| **holdout after** | **0.9581** | **0.3922** | **0.0088** | 160 / 7 / 786 / 248 |

Kept: holdout +4 detections, no new false positive. All data: precision
0.9551, recall 0.3943, F1 0.5582, FPR 0.0092. CI subset: precision 0.9762,
recall 0.41, FPR 0.01; gate raised to `--min-recall 0.41`.

### Step 3: `hidden_brand_mismatch`, not kept (dropped on dev data)

Two candidate definitions on the dev split: (a) a protected brand named
only in hidden text (or comments), not in what the reader sees, from a
sender that is not that brand; (b) a brand the reader sees that a naive
filter reading all text would not find, because hidden spans or invisible
characters split the word.

| Candidate (dev) | Missed phish | Caught phish | Ham |
|---|---|---|---|
| (a) brand only in hidden text or comments | 8 | 9 | 1 |
| (b) visible brand split by hidden content | 2 | 0 | 0 |

The ham hit and **7 of the 8 missed phish** had the "hidden brand" only
in an HTML comment: Microsoft Word's XML namespace
(`urn:schemas-microsoft-com:office:office`), markup rather than text aimed
at anyone. Without comments, the signal covers 3 dev messages. At a
conservative +20 it adds **0** dev detections (those messages score too low
otherwise); at +30 it adds 3, which is too little evidence to justify
raising a weight. Dropped without consulting the holdout, which stays
reserved for changes that help on dev.

### Step 4: `ai_prompt_injection`, not kept as a scored signal

**Design.** Text written for an AI assistant reading the mailbox: in hidden
text or HTML comments, an instruction override ("ignore previous
instructions", "system prompt", "developer mode"), an assistant addressed
together with an action (forward, reveal or include secrets, tell the user,
conceal), or a markdown image whose URL carries data (EchoLeak); in
visible text, only an assistant addressed by name at the start of a line
("Copilot, …") together with an override or a data demand, so that text
*about* prompt injection (security training, AI newsletters) does not
count. The first smoke run missed the visible case because the visible
text had lost its line breaks; keeping one line per block element fixed
that.

**Real data.** The signal fired on **0 of 1,641 dev and 0 of 408 holdout
phishing messages**, and on no ham: the 2019–2025 Nazario phishing does not
contain AI-assistant prompt injection, so this corpus cannot measure the
signal at all. The line-break change, measured with it once on the
holdout, gained one dev detection (`abused_hosting_link`, words no longer
glued across table cells) and lost one holdout detection (recall 0.3922 →
0.3897). Per the rule, both were dropped and the code reverted; rules stay
at `0.6.0`.

**Synthetic smoke test** (`make eval-injection`, `testdata/injection/`,
written by the same author as the rule, so not a measurement): the frozen
detector flagged **5 of 5** injection emails (hidden instruction with
markdown-image exfiltration, comment telling an assistant to forward mail,
visible instruction to Copilot, hidden fake system prompt, off-screen RAG
poisoning) and **0 of 4** legitimate ones (AI newsletter, Copilot tips for
people, security training quoting "ignore previous instructions", receipt
with a preheader). With the signal dropped, the shipped rules flag none of
the 5 by their AI content; the hidden instructions are still visible to an
analyst in the report's hidden-content section and on the demo page.

### Hidden content in the corpus

Counted with the final extractor over the whole corpus (descriptive, after
all designs were frozen):

| | Phishing (2,049 scanned) | Ham (4,150 scanned) |
|---|---|---|
| Any hidden text (preheaders included) | **284 (13.9 %)** | 2 (0.05 %) |
| Hidden text beyond a short preheader | 219 | 2 |
| Invisible characters (zero-width etc.) | 109 | 0 |
| `hidden_text_salting` fired | 56 | 0 |

The ham column is weak evidence for the usual reason: the 2002 ham is mostly
plain text, with little HTML to hide anything in. Modern legitimate mail
hides preview text routinely; the `testdata/` newsletters cover that case.
