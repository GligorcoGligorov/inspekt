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
