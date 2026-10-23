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
