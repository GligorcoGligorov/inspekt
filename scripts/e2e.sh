#!/usr/bin/env bash
# End-to-end check of the async pipeline against the docker compose stack
# (real Redis, real worker). Run via `make e2e`; CI runs it on every push.
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "--- $*"; }

wait_ready() {
	for _ in $(seq 60); do
		curl -sf "$BASE/readyz" >/dev/null && return
		sleep 1
	done
	fail "API not ready at $BASE"
}

# post FILE -> prints the scan's Location path; asserts 202.
post() {
	local hdr code
	hdr=$(mktemp)
	code=$(curl -s -o /dev/null -D "$hdr" -w '%{http_code}' --data-binary @"$1" "$BASE/v1/scans")
	[ "$code" = 202 ] || fail "POST $1: status $code"
	tr -d '\r' <"$hdr" | awk 'tolower($1)=="location:" {print $2}'
	rm -f "$hdr"
}

# result LOCATION -> prints the scan JSON once it is no longer queued.
result() {
	local body
	for _ in $(seq 100); do
		body=$(curl -sf "$BASE$1") || fail "GET $1"
		[ "$(jq -r .status <<<"$body")" != queued ] && { echo "$body"; return; }
		sleep 0.2
	done
	fail "$1 still queued after 20 s"
}

expect() { # expect LOCATION STATUS [VERDICT]
	local body
	body=$(result "$1")
	[ "$(jq -r .status <<<"$body")" = "$2" ] || fail "$1: $(jq -c '{status, error}' <<<"$body"), want $2"
	if [ $# -eq 3 ]; then
		[ "$(jq -r .report.verdict <<<"$body")" = "$3" ] || fail "$1: verdict $(jq -r .report.verdict <<<"$body"), want $3"
	fi
	echo "ok $(jq -c '{status, verdict: .report.verdict, score: .report.score, attempts}' <<<"$body")"
}

wait_ready

step "the demo page is served"
curl -sf "$BASE/" | grep -q "<title>Inspekt</title>" || fail "GET / did not serve the demo page"
echo ok

step "campaigns: 5 emails of one attack become one campaign; 3 unrelated stay apart"
# Runs first, on an empty store: later steps post samples that correlate
# with each other (two of them link to the same lookalike host).
camp=$(mktemp -d)
for i in 1 2 3 4 5; do
	printf 'From: Mail Admin <admin@notice%s.example>\r\nTo: user@example.org\r\nSubject: Your mailbox is full (%s%s7 messages held)\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Your mailbox is full. <a href="https://login.evil-login.xyz/release?u=%s">Release messages</a></p>\r\n' \
		"$i" "$i" "$i" "$i" >"$camp/phish$i.eml"
done
printf 'From: Cafe <menu@cafe.example>\r\nSubject: Lunch menu for Friday\r\nContent-Type: text/plain\r\n\r\nSee https://cafe.example/menu\r\n' >"$camp/u1.eml"
printf 'From: HR <hr@example.org>\r\nSubject: Holiday calendar published\r\nContent-Type: text/plain\r\n\r\nSee https://intranet.example.org/holidays\r\n' >"$camp/u2.eml"
printf 'From: Shop <news@shop.example>\r\nSubject: Autumn sale starts today\r\nContent-Type: text/plain\r\n\r\nSee https://shop.example/sale\r\n' >"$camp/u3.eml"
for f in "$camp"/*.eml; do result "$(post "$f")" >/dev/null; done
campaigns() { curl -sf "$BASE/v1/campaigns?since=1h&min_verdict=clean"; }
got=$(campaigns) || fail "GET /v1/campaigns"
[ "$(jq '[.campaigns[] | .size]' <<<"$got" | tr -d ' \n')" = "[5]" ] ||
	fail "want exactly one campaign of size 5, got $(jq -c '[.campaigns[] | {size, indicators}]' <<<"$got")"
first=$(jq -r '.campaigns[0].id' <<<"$got")
post "$camp/phish3.eml" >/dev/null # redelivered: same scan, no new indicator rows
again=$(campaigns)
[ "$(jq -c '[.campaigns[] | {id, size}]' <<<"$again")" = "[{\"id\":\"$first\",\"size\":5}]" ] ||
	fail "after re-posting: $(jq -c '[.campaigns[] | {id, size}]' <<<"$again")"
rm -rf "$camp"
echo "ok one campaign $first of 5: $(jq -c '[.campaigns[0].indicators[] | "\(.kind)=\(.value)"]' <<<"$again")"

step "phishing and clean samples are analysed by the worker"
phish=$(post testdata/phish_lookalike.eml)
expect "$phish" done malicious
expect "$(post testdata/clean_newsletter.eml)" done clean

step "a link hidden in a QR code image is decoded and checked"
body=$(result "$(post testdata/qr_phish.eml)")
jq -e '.report.verdict == "suspicious" and ([.report.signals[].id] | index("qr_code_link") and index("lookalike_link"))' <<<"$body" >/dev/null ||
	fail "qr_phish: $(jq -c '{verdict: .report.verdict, signals: [.report.signals[].id]}' <<<"$body")"
echo "ok $(jq -c '{verdict: .report.verdict, signals: [.report.signals[].id]}' <<<"$body")"

step "resubmitting the same message returns the same scan"
[ "$(post testdata/phish_lookalike.eml)" = "$phish" ] || fail "idempotency: new id for the same message"
echo ok

step "an unparseable message fails without retries"
garbage=$(mktemp)
printf 'this is not an email' >"$garbage"
expect "$(post "$garbage")" failed
rm -f "$garbage"

step "a scan queued while the worker is down survives a Redis restart"
docker compose stop worker >/dev/null
docker compose logs worker | grep -q '"msg":"worker stopped"' || fail "worker did not shut down gracefully"
queued=$(post testdata/malware_attachment.eml)
[ "$(curl -sf "$BASE$queued" | jq -r .status)" = queued ] || fail "scan processed with no worker running"
docker compose restart redis >/dev/null
wait_ready
docker compose start worker >/dev/null
expect "$queued" done malicious

step "a full Redis refuses new scans with 503 + Retry-After"
docker compose exec -T redis redis-cli CONFIG SET maxmemory 1 >/dev/null
hdr=$(mktemp)
code=$(printf 'Subject: full\r\n\r\nno room\r\n' |
	curl -s -o /dev/null -D "$hdr" -w '%{http_code}' --data-binary @- "$BASE/v1/scans")
docker compose exec -T redis redis-cli CONFIG SET maxmemory 64mb >/dev/null
[ "$code" = 503 ] || fail "POST with Redis full: status $code, want 503"
grep -qi '^retry-after:' "$hdr" || fail "503 without Retry-After"
rm -f "$hdr"
echo ok

step "results are persisted in MariaDB and outlive Redis"
docker compose exec -T redis redis-cli FLUSHALL >/dev/null
body=$(curl -sf "$BASE$phish") || fail "GET $phish after Redis flush"
jq -e '.status == "done" and .report.verdict == "malicious" and .received_at != null and .scanned_at != null' <<<"$body" >/dev/null ||
	fail "after Redis flush: $(jq -c '{status, verdict: .report.verdict, received_at}' <<<"$body")"
# The password is read inside the container, where compose put the real one
# (a .env may override the dev default).
sigs=$(docker compose exec -T mariadb sh -c 'mariadb -N -uinspekt -p"$MARIADB_PASSWORD" inspekt -e "$0"' \
	"SELECT COUNT(*) FROM signals WHERE scan_id = '${phish##*/}'") || fail "could not query MariaDB"
[ "$sigs" -ge 5 ] || fail "signals rows for the phish: $sigs"
echo "ok served from MariaDB, $sigs signal rows"

step "metrics"
metrics=$(curl -sf "$BASE/metrics")
grep -E '^inspekt_queue_(lag|pending|dead_letters)' <<<"$metrics"
grep -q '^inspekt_queue_pending 0$' <<<"$metrics" || fail "entries left pending"
grep -q '^inspekt_queue_dead_letters 0$' <<<"$metrics" || fail "unexpected dead letters"

echo "E2E PASSED"
