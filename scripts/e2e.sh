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

step "phishing and clean samples are analysed by the worker"
phish=$(post testdata/phish_lookalike.eml)
expect "$phish" done malicious
expect "$(post testdata/clean_newsletter.eml)" done clean

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

step "metrics"
metrics=$(curl -sf "$BASE/metrics")
grep -E '^inspekt_queue_(lag|pending|dead_letters)' <<<"$metrics"
grep -q '^inspekt_queue_pending 0$' <<<"$metrics" || fail "entries left pending"
grep -q '^inspekt_queue_dead_letters 0$' <<<"$metrics" || fail "unexpected dead letters"

echo "E2E PASSED"
