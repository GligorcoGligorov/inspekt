#!/usr/bin/env bash
# Downloads the public evaluation corpora into data/ (gitignored) and turns
# them into one .eml file per message:
#
#   data/ham/{easy_ham,easy_ham_2,hard_ham}/   SpamAssassin public corpus
#   data/phish/phishing-YYYY/NNNNN.eml          Nazario phishing corpus
#
# Every download is checked against eval/corpora.sha256, so an evaluation
# always runs on exactly the same bytes. Some upstream files are still being
# updated; if one changes, this fails instead of silently moving the numbers.
# Sources and licences: docs/EVAL.md.
set -euo pipefail
cd "$(dirname "$0")/.."

SA=https://spamassassin.apache.org/old/publiccorpus
NAZARIO=https://monkey.org/~jose/phishing
HAM=(20030228_easy_ham 20030228_easy_ham_2 20030228_hard_ham)
PHISH_YEARS=(2019 2020 2021 2022 2023 2024 2025)

mkdir -p data/raw
fetch() { # fetch URL FILE
	[ -s "data/raw/$2" ] && return
	echo "downloading $2"
	curl -sfL --retry 3 --max-time 600 -o "data/raw/$2.part" "$1"
	mv "data/raw/$2.part" "data/raw/$2"
}
for h in "${HAM[@]}"; do fetch "$SA/$h.tar.bz2" "$h.tar.bz2"; done
for y in "${PHISH_YEARS[@]}"; do fetch "$NAZARIO/phishing-$y" "phishing-$y"; done

(cd data/raw && shasum -a 256 -c ../../eval/corpora.sha256 --quiet) || {
	echo "checksum mismatch: an upstream file changed; see docs/EVAL.md" >&2
	exit 1
}

rm -rf data/ham data/phish
mkdir -p data/ham data/phish
for h in "${HAM[@]}"; do
	tar -xjf "data/raw/$h.tar.bz2" -C data/ham
done
# Each SpamAssassin directory carries a "cmds" file that is not a message.
find data/ham -name cmds -delete
for y in "${PHISH_YEARS[@]}"; do
	python3 eval/split_mbox.py "data/raw/phishing-$y" "data/phish/phishing-$y"
done

echo "ham:   $(find data/ham -type f | wc -l | tr -d ' ') messages"
echo "phish: $(find data/phish -type f | wc -l | tr -d ' ') messages"
