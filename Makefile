.PHONY: test test-db race fuzz lint bench load build run worker scan e2e corpora eval eval-subset eval-sample eval-bec clean

test:        ; go test ./... && python3 -m unittest discover -s eval
test-db:     ; ./scripts/test-db.sh
race:        ; go test -race ./...
fuzz:        ; go test ./internal/email -run='^$$' -fuzz=FuzzParse -fuzztime=60s
bench:       ; go test -run='^$$' -bench=. -benchtime=2s ./internal/analyze
load:        ; go run ./cmd/inspekt-load -n 5000 -c 32   # needs `docker compose up -d`
lint:        ; go vet ./... && test -z "$$(gofmt -l .)"
build:       ; go build -o bin/ ./cmd/...
run:         ; go run ./cmd/inspekt-api
worker:      ; go run ./cmd/inspekt-worker
scan:        ; go run ./cmd/inspekt scan testdata/*.eml
e2e:         ; docker compose up -d --build && ./scripts/e2e.sh; s=$$?; [ $$s -eq 0 ] || docker compose logs --tail 50; docker compose down -v; exit $$s
# BEC grey-zone set: rules only by default; with INSPEKT_LLM_* set, rules + LLM.
eval-bec:    ; python3 eval/evaluate.py --labels testdata/bec/labels.csv --max-fpr 0 --max-parse-errors 0 --out eval/out/bec
eval-sample: ; python3 eval/evaluate.py --labels testdata/labels.csv --min-recall 0.8 --max-fpr 0 --max-parse-errors 0
corpora:     ; ./eval/fetch_corpora.sh
eval:        corpora ; python3 eval/evaluate.py --ham data/ham --phish data/phish --out eval/report && python3 eval/explain.py eval/report.json
# Gate on a fixed holdout subset of the public corpora; numbers in docs/EVAL.md.
eval-subset: corpora ; python3 eval/make_subset.py data/ > data/subset.csv && python3 eval/evaluate.py --labels data/subset.csv --min-recall 0.39 --max-fpr 0.01 --max-parse-errors 0 --out eval/out/subset
clean:       ; rm -rf bin eval/report.*
