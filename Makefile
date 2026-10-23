.PHONY: test race fuzz lint build run worker scan e2e eval eval-sample clean

test:        ; go test ./... && python3 -m unittest discover -s eval
race:        ; go test -race ./...
fuzz:        ; go test ./internal/email -run='^$$' -fuzz=FuzzParse -fuzztime=60s
lint:        ; go vet ./... && test -z "$$(gofmt -l .)"
build:       ; go build -o bin/ ./cmd/...
run:         ; go run ./cmd/inspekt-api
worker:      ; go run ./cmd/inspekt-worker
scan:        ; go run ./cmd/inspekt scan testdata/*.eml
e2e:         ; docker compose up -d --build && ./scripts/e2e.sh; s=$$?; [ $$s -eq 0 ] || docker compose logs --tail 50; docker compose down -v; exit $$s
eval-sample: ; python3 eval/evaluate.py --labels testdata/labels.csv --min-recall 0.6 --max-fpr 0 --max-parse-errors 0
eval:        ; python3 eval/evaluate.py --ham data/ham --phish data/phish --out eval/report
clean:       ; rm -rf bin eval/report.*
