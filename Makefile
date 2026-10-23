.PHONY: test race fuzz lint build run eval eval-sample clean

test:        ; go test ./... && python3 -m unittest discover -s eval
race:        ; go test -race ./...
fuzz:        ; go test ./internal/email -run='^$$' -fuzz=FuzzParse -fuzztime=60s
lint:        ; go vet ./... && test -z "$$(gofmt -l .)"
build:       ; go build -o bin/inspekt ./cmd/inspekt && go build -o bin/inspekt-api ./cmd/inspekt-api
run:         ; go run ./cmd/inspekt-api
scan:        ; go run ./cmd/inspekt scan testdata/*.eml
eval-sample: ; python3 eval/evaluate.py --labels testdata/labels.csv --min-recall 0.6 --max-fpr 0
eval:        ; python3 eval/evaluate.py --ham data/ham --phish data/phish --out eval/report
clean:       ; rm -rf bin eval/report.*
