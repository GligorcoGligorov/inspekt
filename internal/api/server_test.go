package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func newTestServer() *httptest.Server {
	s := &Server{
		Engine: analyze.New(analyze.DefaultConfig),
		Limits: email.Limits{MaxBytes: 64 << 10, MaxParts: 50, MaxDepth: 5},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return httptest.NewServer(s.Handler())
}

func TestScanEndpoint(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	raw, err := os.ReadFile("../../testdata/phish_lookalike.eml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(ts.URL+"/v1/scans", "message/rfc822", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var rep analyze.Report
	if err := json.NewDecoder(res.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != analyze.VerdictMalicious {
		t.Fatalf("verdict %s", rep.Verdict)
	}

	m, _ := http.Get(ts.URL + "/metrics")
	b, _ := io.ReadAll(m.Body)
	if !strings.Contains(string(b), `inspekt_verdicts_total{verdict="malicious"} 1`) {
		t.Fatalf("metrics not updated:\n%s", b)
	}
}

func TestScanRejectsOversized(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	body := "Subject: x\r\n\r\n" + strings.Repeat("a", 70<<10)
	res, err := http.Post(ts.URL+"/v1/scans", "message/rfc822", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", res.StatusCode)
	}
}
