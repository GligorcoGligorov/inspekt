package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/metrics"
	"github.com/GligorcoGligorov/inspekt/internal/pipeline"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
	"github.com/GligorcoGligorov/inspekt/internal/store"
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
	// Metrics are process-wide, so assert on the change, not the value.
	before := testutil.ToFloat64(metrics.Verdicts.WithLabelValues("malicious"))

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

	if got := testutil.ToFloat64(metrics.Verdicts.WithLabelValues("malicious")) - before; got != 1 {
		t.Fatalf("malicious verdicts went up by %v, want 1", got)
	}
	m, _ := http.Get(ts.URL + "/metrics")
	b, _ := io.ReadAll(m.Body)
	for _, want := range []string{`inspekt_verdicts_total{verdict="malicious"}`, `inspekt_check_duration_seconds_bucket{check="lookalike"`, "go_goroutines"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("/metrics missing %q", want)
		}
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

// asyncStack is the production wiring in one process: the API queues into
// (in-memory) Redis, a real worker runs the real engine and saves to an
// in-memory Store, and the API reads results back from that Store.
func asyncStack(t *testing.T) (*httptest.Server, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	q := &queue.Queue{R: rdb}
	eng := analyze.New(analyze.DefaultConfig)
	lim := email.Limits{MaxBytes: 64 << 10, MaxParts: 50, MaxDepth: 5}

	st := &store.Memory{}
	w := &queue.Worker{Q: q, Name: "t", Concurrency: 2, Block: 20 * time.Millisecond,
		Handle: pipeline.Handler(eng, lim, st), Observe: metrics.ObserveOutcome}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	s := &Server{Engine: eng, Limits: lim, Queue: q, Store: st, Log: slog.New(slog.DiscardHandler)}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, mr
}

func postFile(t *testing.T, url, file string) *http.Response {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(url+"/v1/scans", "message/rfc822", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// scanBody is the GET /v1/scans/{id} response.
type scanBody struct {
	Status     queue.Status    `json:"status"`
	Error      string          `json:"error"`
	ReceivedAt *time.Time      `json:"received_at"`
	ScannedAt  *time.Time      `json:"scanned_at"`
	Report     json.RawMessage `json:"report"`
}

func pollScan(t *testing.T, base, location string) scanBody {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		res, err := http.Get(base + location)
		if err != nil {
			t.Fatal(err)
		}
		var s scanBody
		err = json.NewDecoder(res.Body).Decode(&s)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != queue.StatusQueued {
			return s
		}
	}
	t.Fatalf("%s still queued", location)
	return scanBody{}
}

func TestAsyncScan(t *testing.T) {
	ts, _ := asyncStack(t)
	enqueued := testutil.ToFloat64(metrics.Enqueued)
	done := testutil.ToFloat64(metrics.Outcomes.WithLabelValues("done"))
	waits := histogramCount(t, "inspekt_queue_wait_seconds")

	res := postFile(t, ts.URL, "phish_lookalike.eml")
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusAccepted || !strings.HasPrefix(loc, "/v1/scans/") {
		t.Fatalf("status %d, Location %q", res.StatusCode, loc)
	}
	s := pollScan(t, ts.URL, loc)
	var rep analyze.Report
	if err := json.Unmarshal(s.Report, &rep); err != nil || s.Status != queue.StatusDone {
		t.Fatalf("scan %+v (%v)", s, err)
	}
	if rep.Verdict != analyze.VerdictMalicious {
		t.Fatalf("verdict %s", rep.Verdict)
	}
	if s.ReceivedAt == nil || s.ScannedAt == nil || s.ScannedAt.Before(*s.ReceivedAt) {
		t.Fatalf("result not served from the store: received %v, scanned %v", s.ReceivedAt, s.ScannedAt)
	}

	// Same message again: same id, reported as already done.
	again := postFile(t, ts.URL, "phish_lookalike.eml")
	var body map[string]string
	json.NewDecoder(again.Body).Decode(&body)
	if again.Header.Get("Location") != loc || body["status"] != "done" {
		t.Fatalf("resubmit: Location %q, body %v", again.Header.Get("Location"), body)
	}

	if d := testutil.ToFloat64(metrics.Enqueued) - enqueued; d != 2 {
		t.Errorf("enqueued went up by %v, want 2", d)
	}
	// The result is readable once saved; the worker counts "done" just
	// after, when it has acknowledged the entry.
	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(metrics.Outcomes.WithLabelValues("done"))-done < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d := testutil.ToFloat64(metrics.Outcomes.WithLabelValues("done")) - done; d != 1 {
		t.Errorf("done outcomes went up by %v, want 1 (the resubmit is not re-analysed)", d)
	}
	if d := histogramCount(t, "inspekt_queue_wait_seconds") - waits; d != 1 {
		t.Errorf("queue wait observed %d times, want 1", d)
	}
}

// histogramCount is the number of observations in a histogram on the
// default registry.
func histogramCount(t *testing.T, name string) uint64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetHistogram().GetSampleCount()
		}
	}
	t.Fatalf("histogram %s not registered", name)
	return 0
}

func TestAsyncUnparseableFails(t *testing.T) {
	ts, _ := asyncStack(t)
	res, err := http.Post(ts.URL+"/v1/scans", "message/rfc822", strings.NewReader("this is not an email"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if s := pollScan(t, ts.URL, res.Header.Get("Location")); s.Status != queue.StatusFailed || s.Error == "" {
		t.Fatalf("got %+v", s)
	}
}

func TestAsyncErrors(t *testing.T) {
	ts, mr := asyncStack(t)
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/v1/scans/not-an-id", "", http.StatusBadRequest},
		{"GET", "/v1/scans/" + strings.Repeat("ab", 32), "", http.StatusNotFound},
		{"POST", "/v1/scans", "", http.StatusBadRequest},
		{"POST", "/v1/scans", "Subject: x\r\n\r\n" + strings.Repeat("a", 70<<10), http.StatusRequestEntityTooLarge},
		{"GET", "/readyz", "", http.StatusOK},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, strings.NewReader(c.body))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != c.want {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, res.StatusCode, c.want)
		}
	}

	// Redis gone: not ready, and POST answers 503 (after go-redis retries) instead of hanging.
	mr.Close()
	for _, c := range []struct{ method, path string }{{"GET", "/readyz"}, {"POST", "/v1/scans"}} {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, strings.NewReader("Subject: x\r\n\r\nhi"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("redis down, %s %s: status %d, want 503", c.method, c.path, res.StatusCode)
		}
	}
}
