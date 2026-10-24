package metrics

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
)

func scrape(t *testing.T, reg *prometheus.Registry) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	handlerFor(reg).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(b)
}

func TestQueueCollector(t *testing.T) {
	mr := miniredis.RunT(t)
	q := &queue.Queue{R: redis.NewClient(&redis.Options{Addr: mr.Addr()})}
	q.Enqueue(context.Background(), []byte("a"))
	q.Enqueue(context.Background(), []byte("b"))

	reg := prometheus.NewRegistry()
	reg.MustRegister(QueueCollector{Q: q})
	other := prometheus.NewCounter(prometheus.CounterOpts{Name: "other_total", Help: "x"})
	reg.MustRegister(other)

	code, body := scrape(t, reg)
	for _, want := range []string{"inspekt_queue_lag 2", "inspekt_queue_pending 0", "inspekt_queue_dead_letters 0"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("status %d, missing %q in:\n%s", code, want, body)
		}
	}

	// Redis down: the queue gauges disappear, everything else is still served.
	mr.Close()
	code, body = scrape(t, reg)
	if code != 200 || !strings.Contains(body, "other_total 0") || strings.Contains(body, "inspekt_queue_lag") {
		t.Fatalf("Redis down: status %d, body:\n%s", code, body)
	}
}

// Every inspekt_* metric the Grafana dashboard queries must exist in code;
// a renamed metric would otherwise blank a panel without anyone noticing.
func TestDashboardUsesDefinedMetrics(t *testing.T) {
	defined := map[string]bool{}
	ch := make(chan *prometheus.Desc, 64)
	for _, c := range []prometheus.Collector{Scans, Verdicts, ScanDuration, CheckDuration, Signals,
		QueueWait, Outcomes, ScanFailures, Enqueued, LLMCalls, LLMDuration, QueueCollector{}} {
		c.Describe(ch)
	}
	close(ch)
	fqName := regexp.MustCompile(`fqName: "([^"]+)"`)
	for d := range ch {
		defined[fqName.FindStringSubmatch(d.String())[1]] = true
	}

	raw, err := os.ReadFile("../../deploy/grafana/inspekt.json")
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		Panels []struct {
			Title   string
			Targets []struct{ Expr string }
		}
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatal(err)
	}
	name := regexp.MustCompile(`inspekt_[a-z_]+`)
	used := 0
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			for _, m := range name.FindAllString(tg.Expr, -1) {
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(m, "_bucket"), "_sum"), "_count")
				if !defined[base] {
					t.Errorf("panel %q queries %s, which no code defines", p.Title, m)
				}
				used++
			}
		}
	}
	if used == 0 {
		t.Fatal("dashboard queries no inspekt metrics")
	}
}

// Every known signal has a series at 0 from startup, so its first firing
// shows up in increase() (Grafana's "Top signals" read 0 for signals that
// had fired only once).
func TestSignalSeriesStartAtZero(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, mf := range mfs {
		if mf.GetName() != "inspekt_signals_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "signal" {
					have[l.GetValue()] = true
				}
			}
		}
	}
	for _, id := range analyze.SignalIDs {
		if !have[id] {
			t.Errorf("no inspekt_signals_total series for %q at startup", id)
		}
	}
}
