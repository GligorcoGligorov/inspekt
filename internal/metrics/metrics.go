// Package metrics defines Inspekt's Prometheus metrics in one place, so the
// API, the worker and the Grafana dashboard (deploy/grafana/inspekt.json)
// agree on names. Everything is registered on the default registry, which
// also carries the Go runtime and process metrics (memory, goroutines).
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
)

var (
	// Analysis, recorded wherever a message is analysed: the worker in
	// async mode, the API in inline mode.
	Scans = promauto.NewCounter(prometheus.CounterOpts{
		Name: "inspekt_scans_total", Help: "Messages analysed."})
	Verdicts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "inspekt_verdicts_total", Help: "Messages analysed, by verdict."}, []string{"verdict"})
	ScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "inspekt_scan_duration_seconds", Help: "Time to parse and analyse one message.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14)}) // 0.1 ms .. ~0.8 s
	CheckDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "inspekt_check_duration_seconds", Help: "Time spent in each check (and QR decoding) per message.",
		Buckets: prometheus.ExponentialBuckets(0.00001, 4, 10)}, []string{"check"}) // 10 µs .. ~2.6 s
	Signals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "inspekt_signals_total", Help: "Signals fired, by id."}, []string{"signal"})

	// Pipeline (worker).
	QueueWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "inspekt_queue_wait_seconds", Help: "From API acceptance to the result being saved.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 14)}) // 5 ms .. ~41 s
	Outcomes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "inspekt_worker_outcomes_total",
		Help: "Worker results per delivery: done, failed (permanent), retry (transient error), dead (dead-lettered)."},
		[]string{"outcome"})

	// API.
	ScanFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "inspekt_scan_failures_total", Help: "Requests rejected by the API (bad input, too large, queue unavailable)."})
	Enqueued = promauto.NewCounter(prometheus.CounterOpts{
		Name: "inspekt_scans_enqueued_total", Help: "Messages accepted into the queue (including resubmissions)."})
)

// Handler serves the default registry. ContinueOnError matters: with the
// default setting one failing collector (Redis down) turns the whole page
// into a 500, hiding every other metric exactly when they are needed.
func Handler() http.Handler { return handlerFor(prometheus.DefaultGatherer) }

func handlerFor(g prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(g, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

// ObserveReport records one finished analysis.
func ObserveReport(rep *analyze.Report, took time.Duration) {
	Scans.Inc()
	Verdicts.WithLabelValues(string(rep.Verdict)).Inc()
	ScanDuration.Observe(took.Seconds())
	for check, ms := range rep.DurationsMS {
		CheckDuration.WithLabelValues(check).Observe(ms / 1000)
	}
	for _, s := range rep.Signals {
		Signals.WithLabelValues(s.ID).Inc()
	}
}

// ObserveOutcome is the queue.Worker Observe hook.
func ObserveOutcome(outcome string) { Outcomes.WithLabelValues(outcome).Inc() }

// Every verdict and outcome series exists from the start (at 0), so rates
// and dashboards work before the first event of each kind.
func init() {
	for _, v := range []analyze.Verdict{analyze.VerdictClean, analyze.VerdictSuspicious, analyze.VerdictMalicious} {
		Verdicts.WithLabelValues(string(v))
	}
	for _, o := range []string{"done", "failed", "retry", "dead"} {
		Outcomes.WithLabelValues(o)
	}
}

// QueueCollector reports queue depth read from Redis at scrape time, so the
// numbers are right however many API or worker processes exist.
type QueueCollector struct{ Q *queue.Queue }

var (
	lagDesc     = prometheus.NewDesc("inspekt_queue_lag", "Queued scans not yet delivered to a worker.", nil, nil)
	pendingDesc = prometheus.NewDesc("inspekt_queue_pending", "Scans delivered to a worker and not yet acknowledged.", nil, nil)
	deadDesc    = prometheus.NewDesc("inspekt_queue_dead_letters", "Entries in the dead-letter stream.", nil, nil)
)

func (c QueueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lagDesc
	ch <- pendingDesc
	ch <- deadDesc
}

func (c QueueCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := c.Q.Stats(ctx)
	if err != nil {
		// Report nothing rather than zeros: "no data" on the dashboard is
		// honest, a 0 backlog during a Redis outage is not.
		ch <- prometheus.NewInvalidMetric(lagDesc, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(lagDesc, prometheus.GaugeValue, float64(st.Lag))
	ch <- prometheus.MustNewConstMetric(pendingDesc, prometheus.GaugeValue, float64(st.Pending))
	ch <- prometheus.MustNewConstMetric(deadDesc, prometheus.GaugeValue, float64(st.Dead))
}
