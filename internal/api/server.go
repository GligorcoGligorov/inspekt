// Package api exposes the scanner over HTTP.
//
// Step 0 serves scans synchronously. Step 3 of the weekend plan puts a
// Redis Streams queue between POST /v1/scans and the workers; the handler
// signatures below already separate "accept" from "analyze" to make that
// change local.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// Server holds dependencies for the HTTP handlers.
type Server struct {
	Engine *analyze.Engine
	Limits email.Limits
	Log    *slog.Logger

	m metrics
}

// metrics are exported in Prometheus text format without a client library,
// to keep Step 0 dependency-free. Step 7 swaps in prometheus/client_golang
// with histograms.
type metrics struct {
	scans, failures              atomic.Int64
	clean, suspicious, malicious atomic.Int64
	durationMicrosTotal          atomic.Int64
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/scans", s.scan)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body := http.MaxBytesReader(w, r.Body, s.Limits.MaxBytes)
	msg, err := email.Parse(body, s.Limits)

	var maxErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxErr) || errors.Is(err, email.ErrTooLarge):
		s.fail(w, http.StatusRequestEntityTooLarge, err)
		return
	case msg == nil:
		s.fail(w, http.StatusBadRequest, err)
		return
	case err != nil:
		// Limits other than size (depth, parts): we still return a report,
		// the partial parse plus the warning is useful to the analyst.
		msg.Warnings = append(msg.Warnings, err.Error())
	}

	rep := s.Engine.Analyze(msg)
	s.count(rep.Verdict, time.Since(start))
	s.Log.Info("scan",
		"verdict", rep.Verdict, "score", rep.Score,
		"signals", len(rep.Signals), "ms", time.Since(start).Milliseconds())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

func (s *Server) fail(w http.ResponseWriter, code int, err error) {
	s.m.failures.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) count(v analyze.Verdict, d time.Duration) {
	s.m.scans.Add(1)
	s.m.durationMicrosTotal.Add(d.Microseconds())
	switch v {
	case analyze.VerdictClean:
		s.m.clean.Add(1)
	case analyze.VerdictSuspicious:
		s.m.suspicious.Add(1)
	case analyze.VerdictMalicious:
		s.m.malicious.Add(1)
	}
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE inspekt_scans_total counter\ninspekt_scans_total %d\n", s.m.scans.Load())
	fmt.Fprintf(w, "# TYPE inspekt_scan_failures_total counter\ninspekt_scan_failures_total %d\n", s.m.failures.Load())
	fmt.Fprintf(w, "# TYPE inspekt_verdicts_total counter\n")
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"clean\"} %d\n", s.m.clean.Load())
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"suspicious\"} %d\n", s.m.suspicious.Load())
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"malicious\"} %d\n", s.m.malicious.Load())
	fmt.Fprintf(w, "# TYPE inspekt_scan_duration_seconds_sum counter\ninspekt_scan_duration_seconds_sum %f\n",
		float64(s.m.durationMicrosTotal.Load())/1e6)
}
