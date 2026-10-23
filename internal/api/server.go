// Package api exposes the scanner over HTTP.
//
// With a Queue configured, POST /v1/scans only stores and queues the
// message (202 Accepted) and workers analyse it; GET /v1/scans/{id} returns
// the result from the Store (MariaDB), or the queue state while it is
// still pending or if it failed. Without one (local development, tests), POST analyses
// synchronously and returns the report directly.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
	"github.com/GligorcoGligorov/inspekt/internal/store"
)

// Server holds dependencies for the HTTP handlers.
type Server struct {
	Engine *analyze.Engine
	Limits email.Limits
	Log    *slog.Logger
	// Queue, when set, switches POST /v1/scans to asynchronous mode.
	Queue *queue.Queue
	// Store, when set, is where finished results are read from.
	Store store.Store

	m metrics
}

// metrics are exported in Prometheus text format without a client library,
// to keep Step 0 dependency-free. Step 7 swaps in prometheus/client_golang
// with histograms.
type metrics struct {
	scans, failures, enqueued    atomic.Int64
	clean, suspicious, malicious atomic.Int64
	durationMicrosTotal          atomic.Int64
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.Queue != nil {
		mux.HandleFunc("POST /v1/scans", s.enqueue)
		mux.HandleFunc("GET /v1/scans/{id}", s.get)
	} else {
		mux.HandleFunc("POST /v1/scans", s.scan)
	}
	// Liveness: the process is up. Readiness: it can also reach Redis, so
	// a load balancer stops sending traffic it could not queue.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", s.ready)
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

func (s *Server) enqueue(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Limits.MaxBytes))
	var maxErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxErr):
		s.fail(w, http.StatusRequestEntityTooLarge, err)
		return
	case err != nil:
		s.fail(w, http.StatusBadRequest, err)
		return
	case len(raw) == 0:
		s.fail(w, http.StatusBadRequest, errors.New("empty body"))
		return
	}

	id, status, err := s.Queue.Enqueue(r.Context(), raw)
	switch {
	case errors.Is(err, queue.ErrFull):
		w.Header().Set("Retry-After", "30")
		s.fail(w, http.StatusServiceUnavailable, err)
		return
	case err != nil:
		s.Log.Error("enqueue", "err", err)
		s.fail(w, http.StatusServiceUnavailable, errors.New("queue unavailable"))
		return
	}
	s.m.enqueued.Add(1)
	s.Log.Info("enqueued", "id", id, "status", status, "bytes", len(raw))

	w.Header().Set("Location", "/v1/scans/"+id)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": string(status)})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !queue.ValidID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be 64 hex characters"})
		return
	}
	if s.Store != nil {
		rec, err := s.Store.Get(r.Context(), id)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, scanResponse{ID: id, Status: queue.StatusDone,
				ReceivedAt: &rec.ReceivedAt, ScannedAt: &rec.ScannedAt, Report: rec.Report})
			return
		case !errors.Is(err, store.ErrNotFound):
			s.Log.Error("store get", "id", id, "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store unavailable"})
			return
		}
	}
	scan, err := s.Queue.Get(r.Context(), id)
	switch {
	case errors.Is(err, queue.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such scan (unknown or expired)"})
	case err != nil:
		s.Log.Error("get scan", "id", id, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue unavailable"})
	default:
		writeJSON(w, http.StatusOK, scanResponse{ID: id, Status: scan.Status,
			Attempts: scan.Attempts, Error: scan.Error, Report: scan.Report})
	}
}

// scanResponse is the GET /v1/scans/{id} body, whichever store answered.
type scanResponse struct {
	ID         string          `json:"id"`
	Status     queue.Status    `json:"status"`
	Attempts   int             `json:"attempts,omitempty"`
	Error      string          `json:"error,omitempty"`
	ReceivedAt *time.Time      `json:"received_at,omitempty"`
	ScannedAt  *time.Time      `json:"scanned_at,omitempty"`
	Report     json.RawMessage `json:"report,omitempty"`
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.Queue != nil {
		if err := s.Queue.R.Ping(r.Context()).Err(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "redis: " + err.Error()})
			return
		}
	}
	if s.Store != nil {
		if err := s.Store.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store: " + err.Error()})
			return
		}
	}
	w.Write([]byte("ok\n"))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, code int, err error) {
	s.m.failures.Add(1)
	writeJSON(w, code, map[string]string{"error": err.Error()})
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

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE inspekt_scans_total counter\ninspekt_scans_total %d\n", s.m.scans.Load())
	fmt.Fprintf(w, "# TYPE inspekt_scan_failures_total counter\ninspekt_scan_failures_total %d\n", s.m.failures.Load())
	fmt.Fprintf(w, "# TYPE inspekt_verdicts_total counter\n")
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"clean\"} %d\n", s.m.clean.Load())
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"suspicious\"} %d\n", s.m.suspicious.Load())
	fmt.Fprintf(w, "inspekt_verdicts_total{verdict=\"malicious\"} %d\n", s.m.malicious.Load())
	fmt.Fprintf(w, "# TYPE inspekt_scan_duration_seconds_sum counter\ninspekt_scan_duration_seconds_sum %f\n",
		float64(s.m.durationMicrosTotal.Load())/1e6)
	if s.Queue == nil {
		return
	}
	fmt.Fprintf(w, "# TYPE inspekt_scans_enqueued_total counter\ninspekt_scans_enqueued_total %d\n", s.m.enqueued.Load())
	// Queue depth is read from Redis, so it is correct across API replicas.
	if st, err := s.Queue.Stats(r.Context()); err == nil {
		fmt.Fprintf(w, "# TYPE inspekt_queue_lag gauge\ninspekt_queue_lag %d\n", st.Lag)
		fmt.Fprintf(w, "# TYPE inspekt_queue_pending gauge\ninspekt_queue_pending %d\n", st.Pending)
		fmt.Fprintf(w, "# TYPE inspekt_queue_dead_letters gauge\ninspekt_queue_dead_letters %d\n", st.Dead)
	}
}
