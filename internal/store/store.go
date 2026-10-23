// Package store persists scan results beyond Redis's 24-hour window. The
// API and the worker depend only on the Store interface; MariaDB is the
// production implementation and Memory serves tests.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
)

// ErrNotFound means no result is stored for that id.
var ErrNotFound = errors.New("store: scan not found")

// Store saves and loads scan results. Save must be idempotent: with
// at-least-once delivery the same scan can be saved more than once.
type Store interface {
	Save(ctx context.Context, s Scan) error
	Get(ctx context.Context, id string) (*Record, error)
	Ping(ctx context.Context) error
}

// Scan is one finished analysis to save.
type Scan struct {
	ID         string // SHA-256 of the raw message
	ReceivedAt time.Time
	ScannedAt  time.Time
	Report     *analyze.Report
}

// Record is a stored result, shaped for the API.
type Record struct {
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	ScannedAt  time.Time       `json:"scanned_at"`
	Verdict    analyze.Verdict `json:"verdict"`
	Score      int             `json:"score"`
	Engine     string          `json:"engine"`
	Report     json.RawMessage `json:"report"`
}

func (s Scan) record() (*Record, error) {
	rep, err := json.Marshal(s.Report)
	if err != nil {
		return nil, err
	}
	return &Record{
		ID: s.ID, ReceivedAt: s.ReceivedAt.UTC().Truncate(time.Millisecond),
		ScannedAt: s.ScannedAt.UTC().Truncate(time.Millisecond),
		Verdict:   s.Report.Verdict, Score: s.Report.Score, Engine: s.Report.Engine, Report: rep,
	}, nil
}

// Memory is an in-process Store for tests.
type Memory struct {
	mu   sync.Mutex
	recs map[string]*Record
}

func (m *Memory) Save(_ context.Context, s Scan) error {
	r, err := s.record()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recs == nil {
		m.recs = map[string]*Record{}
	}
	if old, ok := m.recs[s.ID]; ok {
		r.ReceivedAt = old.ReceivedAt // first acceptance wins, as in MariaDB
	}
	m.recs[s.ID] = r
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *Memory) Ping(context.Context) error { return nil }
