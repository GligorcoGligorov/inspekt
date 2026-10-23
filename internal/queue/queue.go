// Package queue moves scans through a Redis Stream so the API can accept
// mail faster than it is analysed, and no accepted message is lost when a
// worker crashes.
//
//	POST /v1/scans ─► Enqueue ─► stream "scans" ─► Worker (consumer group)
//	                                                 │ analyse, store, XACK
//	GET /v1/scans/{id} ◄─ Get ◄─ hash scan:{id} ◄────┘
//
// Keys, all expiring after TTL (24 h):
//
//	scan:{id}      hash: status, attempts, received_at, last_error, error,
//	               and report when no Store keeps results
//	scan:raw:{id}  the raw message, deleted once the scan finishes
//
// The id is the SHA-256 of the raw message, which makes submission
// idempotent: the same message posted twice is scanned once.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	Stream     = "scans"
	Group      = "workers"
	DeadStream = "scans:dead"
)

// Status of a scan.
type Status string

const (
	StatusQueued Status = "queued"
	StatusDone   Status = "done"
	StatusFailed Status = "failed"
)

var (
	// ErrNotFound means no scan with that id exists (or it expired).
	ErrNotFound = errors.New("queue: scan not found")
	// ErrFull means Redis refused the write because it hit maxmemory.
	// The API turns this into 503 so clients back off and retry.
	ErrFull = errors.New("queue: redis is out of memory")
)

// Queue is the producer side and the read model.
type Queue struct {
	R *redis.Client
	// TTL bounds how long raw messages and results are kept. Zero means 24 h.
	TTL time.Duration
	// MaxLen caps the stream length (approximate trimming). Zero means 10000.
	MaxLen int64
}

// Scan is the stored state of one submission.
type Scan struct {
	ID       string          `json:"id"`
	Status   Status          `json:"status"`
	Attempts int             `json:"attempts,omitempty"`
	Error    string          `json:"error,omitempty"`
	Report   json.RawMessage `json:"report,omitempty"`
}

// ID is the scan id for a raw message.
func ID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ValidID reports whether s looks like an id returned by ID.
func ValidID(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func scanKey(id string) string { return "scan:" + id }
func rawKey(id string) string  { return "scan:raw:" + id }

func (q *Queue) ttl() time.Duration {
	if q.TTL == 0 {
		return 24 * time.Hour
	}
	return q.TTL
}

func (q *Queue) maxLen() int64 {
	if q.MaxLen == 0 {
		return 10000
	}
	return q.MaxLen
}

// Enqueue stores raw and queues it for analysis. If the same message was
// already submitted, nothing is queued and its current status is returned;
// a scan that failed may be resubmitted.
//
// The check-and-insert is an optimistic transaction (WATCH + MULTI/EXEC):
// two API replicas receiving the same message cannot both queue it, and a
// crash cannot leave a scan marked "queued" with nothing in the stream.
//
// Plain commands inside MULTI, rather than a Lua script, on purpose: Redis
// checks maxmemory for each queued write and aborts the whole transaction
// when memory is full. Redis 7 does not do that check for an EVAL script
// without flags, which let enqueues write far past maxmemory.
func (q *Queue) Enqueue(ctx context.Context, raw []byte) (string, Status, error) {
	id := ID(raw)
	key := scanKey(id)
	status := StatusQueued
	txf := func(tx *redis.Tx) error {
		cur, err := tx.HGet(ctx, key, "status").Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}
		if cur != "" && Status(cur) != StatusFailed {
			status = Status(cur)
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.Del(ctx, key)
			p.HSet(ctx, key, "status", string(StatusQueued), "attempts", 0,
				"received_at", time.Now().UnixMilli())
			p.PExpire(ctx, key, q.ttl())
			p.Set(ctx, rawKey(id), raw, q.ttl())
			p.XAdd(ctx, &redis.XAddArgs{Stream: Stream, MaxLen: q.maxLen(), Approx: true,
				Values: map[string]any{"id": id}})
			return nil
		})
		return err
	}
	// A concurrent submit of the same message changed the key: re-read once.
	for range 2 {
		status = StatusQueued
		err := q.R.Watch(ctx, txf, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return id, "", classify(err)
		}
		return id, status, nil
	}
	return id, "", errors.New("queue: enqueue contended, retry")
}

// Get returns the stored state of scan id.
func (q *Queue) Get(ctx context.Context, id string) (*Scan, error) {
	h, err := q.R.HGetAll(ctx, scanKey(id)).Result()
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, ErrNotFound
	}
	s := &Scan{ID: id, Status: Status(h["status"]), Error: h["error"]}
	s.Attempts, _ = strconv.Atoi(h["attempts"])
	if r := h["report"]; r != "" {
		s.Report = json.RawMessage(r)
	}
	return s, nil
}

// Stats describe the queue for /metrics.
type Stats struct {
	Lag     int64 // entries not yet delivered to any worker
	Pending int64 // delivered but not acknowledged (in progress or stuck)
	Dead    int64 // entries in the dead-letter stream
}

// Stats reads queue depth. Before the first worker starts the consumer
// group does not exist, so everything in the stream counts as lag.
func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	dead, err := q.R.XLen(ctx, DeadStream).Result()
	if err != nil {
		return st, err
	}
	st.Dead = dead
	groups, err := q.R.XInfoGroups(ctx, Stream).Result()
	if err != nil && !isNoSuchKey(err) {
		return st, err
	}
	for _, g := range groups {
		if g.Name == Group {
			st.Lag, st.Pending = g.Lag, g.Pending
			return st, nil
		}
	}
	st.Lag, err = q.R.XLen(ctx, Stream).Result()
	return st, err
}

// classify maps Redis errors callers must handle differently. A write
// refused inside MULTI surfaces as OOM or as the EXECABORT that follows it.
func classify(err error) error {
	if err != nil && (strings.Contains(err.Error(), "OOM command not allowed") ||
		strings.Contains(err.Error(), "EXECABORT")) {
		return ErrFull
	}
	return err
}

func isNoSuchKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such key")
}
