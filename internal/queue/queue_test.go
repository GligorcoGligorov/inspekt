package queue

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newQueue(t *testing.T) (*Queue, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	r := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { r.Close() })
	return &Queue{R: r}, mr
}

// fastWorker uses short timings so retry and recovery paths run in
// milliseconds.
func fastWorker(q *Queue, h Handler) *Worker {
	return &Worker{
		Q: q, Handle: h, Name: "test", Concurrency: 2,
		ClaimIdle: 50 * time.Millisecond, ClaimEvery: 20 * time.Millisecond,
		Block: 20 * time.Millisecond,
	}
}

// start runs w in the background; the returned func stops it and waits.
func start(t *testing.T, w *Worker) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitStatus(t *testing.T, q *Queue, id string, want Status) *Scan {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s, err := q.Get(context.Background(), id)
		if err == nil && s.Status == want {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan %s: want status %s, last %+v (err %v)", id[:8], want, s, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func pending(t *testing.T, q *Queue) int64 {
	t.Helper()
	p, err := q.R.XPending(context.Background(), Stream, Group).Result()
	if err != nil {
		t.Fatal(err)
	}
	return p.Count
}

func echo(_ context.Context, raw []byte) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"len":%d}`, len(raw))), nil
}

func TestEnqueueIsIdempotent(t *testing.T) {
	q, _ := newQueue(t)
	ctx := context.Background()
	id1, st1, err := q.Enqueue(ctx, []byte("Subject: a\r\n\r\nbody"))
	if err != nil || st1 != StatusQueued {
		t.Fatalf("first enqueue: %s %v", st1, err)
	}
	id2, st2, err := q.Enqueue(ctx, []byte("Subject: a\r\n\r\nbody"))
	if err != nil || id2 != id1 || st2 != StatusQueued {
		t.Fatalf("second enqueue: id equal %v, status %s, err %v", id1 == id2, st2, err)
	}
	if n := q.R.XLen(ctx, Stream).Val(); n != 1 {
		t.Fatalf("stream has %d entries, want 1", n)
	}
	if !ValidID(id1) || ValidID("abc") || ValidID(id1[:63]+"z") {
		t.Fatal("ValidID")
	}
}

func TestWorkerStoresResultThenAcks(t *testing.T) {
	q, mr := newQueue(t)
	start(t, fastWorker(q, echo))
	id, _, err := q.Enqueue(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	s := waitStatus(t, q, id, StatusDone)
	if string(s.Report) != `{"len":5}` || s.Attempts != 1 {
		t.Fatalf("got %+v", s)
	}
	if pending(t, q) != 0 {
		t.Fatal("entry not acknowledged")
	}
	if mr.Exists(rawKey(id)) {
		t.Fatal("raw message kept after the scan finished")
	}
	if ttl := mr.TTL(scanKey(id)); ttl <= 0 {
		t.Fatalf("result has no TTL (%v)", ttl)
	}
	// Resubmitting a finished message returns its status, queues nothing.
	if _, st, _ := q.Enqueue(context.Background(), []byte("hello")); st != StatusDone {
		t.Fatalf("resubmit status %s", st)
	}
}

func TestTransientErrorStaysPendingThenRetries(t *testing.T) {
	q, _ := newQueue(t)
	var calls atomic.Int32
	start(t, fastWorker(q, func(ctx context.Context, raw []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("disk on fire")
		}
		return echo(ctx, raw)
	}))
	id, _, _ := q.Enqueue(context.Background(), []byte("retry me"))
	s := waitStatus(t, q, id, StatusDone)
	if s.Attempts != 2 {
		t.Fatalf("attempts %d, want 2 (one failure, one retry by the watchdog)", s.Attempts)
	}
}

// A worker that read an entry and died before acknowledging it must not
// lose the message: the watchdog reclaims it from the pending list.
func TestWatchdogReclaimsFromDeadConsumer(t *testing.T) {
	q, _ := newQueue(t)
	ctx := context.Background()
	if err := q.EnsureGroup(ctx); err != nil {
		t.Fatal(err)
	}
	id, _, _ := q.Enqueue(ctx, []byte("orphaned"))
	// "crashed" reads the entry and never acknowledges it.
	if err := q.R.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: Group, Consumer: "crashed", Streams: []string{Stream, ">"}, Count: 1,
	}).Err(); err != nil {
		t.Fatal(err)
	}
	start(t, fastWorker(q, echo))
	waitStatus(t, q, id, StatusDone)
	if pending(t, q) != 0 {
		t.Fatal("reclaimed entry not acknowledged")
	}
}

func TestPoisonMessageIsDeadLettered(t *testing.T) {
	q, mr := newQueue(t)
	var calls atomic.Int32
	start(t, fastWorker(q, func(context.Context, []byte) ([]byte, error) {
		calls.Add(1)
		panic("parser bug")
	}))
	id, _, _ := q.Enqueue(context.Background(), []byte("poison"))
	s := waitStatus(t, q, id, StatusFailed)
	if calls.Load() != 3 {
		t.Fatalf("handler ran %d times, want 3", calls.Load())
	}
	dead := q.R.XRange(context.Background(), DeadStream, "-", "+").Val()
	if len(dead) != 1 || dead[0].Values["id"] != id {
		t.Fatalf("dead-letter stream: %+v", dead)
	}
	if reason := dead[0].Values["reason"].(string); reason != s.Error || !strings.Contains(reason, "panic: parser bug") {
		t.Fatalf("reason %q, scan error %q", reason, s.Error)
	}
	if pending(t, q) != 0 || mr.Exists(rawKey(id)) {
		t.Fatal("dead-lettered entry still pending or raw kept")
	}
	// A failed scan may be resubmitted.
	if _, st, _ := q.Enqueue(context.Background(), []byte("poison")); st != StatusQueued {
		t.Fatalf("resubmit of failed scan: %s", st)
	}
}

func TestPermanentErrorFailsWithoutRetry(t *testing.T) {
	q, _ := newQueue(t)
	var calls atomic.Int32
	start(t, fastWorker(q, func(context.Context, []byte) ([]byte, error) {
		calls.Add(1)
		return nil, Permanent(errors.New("not an email"))
	}))
	id, _, _ := q.Enqueue(context.Background(), []byte("garbage"))
	s := waitStatus(t, q, id, StatusFailed)
	time.Sleep(150 * time.Millisecond) // longer than ClaimIdle: give a retry the chance to happen
	if calls.Load() != 1 || s.Error != "not an email" {
		t.Fatalf("calls %d, error %q", calls.Load(), s.Error)
	}
	if q.R.XLen(context.Background(), DeadStream).Val() != 0 {
		t.Fatal("permanent failure should not be dead-lettered")
	}
}

func TestMissingRawIsDeadLettered(t *testing.T) {
	q, mr := newQueue(t)
	id, _, _ := q.Enqueue(context.Background(), []byte("expires"))
	mr.Del(rawKey(id))
	start(t, fastWorker(q, echo))
	s := waitStatus(t, q, id, StatusFailed)
	if !strings.Contains(s.Error, "expired or missing") {
		t.Fatalf("error %q", s.Error)
	}
}

// On shutdown the worker stops reading but finishes and acknowledges the
// message it is already analysing.
func TestGracefulShutdownFinishesInFlight(t *testing.T) {
	q, _ := newQueue(t)
	started, release := make(chan struct{}), make(chan struct{})
	w := fastWorker(q, func(ctx context.Context, raw []byte) ([]byte, error) {
		close(started)
		<-release
		return echo(ctx, raw)
	})
	w.Concurrency = 1
	stop := start(t, w)
	id, _, _ := q.Enqueue(context.Background(), []byte("in flight"))
	<-started

	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Run returned while a message was still being analysed")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-stopped
	if s, _ := q.Get(context.Background(), id); s.Status != StatusDone || pending(t, q) != 0 {
		t.Fatalf("in-flight scan not finished: %+v", s)
	}
}

func TestStats(t *testing.T) {
	q, _ := newQueue(t)
	ctx := context.Background()
	q.Enqueue(ctx, []byte("a"))
	q.Enqueue(ctx, []byte("b"))
	if st, err := q.Stats(ctx); err != nil || st.Lag != 2 {
		t.Fatalf("before any worker: %+v %v", st, err)
	}
}

func TestClassifyOOM(t *testing.T) {
	err := classify(errors.New("OOM command not allowed when used memory > 'maxmemory'."))
	if !errors.Is(err, ErrFull) {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(classify(errors.New("EXECABORT Transaction discarded because of previous errors.")), ErrFull) {
		t.Fatal("EXECABORT after a refused write not mapped to ErrFull")
	}
	if other := errors.New("READONLY"); classify(other) != other {
		t.Fatal("non-OOM error changed")
	}
}
