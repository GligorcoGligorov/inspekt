package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Job is one queued scan handed to a Handler.
type Job struct {
	ID         string
	Raw        []byte
	ReceivedAt time.Time // when the API accepted it
}

// Handler analyses one job. A non-nil result is kept in Redis as the
// report; a Handler that persists results elsewhere returns nil.
type Handler func(ctx context.Context, job Job) ([]byte, error)

// Permanent marks an error that retrying cannot fix, such as a message that
// cannot be parsed. The scan fails at once instead of being retried.
func Permanent(err error) error { return permanentError{err} }

type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

// Worker consumes the stream with Concurrency goroutines, each its own
// consumer in the group, plus one watchdog goroutine.
//
// Delivery is at-least-once: a message is acknowledged only in the same
// transaction that stores its result. If the process dies before that, the
// entry stays in the group's pending list and the watchdog hands it to a
// live worker after ClaimIdle. Every attempt is counted; after MaxAttempts
// the entry goes to the dead-letter stream with the reason, so one poison
// message cannot loop forever.
type Worker struct {
	Q      *Queue
	Handle Handler
	Log    *slog.Logger

	Name        string        // consumer-name prefix, unique per process (e.g. hostname)
	Concurrency int           // goroutines reading the stream; default 4
	MaxAttempts int           // deliveries before dead-lettering; default 3
	ClaimIdle   time.Duration // pending this long = worker presumed dead; default 60 s
	ClaimEvery  time.Duration // watchdog interval; default 30 s
	Block       time.Duration // XREADGROUP block time; default 5 s
	JobTimeout  time.Duration // bound on one message, also during shutdown; default 30 s

	// Observe, if set, is told the outcome of every delivery: "done",
	// "failed" (permanent), "retry" (transient error) or "dead".
	Observe func(outcome string)
}

func (w *Worker) observe(outcome string) {
	if w.Observe != nil {
		w.Observe(outcome)
	}
}

func (w *Worker) defaults() {
	if w.Concurrency == 0 {
		w.Concurrency = 4
	}
	if w.MaxAttempts == 0 {
		w.MaxAttempts = 3
	}
	if w.ClaimIdle == 0 {
		w.ClaimIdle = 60 * time.Second
	}
	if w.ClaimEvery == 0 {
		w.ClaimEvery = 30 * time.Second
	}
	if w.Block == 0 {
		w.Block = 5 * time.Second
	}
	if w.JobTimeout == 0 {
		w.JobTimeout = 30 * time.Second
	}
	if w.Log == nil {
		w.Log = slog.New(slog.DiscardHandler)
	}
}

// Run blocks until ctx is cancelled. Messages already being analysed are
// finished and acknowledged before it returns (graceful shutdown); nothing
// new is read after cancellation.
func (w *Worker) Run(ctx context.Context) error {
	w.defaults()
	if err := w.Q.EnsureGroup(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for i := range w.Concurrency {
		wg.Go(func() { w.consume(ctx, fmt.Sprintf("%s-%d", w.Name, i)) })
	}
	wg.Go(func() { w.watchdog(ctx, w.Name+"-watchdog") })
	wg.Wait()
	return nil
}

// EnsureGroup creates the stream and consumer group if missing. Starting
// at "0" means entries queued before any worker existed are processed too.
func (q *Queue) EnsureGroup(ctx context.Context) error {
	err := q.R.XGroupCreateMkStream(ctx, Stream, Group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

func (w *Worker) consume(ctx context.Context, consumer string) {
	for ctx.Err() == nil {
		streams, err := w.Q.R.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group: Group, Consumer: consumer, Streams: []string{Stream, ">"},
			Count: 1, Block: w.Block,
		}).Result()
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, redis.Nil): // block timed out, nothing new
			continue
		case err != nil:
			w.Log.Error("xreadgroup", "consumer", consumer, "err", err)
			sleep(ctx, time.Second) // Redis down: don't spin
			continue
		}
		for _, s := range streams {
			for _, m := range s.Messages {
				w.process(ctx, m)
			}
		}
	}
}

// watchdog reclaims entries whose worker stopped without acknowledging them
// and processes them itself.
func (w *Worker) watchdog(ctx context.Context, consumer string) {
	t := time.NewTicker(w.ClaimEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		start := "0-0"
		for ctx.Err() == nil {
			msgs, next, err := w.Q.R.XAutoClaim(ctx, &redis.XAutoClaimArgs{
				Stream: Stream, Group: Group, Consumer: consumer,
				MinIdle: w.ClaimIdle, Start: start, Count: 10,
			}).Result()
			if err != nil {
				if ctx.Err() == nil {
					w.Log.Error("xautoclaim", "err", err)
				}
				break
			}
			for _, m := range msgs {
				w.Log.Warn("reclaimed stuck scan", "entry", m.ID, "id", m.Values["id"])
				w.process(ctx, m)
			}
			if next == "0-0" {
				break
			}
			start = next
		}
	}
}

// process handles one stream entry. It never acknowledges an entry unless
// its outcome (result, permanent failure or dead letter) is stored in the
// same transaction.
func (w *Worker) process(ctx context.Context, m redis.XMessage) {
	// Finish the job even if shutdown starts now; JobTimeout still bounds it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.JobTimeout)
	defer cancel()

	id, _ := m.Values["id"].(string)
	log := w.Log.With("id", id, "entry", m.ID)
	if !ValidID(id) {
		w.deadLetter(ctx, m, id, 0, "stream entry has no valid scan id")
		return
	}

	attempts, err := w.Q.R.HIncrBy(ctx, scanKey(id), "attempts", 1).Result()
	if err != nil {
		log.Error("count attempt", "err", err) // stays pending; the watchdog retries
		return
	}
	if attempts > int64(w.MaxAttempts) {
		last, _ := w.Q.R.HGet(ctx, scanKey(id), "last_error").Result()
		w.deadLetter(ctx, m, id, attempts-1, fmt.Sprintf("failed %d attempts, last error: %s", attempts-1, last))
		return
	}

	job := Job{ID: id, ReceivedAt: time.Now()}
	if ms, err := w.Q.R.HGet(ctx, scanKey(id), "received_at").Int64(); err == nil {
		job.ReceivedAt = time.UnixMilli(ms)
	}
	raw, err := w.Q.R.Get(ctx, rawKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		w.deadLetter(ctx, m, id, attempts, "raw message expired or missing")
		return
	} else if err != nil {
		log.Error("load raw", "err", err)
		return
	}

	start := time.Now()
	job.Raw = raw
	report, err := w.safeHandle(ctx, job)
	var perm permanentError
	switch {
	case errors.As(err, &perm):
		w.finish(ctx, m, id, map[string]any{"status": string(StatusFailed), "error": err.Error()})
		w.observe("failed")
		log.Warn("scan failed permanently", "err", err)
	case err != nil:
		// Transient: record why, leave the entry pending for a retry.
		w.Q.R.HSet(ctx, scanKey(id), "last_error", err.Error())
		w.observe("retry")
		log.Error("scan attempt failed", "attempt", attempts, "err", err)
	default:
		fields := map[string]any{"status": string(StatusDone)}
		if report != nil {
			fields["report"] = report
		}
		w.finish(ctx, m, id, fields)
		w.observe("done")
		log.Info("scan done", "attempt", attempts, "ms", time.Since(start).Milliseconds())
	}
}

func (w *Worker) safeHandle(ctx context.Context, job Job) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return w.Handle(ctx, job)
}

// finish stores the outcome, drops the raw message and acknowledges the
// entry in one MULTI/EXEC: either all of it happens or none of it does.
func (w *Worker) finish(ctx context.Context, m redis.XMessage, id string, fields map[string]any) {
	_, err := w.Q.R.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, scanKey(id), fields)
		p.HDel(ctx, scanKey(id), "last_error")
		p.Expire(ctx, scanKey(id), w.Q.ttl())
		p.Del(ctx, rawKey(id))
		p.XAck(ctx, Stream, Group, m.ID)
		return nil
	})
	if err != nil {
		w.Log.Error("store result", "id", id, "err", err) // not acked: retried later
	}
}

func (w *Worker) deadLetter(ctx context.Context, m redis.XMessage, id string, attempts int64, reason string) {
	_, err := w.Q.R.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.XAdd(ctx, &redis.XAddArgs{
			Stream: DeadStream, MaxLen: 1000, Approx: true,
			Values: map[string]any{"id": id, "entry": m.ID, "attempts": attempts, "reason": reason},
		})
		if ValidID(id) {
			p.HSet(ctx, scanKey(id), "status", string(StatusFailed), "error", reason)
			p.Expire(ctx, scanKey(id), w.Q.ttl())
			p.Del(ctx, rawKey(id))
		}
		p.XAck(ctx, Stream, Group, m.ID)
		return nil
	})
	if err != nil {
		w.Log.Error("dead-letter", "id", id, "err", err)
		return
	}
	w.observe("dead")
	w.Log.Error("scan dead-lettered", "id", id, "entry", m.ID, "reason", reason)
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
