// Package pipeline is what a worker does with one queued scan: analyse it,
// then persist the result.
package pipeline

import (
	"context"
	"encoding/json"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/metrics"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
	"github.com/GligorcoGligorov/inspekt/internal/store"
)

// Handler analyses each job with eng. With a Store, the result is saved
// there and nothing is kept in Redis; a failed save is returned as a
// transient error, so the scan is retried and never acknowledged unsaved.
// Without a Store (nil), the report is kept in Redis as before.
func Handler(eng *analyze.Engine, lim email.Limits, st store.Store) queue.Handler {
	return func(ctx context.Context, job queue.Job) ([]byte, error) {
		start := time.Now()
		rep, err := eng.ScanRaw(job.Raw, lim)
		if err != nil {
			return nil, queue.Permanent(err) // unparseable: retrying won't help
		}
		metrics.ObserveReport(rep, time.Since(start))
		if st == nil {
			metrics.QueueWait.Observe(time.Since(job.ReceivedAt).Seconds())
			return json.Marshal(rep)
		}
		if err := st.Save(ctx, store.Scan{
			ID: job.ID, ReceivedAt: job.ReceivedAt, ScannedAt: time.Now(), Report: rep,
		}); err != nil {
			return nil, err
		}
		metrics.QueueWait.Observe(time.Since(job.ReceivedAt).Seconds())
		return nil, nil
	}
}
