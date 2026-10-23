// Command inspekt-worker analyses scans queued by inspekt-api.
//
//	INSPEKT_REDIS_ADDR  Redis address (default localhost:6379)
//	INSPEKT_WORKERS     concurrent consumers in this process (default 4)
//
// Run as many processes as needed: each joins the same consumer group, and
// Redis hands every queued scan to exactly one of them.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/config"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fatal := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(2)
	}

	cfg, err := config.Engine()
	if err != nil {
		fatal("config", err)
	}
	workers, err := config.Int("INSPEKT_WORKERS", 4)
	if err != nil {
		fatal("config", err)
	}
	eng := analyze.New(cfg)
	rdb := redis.NewClient(&redis.Options{Addr: config.Env("INSPEKT_REDIS_ADDR", "localhost:6379")})
	defer rdb.Close()

	// The hostname (container id under Docker) keeps consumer names unique
	// per process. After a restart the old name's unacknowledged entries
	// are picked up by a watchdog.
	host, _ := os.Hostname()
	w := &queue.Worker{
		Q:           &queue.Queue{R: rdb},
		Name:        host,
		Concurrency: workers,
		Log:         log,
		Handle: func(_ context.Context, raw []byte) ([]byte, error) {
			rep, err := eng.ScanRaw(raw, email.DefaultLimits)
			if err != nil {
				return nil, queue.Permanent(err) // unparseable: retrying won't help
			}
			return json.Marshal(rep)
		},
	}

	// SIGTERM (docker stop, a deploy) stops reading; scans in progress
	// finish and are acknowledged before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("worker started", "consumer", host, "workers", workers,
		"engine", analyze.Version, "auth_mode", config.AuthMode())
	if err := w.Run(ctx); err != nil {
		log.Error("worker", "err", err)
		os.Exit(1)
	}
	log.Info("worker stopped")
}
