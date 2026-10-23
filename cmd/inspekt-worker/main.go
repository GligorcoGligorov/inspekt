// Command inspekt-worker analyses scans queued by inspekt-api.
//
//	INSPEKT_REDIS_ADDR    Redis address (default localhost:6379)
//	INSPEKT_WORKERS       concurrent consumers in this process (default 4)
//	INSPEKT_METRICS_ADDR  Prometheus /metrics listener (default :9090)
//	INSPEKT_MARIADB_DSN   where results are kept, e.g.
//	                      inspekt:secret@tcp(mariadb:3306)/inspekt
//	                      (unset: results stay in Redis for 24 h)
//
// Run as many processes as needed: each joins the same consumer group, and
// Redis hands every queued scan to exactly one of them.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/config"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/metrics"
	"github.com/GligorcoGligorov/inspekt/internal/pipeline"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
	"github.com/GligorcoGligorov/inspekt/internal/store"
	"github.com/GligorcoGligorov/inspekt/migrations"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fatal := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(2)
	}

	rdb := redis.NewClient(&redis.Options{Addr: config.Env("INSPEKT_REDIS_ADDR", "localhost:6379")})
	defer rdb.Close()
	cfg, err := config.Engine(rdb)
	if err != nil {
		fatal("config", err)
	}
	workers, err := config.Int("INSPEKT_WORKERS", 4)
	if err != nil {
		fatal("config", err)
	}
	eng := analyze.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if dsn := config.Env("INSPEKT_MARIADB_DSN", ""); dsn != "" {
		db, err := store.Open(dsn)
		if err != nil {
			fatal("mariadb", err)
		}
		defer db.Close()
		if err := store.Migrate(ctx, db, migrations.FS); err != nil {
			fatal("migrate", err)
		}
		st = &store.MariaDB{DB: db}
	}

	// The hostname (container id under Docker) keeps consumer names unique
	// per process. After a restart the old name's unacknowledged entries
	// are picked up by a watchdog.
	host, _ := os.Hostname()
	w := &queue.Worker{
		Q:           &queue.Queue{R: rdb},
		Name:        host,
		Concurrency: workers,
		Log:         log,
		Handle:      pipeline.Handler(eng, email.DefaultLimits, st),
		Observe:     metrics.ObserveOutcome,
	}

	// Analysis happens here, so the per-check latency and outcome metrics
	// live here too; Prometheus scrapes every worker.
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	msrv := &http.Server{Addr: config.Env("INSPEKT_METRICS_ADDR", ":9090"), Handler: mux,
		ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := msrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()
	defer msrv.Close()

	// SIGTERM (docker stop, a deploy) stops reading; scans in progress
	// finish and are acknowledged before the process exits.
	log.Info("worker started", "consumer", host, "workers", workers,
		"engine", analyze.Version, "auth_mode", config.AuthMode(), "store", st != nil, "llm", config.LLM())
	if err := w.Run(ctx); err != nil {
		log.Error("worker", "err", err)
		os.Exit(1)
	}
	log.Info("worker stopped")
}
