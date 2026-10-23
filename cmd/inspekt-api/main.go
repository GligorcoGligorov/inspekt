// Command inspekt-api serves the scanner over HTTP.
//
//	curl --data-binary @testdata/phish_lookalike.eml localhost:8080/v1/scans
//
// With INSPEKT_REDIS_ADDR set, scans are queued for inspekt-worker and the
// POST returns 202 with the scan id; without it, they are analysed inline.
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
	"github.com/GligorcoGligorov/inspekt/internal/api"
	"github.com/GligorcoGligorov/inspekt/internal/config"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/queue"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Engine()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	var q *queue.Queue
	if addr := config.Env("INSPEKT_REDIS_ADDR", ""); addr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: addr})
		defer rdb.Close()
		q = &queue.Queue{R: rdb}
	}

	srv := &http.Server{
		Addr: config.Env("INSPEKT_ADDR", ":8080"),
		Handler: (&api.Server{
			Engine: analyze.New(cfg),
			Limits: email.DefaultLimits,
			Log:    log,
			Queue:  q,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown: finish in-flight scans before exiting, so a deploy
	// never drops a message mid-analysis.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("listening", "addr", srv.Addr, "engine", analyze.Version,
		"auth_mode", config.AuthMode(), "async", q != nil)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}
