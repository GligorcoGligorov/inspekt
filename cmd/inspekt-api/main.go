// Command inspekt-api serves the scanner over HTTP.
//
//	curl --data-binary @testdata/phish_lookalike.eml localhost:8080/v1/scans
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/api"
	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := analyze.DefaultConfig
	if ids := os.Getenv("INSPEKT_TRUSTED_AUTHSERV_IDS"); ids != "" {
		cfg.TrustedAuthServIDs = strings.Split(ids, ",")
	}

	srv := &http.Server{
		Addr: envOr("INSPEKT_ADDR", ":8080"),
		Handler: (&api.Server{
			Engine: analyze.New(cfg),
			Limits: email.DefaultLimits,
			Log:    log,
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

	log.Info("listening", "addr", srv.Addr, "engine", analyze.Version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
