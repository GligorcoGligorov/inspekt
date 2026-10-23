// Package config reads the INSPEKT_* environment variables shared by the
// CLI, the API and the worker, so all three analyse mail the same way.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/auth"
	"github.com/GligorcoGligorov/inspekt/internal/llm"
	"github.com/GligorcoGligorov/inspekt/internal/metrics"
)

// Env returns the variable k, or def when it is unset or empty.
func Env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Int returns the variable k as a positive integer, or def when unset.
func Int(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", k, v)
	}
	return n, nil
}

// Engine builds the analysis config:
//
//	INSPEKT_TRUSTED_AUTHSERV_IDS  comma-separated authserv-ids to believe
//	INSPEKT_AUTH_MODE             headers (default) or verify
//	INSPEKT_LLM_BASE_URL          OpenAI-compatible endpoint; with _MODEL set,
//	INSPEKT_LLM_MODEL             enables the grey-zone LLM review (off by default)
//	INSPEKT_LLM_API_KEY           bearer token (not needed for a local Ollama)
//	INSPEKT_LLM_PER_MINUTE        calls per minute, all processes (default 4)
//	INSPEKT_LLM_DAILY_CAP         calls per UTC day, all processes (default 100)
//	INSPEKT_LLM_TIMEOUT_MS        per call (default 5000)
//
// The defaults stay well inside the strictest chat-model row of Groq's
// published limits (openai/gpt-oss-20b: 30 RPM, 1K RPD, 8K TPM, 200K TPD):
// a review is at most ~1,350 tokens, so 4/min is ~5.4K TPM and 100/day
// ~135K TPD.
//
// rdb, when not nil, makes the LLM daily cap shared across processes.
func Engine(rdb *redis.Client) (analyze.Config, error) {
	cfg := analyze.DefaultConfig
	if ids := os.Getenv("INSPEKT_TRUSTED_AUTHSERV_IDS"); ids != "" {
		cfg.TrustedAuthServIDs = strings.Split(ids, ",")
	}
	switch mode := AuthMode(); mode {
	case "headers":
	case "verify":
		cfg.Verifier = &auth.Verifier{Resolver: net.DefaultResolver}
	default:
		return cfg, fmt.Errorf("INSPEKT_AUTH_MODE must be headers or verify, got %q", mode)
	}

	base, model := os.Getenv("INSPEKT_LLM_BASE_URL"), os.Getenv("INSPEKT_LLM_MODEL")
	if base == "" && model == "" {
		return cfg, nil
	}
	if base == "" || model == "" {
		return cfg, errors.New("INSPEKT_LLM_BASE_URL and INSPEKT_LLM_MODEL must be set together")
	}
	daily, err := Int("INSPEKT_LLM_DAILY_CAP", 100)
	if err != nil {
		return cfg, err
	}
	perMinute, err := Int("INSPEKT_LLM_PER_MINUTE", 4)
	if err != nil {
		return cfg, err
	}
	timeoutMS, err := Int("INSPEKT_LLM_TIMEOUT_MS", 5000)
	if err != nil {
		return cfg, err
	}
	var budget llm.Budget = &llm.MemoryBudget{PerMinute: int64(perMinute), PerDay: int64(daily)}
	if rdb != nil {
		budget = llm.RedisBudget{R: rdb, PerMinute: int64(perMinute), PerDay: int64(daily)}
	}
	cfg.Reviewer = &llm.Reviewer{
		Classifier: &llm.Client{BaseURL: base, Model: model, APIKey: os.Getenv("INSPEKT_LLM_API_KEY")},
		Budget:     budget,
		Timeout:    time.Duration(timeoutMS) * time.Millisecond,
		Observe:    metrics.ObserveLLM,
	}
	return cfg, nil
}

// LLM describes the grey-zone review setting for start-up logs, without
// the key.
func LLM() string {
	if m := os.Getenv("INSPEKT_LLM_MODEL"); m != "" {
		return m + " @ " + os.Getenv("INSPEKT_LLM_BASE_URL")
	}
	return "off"
}

// AuthMode is INSPEKT_AUTH_MODE with its default applied.
func AuthMode() string { return Env("INSPEKT_AUTH_MODE", "headers") }
