// Package config reads the INSPEKT_* environment variables shared by the
// CLI, the API and the worker, so all three analyse mail the same way.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/auth"
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
func Engine() (analyze.Config, error) {
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
	return cfg, nil
}

// AuthMode is INSPEKT_AUTH_MODE with its default applied.
func AuthMode() string { return Env("INSPEKT_AUTH_MODE", "headers") }
