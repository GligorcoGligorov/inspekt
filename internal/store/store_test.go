package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/migrations"
)

func newID(t *testing.T) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s-%d", t.Name(), time.Now().UnixNano()))
	return hex.EncodeToString(sum[:])
}

func report(verdict analyze.Verdict, score int, signals ...analyze.Signal) *analyze.Report {
	return &analyze.Report{
		Verdict: verdict, Score: score, Signals: signals, Engine: analyze.Version,
		Message: &email.Message{Subject: "s", From: &email.Address{Email: "a@example.org", Domain: "example.org"}},
	}
}

// contract is the behaviour every Store must have; it runs against each
// implementation so the in-memory one used by API tests cannot drift from
// MariaDB.
func contract(t *testing.T, s Store) {
	ctx := context.Background()
	t.Run("not found", func(t *testing.T) {
		if _, err := s.Get(ctx, newID(t)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
	t.Run("round trip", func(t *testing.T) {
		id := newID(t)
		recv := time.Date(2026, 10, 24, 9, 0, 0, 123456789, time.UTC)
		rep := report(analyze.VerdictMalicious, 80, analyze.Signal{ID: "double_extension", Score: 50})
		if err := s.Save(ctx, Scan{ID: id, ReceivedAt: recv, ScannedAt: recv.Add(40 * time.Millisecond), Report: rep}); err != nil {
			t.Fatal(err)
		}
		r, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Verdict != analyze.VerdictMalicious || r.Score != 80 || r.Engine != analyze.Version ||
			!r.ReceivedAt.Equal(recv.Truncate(time.Millisecond)) || r.ScannedAt.Sub(r.ReceivedAt) != 40*time.Millisecond {
			t.Fatalf("got %+v", r)
		}
		var back analyze.Report
		if err := json.Unmarshal(r.Report, &back); err != nil || back.Signals[0].ID != "double_extension" {
			t.Fatalf("report did not round-trip: %v %s", err, r.Report)
		}
	})
	t.Run("save is idempotent and keeps the first received_at", func(t *testing.T) {
		id := newID(t)
		first := time.Now().Add(-time.Hour)
		s.Save(ctx, Scan{ID: id, ReceivedAt: first, ScannedAt: first, Report: report(analyze.VerdictSuspicious, 40)})
		if err := s.Save(ctx, Scan{ID: id, ReceivedAt: time.Now(), ScannedAt: time.Now(), Report: report(analyze.VerdictClean, 5)}); err != nil {
			t.Fatal(err)
		}
		r, _ := s.Get(ctx, id)
		if r.Verdict != analyze.VerdictClean || !r.ReceivedAt.Equal(first.UTC().Truncate(time.Millisecond)) {
			t.Fatalf("got verdict %s received %v, want clean received %v", r.Verdict, r.ReceivedAt, first)
		}
	})
}

func TestMemory(t *testing.T) { contract(t, &Memory{}) }

// TestMariaDB needs a real server: INSPEKT_TEST_MARIADB_DSN points at a
// throwaway database (CI provides one; locally run `make test-db`).
func TestMariaDB(t *testing.T) {
	dsn := os.Getenv("INSPEKT_TEST_MARIADB_DSN")
	if dsn == "" {
		// In CI a missing DSN means a broken workflow, not "no database
		// here": fail rather than let the real-database tests silently skip.
		if os.Getenv("CI") != "" {
			t.Fatal("INSPEKT_TEST_MARIADB_DSN not set in CI")
		}
		t.Skip("INSPEKT_TEST_MARIADB_DSN not set; run `make test-db`")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	for _, tbl := range []string{"signals", "scans", "schema_migrations"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatal(err)
		}
	}

	// API and worker start together: concurrent Migrate calls must apply
	// each migration exactly once.
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Go(func() { errs <- Migrate(ctx, db, migrations.FS) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, db, migrations.FS); err != nil { // and again later: no-op
		t.Fatal(err)
	}
	var n int
	db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&n)
	if n != 1 {
		t.Fatalf("schema_migrations has %d rows, want 1", n)
	}

	s := &MariaDB{DB: db}
	contract(t, s)

	t.Run("signals rows are replaced on re-save", func(t *testing.T) {
		id := newID(t)
		s.Save(ctx, Scan{ID: id, ReceivedAt: time.Now(), ScannedAt: time.Now(), Report: report(analyze.VerdictMalicious, 70,
			analyze.Signal{ID: "dmarc_fail", Score: 35}, analyze.Signal{ID: "lookalike_link", Score: 35})})
		s.Save(ctx, Scan{ID: id, ReceivedAt: time.Now(), ScannedAt: time.Now(), Report: report(analyze.VerdictSuspicious, 35,
			analyze.Signal{ID: "dmarc_fail", Score: 35})})
		rows, err := db.QueryContext(ctx, "SELECT signal_id, score FROM signals WHERE scan_id = ?", id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var sig string
			var score int
			rows.Scan(&sig, &score)
			got = append(got, fmt.Sprintf("%s=%d", sig, score))
		}
		if len(got) != 1 || got[0] != "dmarc_fail=35" {
			t.Fatalf("signals %v, want [dmarc_fail=35]", got)
		}
		var dom string
		db.QueryRowContext(ctx, "SELECT from_domain FROM scans WHERE id = ?", id).Scan(&dom)
		if dom != "example.org" {
			t.Fatalf("from_domain %q", dom)
		}
	})
}
