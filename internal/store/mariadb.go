package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/campaign"
)

// MariaDB stores results in the scans and signals tables (see migrations/).
type MariaDB struct{ DB *sql.DB }

// Open connects with settings the store relies on: UTC times parsed into
// time.Time, and a pool small enough for a 256 MB container.
func Open(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

// Save upserts the scan and replaces its signals in one transaction, so a
// redelivered scan overwrites rather than duplicates. received_at keeps the
// first value: the message was accepted once, however often it is analysed.
//
// InnoDB may abort a transaction as a deadlock victim (1213) or on a lock
// wait timeout (1205); both mean "try again", so Save retries them a few
// times before reporting the error.
func (m *MariaDB) Save(ctx context.Context, s Scan) error {
	r, err := s.record()
	if err != nil {
		return err
	}
	var from sql.NullString
	if msg := s.Report.Message; msg != nil && msg.From != nil {
		from = sql.NullString{String: msg.From.Domain, Valid: true}
	}
	for attempt := 1; ; attempt++ {
		err = m.save(ctx, r, from, s.Report.Signals, campaign.Extract(s.Report))
		if attempt == 3 || !retryable(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt*10) * time.Millisecond):
		}
	}
}

// saveIndicators writes the scan's campaign indicators in the caller's
// transaction, with the same rule as signals: a re-save replaces them, a new
// scan only inserts (no DELETE, so no gap locks between workers).
// created_at is the stored received_at, which a re-save does not change.
func saveIndicators(ctx context.Context, tx *sql.Tx, id string, resave bool, inds []campaign.Indicator) error {
	if resave {
		if _, err := tx.ExecContext(ctx, `DELETE FROM scan_indicators WHERE scan_id = ?`, id); err != nil {
			return fmt.Errorf("store: clear indicators: %w", err)
		}
	}
	if len(inds) == 0 {
		return nil
	}
	var received time.Time
	if err := tx.QueryRowContext(ctx, `SELECT received_at FROM scans WHERE id = ?`, id).Scan(&received); err != nil {
		return fmt.Errorf("store: read received_at: %w", err)
	}
	q := "INSERT INTO scan_indicators (scan_id, kind, value, created_at) VALUES " +
		strings.TrimSuffix(strings.Repeat("(?, ?, ?, ?),", len(inds)), ",")
	args := make([]any, 0, 4*len(inds))
	for _, ind := range inds {
		args = append(args, id, ind.Kind, ind.Value, received)
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store: save indicators: %w", err)
	}
	return nil
}

func retryable(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == 1213 || me.Number == 1205)
}

func (m *MariaDB) save(ctx context.Context, r *Record, from sql.NullString, sigs []analyze.Signal, inds []campaign.Indicator) error {
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit

	res, err := tx.ExecContext(ctx, `
		INSERT INTO scans (id, received_at, scanned_at, verdict, score, engine, from_domain, report)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			scanned_at = VALUES(scanned_at), verdict = VALUES(verdict), score = VALUES(score),
			engine = VALUES(engine), from_domain = VALUES(from_domain), report = VALUES(report)`,
		r.ID, r.ReceivedAt, r.ScannedAt, r.Verdict, r.Score, r.Engine, from, []byte(r.Report),
	)
	if err != nil {
		return fmt.Errorf("store: save scan: %w", err)
	}
	// 1 row affected = a new scan: it has no signals yet, and skipping the
	// DELETE matters. Deleting rows that do not exist still takes InnoDB
	// gap locks, which collided with other workers' inserts and deadlocked
	// under load. Only a re-save (2 = updated, 0 = unchanged) clears rows.
	n, _ := res.RowsAffected()
	if n != 1 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM signals WHERE scan_id = ?`, r.ID); err != nil {
			return fmt.Errorf("store: clear signals: %w", err)
		}
	}
	if err := saveIndicators(ctx, tx, r.ID, n != 1, inds); err != nil {
		return err
	}
	if len(sigs) > 0 {
		q := "INSERT INTO signals (scan_id, signal_id, score) VALUES " +
			strings.TrimSuffix(strings.Repeat("(?, ?, ?),", len(sigs)), ",")
		args := make([]any, 0, 3*len(sigs))
		for _, sig := range sigs {
			args = append(args, r.ID, sig.ID, sig.Score)
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("store: save signals: %w", err)
		}
	}
	return tx.Commit()
}

func (m *MariaDB) Get(ctx context.Context, id string) (*Record, error) {
	r := &Record{ID: id}
	var report []byte
	err := m.DB.QueryRowContext(ctx, `
		SELECT received_at, scanned_at, verdict, score, engine, report
		FROM scans WHERE id = ?`, id,
	).Scan(&r.ReceivedAt, &r.ScannedAt, &r.Verdict, &r.Score, &r.Engine, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Report = report
	return r, nil
}

func (m *MariaDB) Ping(ctx context.Context) error { return m.DB.PingContext(ctx) }

// migrationName matches NNN_description.sql.
var migrationName = regexp.MustCompile(`^(\d+)_[a-z0-9_]+\.sql$`)

// statementEnd splits a migration file into statements: a semicolon at the
// end of a line. Keep semicolons out of comments in migration files.
var statementEnd = regexp.MustCompile(`;[ \t]*(\r?\n|$)`)

// Migrate applies the not-yet-applied files from fsys in numeric order and
// records each in schema_migrations. Every binary calls it at startup;
// GET_LOCK makes concurrent callers (API and worker starting together) take
// turns, so each migration runs once.
//
// MariaDB cannot roll back DDL, so a file that fails halfway leaves the
// statements before the failure applied: keep one table change per file.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
	conn, err := db.Conn(ctx) // the named lock belongs to one connection
	if err != nil {
		return err
	}
	defer conn.Close()

	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK('inspekt_migrate', 60)`).Scan(&got); err != nil {
		return fmt.Errorf("migrate: lock: %w", err)
	}
	if got.Int64 != 1 {
		return errors.New("migrate: timed out waiting for another migrator")
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT RELEASE_LOCK('inspekt_migrate')`)

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INT          NOT NULL PRIMARY KEY,
			name       VARCHAR(255) NOT NULL,
			applied_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
		) ENGINE = InnoDB`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	applied := map[int]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	type migration struct {
		version int
		name    string
	}
	var todo []migration
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, _ := strconv.Atoi(m[1])
		if !applied[v] {
			todo = append(todo, migration{v, e.Name()})
		}
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].version < todo[j].version })

	for _, mg := range todo {
		body, err := fs.ReadFile(fsys, mg.name)
		if err != nil {
			return err
		}
		for _, stmt := range statementEnd.Split(string(body), -1) {
			if strings.TrimSpace(stripComments(stmt)) == "" {
				continue
			}
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate %s: %w", mg.name, err)
			}
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, mg.version, mg.name); err != nil {
			return fmt.Errorf("migrate %s: record: %w", mg.name, err)
		}
	}
	return nil
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
