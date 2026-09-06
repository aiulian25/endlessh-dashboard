// Package store owns every read and write of the SQLite database. No SQL lives
// outside this package, and every statement is parameterized: machine names,
// labels and search terms all arrive from user input.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	driverName          = "sqlite"
	migrationsDirectory = "migrations"
	busyTimeoutMillis   = 10000
	maxOpenConnections  = 4
	maxIdleConnections  = 4

	// autoVacuumIncremental is SQLite's numeric code for incremental auto-vacuum.
	// It must be set before the first table exists, otherwise a full VACUUM is
	// needed to convert the file — retention pruning cannot reclaim space without it.
	autoVacuumIncremental = 2
)

type Store struct {
	database *sql.DB
}

func Open(path string) (*Store, error) {
	dataSource := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)",
		path, busyTimeoutMillis,
	)
	database, err := sql.Open(driverName, dataSource)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	database.SetMaxOpenConns(maxOpenConnections)
	database.SetMaxIdleConns(maxIdleConnections)

	if err := database.Ping(); err != nil {
		database.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}

	store := &Store{database: database}
	if err := store.ensureIncrementalAutoVacuum(); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.database.Close()
}

// DB exposes the handle for the rare caller that needs it, such as the backup
// routine issuing VACUUM INTO.
func (s *Store) DB() *sql.DB {
	return s.database
}

func (s *Store) ensureIncrementalAutoVacuum() error {
	var mode int
	if err := s.database.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return fmt.Errorf("read auto_vacuum: %w", err)
	}
	if mode == autoVacuumIncremental {
		return nil
	}
	if _, err := s.database.Exec(fmt.Sprintf("PRAGMA auto_vacuum=%d", autoVacuumIncremental)); err != nil {
		return fmt.Errorf("set auto_vacuum: %w", err)
	}
	// A database that already holds pages keeps its old setting until rewritten.
	if _, err := s.database.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum to apply auto_vacuum: %w", err)
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.database.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := s.appliedMigrations(ctx)
	if err != nil {
		return err
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if applied[version] {
			continue
		}
		statements, err := migrationFiles.ReadFile(migrationsDirectory + "/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if err := s.applyMigration(ctx, version, string(statements)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) appliedMigrations(ctx context.Context) (map[int]bool, error) {
	rows, err := s.database.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func (s *Store) applyMigration(ctx context.Context, version int, statements string) error {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx, statements); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
		version, time.Now().Unix()); err != nil {
		return err
	}
	return transaction.Commit()
}

// migrationNames lists the embedded migrations in the order they are applied.
func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, migrationsDirectory)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// LatestMigrationVersion is the newest schema this build knows how to produce.
// A database numbered above it was written by a later release, so it may hold
// tables and columns this binary has never heard of — and Migrate would not
// notice, because it only ever applies versions it does not already find.
func LatestMigrationVersion() (int, error) {
	names, err := migrationNames()
	if err != nil {
		return 0, err
	}
	latest := 0
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return 0, err
		}
		latest = max(latest, version)
	}
	return latest, nil
}

func migrationVersion(name string) (int, error) {
	underscore := strings.Index(name, "_")
	if underscore <= 0 {
		return 0, fmt.Errorf("migration %q must be named <version>_<description>.sql", name)
	}
	version, err := strconv.Atoi(name[:underscore])
	if err != nil {
		return 0, fmt.Errorf("migration %q must start with a numeric version", name)
	}
	return version, nil
}

func unixOrNil(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.Unix()
}

// floatFromNullable keeps a missing coordinate missing: 0,0 is a real place, so
// a NULL column must never arrive in Go as a usable number.
func floatFromNullable(value sql.NullFloat64) *float64 {
	if !value.Valid {
		return nil
	}
	converted := value.Float64
	return &converted
}

func timeFromNullable(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := time.Unix(value.Int64, 0).UTC()
	return &converted
}

// placeholders builds "?,?,?" for an IN clause of the given length.
func placeholders(count int) string {
	if count == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", count), ",")
}

func int64Args(values []int64) []any {
	args := make([]any, len(values))
	for index, value := range values {
		args[index] = value
	}
	return args
}

// withArg copies args before appending, so a shared base slice can safely feed
// several queries in a row.
func withArg(args []any, extra ...any) []any {
	combined := make([]any, 0, len(args)+len(extra))
	combined = append(combined, args...)
	return append(combined, extra...)
}
