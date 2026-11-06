package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"endlessh-dashboard/internal/credentials"
)

func readOnlyURI(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	return u.String() + "?mode=ro&_pragma=trusted_schema(OFF)"
}

// compareSchema admits only the objects produced by our own migrations. In
// particular imported triggers/views must never execute while upgrading a copy.
func compareSchema(ctx context.Context, actual, expected *sql.DB) error {
	objects := func(db *sql.DB) (map[string]string, error) {
		rows, err := db.QueryContext(ctx, "SELECT type, name, sql FROM sqlite_master WHERE type IN ('trigger','view') OR name NOT GLOB 'sqlite_*' ORDER BY name")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var kind, name, definition string
			if err := rows.Scan(&kind, &name, &definition); err != nil {
				return nil, err
			}
			out[kind+":"+name] = strings.Join(strings.Fields(definition), " ")
		}
		return out, rows.Err()
	}
	got, err := objects(actual)
	if err != nil {
		return err
	}
	want, err := objects(expected)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("backup application schema has missing or unsupported objects")
	}
	for key, definition := range want {
		if got[key] != definition {
			return fmt.Errorf("backup application schema mismatch: %s", key)
		}
	}
	return nil
}

func verifyApplicationDatabase(ctx context.Context, database *sql.DB, directory string) error {
	source := &Store{database: database}
	applied, err := source.appliedMigrations(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		return fmt.Errorf("backup has no application migrations")
	}
	reference, err := sql.Open(driverName, ":memory:")
	if err != nil {
		return err
	}
	defer reference.Close()
	reference.SetMaxOpenConns(1)
	expected := &Store{database: reference}
	if _, err = reference.ExecContext(ctx, `CREATE TABLE schema_migrations (
 version INTEGER PRIMARY KEY,
 applied_at INTEGER NOT NULL
 )`); err != nil {
		return err
	}
	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		version, e := migrationVersion(name)
		if e != nil {
			return e
		}
		if version > len(applied) {
			break
		}
		data, e := migrationFiles.ReadFile(migrationsDirectory + "/" + name)
		if e != nil {
			return e
		}
		if e = expected.applyMigration(ctx, version, string(data)); e != nil {
			return e
		}
	}
	if err = compareSchema(ctx, database, reference); err != nil {
		return err
	}
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	broken := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return rowErr
	}
	if broken {
		return fmt.Errorf("backup contains broken foreign keys")
	}
	rows, err = database.QueryContext(ctx, "SELECT password_hash FROM users")
	if err != nil {
		return err
	}
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			break
		}
		if credentials.ValidateHash(hash) != nil {
			err = fmt.Errorf("backup contains unsupported credential metadata")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	directory, err = os.MkdirTemp(directory, ".endlessh-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	copyPath := filepath.Join(directory, "upgrade.db")
	// VACUUM INTO includes committed source WAL data without changing the source.
	if _, err = database.ExecContext(ctx, "VACUUM INTO ?", copyPath); err != nil {
		return fmt.Errorf("copy backup for compatibility check: %w", err)
	}
	copyDB, err := sql.Open(driverName, "file:"+copyPath+"?_pragma=foreign_keys(1)&_pragma=trusted_schema(OFF)")
	if err != nil {
		return err
	}
	defer copyDB.Close()
	candidate := &Store{database: copyDB}
	if err = candidate.Migrate(ctx); err != nil {
		return fmt.Errorf("upgrade backup copy: %w", err)
	}
	if err = validateCanonicalIdentityData(ctx, copyDB); err != nil {
		return err
	}
	if err = expected.Migrate(ctx); err != nil {
		return err
	}
	if err = compareSchema(ctx, copyDB, reference); err != nil {
		return err
	}
	if _, err = candidate.CountUsers(ctx); err != nil {
		return err
	}
	if _, err = candidate.ListMachines(ctx); err != nil {
		return err
	}
	return nil
}
