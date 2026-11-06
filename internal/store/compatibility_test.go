package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreCompatibilityRejectsInvalidApplicationData(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"marker only", "DROP TABLE sessions; DROP TABLE users; DROP TABLE attackers; DROP TABLE counter_states; DROP TABLE machine_totals; DROP TABLE machine_rollups; DROP TABLE machines"},
		{"missing column", "ALTER TABLE machines DROP COLUMN colour"},
		{"missing index", "DROP INDEX idx_attackers_missing_location"},
		{"migration hole", "DELETE FROM schema_migrations WHERE version=2"},
		{"foreign key", "INSERT INTO machine_totals(machine_id) VALUES(999)"},
		{"trigger hidden by LIKE wildcard", "CREATE TRIGGER sqliteXhidden AFTER UPDATE ON machines BEGIN DELETE FROM users; END"},
		{"trigger", "CREATE TRIGGER unexpected AFTER UPDATE ON machines BEGIN DELETE FROM users; END"},
		{"credential cost", "INSERT INTO users(username,password_hash,must_change_password,created_at) VALUES('admin','$argon2id$v=19$m=4294967295,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',0,0)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, _ := newStore(t)
			target := filepath.Join(t.TempDir(), "bad.db")
			if _, err := source.DB().Exec("VACUUM INTO ?", target); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open(driverName, "file:"+target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			db.Close()
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyDatabaseFile(target); err == nil {
				t.Fatal("accepted incompatible database")
			}
			after, _ := os.ReadFile(target)
			if sha256.Sum256(before) != sha256.Sum256(after) {
				t.Fatal("source changed")
			}
			manager := NewBackupManager(source, t.TempDir(), filepath.Join(t.TempDir(), "live.db"), 7)
			file, err := os.Open(target)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err = manager.StageRestoreFromReader(file); err == nil {
				t.Fatal("staged incompatible upload")
			}
			if _, err = os.Stat(manager.databasePath + restorePendingExt); !os.IsNotExist(err) {
				t.Fatal("restore file was staged")
			}
		})
	}
}

func TestRestoreCompatibilitySupportsEveryHistoricalSchema(t *testing.T) {
	names, err := migrationNames()
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= len(names); version++ {
		t.Run(names[version-1], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "older.db")
			db, err := sql.Open(driverName, "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			source := &Store{database: db}
			_, err = db.Exec(`CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
   )`)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < version; i++ {
				data, e := migrationFiles.ReadFile(migrationsDirectory + "/" + names[i])
				if e != nil {
					t.Fatal(e)
				}
				if e = source.applyMigration(context.Background(), i+1, string(data)); e != nil {
					t.Fatal(e)
				}
			}
			if _, err = db.Exec("INSERT INTO machines(name,host,port,created_at) VALUES('historic','192.0.2.1',2112,1)"); err != nil {
				t.Fatal(err)
			}
			db.Close()
			before, _ := os.ReadFile(path)
			if err = VerifyDatabaseFile(path); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if sha256.Sum256(before) != sha256.Sum256(after) {
				t.Fatal("older source modified")
			}
		})
	}
}

func TestMigrateRejectsUnsupportedVersionsBeforeApplyingChanges(t *testing.T) {
	for _, statement := range []string{"INSERT INTO schema_migrations VALUES(999,0)", "DELETE FROM schema_migrations WHERE version=2"} {
		s, _ := newStore(t)
		if _, err := s.DB().Exec(statement); err != nil {
			t.Fatal(err)
		}
		if err := s.Migrate(context.Background()); err == nil {
			t.Fatal("accepted invalid sequence")
		} else if statement[0] == 'I' && !errors.Is(err, ErrDatabaseTooNew) {
			t.Fatal(err)
		}
	}
}

func TestOpenRejectsFutureMigrationBeforeVacuum(t *testing.T) {
	s, path := newStore(t)
	if _, err := s.DB().Exec("INSERT INTO schema_migrations VALUES(999,0)"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path)
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Fatalf("Open error = %v, want ErrDatabaseTooNew", err)
	}
}
