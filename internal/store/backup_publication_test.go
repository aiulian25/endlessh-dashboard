package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBackupPublicationFailuresPreserveExistingSnapshots(t *testing.T) {
	for _, failure := range []string{"snapshot", "verification", "chmod", "sync", "publish", "directory sync", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			source, m, directory := newBackupManager(t, 1)
			if err := m.EnsureDirectory(); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(directory, "endlessh-20240101-000000.db")
			if _, err := source.DB().Exec("VACUUM INTO ?", old); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(old)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch failure {
			case "snapshot":
				m.files.snapshot = func(_ context.Context, path string) error {
					if err := os.WriteFile(path, []byte("partial snapshot"), 0600); err != nil {
						return err
					}
					listed, err := m.List()
					if err != nil {
						return err
					}
					if len(listed) != 1 {
						t.Error("unfinished snapshot was listed")
					}
					return syscall.ENOSPC
				}
			case "verification":
				m.files.snapshot = func(_ context.Context, path string) error {
					return os.WriteFile(path, []byte("invalid snapshot"), 0600)
				}
			case "chmod":
				m.files.chmod = func(string, os.FileMode) error { return os.ErrPermission }
			case "sync":
				m.files.sync = func(string) error { return syscall.ENOSPC }
			case "publish":
				m.files.publish = func(string, string) error { return os.ErrPermission }
			case "directory sync":
				m.files.syncDirectory = func(string) error { return syscall.ENOSPC }
			case "cancel":
				m.files.sync = func(string) error { cancel(); return nil }
			}
			if _, err := m.Create(ctx); err == nil {
				t.Fatal("failed snapshot reported success")
			}
			after, err := os.ReadFile(old)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("older snapshot changed")
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(old) {
				t.Fatalf("incomplete output remained: %v", entries)
			}
			if err := VerifyDatabaseFile(old); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBackupCollisionRejectsIncompleteFile(t *testing.T) {
	_, m, directory := newBackupManager(t, 5)
	if err := m.EnsureDirectory(); err != nil {
		t.Fatal(err)
	}
	alignToSecondBoundary()
	name := backupNamePrefix + time.Now().UTC().Format(backupNameLayout) + backupNameSuffix
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(context.Background()); err == nil {
		t.Fatal("incomplete collision reported success")
	}
	listed, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("pre-existing backup unexpectedly removed: %v", listed)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected preserved original file: %v", entries)
	}
	data, err := os.ReadFile(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "partial" {
		t.Fatal("rejection changed contents")
	}
}

func TestBackupPublicationDoesNotOverwriteCompetingFile(t *testing.T) {
	_, m, directory := newBackupManager(t, 5)
	original := m.files.publish
	m.files.publish = func(source, destination string) error {
		if err := os.WriteFile(destination, []byte("competing file"), 0600); err != nil {
			return err
		}
		return original(source, destination)
	}
	if _, err := m.Create(context.Background()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("publication error = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary output remained: %v", entries)
	}
	data, err := os.ReadFile(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "competing file" {
		t.Fatal("competing file overwritten")
	}
}

func TestBackupCancellationWhileWaitingForPublicationLock(t *testing.T) {
	_, m, _ := newBackupManager(t, 1)
	m.creating.Lock()
	defer m.creating.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := m.Create(ctx); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled backup remained blocked on publication lock")
	}
}

func TestBackupCancellationStopsBlockedSnapshotAndCleansPendingFiles(t *testing.T) {
	_, m, directory := newBackupManager(t, 1)
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.files.snapshot = func(ctx context.Context, _ string) error { close(entered); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { _, err := m.Create(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot did not cancel")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("pending snapshot left behind", entries, err)
	}
}

func TestBackupVerificationHonorsCancelledParent(t *testing.T) {
	_, _, directory := newBackupManager(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyDatabaseFileContext(ctx, filepath.Join(directory, "unused.db")); !errors.Is(err, context.Canceled) {
		t.Fatalf("verification ignored parent cancellation: %v", err)
	}
}
