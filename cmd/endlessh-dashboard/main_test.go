package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"endlessh-dashboard/internal/config"
	"endlessh-dashboard/internal/store"
)

func TestRestoreRemainsUnconfirmedWhenListenerStartupFails(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "endlessh.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	add := func(name string) {
		t.Helper()
		if _, err := s.CreateMachine(ctx, store.Machine{Name: name, Host: "192.0.2.1", Port: 2112, MetricsPath: "/metrics", Enabled: false}); err != nil {
			t.Fatal(err)
		}
	}
	add("snapshot")
	manager := store.NewBackupManager(s, filepath.Join(directory, "backups"), path, 7)
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	add("after-backup")
	if err = manager.StageRestore(info.Name); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(config.EnvDataDirectory, directory)
	t.Setenv(config.EnvListenAddress, listener.Addr().String())
	t.Setenv(config.EnvAdminUsername, "admin")
	t.Setenv(config.EnvAdminPassword, "test-startup-password")
	t.Setenv(config.EnvGeoIPDatabasePath, "")
	t.Setenv(config.EnvGeoIPOnline, "false")
	if err = run(); err == nil {
		t.Fatal("startup succeeded with occupied listener")
	}
	if _, err = os.Stat(path + ".restore-journal"); err != nil {
		t.Fatalf("restore was finalized before listener startup: %v", err)
	}
	if applied, err := store.ApplyPendingRestore(path); err != nil || applied {
		t.Fatalf("failed startup did not roll back: %v %v", applied, err)
	}
	recovered, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	machines, err := recovered.ListMachines(ctx)
	if err != nil || len(machines) != 2 {
		t.Fatalf("startup failure lost old generation: %+v %v", machines, err)
	}
}
