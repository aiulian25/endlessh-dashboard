package store

import (
	"context"
	"testing"
	"time"
)

func TestPortHistoryBoundaryAtomicityRetentionAndRestart(t *testing.T) {
	s, path := newStore(t)
	ctx := context.Background()
	m := createMachine(t, s, "ports")
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 99})
	later := baseTime.Add(time.Minute)
	d := ScrapeDelta{MachineID: m.ID, At: later, Opens: 7, Closes: 3, BytesSent: 70, TrappedSeconds: 17, Ports: []PortDelta{{Port: "22", Opens: 2, Closes: 1, BytesSent: 20, TrappedSeconds: 5}, {Port: "2222", Opens: 5, Closes: 2, BytesSent: 50, TrappedSeconds: 12}}}
	if err := s.ApplyScrape(ctx, d); err != nil {
		t.Fatal(err)
	}
	old, err := s.PortSummary(ctx, []int64{m.ID}, baseTime, later, "")
	if err != nil {
		t.Fatal(err)
	}
	if old.Available || len(old.Rows) != 0 || old.CollectionStartedAt == nil || !old.CollectionStartedAt.Equal(later) {
		t.Fatalf("invented history: %+v", old)
	}
	end := later.Add(time.Minute)
	summary, err := s.PortSummary(ctx, []int64{m.ID}, later, end, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Rows) != 2 || summary.Rows[0].Opens+summary.Rows[1].Opens != 7 {
		t.Fatalf("port totals: %+v", summary)
	}
	all, err := s.TimeSeries(ctx, []Machine{m}, later, end, 60)
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, port := range []string{"22", "2222"} {
		series, err := s.TimeSeriesForPort(ctx, []Machine{m}, later, end, 60, port)
		if err != nil {
			t.Fatal(err)
		}
		sum += series[0].Points[0].Opens
	}
	if sum != all[0].Points[0].Opens {
		t.Fatal("ports differ from machine history")
	}
	bad := d
	bad.At = end
	bad.Ports = []PortDelta{{Port: "22", Opens: 1}}
	if err := s.ApplyScrape(ctx, bad); err == nil {
		t.Fatal("inconsistent ports committed")
	}
	if got := scanInt(t, s, "SELECT opens FROM machine_totals WHERE machine_id=?", m.ID); got != 106 {
		t.Fatalf("failed transaction changed totals: %d", got)
	}
	// Force a port INTEGER overflow while machine totals remain safe; all writes
	// (including the revision and machine rollup) must roll back together.
	if _, err := s.DB().Exec(`UPDATE port_rollups SET opens=9223372036854775807 WHERE port='22'`); err != nil {
		t.Fatal(err)
	}
	poison := ScrapeDelta{MachineID: m.ID, At: later.Add(time.Second), Opens: 1, Ports: []PortDelta{{Port: "22", Opens: 1}}}
	if err := s.ApplyScrape(ctx, poison); err == nil {
		t.Fatal("overflow committed")
	}
	if got := scanInt(t, s, "SELECT opens FROM machine_totals WHERE machine_id=?", m.ID); got != 106 {
		t.Fatal("overflow changed machine totals")
	}
	if _, err := s.DB().Exec(`UPDATE port_rollups SET opens=2 WHERE port='22'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err = s.PortSummary(ctx, []int64{m.ID}, later, end, "22")
	if err != nil || len(summary.Rows) != 1 || summary.Rows[0].Opens != 2 {
		t.Fatalf("restart lost port history: %+v %v", summary, err)
	}
	if _, err = s.Prune(ctx, end); err != nil {
		t.Fatal(err)
	}
	summary, err = s.PortSummary(ctx, []int64{m.ID}, later, end, "")
	if err != nil || summary.Available || summary.CollectionStartedAt == nil {
		t.Fatal("retention lost boundary or retained expired values", err)
	}
	if err = s.DeleteMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if n := scanInt(t, s, `SELECT COUNT(*) FROM port_collection`); n != 0 {
		t.Fatal("machine deletion left port metadata")
	}
}

func TestPortMigrationAndBackupCompatibility(t *testing.T) {
	s, manager, _ := newBackupManager(t, 2)
	ctx := context.Background()
	m := createMachine(t, s, "port backup")
	applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 4})
	// Reconstruct the previous genuine schema, preserving merged history.
	if _, err := s.DB().Exec(`DROP TABLE port_rollups; DROP TABLE port_collection; DELETE FROM schema_migrations WHERE version=13`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err := s.PortSummary(ctx, []int64{m.ID}, baseTime, baseTime.Add(time.Minute), "")
	if err != nil || summary.Available || summary.CollectionStartedAt != nil {
		t.Fatal("migration fabricated data", err)
	}
	d := ScrapeDelta{MachineID: m.ID, At: baseTime.Add(time.Minute), Opens: 3, Ports: []PortDelta{{Port: "22", Opens: 3}}}
	if err = s.ApplyScrape(ctx, d); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.StageRestore(info.Name); err != nil {
		t.Fatal("port schema backup rejected", err)
	}
}
