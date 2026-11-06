package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func insertRollup(t *testing.T, store *Store, machineID int64, bucket time.Time, opens int64) {
	t.Helper()
	_, err := store.DB().Exec(
		`INSERT INTO machine_rollups (machine_id, bucket, opens, closes, bytes_sent, trapped_seconds)
		 VALUES (?, ?, ?, 0, 0, 0)`,
		machineID, bucket.Unix(), opens)
	if err != nil {
		t.Fatalf("insert rollup at %v: %v", bucket, err)
	}
}

func insertAttacker(t *testing.T, store *Store, machineID int64, ip string, lastSeen time.Time) {
	t.Helper()
	_, err := store.DB().Exec(
		`INSERT INTO attackers
			(machine_id, ip_address, first_seen, last_seen, last_activity_at, connections, trapped_seconds, country, geohash, location)
		 VALUES (?, ?, ?, ?, ?, 1, 1, 'US', '', '')`,
		machineID, ip, lastSeen.Unix(), lastSeen.Unix(), lastSeen.Unix())
	if err != nil {
		t.Fatalf("insert attacker %s: %v", ip, err)
	}
}

func TestPruneKeepsTheCutoffBoundary(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	cutoff := baseTime
	insertRollup(t, store, machine.ID, cutoff.Add(-2*time.Minute), 1)
	insertRollup(t, store, machine.ID, cutoff.Add(-time.Minute), 2)
	insertRollup(t, store, machine.ID, cutoff, 3)
	insertRollup(t, store, machine.ID, cutoff.Add(time.Minute), 4)

	insertAttacker(t, store, machine.ID, "10.0.0.1", cutoff.Add(-time.Hour))
	insertAttacker(t, store, machine.ID, "10.0.0.2", cutoff.Add(-time.Second))
	insertAttacker(t, store, machine.ID, "10.0.0.3", cutoff)
	insertAttacker(t, store, machine.ID, "10.0.0.4", cutoff.Add(time.Hour))

	stats, err := store.Prune(ctx, cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	assertInt(t, "pruned rollups", stats.Rollups, 2)
	assertInt(t, "pruned attackers", stats.Attackers, 2)

	assertInt(t, "rollups left", scanInt(t, store, "SELECT COUNT(*) FROM machine_rollups"), 2)
	assertInt(t, "boundary rollup survives", scanInt(t, store,
		"SELECT COUNT(*) FROM machine_rollups WHERE bucket = ?", cutoff.Unix()), 1)
	assertInt(t, "oldest surviving rollup", scanInt(t, store,
		"SELECT MIN(bucket) FROM machine_rollups"), cutoff.Unix())

	assertInt(t, "attackers left", scanInt(t, store, "SELECT COUNT(*) FROM attackers"), 2)
	assertInt(t, "boundary attacker survives", scanInt(t, store,
		"SELECT COUNT(*) FROM attackers WHERE ip_address = '10.0.0.3'"), 1)
	assertInt(t, "attacker one second before the cutoff is gone", scanInt(t, store,
		"SELECT COUNT(*) FROM attackers WHERE ip_address = '10.0.0.2'"), 0)
}

func TestPruneKeepsAggregateCounterStates(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	cutoff := baseTime
	stale := cutoff.Add(-time.Hour)
	fresh := cutoff.Add(time.Hour)

	staleStates := map[string]float64{
		SeriesPrefixClient + "10.0.0.1": 5,
		SeriesPrefixClient + "10.0.0.2": 6,
		SeriesPrefixTotal + "opens":     100,
		SeriesPrefixTotal + "bytes":     200,
	}
	seedCounterStates(t, store, machine.ID, staleStates, stale)
	freshStates := map[string]float64{
		SeriesPrefixClient + "10.0.0.9": 7,
		SeriesPrefixTotal + "closes":    300,
	}
	seedCounterStates(t, store, machine.ID, freshStates, fresh)

	stats, err := store.Prune(ctx, cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	assertInt(t, "pruned counter states", stats.CounterStates, 2)

	states, err := store.LoadCounterStates(ctx, machine.ID)
	if err != nil {
		t.Fatalf("LoadCounterStates: %v", err)
	}
	for _, series := range []string{SeriesPrefixTotal + "opens", SeriesPrefixTotal + "bytes", SeriesPrefixTotal + "closes"} {
		if _, ok := states[series]; !ok {
			t.Errorf("aggregate series %q was pruned; the next scrape would lose its delta", series)
		}
	}
	assertFloat(t, "stale aggregate value kept", states[SeriesPrefixTotal+"opens"], 100)

	if _, ok := states[SeriesPrefixClient+"10.0.0.9"]; !ok {
		t.Error("fresh per-client series was pruned")
	}
	for _, series := range []string{SeriesPrefixClient + "10.0.0.1", SeriesPrefixClient + "10.0.0.2"} {
		if _, ok := states[series]; ok {
			t.Errorf("stale per-client series %q survived pruning", series)
		}
	}
	if len(states) != 4 {
		t.Errorf("counter_states holds %d rows (%v), want 4", len(states), states)
	}
}

func TestPruneLeavesLifetimeTotals(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	old := baseTime.Add(-24 * time.Hour)
	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID, At: old,
		Opens: 40, Closes: 30, BytesSent: 4096, TrappedSeconds: 900,
		Attackers: []AttackerDelta{{IPAddress: "10.0.0.1", Connections: 3, TrappedSeconds: 900, Active: true}},
	})

	before, err := store.Overview(ctx, []int64{machine.ID}, time.Unix(0, 0), time.Unix(0, 0))
	if err != nil {
		t.Fatalf("Overview before prune: %v", err)
	}

	stats, err := store.Prune(ctx, baseTime)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if stats.Rollups == 0 || stats.Attackers == 0 {
		t.Fatalf("Prune removed nothing: %+v", stats)
	}

	assertInt(t, "totals opens", scanInt(t, store,
		"SELECT opens FROM machine_totals WHERE machine_id = ?", machine.ID), 40)
	assertInt(t, "totals bytes_sent", scanInt(t, store,
		"SELECT bytes_sent FROM machine_totals WHERE machine_id = ?", machine.ID), 4096)
	assertFloat(t, "totals trapped_seconds", scanFloat(t, store,
		"SELECT trapped_seconds FROM machine_totals WHERE machine_id = ?", machine.ID), 900)
	// The only attacker was last seen before the cutoff, so its row is gone.
	assertInt(t, "retained distinct attackers", scanInt(t, store,
		"SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE machine_id = ?", machine.ID), 0)

	after, err := store.Overview(ctx, []int64{machine.ID}, time.Unix(0, 0), time.Unix(0, 0))
	if err != nil {
		t.Fatalf("Overview after prune: %v", err)
	}
	// Time and bytes are lifetime counters held in machine_totals, so pruning
	// history must not move them.
	assertFloat(t, "headline TimeWastedSeconds survives pruning", after.TimeWastedSeconds, before.TimeWastedSeconds)
	assertInt(t, "headline BytesSent survives pruning", after.BytesSent, before.BytesSent)

	// The attacker headline is deliberately different: it is the cardinality of
	// the attacker rows still retained, counted fresh each time. It therefore
	// falls when those rows are pruned, and — unlike a stored running total — it
	// cannot double-count an IP that is pruned and later returns.
	assertInt(t, "AttackersTrapped before pruning", before.AttackersTrapped, 1)
	assertInt(t, "AttackersTrapped reflects only retained rows", after.AttackersTrapped, 0)
}

func TestPruneClearsExpiredSessions(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, User{Username: "admin", PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	now := time.Now()
	sessions := []Session{
		{TokenHash: "expired", UserID: user.ID, CSRFToken: "a", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{TokenHash: "live", UserID: user.ID, CSRFToken: "b", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for _, session := range sessions {
		if err := store.CreateSession(ctx, session, user.PasswordHash); err != nil {
			t.Fatalf("CreateSession(%s): %v", session.TokenHash, err)
		}
	}

	stats, err := store.Prune(ctx, baseTime)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	assertInt(t, "pruned sessions", stats.Sessions, 1)
	assertInt(t, "sessions left", scanInt(t, store, "SELECT COUNT(*) FROM sessions"), 1)
	assertInt(t, "the live session is the survivor", scanInt(t, store,
		"SELECT COUNT(*) FROM sessions WHERE token_hash = 'live'"), 1)
}

func TestPruneFreesPages(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	const rowCount = 4000
	padding := ""
	for len(padding) < 120 {
		padding += "location-padding-"
	}

	transaction, err := store.DB().Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	statement, err := transaction.Prepare(
		`INSERT INTO attackers
			(machine_id, ip_address, first_seen, last_seen, last_activity_at, connections, trapped_seconds, country, geohash, location)
		 VALUES (?, ?, ?, ?, ?, 1, 1, 'US', 'u4pruyd', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	stale := baseTime.Add(-time.Hour).Unix()
	for index := 0; index < rowCount; index++ {
		ip := fmt.Sprintf("10.%d.%d.%d", index/65536, (index/256)%256, index%256)
		if _, err := statement.Exec(machine.ID, ip, stale, stale, stale, padding); err != nil {
			t.Fatalf("insert attacker %d: %v", index, err)
		}
	}
	statement.Close()
	if err := transaction.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	pagesBefore := scanInt(t, store, "PRAGMA page_count")

	stats, err := store.Prune(ctx, baseTime)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	assertInt(t, "pruned attackers", stats.Attackers, rowCount)

	if stats.PagesFreed <= 0 {
		t.Fatalf("PagesFreed = %d, want a positive number — incremental auto-vacuum is not reclaiming space", stats.PagesFreed)
	}
	pagesAfter := scanInt(t, store, "PRAGMA page_count")
	if pagesAfter >= pagesBefore {
		t.Errorf("page_count went from %d to %d, want it to shrink", pagesBefore, pagesAfter)
	}
	if pagesBefore-pagesAfter != stats.PagesFreed {
		t.Errorf("PagesFreed = %d, but page_count dropped by %d", stats.PagesFreed, pagesBefore-pagesAfter)
	}
}
