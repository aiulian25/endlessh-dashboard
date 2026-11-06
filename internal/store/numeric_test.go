package store

import (
	"context"
	"encoding/json"
	"math"
	"testing"
)

func numericHistory(t *testing.T, s *Store) string {
	t.Helper()
	out := map[string][][]any{}
	for _, table := range []string{"machine_totals", "machine_rollups", "attackers", "counter_states"} {
		rows, err := s.DB().Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			out[table] = append(out[table], values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestNumericOverflowRollsBackCompleteScrape(t *testing.T) {
	for _, kind := range []string{"integer", "rollup", "time", "attacker", "nonfinite", "negative"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			m := createMachine(t, s, "numeric")
			ctx := context.Background()
			seed := ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 1, TrappedSeconds: 1, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 1, TrappedSeconds: 1}}, CounterStates: map[string]float64{"test": 1}}
			switch kind {
			case "integer":
				seed.Opens = math.MaxInt64
			case "rollup":
				seed.BytesSent = math.MaxInt64
			case "time":
				seed.TrappedSeconds = math.MaxFloat64
			case "attacker":
				seed.Attackers[0].Connections = math.MaxInt64
			}
			if err := s.ApplyScrape(ctx, seed); err != nil {
				t.Fatal(err)
			}
			// Separate rollup overflow from machine lifetime overflow.
			if kind == "rollup" {
				if _, err := s.DB().Exec("UPDATE machine_totals SET bytes_sent=0"); err != nil {
					t.Fatal(err)
				}
			}
			before := numericHistory(t, s)
			next := ScrapeDelta{MachineID: m.ID, At: baseTime, Opens: 1, BytesSent: 1, TrappedSeconds: math.MaxFloat64, Attackers: []AttackerDelta{{IPAddress: "192.0.2.1", Connections: 1}}, CounterStates: map[string]float64{"test": 2}}
			if kind == "nonfinite" {
				next.TrappedSeconds = math.Inf(1)
			}
			if kind == "negative" {
				next.Opens = -1
			}
			if err := s.ApplyScrape(ctx, next); err == nil {
				t.Fatal("invalid or overflowing scrape committed")
			}
			if after := numericHistory(t, s); after != before {
				t.Fatal("rejection left partial history/baseline changes")
			}
		})
	}
}
