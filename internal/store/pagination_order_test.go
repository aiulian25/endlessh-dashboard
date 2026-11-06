package store

import (
	"context"
	"fmt"
	"testing"
)

func TestAttackerPagesUseCompleteOrderingKey(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var ids []int64
	for i := range 3 {
		m := createMachine(t, s, fmt.Sprintf("machine-%d", i))
		ids = append(ids, m.ID)
		applyScrape(t, s, ScrapeDelta{MachineID: m.ID, At: baseTime, Attackers: []AttackerDelta{
			{IPAddress: "192.0.2.2", Connections: 5, TrappedSeconds: 7, Country: "Germany"},
			{IPAddress: "192.0.2.1", Connections: 5, TrappedSeconds: 7, Country: "Germany"},
		}})
	}
	// Deliberately reverse caller selection; it must not define tied-row order.
	selected := []int64{ids[2], ids[1], ids[0]}
	for column := range attackerSortColumns {
		for _, descending := range []bool{false, true} {
			seen := map[string]bool{}
			for page := 1; page <= 3; page++ {
				got, err := s.ListAttackers(ctx, AttackerFilter{MachineIDs: selected, SortColumn: column, SortDescending: descending, Page: page, PerPage: 2})
				if err != nil || got.Total != 6 || len(got.Rows) != 2 {
					t.Fatalf("%s: %+v %v", column, got, err)
				}
				for j, row := range got.Rows {
					index := (page-1)*2 + j
					wantIP := fmt.Sprintf("192.0.2.%d", index/3+1)
					// IP itself is the primary sort for this particular column.
					if column == "ip" && descending {
						wantIP = fmt.Sprintf("192.0.2.%d", 2-index/3)
					}
					if row.IPAddress != wantIP || row.MachineID != ids[index%3] {
						t.Fatalf("%s desc=%t page=%d: %+v", column, descending, page, got.Rows)
					}
					key := fmt.Sprintf("%s/%d", row.IPAddress, row.MachineID)
					if seen[key] {
						t.Fatal("repeated row", key)
					}
					seen[key] = true
				}
			}
		}
	}
	latest, ok, err := s.LatestAttacker(ctx, selected)
	if err != nil || !ok || latest.MachineID != ids[0] || latest.IPAddress != "192.0.2.1" {
		t.Fatal(latest, ok, err)
	}
}
