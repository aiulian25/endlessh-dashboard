package scrape

import (
	"context"
	"database/sql"
	"math"
	"testing"

	"endlessh-dashboard/internal/store"
)

func readCoordinate(t *testing.T, dataStore *store.Store, machineID int64, ipAddress string) (sql.NullFloat64, sql.NullFloat64) {
	t.Helper()
	var latitude, longitude sql.NullFloat64
	if err := dataStore.DB().QueryRow(
		"SELECT latitude, longitude FROM attackers WHERE machine_id = ? AND ip_address = ?",
		machineID, ipAddress).Scan(&latitude, &longitude); err != nil {
		t.Fatalf("read coordinate for %s: %v", ipAddress, err)
	}
	return latitude, longitude
}

// TestPollerStoresCoordinateFromGeohash covers the free geography source: the
// tarpit already published a geohash, so the map costs nothing to fill.
func TestPollerStoresCoordinateFromGeohash(t *testing.T) {
	dataStore, poller, _, machine := newScrapeFixture(t, "normal.txt")

	poller.pollOne(context.Background(), machine)

	// u0yjjd6, the geohash the fixture labels this client with, is Frankfurt.
	latitude, longitude := readCoordinate(t, dataStore, machine.ID, "45.155.205.233")
	if !latitude.Valid || !longitude.Valid {
		t.Fatal("a client with a usable geohash was stored without a coordinate")
	}
	if math.Abs(latitude.Float64-50.11) > 0.01 || math.Abs(longitude.Float64-8.68) > 0.01 {
		t.Errorf("coordinate = %v,%v, want Frankfurt at 50.11,8.68",
			latitude.Float64, longitude.Float64)
	}
}

// TestPollerPlaceholderGeohashNeverBecomesACoordinate is the whole reason the
// decoder rejects "s000" by name: it is a real point in the Atlantic, so a
// tarpit with GeoIP switched off would otherwise pin every one of its attackers
// to the same empty patch of ocean.
func TestPollerPlaceholderGeohashNeverBecomesACoordinate(t *testing.T) {
	dataStore, poller, _, machine := newScrapeFixture(t, "geoip-off.txt")

	poller.pollOne(context.Background(), machine)

	placed := countRows(t, dataStore,
		"SELECT COUNT(*) FROM attackers WHERE machine_id = ? AND latitude IS NOT NULL", machine.ID)
	if placed != 0 {
		t.Errorf("%d attackers got a coordinate from the GeoIP-off placeholder, want none", placed)
	}
	if total := countAttackers(t, dataStore, machine.ID); total == 0 {
		t.Fatal("the fixture stored no attackers at all, so the check above proves nothing")
	}
}
