package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

func coordinate(latitude, longitude float64) (*float64, *float64) {
	return &latitude, &longitude
}

func scanNullableFloat(t *testing.T, store *Store, query string, args ...any) sql.NullFloat64 {
	t.Helper()
	var value sql.NullFloat64
	if err := store.DB().QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return value
}

// geographyFixture seeds two machines with attackers whose coordinates, shared
// addresses and missing data make every geography query observable:
//   - two San Francisco addresses that must collapse into one bubble
//   - one Berlin address seen by both machines: one attacker, two sets of traffic
//   - one address with a country but no coordinate: on the breakdown, off the map
//   - one stale address outside the window
func geographyFixture(t *testing.T, store *Store) (Machine, Machine) {
	t.Helper()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	sanFranciscoLatitude, sanFranciscoLongitude := coordinate(37.7749, -122.4194)
	nearbyLatitude, nearbyLongitude := coordinate(37.7751, -122.4180)
	berlinLatitude, berlinLongitude := coordinate(52.5200, 13.4050)
	tokyoLatitude, tokyoLongitude := coordinate(35.6762, 139.6503)

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: baseTime, Attackers: []AttackerDelta{
		{
			IPAddress: "1.1.1.1", Connections: 10, TrappedSeconds: 100,
			Country: "United States", CountryCode: "US", Location: "United States, California, San Francisco",
			Latitude: sanFranciscoLatitude, Longitude: sanFranciscoLongitude,
		},
		{
			IPAddress: "1.1.1.2", Connections: 5, TrappedSeconds: 50,
			Country: "United States", CountryCode: "US", Location: "United States, California, San Francisco",
			Latitude: nearbyLatitude, Longitude: nearbyLongitude,
		},
		{
			IPAddress: "2.2.2.1", Connections: 100, TrappedSeconds: 20,
			Country: "Germany", CountryCode: "DE", Location: "Germany, Berlin",
			Latitude: berlinLatitude, Longitude: berlinLongitude,
		},
		{
			IPAddress: "3.3.3.3", Connections: 1, TrappedSeconds: 5,
			Country: "France", CountryCode: "FR", Location: "France",
		},
	}})

	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: baseTime, Attackers: []AttackerDelta{{
		IPAddress: "2.2.2.1", Connections: 30, TrappedSeconds: 7,
		Country: "Germany", CountryCode: "DE", Location: "Germany, Berlin",
		Latitude: berlinLatitude, Longitude: berlinLongitude,
	}}})

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: baseTime.Add(-2 * time.Hour), Attackers: []AttackerDelta{{
		IPAddress: "4.4.4.4", Connections: 999, TrappedSeconds: 999,
		Country: "Japan", CountryCode: "JP", Location: "Japan, Tokyo",
		Latitude: tokyoLatitude, Longitude: tokyoLongitude,
	}}})

	return alpha, beta
}

func TestGeoPointsGroupByPlace(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha, beta := geographyFixture(t, store)

	points, err := store.GeoPoints(ctx, []int64{alpha.ID, beta.ID}, baseTime)
	if err != nil {
		t.Fatalf("GeoPoints: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("got %d bubbles (%+v), want two: one per city, with the coordinate-less and stale rows left out", len(points), points)
	}

	// Berlin carries more connections than the two San Francisco addresses put
	// together, so it leads.
	berlin := points[0]
	assertFloat(t, "berlin latitude", berlin.Latitude, 52.5)
	assertFloat(t, "berlin longitude", berlin.Longitude, 13.4)
	if berlin.Country != "Germany" || berlin.CountryCode != "DE" {
		t.Errorf("berlin labels = %q/%q, want Germany/DE", berlin.Country, berlin.CountryCode)
	}
	// One address seen by two machines is one attacker but both machines' traffic.
	assertInt(t, "berlin attackers", int64(berlin.Attackers), 1)
	assertInt(t, "berlin connections", berlin.Connections, 130)
	assertFloat(t, "berlin trapped seconds", berlin.TrappedSeconds, 27)

	sanFrancisco := points[1]
	assertFloat(t, "san francisco latitude", sanFrancisco.Latitude, 37.8)
	assertFloat(t, "san francisco longitude", sanFrancisco.Longitude, -122.4)
	// Two addresses a few hundred metres apart are one bubble, not two.
	assertInt(t, "san francisco attackers", int64(sanFrancisco.Attackers), 2)
	assertInt(t, "san francisco connections", sanFrancisco.Connections, 15)
	assertFloat(t, "san francisco trapped seconds", sanFrancisco.TrappedSeconds, 150)

	onlyBeta, err := store.GeoPoints(ctx, []int64{beta.ID}, baseTime)
	if err != nil {
		t.Fatalf("GeoPoints for one machine: %v", err)
	}
	if len(onlyBeta) != 1 || onlyBeta[0].Connections != 30 {
		t.Errorf("beta's bubbles = %+v, want only its own Berlin traffic", onlyBeta)
	}

	all, err := store.GeoPoints(ctx, []int64{alpha.ID, beta.ID}, time.Time{})
	if err != nil {
		t.Fatalf("GeoPoints without a window: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("got %d bubbles without a window, want the stale one back", len(all))
	}

	if none, err := store.GeoPoints(ctx, nil, baseTime); err != nil || none != nil {
		t.Errorf("GeoPoints with no machines = %v, %v, want nil, nil", none, err)
	}
}

func TestCountryTotals(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha, beta := geographyFixture(t, store)

	totals, err := store.CountryTotals(ctx, []int64{alpha.ID, beta.ID}, baseTime)
	if err != nil {
		t.Fatalf("CountryTotals: %v", err)
	}

	want := []CountryTotal{
		// Two distinct addresses beat one, however much traffic the one made.
		{Country: "United States", CountryCode: "US", CountryKey: "code:US", Attackers: 2, Connections: 15},
		// One address on two machines is one attacker, and both machines' traffic.
		{Country: "Germany", CountryCode: "DE", CountryKey: "code:DE", Attackers: 1, Connections: 130},
		{Country: "France", CountryCode: "FR", CountryKey: "code:FR", Attackers: 1, Connections: 1},
	}
	if len(totals) != len(want) {
		t.Fatalf("got %d countries (%+v), want %d", len(totals), totals, len(want))
	}
	for index, expected := range want {
		if totals[index] != expected {
			t.Errorf("position %d = %+v, want %+v", index, totals[index], expected)
		}
	}

	windowed, err := store.CountryTotals(ctx, []int64{alpha.ID, beta.ID}, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("CountryTotals with a later window: %v", err)
	}
	if len(windowed) != 0 {
		t.Errorf("a window past every sighting returned %+v, want nothing", windowed)
	}

	if none, err := store.CountryTotals(ctx, nil, baseTime); err != nil || none != nil {
		t.Errorf("CountryTotals with no machines = %v, %v, want nil, nil", none, err)
	}
}

func TestCountryTotalsIgnoresUnknownCountries(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "5.5.5.1", Connections: 1, Country: "Spain", CountryCode: "ES"},
		{IPAddress: "5.5.5.2", Connections: 1},
	}})

	totals, err := store.CountryTotals(ctx, []int64{machine.ID}, time.Time{})
	if err != nil {
		t.Fatalf("CountryTotals: %v", err)
	}
	if len(totals) != 1 || totals[0].Country != "Spain" {
		t.Errorf("totals = %+v, want only the country that is known", totals)
	}
}

func TestLatestAttacker(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	if _, found, err := store.LatestAttacker(ctx, nil); err != nil || found {
		t.Errorf("LatestAttacker with no machines = %v, %v, want no row", found, err)
	}

	alpha, beta := geographyFixture(t, store)
	if _, found, err := store.LatestAttacker(ctx, []int64{alpha.ID + beta.ID + 999}); err != nil || found {
		t.Errorf("LatestAttacker for an unknown machine = %v, %v, want no row", found, err)
	}

	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: baseTime.Add(time.Hour), Attackers: []AttackerDelta{{
		IPAddress: "9.9.9.9", Connections: 2, TrappedSeconds: 3,
		Country: "Sweden", CountryCode: "SE", Location: "Sweden, Stockholm",
		Geohash: "u6sce",
	}}})

	row, found, err := store.LatestAttacker(ctx, []int64{alpha.ID, beta.ID})
	if err != nil {
		t.Fatalf("LatestAttacker: %v", err)
	}
	if !found {
		t.Fatal("LatestAttacker found nothing after a scrape")
	}
	if row.IPAddress != "9.9.9.9" || row.MachineName != "beta" {
		t.Errorf("latest = %s on %q, want 9.9.9.9 on beta", row.IPAddress, row.MachineName)
	}
	if row.Country != "Sweden" || row.CountryCode != "SE" || row.Geohash != "u6sce" {
		t.Errorf("latest row = %+v, want the geography it was scraped with", row)
	}
	if !row.LastSeen.Equal(baseTime.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want %v", row.LastSeen, baseTime.Add(time.Hour))
	}

	// Restricted to the other machine, the newest row is that machine's own.
	onlyAlpha, found, err := store.LatestAttacker(ctx, []int64{alpha.ID})
	if err != nil || !found {
		t.Fatalf("LatestAttacker for alpha = %v, %v", found, err)
	}
	if onlyAlpha.MachineName != "alpha" {
		t.Errorf("latest for alpha came from %q", onlyAlpha.MachineName)
	}
}

func TestListAttackersCarriesGeography(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha, beta := geographyFixture(t, store)

	page, err := store.ListAttackers(ctx, AttackerFilter{
		MachineIDs: []int64{alpha.ID, beta.ID},
		Search:     "1.1.1.1",
		Page:       1,
		PerPage:    10,
	})
	if err != nil {
		t.Fatalf("ListAttackers: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(page.Rows))
	}
	row := page.Rows[0]
	if row.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want US", row.CountryCode)
	}
	if row.Latitude == nil || row.Longitude == nil {
		t.Fatalf("row carries no coordinate: %+v", row)
	}
	assertFloat(t, "row latitude", *row.Latitude, 37.7749)
	assertFloat(t, "row longitude", *row.Longitude, -122.4194)

	withoutCoordinates, err := store.ListAttackers(ctx, AttackerFilter{
		MachineIDs: []int64{alpha.ID},
		Search:     "3.3.3.3",
		Page:       1,
		PerPage:    10,
	})
	if err != nil {
		t.Fatalf("ListAttackers: %v", err)
	}
	if len(withoutCoordinates.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(withoutCoordinates.Rows))
	}
	// 0,0 is a real place, so an attacker nobody could place must arrive as nil.
	if withoutCoordinates.Rows[0].Latitude != nil || withoutCoordinates.Rows[0].Longitude != nil {
		t.Errorf("unplaced attacker carries a coordinate: %+v", withoutCoordinates.Rows[0])
	}
}

func TestAttackersMissingLocation(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: baseTime, Attackers: []AttackerDelta{
		// Placed from the tarpit's own labels: it has a location, but labels
		// carry no ISO code and no network operator, so it still needs a lookup.
		{IPAddress: "6.6.6.1", Country: "Germany", Location: "Germany, Berlin"},
		{IPAddress: "6.6.6.2"},
	}})
	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: baseTime.Add(time.Minute), Attackers: []AttackerDelta{
		// The same unplaced address on a second machine: one address to resolve.
		{IPAddress: "6.6.6.2"},
		{IPAddress: "6.6.6.3"},
	}})

	missing, err := store.AttackersMissingLocation(ctx, 10)
	if err != nil {
		t.Fatalf("AttackersMissingLocation: %v", err)
	}
	if len(missing) != 3 {
		t.Fatalf("got %+v, want every address that is not fully placed", missing)
	}
	queued := map[string]bool{}
	for _, entry := range missing {
		queued[entry.IPAddress] = true
		if entry.MachineID == 0 {
			t.Errorf("entry %+v carries no machine", entry)
		}
	}
	if !queued["6.6.6.1"] {
		t.Error("an address placed from labels, with no country code or ISP, was not queued for lookup")
	}

	// Once it is fully placed it must drop out, or the enricher would look the
	// same address up on every sweep for the life of the process.
	if err := store.SetAttackerLocation(ctx, "6.6.6.1", AttackerLocation{
		Country: "Germany", CountryCode: "DE", Location: "Germany, Berlin", ISP: "Example AS",
	}); err != nil {
		t.Fatalf("SetAttackerLocation: %v", err)
	}
	afterPlacing, err := store.AttackersMissingLocation(ctx, 10)
	if err != nil {
		t.Fatalf("AttackersMissingLocation after placing: %v", err)
	}
	for _, entry := range afterPlacing {
		if entry.IPAddress == "6.6.6.1" {
			t.Errorf("a fully placed address is still queued for lookup: %+v", entry)
		}
	}

	limited, err := store.AttackersMissingLocation(ctx, 1)
	if err != nil {
		t.Fatalf("AttackersMissingLocation with a limit: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limit of 1 returned %d rows", len(limited))
	}
	// Newest sighting first, so a fresh attacker is placed before an old one.
	if limited[0].IPAddress != "6.6.6.3" && limited[0].IPAddress != "6.6.6.2" {
		t.Errorf("first row = %+v, want the most recently seen address", limited[0])
	}

	if none, err := store.AttackersMissingLocation(ctx, 0); err != nil || none != nil {
		t.Errorf("AttackersMissingLocation with no limit = %v, %v, want nil, nil", none, err)
	}
}

func TestSetAttackerLocationAppliesToEveryMachine(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	for _, machine := range []Machine{alpha, beta} {
		applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
			{IPAddress: "7.7.7.7", Connections: 1},
			{IPAddress: "8.8.8.8", Connections: 1},
		}})
	}

	latitude, longitude := coordinate(59.3293, 18.0686)
	if err := store.SetAttackerLocation(ctx, "7.7.7.7", AttackerLocation{
		Country:     "Sweden",
		CountryCode: "SE",
		Location:    "Sweden, Stockholm",
		ISP:         "Bahnhof AB",
		Latitude:    latitude,
		Longitude:   longitude,
	}); err != nil {
		t.Fatalf("SetAttackerLocation: %v", err)
	}

	placed := scanInt(t, store,
		`SELECT COUNT(*) FROM attackers
		 WHERE ip_address = '7.7.7.7' AND country = 'Sweden' AND country_code = 'SE'
		   AND location = 'Sweden, Stockholm' AND isp = 'Bahnhof AB'
		   AND latitude IS NOT NULL AND longitude IS NOT NULL`)
	assertInt(t, "rows updated for the address", placed, 2)

	untouched := scanInt(t, store,
		"SELECT COUNT(*) FROM attackers WHERE ip_address = '8.8.8.8' AND country = ''")
	assertInt(t, "rows left alone", untouched, 2)

	// A later resolver that knows less must not erase what is already known.
	if err := store.SetAttackerLocation(ctx, "7.7.7.7", AttackerLocation{}); err != nil {
		t.Fatalf("SetAttackerLocation with an empty result: %v", err)
	}
	if country := scanText(t, store, "SELECT country FROM attackers WHERE ip_address = '7.7.7.7' LIMIT 1"); country != "Sweden" {
		t.Errorf("country = %q after an empty update, want it preserved", country)
	}
	if stored := scanNullableFloat(t, store, "SELECT latitude FROM attackers WHERE ip_address = '7.7.7.7' LIMIT 1"); !stored.Valid {
		t.Error("latitude was erased by an empty update")
	}

	if err := store.SetAttackerLocation(ctx, "192.0.2.254", AttackerLocation{Country: "Sweden"}); err != nil {
		t.Errorf("SetAttackerLocation for an unknown address = %v, want nil", err)
	}
}

// The resolver is there to finish a half-placed row, not to restate the parts
// the tarpit already reported in its own words. It spells countries differently
// from any given tarpit — "The Netherlands" against "Netherlands" — and the
// country name is what the breakdown groups on, so overwriting it would split
// one country into two rows.
func TestSetAttackerLocationFillsWhatTheTarpitDidNotReport(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	labelLatitude, labelLongitude := coordinate(52.37, 4.89)
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
		// Placed from the tarpit's own labels: a country and a location, decoded
		// down to a geohash coordinate, but no ISO code and no network operator.
		{
			IPAddress: "5.5.5.5", Connections: 1,
			Country: "Netherlands", Location: "Netherlands, Amsterdam",
			Latitude: labelLatitude, Longitude: labelLongitude,
		},
		// A tarpit running without geography publishes nothing to preserve.
		{IPAddress: "5.5.5.6", Connections: 1},
	}})

	resolved := AttackerLocation{
		Country: "The Netherlands", CountryCode: "NL",
		Location: "The Netherlands, North Holland, Amsterdam", ISP: "Example Hosting",
	}
	for _, address := range []string{"5.5.5.5", "5.5.5.6"} {
		if err := store.SetAttackerLocation(ctx, address, resolved); err != nil {
			t.Fatalf("SetAttackerLocation(%s): %v", address, err)
		}
	}

	labelled := func(column string) string {
		return scanText(t, store, "SELECT "+column+" FROM attackers WHERE ip_address = '5.5.5.5'")
	}
	if country := labelled("country"); country != "Netherlands" {
		t.Errorf("country = %q, want the tarpit's own label kept", country)
	}
	if location := labelled("location"); location != "Netherlands, Amsterdam" {
		t.Errorf("location = %q, want the tarpit's own label kept", location)
	}

	// Everything the labels never carried is exactly what the lookup was for.
	if code := labelled("country_code"); code != "NL" {
		t.Errorf("country_code = %q, want it filled in by the resolver", code)
	}
	if isp := labelled("isp"); isp != "Example Hosting" {
		t.Errorf("isp = %q, want it filled in by the resolver", isp)
	}

	// A row with nothing to preserve takes the resolver's answer whole, which is
	// the only way an unlabelled tarpit's attackers ever reach the map.
	unlabelled := scanInt(t, store,
		`SELECT COUNT(*) FROM attackers WHERE ip_address = '5.5.5.6'
		   AND country = 'The Netherlands' AND country_code = 'NL'
		   AND location = 'The Netherlands, North Holland, Amsterdam'`)
	assertInt(t, "an unplaced row filled from the resolver", unlabelled, 1)
}

func TestApplyScrapeKeepsKnownCoordinateWhenNewScrapeHasNone(t *testing.T) {
	store, _ := newStore(t)
	machine := createMachine(t, store, "alpha")

	latitude, longitude := coordinate(52.5200, 13.4050)
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{{
		IPAddress: "9.9.9.9", Country: "Germany", CountryCode: "DE",
		Latitude: latitude, Longitude: longitude,
	}}})

	// A tarpit that lost its GeoIP database publishes nothing; the coordinate it
	// gave earlier must survive that.
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime.Add(time.Minute), Attackers: []AttackerDelta{{
		IPAddress: "9.9.9.9", Connections: 1,
	}}})

	stored := scanNullableFloat(t, store, "SELECT latitude FROM attackers WHERE ip_address = '9.9.9.9'")
	if !stored.Valid {
		t.Fatal("latitude was erased by a scrape that carried no coordinate")
	}
	assertFloat(t, "preserved latitude", stored.Float64, 52.52)
	if code := scanText(t, store, "SELECT country_code FROM attackers WHERE ip_address = '9.9.9.9'"); code != "DE" {
		t.Errorf("country_code = %q after an empty update, want DE", code)
	}
}

func TestAttackerWithoutCoordinateStoresNull(t *testing.T) {
	store, _ := newStore(t)
	machine := createMachine(t, store, "alpha")

	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "10.10.10.10", Connections: 1, Country: "France"},
	}})

	// Not 0.0: the Gulf of Guinea is a real place, and an attacker nobody could
	// locate must not be plotted there.
	stored := scanNullableFloat(t, store, "SELECT latitude FROM attackers WHERE ip_address = '10.10.10.10'")
	if stored.Valid {
		t.Errorf("latitude = %v for an attacker with no coordinate, want NULL", stored.Float64)
	}
}

// The chips on the attackers page carry a country name, while anything keyed off
// the map or the donut carries the ISO code — and after the backfill fills codes
// in, one country commonly holds two names under a single code, because a tarpit
// labels its own clients "Netherlands" while the online lookup that placed the
// rest calls the same place "The Netherlands". Filtering by the code has to
// reach every row that carries it, or the attackers page shows "No attackers
// match" for a country whose chip is sitting right beside the empty table.
func TestListAttackersFilterMatchesCountryNameOrCode(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: []AttackerDelta{
		// Two spellings of one country, joined by the ISO code the backfill wrote.
		{IPAddress: "5.1.1.1", Connections: 3, TrappedSeconds: 30, Country: "Netherlands", CountryCode: "NL"},
		{IPAddress: "5.1.1.2", Connections: 2, TrappedSeconds: 20, Country: "The Netherlands", CountryCode: "NL"},
		// A different country entirely, which must never come back.
		{IPAddress: "6.1.1.1", Connections: 1, TrappedSeconds: 10, Country: "Germany", CountryCode: "DE"},
	}})

	filterBy := func(country string) []string {
		t.Helper()
		page, err := store.ListAttackers(ctx, AttackerFilter{
			MachineIDs:  []int64{machine.ID},
			Country:     country,
			Page:        1,
			PerPage:     10,
			ActiveSince: baseTime,
		})
		if err != nil {
			t.Fatalf("ListAttackers(country=%q): %v", country, err)
		}
		addresses := make([]string, 0, len(page.Rows))
		for _, row := range page.Rows {
			addresses = append(addresses, row.IPAddress)
		}
		if page.Total != len(addresses) {
			t.Errorf("country=%q: Total is %d but %d rows came back", country, page.Total, len(addresses))
		}
		return addresses
	}

	// The ISO code is the key the map and the donut carry. Before this filter
	// matched country_code, an ISO code found nothing at all, however many rows
	// carried it.
	if got := filterBy("NL"); len(got) != 2 {
		t.Errorf(`filter "NL" returned %v, want both Dutch rows however each was spelled`, got)
	}

	// A chip built from the tarpit's own name still selects that spelling.
	if got := filterBy("Netherlands"); len(got) != 1 || got[0] != "5.1.1.1" {
		t.Errorf(`filter "Netherlands" returned %v, want the row stored under that exact name`, got)
	}

	// Matching two columns must not start matching two countries.
	if got := filterBy("DE"); len(got) != 1 || got[0] != "6.1.1.1" {
		t.Errorf(`filter "DE" returned %v, want only the German address`, got)
	}
	if got := filterBy("FR"); len(got) != 0 {
		t.Errorf(`filter "FR" returned %v, want nothing`, got)
	}
}

// The map groups by a rounded coordinate, so its row count grows with how many
// distinct places have attacked. The cap is what stops a long-lived public
// tarpit sending a larger payload on every refresh — and because the ordering is
// busiest-first, what survives the cap has to be the traffic worth drawing, not
// an arbitrary slice.
func TestGeoPointsCapsThePayloadKeepingTheBusiest(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	// One more place than the cap allows, each with a different amount of
	// traffic: the quietest is the one that must be dropped.
	const extra = 20
	attackers := make([]AttackerDelta, 0, maxGeoPoints+extra)
	for index := range maxGeoPoints + extra {
		// 0.2 degrees apart so no two collapse into one bubble when rounded.
		latitude, longitude := coordinate(float64(index)*0.2-80, float64(index)*0.2-170)
		attackers = append(attackers, AttackerDelta{
			IPAddress:   fmt.Sprintf("10.%d.%d.%d", index/65536%256, index/256%256, index%256),
			Connections: int64(index + 1),
			Country:     "Testland",
			CountryCode: "TL",
			Latitude:    latitude,
			Longitude:   longitude,
		})
	}
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: attackers})

	points, err := store.GeoPoints(ctx, []int64{machine.ID}, time.Time{})
	if err != nil {
		t.Fatalf("GeoPoints: %v", err)
	}
	if len(points) != maxGeoPoints {
		t.Fatalf("GeoPoints returned %d points, want the cap of %d", len(points), maxGeoPoints)
	}

	// Busiest first, and the survivors are the busiest ones: the loudest place
	// made maxGeoPoints+extra connections, and nothing quieter than the cut can
	// have got in.
	if points[0].Connections != int64(maxGeoPoints+extra) {
		t.Errorf("first point has %d connections, want the busiest place (%d)",
			points[0].Connections, maxGeoPoints+extra)
	}
	quietestKept := points[len(points)-1].Connections
	if quietestKept <= int64(extra) {
		t.Errorf("quietest kept point has %d connections; the %d quietest places should have been dropped",
			quietestKept, extra)
	}
	for index := 1; index < len(points); index++ {
		if points[index].Connections > points[index-1].Connections {
			t.Fatalf("points are not busiest-first at %d: %d follows %d",
				index, points[index].Connections, points[index-1].Connections)
		}
	}
}

// The country breakdown cannot run away the way the map can — grouping by
// country name is bounded by how many countries exist — so its limit is a
// ceiling rather than a display cap. It has to sit above any real cardinality,
// because the donut prints the number of countries it was handed: a limit low
// enough to bite would quietly understate the world.
func TestCountryTotalsCeilingSitsAboveRealCardinality(t *testing.T) {
	// Every country on earth, plus room for two sources spelling some of them
	// differently, still has to fit under the ceiling untruncated.
	const countriesOnEarth = 195
	if maxCountryTotals <= countriesOnEarth {
		t.Fatalf("maxCountryTotals is %d, which is at or below the %d countries that exist: "+
			"the donut would report fewer countries than there are", maxCountryTotals, countriesOnEarth)
	}

	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	const extra = 10
	attackers := make([]AttackerDelta, 0, maxCountryTotals+extra)
	for index := range maxCountryTotals + extra {
		attackers = append(attackers, AttackerDelta{
			IPAddress:   fmt.Sprintf("10.%d.%d.%d", index/65536%256, index/256%256, index%256),
			Connections: int64(index + 1),
			Country:     fmt.Sprintf("Country %04d", index),
		})
	}
	applyScrape(t, store, ScrapeDelta{MachineID: machine.ID, At: baseTime, Attackers: attackers})

	totals, err := store.CountryTotals(ctx, []int64{machine.ID}, time.Time{})
	if err != nil {
		t.Fatalf("CountryTotals: %v", err)
	}
	if len(totals) != maxCountryTotals {
		t.Fatalf("CountryTotals returned %d rows, want the ceiling of %d", len(totals), maxCountryTotals)
	}
}

// The sidebar card and the headline both say "trapped now" but answer different
// questions, and the difference is visible whenever one address is hitting more
// than one machine: each card counts it, the headline counts it once. This test
// pins that on purpose — the two figures agreeing for a single machine, and
// deliberately disagreeing across machines — so a later attempt to "reconcile"
// them cannot quietly make one of them wrong.
func TestTrappedNowPerMachineAndHeadlineCountDifferentThings(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	alpha := createMachine(t, store, "alpha")
	beta := createMachine(t, store, "beta")

	// One address caught by both machines, plus one caught only by alpha.
	applyScrape(t, store, ScrapeDelta{MachineID: alpha.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "7.7.7.7", Connections: 1, TrappedSeconds: 5, Active: true},
		{IPAddress: "8.8.8.8", Connections: 1, TrappedSeconds: 5, Active: true},
	}})
	applyScrape(t, store, ScrapeDelta{MachineID: beta.ID, At: baseTime, Attackers: []AttackerDelta{
		{IPAddress: "7.7.7.7", Connections: 1, TrappedSeconds: 5, Active: true},
	}})

	activeSince := baseTime.Add(-time.Minute)

	perMachine, err := store.TrappedNowByMachine(ctx, activeSince)
	if err != nil {
		t.Fatalf("TrappedNowByMachine: %v", err)
	}
	if perMachine[alpha.ID] != 2 {
		t.Errorf("alpha card shows %d trapped, want 2", perMachine[alpha.ID])
	}
	if perMachine[beta.ID] != 1 {
		t.Errorf("beta card shows %d trapped, want 1", perMachine[beta.ID])
	}

	// Scoped to one machine, the card and the headline must agree exactly.
	alphaOnly, err := store.Overview(ctx, []int64{alpha.ID}, baseTime.Add(-time.Hour), activeSince)
	if err != nil {
		t.Fatalf("Overview(alpha): %v", err)
	}
	if alphaOnly.TrappedNow != int64(perMachine[alpha.ID]) {
		t.Errorf("for one machine the headline says %d and its card says %d; these must agree",
			alphaOnly.TrappedNow, perMachine[alpha.ID])
	}

	// Across both machines the shared address is one attacker, so the headline is
	// deliberately lower than the cards added up. This is the correct answer, not
	// a discrepancy to be flattened.
	both, err := store.Overview(ctx, []int64{alpha.ID, beta.ID}, baseTime.Add(-time.Hour), activeSince)
	if err != nil {
		t.Fatalf("Overview(alpha, beta): %v", err)
	}
	if both.TrappedNow != 2 {
		t.Errorf("headline says %d attackers trapped, want 2 distinct addresses", both.TrappedNow)
	}
	if summed := perMachine[alpha.ID] + perMachine[beta.ID]; int64(summed) <= both.TrappedNow {
		t.Errorf("cards sum to %d and the headline says %d; the shared address should make the cards sum higher",
			summed, both.TrappedNow)
	}
}

// backfillIndexName is the index the geography backfill depends on. Named here
// so a rename has to be deliberate rather than quietly dropping the query back
// to a full table scan.
const backfillIndexName = "idx_attackers_missing_location"

func TestBackfillQueryUsesItsIndex(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	machine := createMachine(t, store, "alpha")

	// Enough rows, mostly placed, for the planner to have a reason to prefer an
	// index. On an empty table it may reasonably choose to scan either way.
	for i := 0; i < 500; i++ {
		country, location := "DE", "Berlin"
		if i%20 == 0 {
			country, location = "", ""
		}
		applyScrape(t, store, ScrapeDelta{
			MachineID: machine.ID,
			At:        baseTime,
			Attackers: []AttackerDelta{{
				IPAddress:   fmt.Sprintf("198.51.%d.%d", i/256, i%256),
				Country:     country,
				CountryCode: country,
				Location:    location,
				Connections: 1,
			}},
		})
	}
	if _, err := store.database.ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// The plan is asked for the real query, spelled the way the store spells it.
	// A partial index is only used while the query's condition still matches the
	// index's, so this is really a test that the two have not drifted apart.
	rows, err := store.database.QueryContext(ctx,
		`EXPLAIN QUERY PLAN
		 SELECT MIN(machine_id), ip_address
		 FROM attackers
		 WHERE location = '' OR country_code = ''
		 GROUP BY ip_address
		 ORDER BY MAX(last_seen) DESC
		 LIMIT ?`, 100)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()

	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan the plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the plan: %v", err)
	}

	joined := strings.Join(plan, " | ")
	if !strings.Contains(joined, backfillIndexName) {
		t.Errorf("the backfill query does not use %s; plan: %s", backfillIndexName, joined)
	}
	// Leading on the grouped column is what saves the temporary B-tree; if that
	// goes, the index is still used but has lost half of what it is for.
	if strings.Contains(joined, "TEMP B-TREE FOR GROUP BY") {
		t.Errorf("the backfill query still builds a temporary B-tree to group; plan: %s", joined)
	}
}

func TestBackfillIndexAppliesToAnExistingDatabase(t *testing.T) {
	store, path := newStore(t)
	ctx := context.Background()

	// A database that already carries data from before this migration: the
	// upgrade path, which is the one that matters for anybody already running.
	machine := createMachine(t, store, "alpha")
	applyScrape(t, store, ScrapeDelta{
		MachineID: machine.ID,
		At:        baseTime,
		Attackers: []AttackerDelta{{IPAddress: "198.51.100.7", Connections: 1}},
	})
	if _, err := store.database.ExecContext(ctx, "DROP INDEX "+backfillIndexName); err != nil {
		t.Fatalf("drop the index to simulate the older schema: %v", err)
	}
	if _, err := store.database.ExecContext(ctx,
		"DELETE FROM schema_migrations WHERE version >= 6"); err != nil {
		t.Fatalf("rewind the migration record: %v", err)
	}
	if _, err := store.database.ExecContext(ctx, "DROP TRIGGER enrichment_progress_last_copy_deleted; DROP TABLE enrichment_progress; DROP INDEX idx_attackers_enrichment_ip; DELETE FROM schema_migrations WHERE version=12; DROP TABLE scrape_coverage; DROP TABLE scrape_coverage_state; DELETE FROM schema_migrations WHERE version=11; DROP TABLE attacker_ip_archive; DROP TABLE counter_ip_archive; DELETE FROM schema_migrations WHERE version=10; DROP INDEX idx_attackers_measured_activity; ALTER TABLE attackers DROP COLUMN last_observed_at; ALTER TABLE attackers DROP COLUMN last_measured_activity_at; ALTER TABLE attackers DROP COLUMN has_undated_history; ALTER TABLE attackers DROP COLUMN first_observation_known; ALTER TABLE machines DROP COLUMN target_generation; ALTER TABLE machines DROP COLUMN target_changed_at_ns; ALTER TABLE machines DROP COLUMN scrape_revision; ALTER TABLE machines DROP COLUMN last_metric_sample_ns; ALTER TABLE machines DROP COLUMN last_status_sample_ns; ALTER TABLE machines DROP COLUMN client_counter_policy"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if err := reopened.Migrate(ctx); err != nil {
		t.Fatalf("Migrate an existing database: %v", err)
	}

	assertInt(t, "index present after the upgrade", scanInt(t, reopened,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?", backfillIndexName), 1)

	// The data it was carrying is still there and still findable.
	missing, err := reopened.AttackersMissingLocation(ctx, 10)
	if err != nil {
		t.Fatalf("AttackersMissingLocation after the upgrade: %v", err)
	}
	if len(missing) != 1 || missing[0].IPAddress != "198.51.100.7" {
		t.Errorf("unplaced attackers after the upgrade = %+v, want the one that was there", missing)
	}
}
