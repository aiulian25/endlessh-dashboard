package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// StatusTrapped means the client's trapped time was still growing at the last scrape.
const (
	StatusTrapped = "trapped"
	StatusGaveUp  = "gave_up"
)

type Overview struct {
	TimeWastedSeconds      float64
	TimeWastedDeltaSeconds float64
	AttackersTrapped       int64
	AttackersTrappedDelta  int64
	BytesSent              int64
	BytesSentDelta         int64
	TrappedNow             int64
	MachineCount           int
	// UniqueAttackers counts the addresses seen inside the window, unlike
	// AttackersTrapped, which is the lifetime figure, and
	// AttackersTrappedDelta, which counts only the ones first met in it.
	UniqueAttackers int64
	Countries       int
}

type SeriesPoint struct {
	At             time.Time
	TrappedSeconds float64
	Opens          int64
	BytesSent      int64
}

type MachineSeries struct {
	MachineID   int64
	MachineName string
	Points      []SeriesPoint
}

type AttackerRow struct {
	MachineID      int64
	MachineName    string
	IPAddress      string
	Country        string
	CountryCode    string
	Geohash        string
	Location       string
	ISP            string
	Latitude       *float64
	Longitude      *float64
	FirstSeen      time.Time
	LastSeen       time.Time
	Connections    int64
	TrappedSeconds float64
	Status         string
}

type AttackerFilter struct {
	MachineIDs     []int64
	Since          time.Time
	Country        string
	Status         string
	Search         string
	SortColumn     string
	SortDescending bool
	Page           int
	PerPage        int
	ActiveSince    time.Time
}

type AttackerPage struct {
	Total   int
	Page    int
	PerPage int
	Rows    []AttackerRow
}

// GeoPoint is one bubble on the map: every attacker whose coordinate rounds to
// the same place, counted once each however many machines saw it.
type GeoPoint struct {
	Latitude       float64
	Longitude      float64
	Country        string
	CountryCode    string
	Attackers      int
	Connections    int64
	TrappedSeconds float64
}

// CountryTotal is one row of the country breakdown beside the map.
type CountryTotal struct {
	Country     string
	CountryCode string
	Attackers   int
	Connections int64
}

// MissingLocation is one address the backfill worker still has to place. The
// machine is whichever one saw the address, carried for the log: geography
// belongs to the address, not to the machine that met it.
type MissingLocation struct {
	MachineID int64
	IPAddress string
}

// AttackerLocation is what a resolver established about an address, ready to be
// written to every row holding it. Empty fields and a nil coordinate mean "this
// resolver did not know", never "erase what is stored".
type AttackerLocation struct {
	Country     string
	CountryCode string
	Location    string
	ISP         string
	Latitude    *float64
	Longitude   *float64
}

// attackerColumns is the row shape both attacker reads share, in the order
// scanAttackerRow expects.
const attackerColumns = `attackers.machine_id, machines.name, attackers.ip_address,
		attackers.country, attackers.country_code, attackers.geohash,
		attackers.location, attackers.isp, attackers.latitude, attackers.longitude,
		attackers.first_seen, attackers.last_seen, attackers.last_activity_at,
		attackers.connections, attackers.trapped_seconds`

// geoPointDecimalPlaces rounds coordinates to about eleven kilometres, so one
// city is one bubble instead of a smear of near-identical points.
const geoPointDecimalPlaces = 1

// maxGeoPoints caps the map payload. Bubbles are grouped by a rounded
// coordinate, so the number of them grows with how many distinct places have
// attacked — without a ceiling, a long-lived public tarpit would send a larger
// map on every refresh forever. Ordering is busiest-first, so the cap drops the
// quietest tail, and 500 overlapping bubbles already saturate a world map.
const maxGeoPoints = 500

// maxCountryTotals is a ceiling, not a display cap. Grouping by country can
// only produce as many rows as there are country names — about two hundred,
// plus the odd duplicate where two geography sources spell one country
// differently — so this query cannot run away the way the map can. The limit
// sits well above that so it never truncates in practice: the donut prints the
// number of countries it was given (web/donut.js), and a cap low enough to bite
// would make it understate the world rather than bound anything real.
const maxCountryTotals = 300

var attackerSortColumns = map[string]string{
	"trapped_seconds": "trapped_seconds",
	"last_seen":       "last_seen",
	"first_seen":      "first_seen",
	"connections":     "connections",
	"ip":              "ip_address",
	"country":         "country",
}

const defaultAttackerSort = "trapped_seconds"

func (s *Store) Overview(ctx context.Context, machineIDs []int64, since, activeSince time.Time) (Overview, error) {
	overview := Overview{MachineCount: len(machineIDs)}
	if len(machineIDs) == 0 {
		return overview, nil
	}
	machineFilter := "machine_id IN (" + placeholders(len(machineIDs)) + ")"
	args := int64Args(machineIDs)

	// Time and bytes are lifetime figures kept in machine_totals, so they survive
	// retention pruning. The attacker count is a set cardinality, which cannot be
	// carried that way, so it is counted from the rows still retained — and
	// counted DISTINCT, so one IP hitting three machines is one attacker.
	lifetime := s.database.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(trapped_seconds), 0), COALESCE(SUM(bytes_sent), 0)
		 FROM machine_totals WHERE `+machineFilter, args...)
	if err := lifetime.Scan(&overview.TimeWastedSeconds, &overview.BytesSent); err != nil {
		return Overview{}, fmt.Errorf("overview totals: %w", err)
	}

	distinct := s.database.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE `+machineFilter, args...)
	if err := distinct.Scan(&overview.AttackersTrapped); err != nil {
		return Overview{}, fmt.Errorf("overview attackers: %w", err)
	}

	windowed := s.database.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(trapped_seconds), 0), COALESCE(SUM(bytes_sent), 0)
		 FROM machine_rollups WHERE `+machineFilter+` AND bucket >= ?`,
		withArg(args, since.Unix())...)
	if err := windowed.Scan(&overview.TimeWastedDeltaSeconds, &overview.BytesSentDelta); err != nil {
		return Overview{}, fmt.Errorf("overview window: %w", err)
	}

	newAttackers := s.database.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE `+machineFilter+` AND first_seen >= ?`,
		withArg(args, since.Unix())...)
	if err := newAttackers.Scan(&overview.AttackersTrappedDelta); err != nil {
		return Overview{}, fmt.Errorf("overview new attackers: %w", err)
	}

	trappedNow := s.database.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE `+machineFilter+` AND last_activity_at >= ?`,
		withArg(args, activeSince.Unix())...)
	if err := trappedNow.Scan(&overview.TrappedNow); err != nil {
		return Overview{}, fmt.Errorf("overview trapped now: %w", err)
	}

	// COUNT(DISTINCT ...) skips NULLs, so the CASE turns an unplaced address into
	// one instead of counting "" as a country of its own.
	inWindow := s.database.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address),
				COUNT(DISTINCT CASE WHEN country <> '' THEN country END)
		 FROM attackers WHERE `+machineFilter+` AND last_seen >= ?`,
		withArg(args, since.Unix())...)
	if err := inWindow.Scan(&overview.UniqueAttackers, &overview.Countries); err != nil {
		return Overview{}, fmt.Errorf("overview window attackers: %w", err)
	}
	return overview, nil
}

// TrappedNowByMachine powers the per-machine health strip: how many attackers
// each machine is holding right now, for every machine, whatever the dashboard
// is currently filtered to.
//
// This counts one attacker once per machine, so an address hitting three
// machines is counted on all three. Overview.TrappedNow counts the same moment
// DISTINCT across the selected machines, where that address is one attacker. The
// two therefore disagree by design whenever an address spans machines, and
// summing these cards is not meant to reproduce the headline figure.
//
// The DISTINCT is redundant today — the attackers primary key is
// (machine_id, ip_address), so a machine cannot hold an address twice, and the
// query plan is identical either way — but it states the intent, and it keeps
// this count from silently diverging from the headline if that key ever gains a
// column such as the local port.
func (s *Store) TrappedNowByMachine(ctx context.Context, activeSince time.Time) (map[int64]int, error) {
	rows, err := s.database.QueryContext(ctx,
		`SELECT machine_id, COUNT(DISTINCT ip_address) FROM attackers WHERE last_activity_at >= ? GROUP BY machine_id`,
		activeSince.Unix())
	if err != nil {
		return nil, fmt.Errorf("trapped now by machine: %w", err)
	}
	defer rows.Close()

	counts := map[int64]int{}
	for rows.Next() {
		var (
			machineID int64
			count     int
		)
		if err := rows.Scan(&machineID, &count); err != nil {
			return nil, err
		}
		counts[machineID] = count
	}
	return counts, rows.Err()
}

// TimeSeries returns one dense series per machine: every series carries the same
// bucket timestamps, with zero-filled gaps, so the chart can stack them directly.
func (s *Store) TimeSeries(ctx context.Context, machines []Machine, from, to time.Time, bucketSeconds int) ([]MachineSeries, error) {
	if len(machines) == 0 || bucketSeconds <= 0 {
		return nil, nil
	}
	machineIDs := make([]int64, len(machines))
	for index, machine := range machines {
		machineIDs[index] = machine.ID
	}

	firstBucket := from.Unix() / int64(bucketSeconds) * int64(bucketSeconds)
	lastBucket := to.Unix() / int64(bucketSeconds) * int64(bucketSeconds)

	// The filter runs against the per-minute rollup key, so the upper bound has
	// to cover the whole final bucket. Filtering on lastBucket itself would keep
	// only the single minute that happens to align with it and silently drop the
	// rest of the newest point — the one the operator is actually watching.
	lastMinuteInRange := lastBucket + int64(bucketSeconds) - 1

	args := append(int64Args(machineIDs), firstBucket, lastMinuteInRange)
	rows, err := s.database.QueryContext(ctx,
		`SELECT machine_id,
				bucket / ? * ? AS aligned,
				SUM(trapped_seconds), SUM(opens), SUM(bytes_sent)
		 FROM machine_rollups
		 WHERE machine_id IN (`+placeholders(len(machineIDs))+`) AND bucket >= ? AND bucket <= ?
		 GROUP BY machine_id, aligned`,
		append([]any{bucketSeconds, bucketSeconds}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("time series: %w", err)
	}
	defer rows.Close()

	type bucketKey struct {
		machineID int64
		bucket    int64
	}
	values := map[bucketKey]SeriesPoint{}
	for rows.Next() {
		var (
			machineID int64
			bucket    int64
			point     SeriesPoint
		)
		if err := rows.Scan(&machineID, &bucket, &point.TrappedSeconds, &point.Opens, &point.BytesSent); err != nil {
			return nil, err
		}
		values[bucketKey{machineID, bucket}] = point
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	series := make([]MachineSeries, 0, len(machines))
	for _, machine := range machines {
		machineSeries := MachineSeries{MachineID: machine.ID, MachineName: machine.Name}
		for bucket := firstBucket; bucket <= lastBucket; bucket += int64(bucketSeconds) {
			point := values[bucketKey{machine.ID, bucket}]
			point.At = time.Unix(bucket, 0).UTC()
			machineSeries.Points = append(machineSeries.Points, point)
		}
		series = append(series, machineSeries)
	}
	return series, nil
}

// RecentActivityByMachine returns the trapped seconds each machine recorded in
// the last `buckets` buckets of `bucketSeconds`, oldest first, for every machine
// in one query. Each slice is dense: exactly `buckets` values, zero where no
// traffic landed. A machine with no rows at all is absent from the map.
func (s *Store) RecentActivityByMachine(ctx context.Context, now time.Time, bucketSeconds, buckets int) (map[int64][]float64, error) {
	if bucketSeconds <= 0 || buckets <= 0 {
		return nil, nil
	}

	newestBucket := now.Unix() / int64(bucketSeconds) * int64(bucketSeconds)
	oldestBucket := newestBucket - int64(buckets-1)*int64(bucketSeconds)
	// Same upper bound as TimeSeries: the filter runs against the per-minute
	// rollup key, so it has to reach the end of the newest wide bucket instead of
	// the single minute that happens to align with it.
	lastMinuteInRange := newestBucket + int64(bucketSeconds) - 1

	rows, err := s.database.QueryContext(ctx,
		`SELECT machine_id, bucket / ? * ? AS aligned, SUM(trapped_seconds)
		 FROM machine_rollups
		 WHERE bucket >= ? AND bucket <= ?
		 GROUP BY machine_id, aligned`,
		bucketSeconds, bucketSeconds, oldestBucket, lastMinuteInRange)
	if err != nil {
		return nil, fmt.Errorf("recent activity by machine: %w", err)
	}
	defer rows.Close()

	activity := map[int64][]float64{}
	for rows.Next() {
		var (
			machineID      int64
			alignedBucket  int64
			trappedSeconds float64
		)
		if err := rows.Scan(&machineID, &alignedBucket, &trappedSeconds); err != nil {
			return nil, err
		}
		series, ok := activity[machineID]
		if !ok {
			series = make([]float64, buckets)
			activity[machineID] = series
		}
		series[(alignedBucket-oldestBucket)/int64(bucketSeconds)] = trappedSeconds
	}
	return activity, rows.Err()
}

func (s *Store) ListAttackers(ctx context.Context, filter AttackerFilter) (AttackerPage, error) {
	page := AttackerPage{Page: filter.Page, PerPage: filter.PerPage}
	if len(filter.MachineIDs) == 0 {
		return page, nil
	}

	conditions := []string{"attackers.machine_id IN (" + placeholders(len(filter.MachineIDs)) + ")"}
	args := int64Args(filter.MachineIDs)

	if !filter.Since.IsZero() {
		conditions = append(conditions, "attackers.last_seen >= ?")
		args = append(args, filter.Since.Unix())
	}
	// A country arrives here as whatever the caller had to hand: the chips on the
	// attackers page are built from the country name, while anything keyed off
	// the map or the donut carries the ISO code. The same country can also be
	// stored under both spellings at once, because a tarpit's own labels say
	// "Netherlands" while the online lookup that filled in the ISO code says
	// "The Netherlands". Matching either column keeps one country one filter
	// however its rows were labelled.
	if filter.Country != "" {
		conditions = append(conditions, "(attackers.country = ? OR attackers.country_code = ?)")
		args = append(args, filter.Country, filter.Country)
	}
	if filter.Search != "" {
		conditions = append(conditions, "attackers.ip_address LIKE ?")
		args = append(args, escapeLikePrefix(filter.Search)+"%")
	}
	switch filter.Status {
	case StatusTrapped:
		conditions = append(conditions, "attackers.last_activity_at >= ?")
		args = append(args, filter.ActiveSince.Unix())
	case StatusGaveUp:
		conditions = append(conditions, "attackers.last_activity_at < ?")
		args = append(args, filter.ActiveSince.Unix())
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	if err := s.database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM attackers"+where, args...).Scan(&page.Total); err != nil {
		return AttackerPage{}, fmt.Errorf("count attackers: %w", err)
	}

	sortColumn, ok := attackerSortColumns[filter.SortColumn]
	if !ok {
		sortColumn = attackerSortColumns[defaultAttackerSort]
	}
	direction := "ASC"
	if filter.SortDescending {
		direction = "DESC"
	}

	offset := (filter.Page - 1) * filter.PerPage
	if offset < 0 {
		offset = 0
	}

	rows, err := s.database.QueryContext(ctx,
		`SELECT `+attackerColumns+`
		 FROM attackers
		 JOIN machines ON machines.id = attackers.machine_id`+where+
			` ORDER BY attackers.`+sortColumn+` `+direction+`, attackers.ip_address ASC
		 LIMIT ? OFFSET ?`,
		append(args, filter.PerPage, offset)...)
	if err != nil {
		return AttackerPage{}, fmt.Errorf("list attackers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		row, lastActivityAt, err := scanAttackerRow(rows)
		if err != nil {
			return AttackerPage{}, err
		}
		row.Status = StatusGaveUp
		if lastActivityAt >= filter.ActiveSince.Unix() {
			row.Status = StatusTrapped
		}
		page.Rows = append(page.Rows, row)
	}
	return page, rows.Err()
}

// LatestAttacker returns the most recently seen attacker across the given
// machines, for the "newest catch" strip. Status is left empty: liveness needs
// a staleness threshold this query has no business inventing, and LastSeen
// carries everything a caller needs to decide it.
func (s *Store) LatestAttacker(ctx context.Context, machineIDs []int64) (AttackerRow, bool, error) {
	if len(machineIDs) == 0 {
		return AttackerRow{}, false, nil
	}
	row, _, err := scanAttackerRow(s.database.QueryRowContext(ctx,
		`SELECT `+attackerColumns+`
		 FROM attackers
		 JOIN machines ON machines.id = attackers.machine_id
		 WHERE attackers.machine_id IN (`+placeholders(len(machineIDs))+`)
		 ORDER BY attackers.last_seen DESC, attackers.ip_address ASC
		 LIMIT 1`, int64Args(machineIDs)...))
	if errors.Is(err, sql.ErrNoRows) {
		return AttackerRow{}, false, nil
	}
	if err != nil {
		return AttackerRow{}, false, fmt.Errorf("latest attacker: %w", err)
	}
	return row, true, nil
}

// scanAttackerRow reads attackerColumns through the package's rowScanner, so
// the paged list and the single newest row share one column order. It also
// returns last_activity_at, which is a status input rather than a row field.
func scanAttackerRow(source rowScanner) (AttackerRow, int64, error) {
	var (
		row            AttackerRow
		latitude       sql.NullFloat64
		longitude      sql.NullFloat64
		firstSeen      int64
		lastSeen       int64
		lastActivityAt int64
	)
	if err := source.Scan(&row.MachineID, &row.MachineName, &row.IPAddress,
		&row.Country, &row.CountryCode, &row.Geohash,
		&row.Location, &row.ISP, &latitude, &longitude,
		&firstSeen, &lastSeen, &lastActivityAt,
		&row.Connections, &row.TrappedSeconds); err != nil {
		return AttackerRow{}, 0, err
	}
	row.FirstSeen = time.Unix(firstSeen, 0).UTC()
	row.LastSeen = time.Unix(lastSeen, 0).UTC()
	row.Latitude = floatFromNullable(latitude)
	row.Longitude = floatFromNullable(longitude)
	return row, lastActivityAt, nil
}

// GeoPoints returns the map's bubbles: attackers with a known coordinate,
// grouped by that coordinate rounded to a city, busiest first.
func (s *Store) GeoPoints(ctx context.Context, machineIDs []int64, since time.Time) ([]GeoPoint, error) {
	if len(machineIDs) == 0 {
		return nil, nil
	}
	args := append([]any{geoPointDecimalPlaces, geoPointDecimalPlaces}, int64Args(machineIDs)...)
	// One address seen by three machines is one attacker but three sets of
	// connections, so the head count is DISTINCT and the traffic is not. The
	// labels are whichever non-empty value the group carries, because a bubble
	// this small cannot straddle two countries.
	query := `SELECT ROUND(latitude, ?) AS bubble_latitude,
					 ROUND(longitude, ?) AS bubble_longitude,
					 COALESCE(MIN(NULLIF(country, '')), ''),
					 COALESCE(MIN(NULLIF(country_code, '')), ''),
					 COUNT(DISTINCT ip_address),
					 COALESCE(SUM(connections), 0),
					 COALESCE(SUM(trapped_seconds), 0)
			  FROM attackers
			  WHERE machine_id IN (` + placeholders(len(machineIDs)) + `)
				AND latitude IS NOT NULL AND longitude IS NOT NULL`
	if !since.IsZero() {
		query += " AND last_seen >= ?"
		args = append(args, since.Unix())
	}
	query += ` GROUP BY bubble_latitude, bubble_longitude
			   ORDER BY SUM(connections) DESC, bubble_latitude ASC, bubble_longitude ASC
			   LIMIT ?`
	args = append(args, maxGeoPoints)

	rows, err := s.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("geo points: %w", err)
	}
	defer rows.Close()

	var points []GeoPoint
	for rows.Next() {
		var point GeoPoint
		if err := rows.Scan(&point.Latitude, &point.Longitude,
			&point.Country, &point.CountryCode,
			&point.Attackers, &point.Connections, &point.TrappedSeconds); err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, rows.Err()
}

// CountryTotals is the breakdown beside the map: distinct attackers and their
// traffic per country, busiest first.
func (s *Store) CountryTotals(ctx context.Context, machineIDs []int64, since time.Time) ([]CountryTotal, error) {
	if len(machineIDs) == 0 {
		return nil, nil
	}
	args := int64Args(machineIDs)
	query := `SELECT country,
					 COALESCE(MIN(NULLIF(country_code, '')), ''),
					 COUNT(DISTINCT ip_address),
					 COALESCE(SUM(connections), 0)
			  FROM attackers
			  WHERE machine_id IN (` + placeholders(len(machineIDs)) + `) AND country <> ''`
	if !since.IsZero() {
		query += " AND last_seen >= ?"
		args = append(args, since.Unix())
	}
	query += ` GROUP BY country
			   ORDER BY COUNT(DISTINCT ip_address) DESC, SUM(connections) DESC, country ASC
			   LIMIT ?`
	args = append(args, maxCountryTotals)

	rows, err := s.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("country totals: %w", err)
	}
	defer rows.Close()

	var totals []CountryTotal
	for rows.Next() {
		var total CountryTotal
		if err := rows.Scan(&total.Country, &total.CountryCode, &total.Attackers, &total.Connections); err != nil {
			return nil, err
		}
		totals = append(totals, total)
	}
	return totals, rows.Err()
}

// AttackersMissingLocation lists addresses no source has placed yet, newest
// sighting first, one row per address however many machines met it.
func (s *Store) AttackersMissingLocation(ctx context.Context, limit int) ([]MissingLocation, error) {
	if limit <= 0 {
		return nil, nil
	}
	// Two kinds of row need a lookup. One has no location at all. The other was
	// placed from the tarpit's own labels, which carry a country name and a
	// geohash but never an ISO code or a network operator — so it has a location
	// and still cannot show a country badge or say who owns the address.
	rows, err := s.database.QueryContext(ctx,
		`SELECT MIN(machine_id), ip_address
		 FROM attackers
		 WHERE location = '' OR country_code = ''
		 GROUP BY ip_address
		 ORDER BY MAX(last_seen) DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("attackers missing location: %w", err)
	}
	defer rows.Close()

	var missing []MissingLocation
	for rows.Next() {
		var entry MissingLocation
		if err := rows.Scan(&entry.MachineID, &entry.IPAddress); err != nil {
			return nil, err
		}
		missing = append(missing, entry)
	}
	return missing, rows.Err()
}

// SetAttackerLocation writes a resolved place to every machine's copy of that
// address: geography is a property of the address, not of the machine that
// happened to see it. Like the scrape upsert, it never replaces a known value
// with an empty one.
//
// The two columns a tarpit publishes itself, country and location, are only
// ever filled here, never replaced. The tarpit is the operator's own source and
// the scrape re-asserts its labels on every poll, so a resolver writing its own
// spelling over them would not even hold: the label would win back at the next
// scrape and the country would alternate between two spellings. The columns no
// tarpit label carries — the ISO code, the network operator and the coordinate,
// which is why such a row was queued for lookup at all — are written whenever
// the resolver has them.
func (s *Store) SetAttackerLocation(ctx context.Context, ipAddress string, location AttackerLocation) error {
	_, err := s.database.ExecContext(ctx,
		`UPDATE attackers SET
			country = CASE WHEN country = '' AND ? <> '' THEN ? ELSE country END,
			country_code = CASE WHEN ? <> '' THEN ? ELSE country_code END,
			location = CASE WHEN location = '' AND ? <> '' THEN ? ELSE location END,
			isp = CASE WHEN ? <> '' THEN ? ELSE isp END,
			latitude = CASE WHEN ? IS NOT NULL THEN ? ELSE latitude END,
			longitude = CASE WHEN ? IS NOT NULL THEN ? ELSE longitude END
		 WHERE ip_address = ?`,
		location.Country, location.Country,
		location.CountryCode, location.CountryCode,
		location.Location, location.Location,
		location.ISP, location.ISP,
		location.Latitude, location.Latitude,
		location.Longitude, location.Longitude,
		ipAddress)
	if err != nil {
		return fmt.Errorf("set attacker location: %w", err)
	}
	return nil
}

// escapeLikePrefix neutralises the LIKE wildcards a user may type into search.
func escapeLikePrefix(value string) string {
	replacer := strings.NewReplacer("%", "", "_", "", "\\", "")
	return replacer.Replace(value)
}
