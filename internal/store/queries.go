package store

import (
	"context"
	"database/sql"
	"endlessh-dashboard/internal/ipidentity"
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
	// AttackersTrapped, which counts every address still inside the retention
	// window, and AttackersTrappedDelta, which counts only the ones first met
	// in the display window.
	UniqueAttackers int64
	Countries       int
}

type SeriesPoint struct {
	At              time.Time
	To              time.Time
	Coverage        string
	ObservedSeconds float64
	Attempts        int64
	Successes       int64
	UncertainFrom   *time.Time
	UncertainTo     *time.Time
	Partial         bool
	TrappedSeconds  float64
	Opens           int64
	BytesSent       int64
}

type MachineSeries struct {
	MachineID   int64
	MachineName string
	Points      []SeriesPoint
}

type AttackerRow struct {
	MachineID              int64
	MachineName            string
	IPAddress              string
	Country                string
	CountryCode            string
	Geohash                string
	Location               string
	ISP                    string
	Latitude               *float64
	Longitude              *float64
	FirstSeen              time.Time
	LastSeen               time.Time
	LastObservedAt         time.Time
	LastMeasuredActivityAt *time.Time
	HasUndatedHistory      bool
	FirstObservationKnown  bool
	Connections            int64
	TrappedSeconds         float64
	Status                 string
}

type AttackerFilter struct {
	MachineIDs      []int64
	Since           time.Time
	Country         string
	CountryKey      string
	Status          string
	Search          string
	SortColumn      string
	SortDescending  bool
	Page            int
	PerPage         int
	ActiveSince     time.Time
	ObservationOnly bool
	Until           time.Time
}

type AttackerPage struct {
	DistinctIPs int
	Total       int
	Page        int
	PerPage     int
	Rows        []AttackerRow
}

// GeoPoint is one bubble on the map: every attacker whose coordinate rounds to
// the same place, counted once each however many machines saw it.
type GeoPoint struct {
	CountryKey     string
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
	CountryKey  string
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
		attackers.connections, attackers.trapped_seconds, attackers.last_observed_at, attackers.last_measured_activity_at, attackers.has_undated_history, attackers.first_observation_known`

// geoPointDecimalPlaces rounds coordinates to about eleven kilometres, so one
// city is one bubble instead of a smear of near-identical points.
const geoPointDecimalPlaces = 1

// maxGeoPoints caps the map payload. Bubbles are grouped by a rounded
// coordinate, so the number of them grows with how many distinct places have
// attacked — without a ceiling, a long-lived public tarpit would send a larger
// map on every refresh forever. Ordering is busiest-first, so the cap drops the
// quietest tail, and 500 overlapping bubbles already saturate a world map.
const maxGeoPoints = 500

// maxCountryTotals bounds summaries, including arbitrary name-only fallback groups.
const maxCountryTotals = 300

var attackerSortColumns = map[string]string{
	"trapped_seconds": "trapped_seconds",
	"last_seen":       "last_seen",
	"last_activity":   "last_measured_activity_at",
	"first_seen":      "first_seen",
	"connections":     "connections",
	"ip":              "ip_address",
	"country":         "country",
}

const defaultAttackerSort = "trapped_seconds"

func (s *Store) Overview(ctx context.Context, machineIDs []int64, since, activeSince time.Time, until ...time.Time) (Overview, error) {
	since = MinuteBoundary(since)
	end := optionalUntil(until)
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

	rangeArgs := withArg(args, since.Unix())
	upper := ""
	newUpper := ""
	if !end.IsZero() {
		upper = " AND bucket < ?"
		newUpper = " AND MIN(first_seen) < ?"
		rangeArgs = append(rangeArgs, end.Unix())
	}
	windowed := s.database.QueryRowContext(ctx, `SELECT COALESCE(SUM(trapped_seconds),0),COALESCE(SUM(bytes_sent),0) FROM machine_rollups WHERE `+machineFilter+` AND bucket >= ?`+upper, rangeArgs...)
	if err := windowed.Scan(&overview.TimeWastedDeltaSeconds, &overview.BytesSentDelta); err != nil {
		return Overview{}, fmt.Errorf("overview window: %w", err)
	}
	newAttackers := s.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT ip_address FROM attackers WHERE `+machineFilter+` GROUP BY ip_address HAVING MIN(first_seen)>=? AND MIN(first_observation_known)=1`+newUpper+`)`, rangeArgs...)
	if err := newAttackers.Scan(&overview.AttackersTrappedDelta); err != nil {
		return Overview{}, fmt.Errorf("overview new attackers: %w", err)
	}

	trappedNow := s.database.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address) FROM attackers WHERE `+machineFilter+` AND last_activity_at >= ?`,
		withArg(args, activeSince.Unix())...)
	if err := trappedNow.Scan(&overview.TrappedNow); err != nil {
		return Overview{}, fmt.Errorf("overview trapped now: %w", err)
	}

	// COUNT(DISTINCT ...) skips the NULL identity of an unknown country.
	activityUpper := ""
	if !end.IsZero() {
		activityUpper = " AND last_measured_activity_at < ?"
	}
	inWindow := s.database.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip_address),COUNT(DISTINCT `+countryKeySQL+`) FROM attackers WHERE `+machineFilter+` AND last_measured_activity_at >= ?`+activityUpper, rangeArgs...)
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
	return s.timeSeries(ctx, machines, from, to, bucketSeconds, "")
}

func (s *Store) TimeSeriesForPort(ctx context.Context, machines []Machine, from, to time.Time, bucketSeconds int, port string) ([]MachineSeries, error) {
	if err := ValidatePort(port); err != nil {
		return nil, err
	}
	return s.timeSeries(ctx, machines, from, to, bucketSeconds, port)
}
func (s *Store) timeSeries(ctx context.Context, machines []Machine, from, to time.Time, bucketSeconds int, port string) ([]MachineSeries, error) {
	if len(machines) == 0 || bucketSeconds <= 0 {
		return nil, nil
	}
	machineIDs := make([]int64, len(machines))
	for index, machine := range machines {
		machineIDs[index] = machine.ID
	}

	if bucketSeconds < 60 || bucketSeconds%60 != 0 {
		return nil, fmt.Errorf("chart bucket must be a whole number of minutes")
	}
	if to.Before(from) {
		return nil, fmt.Errorf("range end precedes start")
	}
	span := NewTimeRange(from, to)
	from, to = span.From, span.To
	firstBucket := from.Unix() / int64(bucketSeconds) * int64(bucketSeconds)
	args := append(int64Args(machineIDs), from.Unix(), to.Unix())
	table, coverageTable, portWhere := "machine_rollups", "scrape_coverage", ""
	if port != "" {
		table, coverageTable, portWhere = "port_rollups", "port_rollups", " AND port=?"
		args = append(args, port)
	}
	tx, err := s.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx,
		`SELECT machine_id,
				bucket / ? * ? AS aligned,
				SUM(trapped_seconds), SUM(opens), SUM(bytes_sent)
		 FROM `+table+`
		 WHERE machine_id IN (`+placeholders(len(machineIDs))+`) AND bucket >= ? AND bucket < ?`+portWhere+`
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

	rows.Close()
	coverageRows, err := tx.QueryContext(ctx, `SELECT machine_id,bucket / ? * ?,SUM(covered_seconds),SUM(attempts),SUM(successes),MIN(uncertain_from),MAX(uncertain_to)
 FROM `+coverageTable+` WHERE machine_id IN (`+placeholders(len(machineIDs))+`) AND bucket>=? AND bucket<?`+portWhere+` GROUP BY machine_id,bucket / ?`, append(append([]any{bucketSeconds, bucketSeconds}, args...), bucketSeconds)...)
	if err != nil {
		return nil, err
	}
	for coverageRows.Next() {
		var id, b int64
		var seconds float64
		var attempts, successes int64
		var low, high sql.NullInt64
		if err = coverageRows.Scan(&id, &b, &seconds, &attempts, &successes, &low, &high); err != nil {
			break
		}
		key := bucketKey{id, b}
		p := values[key]
		p.ObservedSeconds = seconds
		p.Attempts = attempts
		p.Successes = successes
		p.UncertainFrom = timeFromNullable(low)
		p.UncertainTo = timeFromNullable(high)
		values[key] = p
	}
	if err == nil {
		err = coverageRows.Err()
	}
	coverageRows.Close()
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	series := make([]MachineSeries, 0, len(machines))
	for _, machine := range machines {
		machineSeries := MachineSeries{MachineID: machine.ID, MachineName: machine.Name}
		for bucket := firstBucket; from.Before(to) && bucket < to.Unix(); bucket += int64(bucketSeconds) {
			point := values[bucketKey{machine.ID, bucket}]
			start := time.Unix(bucket, 0).UTC()
			end := start.Add(time.Duration(bucketSeconds) * time.Second)
			point.At = start
			point.To = end
			if point.At.Before(from) {
				point.At = from
				point.Partial = true
			}
			if point.To.After(to) {
				point.To = to
				point.Partial = true
			}
			point.Coverage = "unknown"
			if point.ObservedSeconds > 0 || point.Attempts > 0 {
				point.Coverage = "incomplete"
			}
			if point.ObservedSeconds+0.000001 >= point.To.Sub(point.At).Seconds() {
				point.Coverage = "complete"
			}
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
		column := "attackers.last_measured_activity_at"
		if filter.ObservationOnly {
			column = "attackers.last_observed_at"
		}
		conditions = append(conditions, column+" >= ?")
		args = append(args, MinuteBoundary(filter.Since).Unix())
	}
	if !filter.Until.IsZero() {
		column := "attackers.last_measured_activity_at"
		if filter.ObservationOnly {
			column = "attackers.last_observed_at"
		}
		conditions = append(conditions, column+" < ?")
		args = append(args, MinuteBoundary(filter.Until).Unix())
	}
	// Stable keys take precedence; keep the original name/code filter for clients.
	if filter.CountryKey != "" {
		conditions = append(conditions, "("+countryKeySQL+") = ?")
		args = append(args, filter.CountryKey)
	} else if filter.Country != "" {
		conditions = append(conditions, "(attackers.country = ? OR attackers.country_code = ?)")
		args = append(args, filter.Country, filter.Country)
	}
	if filter.Search != "" {
		conditions = append(conditions, "attackers.ip_address LIKE ?")
		search := filter.Search
		if canonical, err := ipidentity.Canonical(search); err == nil {
			search = canonical
		}
		args = append(args, escapeLikePrefix(search)+"%")
	}
	switch filter.Status {
	case "unknown":
		conditions = append(conditions, "attackers.last_measured_activity_at IS NULL")
	case StatusTrapped:
		conditions = append(conditions, "attackers.last_activity_at >= ?")
		args = append(args, filter.ActiveSince.Unix())
	case StatusGaveUp:
		conditions = append(conditions, "attackers.last_activity_at < ? AND attackers.last_measured_activity_at IS NOT NULL")
		args = append(args, filter.ActiveSince.Unix())
	}
	where := " WHERE " + strings.Join(conditions, " AND ")

	if err := s.database.QueryRowContext(ctx,
		"SELECT COUNT(*),COUNT(DISTINCT ip_address) FROM attackers"+where, args...).Scan(&page.Total, &page.DistinctIPs); err != nil {
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
		attackerPageQuery(where, sortColumn, direction),
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
		if row.LastMeasuredActivityAt == nil {
			row.Status = "unknown"
		}
		if row.LastMeasuredActivityAt != nil && lastActivityAt >= filter.ActiveSince.Unix() {
			row.Status = StatusTrapped
		}
		page.Rows = append(page.Rows, row)
	}
	return page, rows.Err()
}

// attackerPageQuery is shared with the offline benchmark's EXPLAIN capture.
// Sort narrow keys before joining details to reduce large-OFFSET sort width.
// Keep the final order explicit across joins. Fragments use allowlisted sorts.
func attackerPageQuery(where, sortColumn, direction string) string {
	return `SELECT ` + attackerColumns + `
		 FROM (SELECT attackers.machine_id, attackers.ip_address, attackers.` + sortColumn + ` AS sort_value
		 FROM attackers` + where + `
		 ORDER BY attackers.` + sortColumn + ` ` + direction + `, attackers.ip_address ASC, attackers.machine_id ASC
		 LIMIT ? OFFSET ?) AS page_keys
		 JOIN attackers ON attackers.machine_id=page_keys.machine_id AND attackers.ip_address=page_keys.ip_address
		 JOIN machines ON machines.id=attackers.machine_id
		 ORDER BY page_keys.sort_value ` + direction + `, page_keys.ip_address ASC, page_keys.machine_id ASC`
}

// LatestAttacker returns the IP with the latest measured positive counter delta.
// Observation-only imports are excluded; status requires a separate threshold.
func (s *Store) LatestAttacker(ctx context.Context, machineIDs []int64) (AttackerRow, bool, error) {
	if len(machineIDs) == 0 {
		return AttackerRow{}, false, nil
	}
	row, _, err := scanAttackerRow(s.database.QueryRowContext(ctx,
		`SELECT `+attackerColumns+`
		 FROM attackers
		 JOIN machines ON machines.id = attackers.machine_id
		 WHERE attackers.machine_id IN (`+placeholders(len(machineIDs))+`)
		 AND attackers.last_measured_activity_at IS NOT NULL
 ORDER BY attackers.last_measured_activity_at DESC, attackers.ip_address ASC, attackers.machine_id ASC
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
		lastObserved   int64
		measuredAt     sql.NullInt64
	)
	if err := source.Scan(&row.MachineID, &row.MachineName, &row.IPAddress,
		&row.Country, &row.CountryCode, &row.Geohash,
		&row.Location, &row.ISP, &latitude, &longitude,
		&firstSeen, &lastSeen, &lastActivityAt,
		&row.Connections, &row.TrappedSeconds, &lastObserved, &measuredAt, &row.HasUndatedHistory, &row.FirstObservationKnown); err != nil {
		return AttackerRow{}, 0, err
	}
	row.FirstSeen = time.Unix(firstSeen, 0).UTC()
	row.LastSeen = time.Unix(lastSeen, 0).UTC()
	row.LastObservedAt = time.Unix(lastObserved, 0).UTC()
	row.LastMeasuredActivityAt = timeFromNullable(measuredAt)
	row.Latitude = floatFromNullable(latitude)
	row.Longitude = floatFromNullable(longitude)
	return row, lastActivityAt, nil
}

// GeoPoints returns the map's bubbles: attackers with a known coordinate,
// grouped by that coordinate rounded to a city, busiest first.
func (s *Store) GeoPoints(ctx context.Context, machineIDs []int64, since time.Time, until ...time.Time) ([]GeoPoint, error) {
	since = MinuteBoundary(since)
	end := optionalUntil(until)
	if len(machineIDs) == 0 {
		return nil, nil
	}
	args := append([]any{geoPointDecimalPlaces, geoPointDecimalPlaces}, int64Args(machineIDs)...)
	// One address seen by three machines is one attacker but three sets of
	// connections, so the head count is DISTINCT and the traffic is not. The
	// labels use a deterministic representative within each country identity;
	// conflicting identities at the same coordinate remain separate bubbles.
	query := `SELECT ROUND(latitude, ?) AS bubble_latitude,
					 ROUND(longitude, ?) AS bubble_longitude,
					 ` + countryDisplaySQL + `,
					 MIN(` + countryCodeSQL + `),
					 COALESCE(` + countryKeySQL + `, ''),
					 COUNT(DISTINCT ip_address),
					 COALESCE(SUM(connections), 0),
					 COALESCE(SUM(trapped_seconds), 0)
			  FROM attackers
			  WHERE machine_id IN (` + placeholders(len(machineIDs)) + `)
				AND latitude IS NOT NULL AND longitude IS NOT NULL`
	if !since.IsZero() {
		query += " AND last_measured_activity_at >= ?"
		args = append(args, since.Unix())
	}
	if !end.IsZero() {
		query += " AND last_measured_activity_at < ?"
		args = append(args, end.Unix())
	}
	query += ` GROUP BY bubble_latitude, bubble_longitude, ` + countryKeySQL + `
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
			&point.Country, &point.CountryCode, &point.CountryKey,
			&point.Attackers, &point.Connections, &point.TrappedSeconds); err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, rows.Err()
}

// CountryTotals is the breakdown beside the map: distinct attackers and their
// traffic per country, busiest first.
func (s *Store) CountryTotals(ctx context.Context, machineIDs []int64, since time.Time, observation ...bool) ([]CountryTotal, error) {
	return s.countryTotals(ctx, machineIDs, since, time.Time{}, len(observation) > 0 && observation[0])
}
func (s *Store) CountryTotalsInRange(ctx context.Context, machineIDs []int64, span TimeRange, observation bool) ([]CountryTotal, error) {
	return s.countryTotals(ctx, machineIDs, span.From, span.To, observation)
}
func (s *Store) countryTotals(ctx context.Context, machineIDs []int64, since, end time.Time, observation bool) ([]CountryTotal, error) {
	since = MinuteBoundary(since)
	end = MinuteBoundary(end)
	if len(machineIDs) == 0 {
		return nil, nil
	}
	args := int64Args(machineIDs)
	query := `SELECT ` + countryDisplaySQL + `,
					 MIN(` + countryCodeSQL + `),
					 ` + countryKeySQL + `,
					 COUNT(DISTINCT ip_address),
					 COALESCE(SUM(connections), 0)
			  FROM attackers
			  WHERE machine_id IN (` + placeholders(len(machineIDs)) + `) AND (` + countryKeySQL + `) IS NOT NULL`
	if !since.IsZero() {
		column := "last_measured_activity_at"
		if observation {
			column = "last_observed_at"
		}
		query += " AND " + column + " >= ?"
		args = append(args, since.Unix())
	}
	if !end.IsZero() {
		column := "last_measured_activity_at"
		if observation {
			column = "last_observed_at"
		}
		query += " AND " + column + " < ?"
		args = append(args, end.Unix())
	}
	query += ` GROUP BY ` + countryKeySQL + `
			   ORDER BY COUNT(DISTINCT ip_address) DESC, SUM(connections) DESC, ` + countryKeySQL + ` ASC
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
		if err := rows.Scan(&total.Country, &total.CountryCode, &total.CountryKey, &total.Attackers, &total.Connections); err != nil {
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
	canonical, err := ipidentity.Canonical(ipAddress)
	if err != nil {
		return err
	}
	return setAttackerLocation(ctx, s.database, canonical, location)
}

func setAttackerLocation(ctx context.Context, writer transactionExecer, ipAddress string, location AttackerLocation) error {
	_, err := writer.ExecContext(ctx,
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
