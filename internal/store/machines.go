package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// maxLastErrorLength bounds what is kept from a failed scrape. The message
// quotes the remote endpoint's own status line and, after a refused redirect,
// its URL — so how long it is, is decided by the machine being scraped rather
// than by this app. It is stored on the machine row and returned in every
// /api/machines response, which is a lot of places for somebody else to choose
// the size of. 512 bytes is far more than any real error needs.
const maxLastErrorLength = 512

var ErrMachineNotFound = errors.New("machine not found")

// ErrDuplicateMachineName is returned when a name collides with an existing machine.
var ErrDuplicateMachineName = errors.New("a machine with that name already exists")

type Machine struct {
	ID                  int64
	Name                string
	Host                string
	Port                int
	MetricsPath         string
	GroupLabel          string
	Enabled             bool
	CreatedAt           time.Time
	LastScrapeAt        *time.Time
	LastOKAt            *time.Time
	ConsecutiveFailures int
	LastError           string
	Colour              string
	TargetGeneration    int64
	TargetChangedAt     *time.Time
}

const machineColumns = `id, name, host, port, metrics_path, group_label, enabled, created_at,
	last_scrape_at, last_ok_at, consecutive_failures, last_error, colour, target_generation, target_changed_at_ns`

// SetMachineOrder records the sidebar order. Ids are positioned in the order
// given; every machine not named is reset to unplaced, so it sorts after them by
// name. One transaction, because a half-applied order is a sidebar in an order
// nobody chose.
//
// Unknown ids are ignored rather than refused: the list is a view preference,
// and a stale tab reordering around a machine deleted a moment ago should place
// the ones that still exist, not fail outright.
func (s *Store) SetMachineOrder(ctx context.Context, machineIDs []int64) error {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set machine order: %w", err)
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx, "UPDATE machines SET sort_order = NULL"); err != nil {
		return fmt.Errorf("clear machine order: %w", err)
	}
	for position, machineID := range machineIDs {
		if _, err := transaction.ExecContext(ctx,
			"UPDATE machines SET sort_order = ? WHERE id = ?", position, machineID); err != nil {
			return fmt.Errorf("set machine order: %w", err)
		}
	}
	return transaction.Commit()
}

func (s *Store) ListMachines(ctx context.Context) ([]Machine, error) {
	rows, err := s.database.QueryContext(ctx,
		// Hand-arranged machines first, in the arranged order; everything never
		// placed by hand after them, by name, exactly as before this existed.
		"SELECT "+machineColumns+` FROM machines
		 ORDER BY sort_order IS NULL, sort_order, name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer rows.Close()

	var machines []Machine
	for rows.Next() {
		machine, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		machines = append(machines, machine)
	}
	return machines, rows.Err()
}

func (s *Store) ListEnabledMachines(ctx context.Context) ([]Machine, error) {
	all, err := s.ListMachines(ctx)
	if err != nil {
		return nil, err
	}
	enabled := make([]Machine, 0, len(all))
	for _, machine := range all {
		if machine.Enabled {
			enabled = append(enabled, machine)
		}
	}
	return enabled, nil
}

func (s *Store) GetMachine(ctx context.Context, id int64) (Machine, error) {
	row := s.database.QueryRowContext(ctx,
		"SELECT "+machineColumns+" FROM machines WHERE id = ?", id)
	machine, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Machine{}, ErrMachineNotFound
	}
	if err != nil {
		return Machine{}, fmt.Errorf("get machine: %w", err)
	}
	return machine, nil
}

// UsedColours counts how many machines carry each colour, so a machine created
// without one can be given a slot nobody is using rather than a duplicate.
func (s *Store) UsedColours(ctx context.Context) (map[string]int, error) {
	rows, err := s.database.QueryContext(ctx,
		"SELECT colour, COUNT(*) FROM machines WHERE colour <> '' GROUP BY colour")
	if err != nil {
		return nil, fmt.Errorf("used colours: %w", err)
	}
	defer rows.Close()

	used := map[string]int{}
	for rows.Next() {
		var colour string
		var count int
		if err := rows.Scan(&colour, &count); err != nil {
			return nil, err
		}
		used[colour] = count
	}
	return used, rows.Err()
}

// CreateMachine registers a machine and opens its lifetime totals. One
// transaction, because a machine without a totals row is worse than no machine
// at all: nothing errors, the sidebar lists it, and every lifetime figure it
// reports stays at zero for as long as it exists.
func (s *Store) CreateMachine(ctx context.Context, machine Machine) (Machine, error) {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, fmt.Errorf("create machine: %w", err)
	}
	defer transaction.Rollback()

	machine.CreatedAt = time.Now().UTC()
	result, err := transaction.ExecContext(ctx,
		`INSERT INTO machines (name, host, port, metrics_path, group_label, enabled, created_at, colour)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		machine.Name, machine.Host, machine.Port, machine.MetricsPath,
		machine.GroupLabel, machine.Enabled, machine.CreatedAt.Unix(), machine.Colour)
	if err != nil {
		if isUniqueViolation(err) {
			return Machine{}, ErrDuplicateMachineName
		}
		return Machine{}, fmt.Errorf("create machine: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Machine{}, fmt.Errorf("create machine: %w", err)
	}
	machine.ID = id

	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO machine_totals (machine_id) VALUES (?)", id); err != nil {
		return Machine{}, fmt.Errorf("create machine totals: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Machine{}, fmt.Errorf("create machine: %w", err)
	}
	return machine, nil
}

func (s *Store) UpdateMachine(ctx context.Context, machine Machine) error {
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Acquire the writer before reading identity, avoiding a WAL read-to-write
	// upgrade conflict with a scrape committing between the read and the edit.
	claim, err := tx.ExecContext(ctx, "UPDATE machines SET target_generation=target_generation WHERE id=?", machine.ID)
	if err != nil {
		return err
	}
	if err = requireOneRow(claim, ErrMachineNotFound); err != nil {
		return err
	}
	existing, err := scanMachine(tx.QueryRowContext(ctx, "SELECT "+machineColumns+" FROM machines WHERE id = ?", machine.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMachineNotFound
	}
	if err != nil {
		return err
	}
	targetChanged := existing.Host != machine.Host || existing.Port != machine.Port || existing.MetricsPath != machine.MetricsPath
	invalidated := targetChanged || existing.Enabled != machine.Enabled
	if _, err = tx.ExecContext(ctx, `UPDATE machines SET name=?,host=?,port=?,metrics_path=?,group_label=?,enabled=?,colour=? WHERE id=?`, machine.Name, machine.Host, machine.Port, machine.MetricsPath, machine.GroupLabel, machine.Enabled, machine.Colour, machine.ID); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateMachineName
		}
		return err
	}
	if invalidated {
		if _, err = tx.ExecContext(ctx, `UPDATE machines SET target_generation=target_generation+1, scrape_revision=scrape_revision+1 WHERE id=?`, machine.ID); err != nil {
			return err
		}
	}
	if targetChanged {
		if _, err = tx.ExecContext(ctx, "DELETE FROM counter_states WHERE machine_id=?", machine.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE machines SET client_counter_policy='baseline_only',target_changed_at_ns=?,
 last_scrape_at=NULL,last_ok_at=NULL,consecutive_failures=0,last_error='',last_metric_sample_ns=NULL,last_status_sample_ns=NULL WHERE id=?`, time.Now().UTC().UnixNano(), machine.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteMachine(ctx context.Context, id int64) error {
	result, err := s.database.ExecContext(ctx, "DELETE FROM machines WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete machine: %w", err)
	}
	return requireOneRow(result, ErrMachineNotFound)
}

// RecordScrapeSuccess clears the failure streak and stamps both timestamps.
func (s *Store) RecordScrapeSuccess(ctx context.Context, id int64, at time.Time, generations ...int64) error {
	generation := int64(0)
	if len(generations) > 0 {
		generation = generations[0]
	}
	result, err := s.database.ExecContext(ctx,
		`UPDATE machines
		 SET last_scrape_at = ?, last_ok_at = ?, consecutive_failures = 0, last_error = '',last_status_sample_ns=?
		 WHERE id = ? AND target_generation=? AND enabled=1
 AND (last_metric_sample_ns IS NULL OR last_metric_sample_ns<=?)
 AND (last_status_sample_ns IS NULL OR last_status_sample_ns<=?)`,
		at.Unix(), at.Unix(), at.UnixNano(), id, generation, at.UnixNano(), at.UnixNano())
	if err != nil {
		return fmt.Errorf("record scrape success: %w", err)
	}
	return requireOneRow(result, ErrObsoleteScrape)
}

// RecordScrapeFailure keeps last_ok_at untouched so the UI can say how long a
// machine has been unreachable while its history stays intact.
func (s *Store) RecordScrapeFailure(ctx context.Context, id int64, at time.Time, message string, generations ...int64) error {
	generation := int64(0)
	if len(generations) > 0 {
		generation = generations[0]
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE machines
		 SET last_scrape_at = ?, consecutive_failures = consecutive_failures + 1, last_error = ?,last_status_sample_ns=?
 WHERE id = ? AND target_generation=? AND enabled=1
 AND (last_metric_sample_ns IS NULL OR last_metric_sample_ns<=?)
 AND (last_status_sample_ns IS NULL OR last_status_sample_ns<=?)`,
		at.Unix(), truncateToBytes(message, maxLastErrorLength), at.UnixNano(), id, generation, at.UnixNano(), at.UnixNano())
	if err != nil {
		return fmt.Errorf("record scrape failure: %w", err)
	}
	if err = requireOneRow(result, ErrObsoleteScrape); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO scrape_coverage(machine_id,bucket,attempts) VALUES(?,?,1) ON CONFLICT(machine_id,bucket) DO UPDATE SET attempts=attempts+1`, id, at.Unix()/60*60); err != nil {
		return err
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMachine(scanner rowScanner) (Machine, error) {
	var (
		machine       Machine
		createdAt     int64
		lastScrapeAt  sql.NullInt64
		lastOKAt      sql.NullInt64
		targetChanged sql.NullInt64
	)
	err := scanner.Scan(
		&machine.ID, &machine.Name, &machine.Host, &machine.Port, &machine.MetricsPath,
		&machine.GroupLabel, &machine.Enabled, &createdAt, &lastScrapeAt, &lastOKAt,
		&machine.ConsecutiveFailures, &machine.LastError, &machine.Colour, &machine.TargetGeneration, &targetChanged,
	)
	if err != nil {
		return Machine{}, err
	}
	machine.CreatedAt = time.Unix(createdAt, 0).UTC()
	machine.LastScrapeAt = timeFromNullable(lastScrapeAt)
	machine.LastOKAt = timeFromNullable(lastOKAt)
	if targetChanged.Valid {
		at := time.Unix(0, targetChanged.Int64).UTC()
		machine.TargetChangedAt = &at
	}
	return machine, nil
}

func requireOneRow(result sql.Result, notFound error) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return notFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// truncateToBytes cuts a string to at most limit bytes, stepping back to a rune
// boundary rather than through one. A byte limit is what actually bounds a row
// and a JSON response; splitting a multi-byte character to reach it exactly
// would store something that is no longer text.
func truncateToBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
