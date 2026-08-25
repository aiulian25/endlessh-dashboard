package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
}

const machineColumns = `id, name, host, port, metrics_path, group_label, enabled, created_at,
	last_scrape_at, last_ok_at, consecutive_failures, last_error`

func (s *Store) ListMachines(ctx context.Context) ([]Machine, error) {
	rows, err := s.database.QueryContext(ctx,
		"SELECT "+machineColumns+" FROM machines ORDER BY name COLLATE NOCASE")
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

func (s *Store) CreateMachine(ctx context.Context, machine Machine) (Machine, error) {
	machine.CreatedAt = time.Now().UTC()
	result, err := s.database.ExecContext(ctx,
		`INSERT INTO machines (name, host, port, metrics_path, group_label, enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		machine.Name, machine.Host, machine.Port, machine.MetricsPath,
		machine.GroupLabel, machine.Enabled, machine.CreatedAt.Unix())
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

	if _, err := s.database.ExecContext(ctx,
		"INSERT INTO machine_totals (machine_id) VALUES (?)", id); err != nil {
		return Machine{}, fmt.Errorf("create machine totals: %w", err)
	}
	return machine, nil
}

func (s *Store) UpdateMachine(ctx context.Context, machine Machine) error {
	result, err := s.database.ExecContext(ctx,
		`UPDATE machines
		 SET name = ?, host = ?, port = ?, metrics_path = ?, group_label = ?, enabled = ?
		 WHERE id = ?`,
		machine.Name, machine.Host, machine.Port, machine.MetricsPath,
		machine.GroupLabel, machine.Enabled, machine.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateMachineName
		}
		return fmt.Errorf("update machine: %w", err)
	}
	return requireOneRow(result, ErrMachineNotFound)
}

func (s *Store) DeleteMachine(ctx context.Context, id int64) error {
	result, err := s.database.ExecContext(ctx, "DELETE FROM machines WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete machine: %w", err)
	}
	return requireOneRow(result, ErrMachineNotFound)
}

// RecordScrapeSuccess clears the failure streak and stamps both timestamps.
func (s *Store) RecordScrapeSuccess(ctx context.Context, id int64, at time.Time) error {
	_, err := s.database.ExecContext(ctx,
		`UPDATE machines
		 SET last_scrape_at = ?, last_ok_at = ?, consecutive_failures = 0, last_error = ''
		 WHERE id = ?`,
		at.Unix(), at.Unix(), id)
	if err != nil {
		return fmt.Errorf("record scrape success: %w", err)
	}
	return nil
}

// RecordScrapeFailure keeps last_ok_at untouched so the UI can say how long a
// machine has been unreachable while its history stays intact.
func (s *Store) RecordScrapeFailure(ctx context.Context, id int64, at time.Time, message string) error {
	_, err := s.database.ExecContext(ctx,
		`UPDATE machines
		 SET last_scrape_at = ?, consecutive_failures = consecutive_failures + 1, last_error = ?
		 WHERE id = ?`,
		at.Unix(), message, id)
	if err != nil {
		return fmt.Errorf("record scrape failure: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMachine(scanner rowScanner) (Machine, error) {
	var (
		machine      Machine
		createdAt    int64
		lastScrapeAt sql.NullInt64
		lastOKAt     sql.NullInt64
	)
	err := scanner.Scan(
		&machine.ID, &machine.Name, &machine.Host, &machine.Port, &machine.MetricsPath,
		&machine.GroupLabel, &machine.Enabled, &createdAt, &lastScrapeAt, &lastOKAt,
		&machine.ConsecutiveFailures, &machine.LastError,
	)
	if err != nil {
		return Machine{}, err
	}
	machine.CreatedAt = time.Unix(createdAt, 0).UTC()
	machine.LastScrapeAt = timeFromNullable(lastScrapeAt)
	machine.LastOKAt = timeFromNullable(lastOKAt)
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
