package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"endlessh-dashboard/internal/ipidentity"
	"endlessh-dashboard/internal/metricvalue"
)

const identityAttackerColumns = "machine_id,ip_address,first_seen,last_seen,last_activity_at,connections,trapped_seconds,country,geohash,location,latitude,longitude,country_code,isp,last_observed_at,last_measured_activity_at,has_undated_history,first_observation_known"

type identityRow map[string]any

func identityRows(ctx context.Context, tx *sql.Tx, query string) ([]identityRow, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var result []identityRow
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err = rows.Scan(dest...); err != nil {
			return nil, err
		}
		row := identityRow{}
		for i, col := range columns {
			row[col] = values[i]
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
func identityInt(row identityRow, key string) int64 {
	if row[key] == nil {
		return 0
	}
	return row[key].(int64)
}
func identityFloat(row identityRow, key string) float64 {
	if value, ok := row[key].(int64); ok {
		return float64(value)
	}
	return row[key].(float64)
}
func archiveIdentity(ctx context.Context, tx *sql.Tx, table, original, canonical, reason string, row identityRow) error {
	data, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("archive identity source: %w", err)
	}
	column := "original_ip,canonical_ip"
	if table == "counter_ip_archive" {
		column = "original_series,canonical_series"
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO "+table+" (machine_id,"+column+",reason,row_json) VALUES (?,?,?,?,?)", row["machine_id"], original, canonical, reason, string(data))
	return err
}

// migrateIPIdentities is part of migration 10's transaction, before its marker.
// Original rows are archived before renaming, quarantine or conservative merge.
func migrateIPIdentities(ctx context.Context, tx *sql.Tx) error {
	rows, err := identityRows(ctx, tx, "SELECT "+identityAttackerColumns+" FROM attackers ORDER BY machine_id,ip_address")
	if err != nil {
		return err
	}
	affected := map[int64]bool{} // bool means raw continuity is ambiguous.
	groups := map[string][]identityRow{}
	for _, row := range rows {
		for _, key := range []string{"machine_id", "first_seen", "last_seen", "last_activity_at", "connections", "last_observed_at", "has_undated_history", "first_observation_known"} {
			if _, ok := row[key].(int64); !ok {
				return fmt.Errorf("invalid stored identity field %s", key)
			}
		}
		if v := row["last_measured_activity_at"]; v != nil {
			if _, ok := v.(int64); !ok {
				return fmt.Errorf("invalid stored activity timestamp")
			}
		}
		if _, err := metricvalue.AddInt(0, identityInt(row, "connections")); err != nil {
			return err
		}
		switch row["trapped_seconds"].(type) {
		case int64, float64:
		default:
			return fmt.Errorf("invalid stored identity duration")
		}
		if err := metricvalue.Validate(identityFloat(row, "trapped_seconds"), false); err != nil {
			return err
		}
		original, ok := row["ip_address"].(string)
		if !ok {
			return fmt.Errorf("invalid stored attacker label type")
		}
		machine := identityInt(row, "machine_id")
		canonical, e := ipidentity.Canonical(original)
		if e != nil {
			if err = archiveIdentity(ctx, tx, "attacker_ip_archive", original, "", "invalid", row); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM attackers WHERE machine_id=? AND ip_address=?", machine, original); err != nil {
				return err
			}
			affected[machine] = true
			continue
		}
		key := fmt.Sprintf("%d|%s", machine, canonical)
		groups[key] = append(groups[key], row)
	}
	columns := strings.Split(identityAttackerColumns, ",")
	for _, group := range groups {
		first := group[0]
		machine := identityInt(first, "machine_id")
		canonical, _ := ipidentity.Canonical(first["ip_address"].(string))
		if len(group) == 1 && first["ip_address"] == canonical {
			continue
		}
		reason := "normalized"
		if len(group) > 1 {
			reason = "collision"
			affected[machine] = true
		} else {
			if _, ok := affected[machine]; !ok {
				affected[machine] = false
			}
		}
		// Metadata comes from the latest observed row, with lexical ties determined
		// by the source query. Numeric counters are independent maxima, never sums.
		winner := first
		for _, row := range group {
			if identityInt(row, "last_observed_at") > identityInt(winner, "last_observed_at") {
				winner = row
			}
		}
		merged := identityRow{}
		for key, value := range winner {
			merged[key] = value
		}
		for _, row := range group {
			if err = archiveIdentity(ctx, tx, "attacker_ip_archive", row["ip_address"].(string), canonical, reason, row); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM attackers WHERE machine_id=? AND ip_address=?", machine, row["ip_address"]); err != nil {
				return err
			}
			for _, key := range []string{"last_seen", "last_activity_at", "connections", "last_observed_at", "has_undated_history"} {
				merged[key] = max(identityInt(merged, key), identityInt(row, key))
			}
			for _, key := range []string{"first_seen", "first_observation_known"} {
				merged[key] = min(identityInt(merged, key), identityInt(row, key))
			}
			if row["last_measured_activity_at"] != nil {
				merged["last_measured_activity_at"] = max(identityInt(merged, "last_measured_activity_at"), identityInt(row, "last_measured_activity_at"))
			}
			merged["trapped_seconds"] = math.Max(identityFloat(merged, "trapped_seconds"), identityFloat(row, "trapped_seconds"))
		}
		merged["ip_address"] = canonical
		args := make([]any, len(columns))
		for i, col := range columns {
			args[i] = merged[col]
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO attackers ("+identityAttackerColumns+") VALUES ("+placeholders(len(columns))+")", args...); err != nil {
			return err
		}
	}
	baselines, err := identityRows(ctx, tx, "SELECT machine_id,series,value,updated_at FROM counter_states WHERE typeof(series)!='text' OR series LIKE 'ip:%' ORDER BY machine_id,series")
	if err != nil {
		return err
	}
	rawGroups := map[string][]identityRow{}
	for _, row := range baselines {
		if _, ok := row["machine_id"].(int64); !ok {
			return fmt.Errorf("invalid stored raw machine identity")
		}
		machine := identityInt(row, "machine_id")
		original, ok := row["series"].(string)
		if !ok {
			return fmt.Errorf("invalid stored raw series type")
		}
		canonical, _, e := ipidentity.NormalizeRawKey(original)
		if e != nil {
			reason := "legacy_collapsed"
			if strings.HasPrefix(original, "ip:v2:") {
				reason = "invalid"
			}
			if err = archiveIdentity(ctx, tx, "counter_ip_archive", original, "", reason, row); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM counter_states WHERE machine_id=? AND series=?", machine, original); err != nil {
				return err
			}
			affected[machine] = true
			continue
		}
		key := fmt.Sprintf("%d|%s", machine, canonical)
		rawGroups[key] = append(rawGroups[key], row)
	}
	for _, group := range rawGroups {
		first := group[0]
		machine := identityInt(first, "machine_id")
		canonical, _, _ := ipidentity.NormalizeRawKey(first["series"].(string))
		if len(group) == 1 && first["series"] == canonical {
			continue
		}
		reason := "normalized"
		if len(group) > 1 {
			reason = "collision"
			affected[machine] = true
		} else {
			if _, ok := affected[machine]; !ok {
				affected[machine] = false
			}
		}
		for _, row := range group {
			if err = archiveIdentity(ctx, tx, "counter_ip_archive", row["series"].(string), canonical, reason, row); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM counter_states WHERE machine_id=? AND series=?", machine, row["series"]); err != nil {
				return err
			}
		}
		if len(group) == 1 {
			if _, err = tx.ExecContext(ctx, "INSERT INTO counter_states(machine_id,series,value,updated_at) VALUES(?,?,?,?)", machine, canonical, first["value"], first["updated_at"]); err != nil {
				return err
			}
		}
	}
	for machine, ambiguous := range affected {
		if _, err = tx.ExecContext(ctx, `UPDATE machines SET scrape_revision=scrape_revision+1,client_counter_policy=CASE WHEN ? THEN 'baseline_only' ELSE client_counter_policy END WHERE id=?`, ambiguous, machine); err != nil {
			return err
		}
	}
	return nil
}

// IPIdentityReviewCount reports preserved ambiguous/invalid source rows without
// exposing untrusted labels in logs. Normal one-to-one renames need no review.
func (s *Store) IPIdentityReviewCount(ctx context.Context) (int, error) {
	var count int
	err := s.database.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM attacker_ip_archive WHERE reason!='normalized')+(SELECT COUNT(*) FROM counter_ip_archive WHERE reason!='normalized')`).Scan(&count)
	return count, err
}

// Restores of already-current schemas must satisfy the same identity contract
// as migrated copies. Archives intentionally retain noncanonical source text.
func validateCanonicalIdentityData(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "SELECT ip_address,typeof(ip_address) FROM attackers")
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip, kind string
		if err = rows.Scan(&ip, &kind); err != nil {
			break
		}
		canonical, e := ipidentity.Canonical(ip)
		if e != nil || canonical != ip || kind != "text" {
			err = fmt.Errorf("backup has noncanonical active attacker identity")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = db.QueryContext(ctx, "SELECT series,typeof(series) FROM counter_states")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, kind string
		if err = rows.Scan(&key, &kind); err != nil {
			return err
		}
		if kind != "text" {
			return fmt.Errorf("backup has invalid baseline identity type")
		}
		if !strings.HasPrefix(key, "ip:") {
			continue
		}
		canonical, _, e := ipidentity.NormalizeRawKey(key)
		if e != nil || canonical != key {
			return fmt.Errorf("backup has noncanonical active client baseline")
		}
	}
	return rows.Err()
}
