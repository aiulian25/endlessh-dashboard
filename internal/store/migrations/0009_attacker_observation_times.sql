-- Old last_seen records exporter observation, never an activity timestamp.
ALTER TABLE attackers ADD COLUMN last_observed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attackers ADD COLUMN last_measured_activity_at INTEGER;
ALTER TABLE attackers ADD COLUMN has_undated_history INTEGER NOT NULL DEFAULT 1;
ALTER TABLE attackers ADD COLUMN first_observation_known INTEGER NOT NULL DEFAULT 1;
UPDATE attackers SET last_observed_at=last_seen,
 last_measured_activity_at=CASE WHEN last_activity_at>0 THEN last_activity_at ELSE NULL END;
CREATE INDEX idx_attackers_measured_activity ON attackers(last_measured_activity_at);
