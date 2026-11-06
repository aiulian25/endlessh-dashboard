-- One current-source attempt record per retained canonical IP; no event log.
CREATE TABLE enrichment_progress (
    ip_address TEXT PRIMARY KEY,
    source_generation TEXT NOT NULL,
    last_attempt_at INTEGER NOT NULL,
    next_attempt_at INTEGER,
    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 16),
    outcome TEXT NOT NULL CHECK(outcome IN ('resolved','partial','miss','unlookupable','transient'))
) WITHOUT ROWID;

-- Needed for per-IP completion and last-copy cleanup, including already placed rows.
CREATE INDEX idx_attackers_enrichment_ip ON attackers(ip_address);
CREATE TRIGGER enrichment_progress_last_copy_deleted
AFTER DELETE ON attackers
WHEN NOT EXISTS (SELECT 1 FROM attackers WHERE ip_address = OLD.ip_address)
BEGIN
    DELETE FROM enrichment_progress WHERE ip_address = OLD.ip_address;
END;
