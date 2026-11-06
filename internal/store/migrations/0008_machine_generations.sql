-- Endpoint/enable changes invalidate fetched work without deleting history.
ALTER TABLE machines ADD COLUMN target_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE machines ADD COLUMN target_changed_at_ns INTEGER;
ALTER TABLE machines ADD COLUMN scrape_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE machines ADD COLUMN last_metric_sample_ns INTEGER;
ALTER TABLE machines ADD COLUMN last_status_sample_ns INTEGER;
