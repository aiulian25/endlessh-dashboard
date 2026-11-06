-- No backfill: old rollups cannot establish successful observation coverage.
CREATE TABLE scrape_coverage (
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    covered_seconds REAL NOT NULL DEFAULT 0 CHECK(covered_seconds >= 0 AND covered_seconds <= 60),
    uncertain_from INTEGER,
    uncertain_to INTEGER,
    PRIMARY KEY (machine_id, bucket)
);
CREATE TABLE scrape_coverage_state (
    machine_id INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    sample_ns INTEGER NOT NULL,
    cadence_ns INTEGER NOT NULL
);

CREATE INDEX idx_scrape_coverage_bucket ON scrape_coverage(bucket);
