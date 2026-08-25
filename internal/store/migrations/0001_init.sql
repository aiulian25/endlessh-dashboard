CREATE TABLE machines (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT    NOT NULL UNIQUE,
    host                 TEXT    NOT NULL,
    port                 INTEGER NOT NULL,
    metrics_path         TEXT    NOT NULL DEFAULT '/metrics',
    group_label          TEXT    NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           INTEGER NOT NULL,
    last_scrape_at       INTEGER,
    last_ok_at           INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error           TEXT    NOT NULL DEFAULT ''
);

-- Per-minute deltas derived from the four aggregate counters. Pruned by retention.
CREATE TABLE machine_rollups (
    machine_id      INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    bucket          INTEGER NOT NULL,
    opens           INTEGER NOT NULL DEFAULT 0,
    closes          INTEGER NOT NULL DEFAULT 0,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    trapped_seconds REAL    NOT NULL DEFAULT 0,
    PRIMARY KEY (machine_id, bucket)
) WITHOUT ROWID;

CREATE INDEX idx_machine_rollups_bucket ON machine_rollups(bucket);

-- Lifetime running totals. Never pruned, so headline numbers survive retention.
CREATE TABLE machine_totals (
    machine_id      INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    opens           INTEGER NOT NULL DEFAULT 0,
    closes          INTEGER NOT NULL DEFAULT 0,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    trapped_seconds REAL    NOT NULL DEFAULT 0,
    distinct_ips    INTEGER NOT NULL DEFAULT 0
);

-- Last raw counter value per series, so the next scrape can compute a delta and
-- detect a restart of the monitored instance (a value that went backwards).
CREATE TABLE counter_states (
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    series     TEXT    NOT NULL,
    value      REAL    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (machine_id, series)
) WITHOUT ROWID;

CREATE INDEX idx_counter_states_updated_at ON counter_states(updated_at);

CREATE TABLE attackers (
    machine_id       INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    ip_address       TEXT    NOT NULL,
    first_seen       INTEGER NOT NULL,
    last_seen        INTEGER NOT NULL,
    last_activity_at INTEGER NOT NULL,
    connections      INTEGER NOT NULL DEFAULT 0,
    trapped_seconds  REAL    NOT NULL DEFAULT 0,
    country          TEXT    NOT NULL DEFAULT '',
    geohash          TEXT    NOT NULL DEFAULT '',
    location         TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (machine_id, ip_address)
) WITHOUT ROWID;

CREATE INDEX idx_attackers_last_seen ON attackers(last_seen);
CREATE INDEX idx_attackers_last_activity_at ON attackers(last_activity_at);
CREATE INDEX idx_attackers_trapped_seconds ON attackers(trapped_seconds);
CREATE INDEX idx_attackers_country ON attackers(country);

CREATE TABLE users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT    NOT NULL UNIQUE,
    password_hash        TEXT    NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
