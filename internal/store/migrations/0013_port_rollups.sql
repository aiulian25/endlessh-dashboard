-- Forward-only: merged historic totals cannot be divided into ports.
CREATE TABLE port_collection (
 machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 started_at_ns INTEGER NOT NULL,
 PRIMARY KEY(machine_id,generation)
);
CREATE TABLE port_rollups (
 machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 port TEXT NOT NULL,
 bucket INTEGER NOT NULL,
 opens INTEGER NOT NULL DEFAULT 0,
 closes INTEGER NOT NULL DEFAULT 0,
 bytes_sent INTEGER NOT NULL DEFAULT 0,
 trapped_seconds REAL NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0,
 successes INTEGER NOT NULL DEFAULT 0,
 covered_seconds REAL NOT NULL DEFAULT 0 CHECK(covered_seconds>=0 AND covered_seconds<=60),
 uncertain_from INTEGER,
 uncertain_to INTEGER,
 PRIMARY KEY(machine_id,generation,port,bucket)
);
CREATE INDEX idx_port_rollups_bucket ON port_rollups(bucket);
