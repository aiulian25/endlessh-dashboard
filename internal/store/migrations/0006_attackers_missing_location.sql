-- The geography backfill asks, once a minute for the life of the process, which
-- attackers still have no place attached to them. attackers is the largest table
-- in the schema and the answer is a small minority of it, so without an index
-- that question reads every row that has already been placed in order to skip it.
--
-- The WHERE below has to stay character-for-character the same as the one in
-- AttackersMissingLocation. SQLite only uses a partial index when it can prove
-- the query's condition implies the index's, and for a two-branch OR that proof
-- is the two being identical. Change one and this index silently stops being
-- used; nothing fails, the query just goes back to reading the whole table.
--
-- ip_address leads because that is what the query groups by, which lets SQLite
-- read the groups in order instead of building a temporary B-tree for them.
-- last_seen follows for the ordering. machine_id is deliberately absent: this
-- table is WITHOUT ROWID, so every index entry already carries the primary key,
-- and naming it again measured identically while reading as though it did
-- something.
CREATE INDEX idx_attackers_missing_location
    ON attackers(ip_address, last_seen)
    WHERE location = '' OR country_code = '';
