-- Source records retained by the transactional Go data migration for review.
-- No collision counters are added together. Machine deletion removes archives.
CREATE TABLE attacker_ip_archive (
 machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
 original_ip TEXT NOT NULL,
 canonical_ip TEXT NOT NULL,
 reason TEXT NOT NULL,
 row_json TEXT NOT NULL,
 PRIMARY KEY(machine_id,original_ip)
) WITHOUT ROWID;
CREATE TABLE counter_ip_archive (
 machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
 original_series TEXT NOT NULL,
 canonical_series TEXT NOT NULL,
 reason TEXT NOT NULL,
 row_json TEXT NOT NULL,
 PRIMARY KEY(machine_id,original_series)
) WITHOUT ROWID;
