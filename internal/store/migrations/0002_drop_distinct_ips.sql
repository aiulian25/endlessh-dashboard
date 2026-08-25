-- distinct_ips was a running count incremented whenever an attacker row was
-- inserted. Retention deletes attacker rows, so an IP that was pruned and later
-- came back was counted twice, inflating the headline figure permanently.
-- The number is now counted directly from the attackers table, which cannot
-- drift, and counts one attacker once even when it hit several machines.
ALTER TABLE machine_totals DROP COLUMN distinct_ips;
