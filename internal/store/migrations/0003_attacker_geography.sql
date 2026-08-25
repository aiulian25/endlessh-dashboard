-- The tarpit's own labels give a country, a geohash and a free-text location,
-- which is enough to list an attacker but not to plot one: a map needs numbers,
-- and a geohash is a string. These columns hold what any of the three geography
-- sources produced — the tarpit's labels, a local MaxMind database, or the
-- opt-in online lookup — so the map never has to decode anything at read time.
--
-- latitude and longitude are nullable on purpose. 0,0 is a real point in the
-- Gulf of Guinea, so "no coordinate known" cannot be spelled as a number; NULL
-- is the only honest value, and it keeps unlocatable attackers off the map.
ALTER TABLE attackers ADD COLUMN latitude  REAL;
ALTER TABLE attackers ADD COLUMN longitude REAL;

-- country holds whatever the source called the country: MaxMind says "Germany",
-- a tarpit configured with a country-only database may say "DE". The ISO code is
-- kept separately so a flag, and a breakdown that has to agree across machines
-- whose tarpits label countries differently, have one stable key to work from.
ALTER TABLE attackers ADD COLUMN country_code TEXT NOT NULL DEFAULT '';

-- The network an address belongs to says more about an attacker than its city
-- does: a hosting provider means a rented scanner, a consumer ISP means a
-- compromised box. Only the online provider fills this in; it stays empty
-- otherwise, like every other geography column with no source.
ALTER TABLE attackers ADD COLUMN isp TEXT NOT NULL DEFAULT '';
