-- The colour the operator picked for each machine. Empty means "not chosen",
-- which the registry fills with the least-used slot when a machine is created,
-- so a machine added without a choice still gets one nobody else is using.
ALTER TABLE machines ADD COLUMN colour TEXT NOT NULL DEFAULT '';

-- Give every machine that already exists the colour it is being drawn in right
-- now, so an upgrade changes nothing on screen. Until this migration the colour
-- was derived, not stored: rank the machines by id and take that position in a
-- palette of eight. The count of machines with a smaller id is exactly that
-- 0-based rank, which avoids needing a window function here.
UPDATE machines SET colour = 's-' || (
    ((SELECT COUNT(*) FROM machines AS earlier WHERE earlier.id < machines.id) % 8) + 1
);
