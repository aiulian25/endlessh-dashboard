-- Existing machines cannot recover per-port baselines from collapsed history.
-- Persist the conservative first-observation policy, including across restarts
-- and for series absent at upgrade. New registrations retain lifetime imports.
ALTER TABLE machines ADD COLUMN client_counter_policy TEXT NOT NULL
    DEFAULT 'import_lifetime'
    CHECK (client_counter_policy IN ('import_lifetime', 'baseline_only'));
UPDATE machines SET client_counter_policy = 'baseline_only';
