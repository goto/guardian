BEGIN;
CREATE INDEX IF NOT EXISTS idx_grants_lower_owner_status ON grants (LOWER(owner), status);
COMMIT;