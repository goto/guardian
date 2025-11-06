BEGIN;

CREATE INDEX IF NOT EXISTS "appeal_group_index" ON "appeals" ("group_id", "group_type");
CREATE INDEX IF NOT EXISTS "grant_group_index" ON "grants" ("group_id", "group_type");
COMMIT;