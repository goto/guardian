BEGIN;

ALTER TABLE
  "resources"
ADD COLUMN IF NOT EXISTS "group_id" text,
ADD COLUMN IF NOT EXISTS "group_type" text;

CREATE INDEX IF NOT EXISTS "resource_group_index" ON "resources" ("group_id", "group_type");

COMMIT;