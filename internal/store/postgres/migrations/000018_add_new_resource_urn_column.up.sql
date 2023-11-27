BEGIN;

ALTER TABLE
  "resources"
ADD
  COLUMN IF NOT EXISTS "global_urn" text;

CREATE UNIQUE INDEX IF NOT EXISTS "resource_global_urn" ON "resources" ("global_urn")
WHERE
  "deleted_at" IS NULL;

COMMIT;