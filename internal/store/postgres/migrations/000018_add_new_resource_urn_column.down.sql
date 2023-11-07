BEGIN;

DROP INDEX IF EXISTS "resource_global_urn";

ALTER TABLE
  "resources"
DROP
  COLUMN IF EXISTS "global_urn";

COMMIT;