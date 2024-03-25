BEGIN;

ALTER TABLE
  "policies" DROP COLUMN IF EXISTS "appeal_metadata_sources";

COMMIT;