BEGIN;

ALTER TABLE
  "policies"
ADD
  COLUMN IF NOT EXISTS "appeal_metadata_sources" JSONB;

COMMIT;