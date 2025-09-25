BEGIN;

ALTER TABLE
    "policies"
DROP COLUMN IF EXISTS "custom_steps";

COMMIT;