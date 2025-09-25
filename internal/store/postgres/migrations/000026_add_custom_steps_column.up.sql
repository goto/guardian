BEGIN;

ALTER TABLE
    "policies"
    ADD COLUMN IF NOT EXISTS "custom_steps" jsonb;

COMMIT;