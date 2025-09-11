BEGIN;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_id" uuid;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_type" text;

COMMIT;