BEGIN;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_id" uuid;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_type" text;

ALTER TABLE
    "grants"
    ADD COLUMN IF NOT EXISTS "group_id" uuid;

ALTER TABLE
    "grants"
    ADD COLUMN IF NOT EXISTS "group_type" text;

COMMIT;