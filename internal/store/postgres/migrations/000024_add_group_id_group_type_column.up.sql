BEGIN;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_id" text;

ALTER TABLE
    "appeals"
    ADD COLUMN IF NOT EXISTS "group_type" text;

ALTER TABLE
    "grants"
    ADD COLUMN IF NOT EXISTS "group_id" text;

ALTER TABLE
    "grants"
    ADD COLUMN IF NOT EXISTS "group_type" text;

COMMIT;