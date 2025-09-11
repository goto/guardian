BEGIN;

ALTER TABLE
    "appeals"
DROP COLUMN IF EXISTS "group_id";

ALTER TABLE
    "appeals"
DROP COLUMN IF EXISTS "group_type";

COMMIT;