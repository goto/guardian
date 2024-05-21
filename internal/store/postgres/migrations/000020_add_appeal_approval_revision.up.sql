BEGIN;

ALTER TABLE
    "appeals"
ADD
    COLUMN IF NOT EXISTS "revision" int;

ALTER TABLE
    "approvals"
ADD 
    COLUMN IF NOT EXISTS "appeal_revision" int,
ADD 
    COLUMN IF NOT EXISTS "is_stale" boolean;

COMMIT;
