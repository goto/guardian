BEGIN;

ALTER TABLE
    "appeals"
ADD
    COLUMN IF NOT EXISTS "revision" bigint;

ALTER TABLE
    "approvals"
ADD 
    COLUMN IF NOT EXISTS "appeal_revision" bigint,
ADD 
    COLUMN IF NOT EXISTS "is_stale" boolean;

COMMIT;
