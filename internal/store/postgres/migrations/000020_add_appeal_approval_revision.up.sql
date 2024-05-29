BEGIN;

ALTER TABLE
    "appeals"
ADD
    COLUMN IF NOT EXISTS "revision" int NOT NULL DEFAULT 0;

ALTER TABLE
    "approvals"
ADD 
    COLUMN IF NOT EXISTS "appeal_revision" int NOT NULL DEFAULT 0,
ADD 
    COLUMN IF NOT EXISTS "is_stale" boolean NOT NULL DEFAULT FALSE;

COMMIT;
