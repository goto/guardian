BEGIN;

ALTER TABLE
    "approvals"
DROP 
    COLUMN IF EXISTS "appeal_revision",
DROP 
    COLUMN IF EXISTS "is_stale";

ALTER TABLE
    "appeals"
DROP
    COLUMN IF EXISTS "revision";

COMMIT;