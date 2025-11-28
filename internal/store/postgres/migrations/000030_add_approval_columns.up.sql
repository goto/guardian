BEGIN;

ALTER TABLE
    "approvals"
    ADD
        COLUMN IF NOT EXISTS "allow_failed" boolean;

ALTER TABLE
    "approvals"
    ADD
        COLUMN IF NOT EXISTS "dont_allow_self_approval" string;

ALTER TABLE
    "approvals"
    ADD
        COLUMN IF NOT EXISTS "details" jsonb;

COMMIT;