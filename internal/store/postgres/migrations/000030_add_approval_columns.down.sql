BEGIN;

ALTER TABLE
    "approvals" DROP COLUMN IF EXISTS "details";

ALTER TABLE
    "approvals" DROP COLUMN IF EXISTS "dont_allow_self_approval";

ALTER TABLE
    "approvals" DROP COLUMN IF EXISTS "allow_failed";

COMMIT;