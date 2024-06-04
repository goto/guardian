ALTER TABLE
  "grants" DROP COLUMN IF EXISTS "restore_reason",
  DROP COLUMN IF EXISTS "restored_at",
  DROP COLUMN IF EXISTS "restored_by";