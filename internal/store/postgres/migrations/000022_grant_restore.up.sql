ALTER TABLE
  "grants"
ADD
  COLUMN IF NOT EXISTS "restored_by" text,
ADD
  COLUMN IF NOT EXISTS "restored_at" timestamptz,
ADD
  COLUMN IF NOT EXISTS "restore_reason" text;