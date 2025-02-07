BEGIN;

ALTER TABLE "audit_logs"
ADD COLUMN IF NOT EXISTS "id" UUID DEFAULT uuid_generate_v4();

UPDATE "audit_logs"
SET "id" = uuid_generate_v4()
WHERE "id" IS NULL;

ALTER TABLE "audit_logs"
ADD CONSTRAINT IF NOT EXISTS audit_logs_pkey PRIMARY KEY ("id");

COMMIT;