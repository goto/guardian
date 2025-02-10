BEGIN;

ALTER TABLE "audit_logs"
ADD COLUMN IF NOT EXISTS "id" UUID DEFAULT uuid_generate_v4();

DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'audit_logs_pkey'
  ) THEN
    ALTER TABLE "audit_logs" ADD CONSTRAINT audit_logs_pkey PRIMARY KEY ("id");
  END IF;
END $$;

COMMIT;