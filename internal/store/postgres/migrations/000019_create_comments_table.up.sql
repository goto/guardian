CREATE TABLE IF NOT EXISTS "comments" (
  "id" uuid DEFAULT uuid_generate_v4(),
  "appeal_id" uuid,
  "created_by" text,
  "body" text,
  "created_at" timestamptz,
  "updated_at" timestamptz,
  "deleted_at" timestamptz,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_comments_appeal" FOREIGN KEY ("appeal_id") REFERENCES "appeals"("id")
);

CREATE INDEX IF NOT EXISTS "idx_comments_deleted_at" ON "comments" ("deleted_at");

CREATE INDEX IF NOT EXISTS "idx_comments_appeal_id" ON "comments" ("appeal_id")
WHERE
  "deleted_at" IS NULL;