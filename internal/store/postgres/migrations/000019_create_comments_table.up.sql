CREATE TABLE IF NOT EXISTS "comments" (
  "id" uuid DEFAULT uuid_generate_v4(),
  "parent_type" text,
  "parent_id" text,
  "created_by" text,
  "body" text,
  "created_at" timestamptz,
  "updated_at" timestamptz,
  "deleted_at" timestamptz,
  PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "idx_comments_deleted_at" ON "comments" ("deleted_at");

CREATE INDEX IF NOT EXISTS "idx_comments_parent_id" ON "comments" ("parent_id")
WHERE
  "deleted_at" IS NULL;

CREATE INDEX IF NOT EXISTS "idx_comments_parent_type" ON "comments" ("parent_type")
WHERE
  "deleted_at" IS NULL;