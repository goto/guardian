CREATE UNIQUE INDEX IF NOT EXISTS "unique_active_grants_index" ON "grants" ("account_id", "account_type", "resource_id", "permissions")
WHERE
  "status" = 'active';
