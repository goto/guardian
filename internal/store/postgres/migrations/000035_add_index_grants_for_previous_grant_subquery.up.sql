CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_grants_account_resource_role_deleted_created
    ON grants (account_id, resource_id, role, deleted_at, created_at DESC)
    INCLUDE (expiration_date, group_id, group_type);
