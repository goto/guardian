CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_grants_account_resource_role_created
    ON grants (account_id, resource_id, role, group_id, group_type, created_at DESC)
    INCLUDE (expiration_date, is_permanent, revoked_at);
