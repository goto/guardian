CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policies_created_at_not_deleted ON policies (created_at) WHERE deleted_at IS NULL;
