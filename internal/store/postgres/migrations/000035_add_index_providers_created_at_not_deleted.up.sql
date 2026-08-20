CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_providers_created_at_not_deleted ON providers (created_at) WHERE deleted_at IS NULL;
