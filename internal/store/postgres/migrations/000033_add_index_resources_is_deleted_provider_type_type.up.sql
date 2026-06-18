CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_resources_is_deleted_provider_type_type ON resources (is_deleted, provider_type, type) WHERE deleted_at IS NULL;
