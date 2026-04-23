-- Indexes added to address slow queries identified from the production slow log.
-- Each CREATE INDEX CONCURRENTLY is its own statement (cannot run inside a transaction).

-- Covers: SELECT [count(*)|*] FROM resources
--         WHERE is_deleted = ? AND provider_type IN (?) AND type IN (?) AND deleted_at IS NULL
--         [ORDER BY global_urn LIMIT ? OFFSET ?]
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_resources_is_deleted_provider_type_type
    ON resources (is_deleted, provider_type, type)
    WHERE deleted_at IS NULL;

-- Covers: SELECT * FROM policies WHERE deleted_at IS NULL ORDER BY created_at ASC
-- Partial index keeps it small (only live rows) and lets the planner satisfy ORDER BY from the index.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policies_created_at_not_deleted
    ON policies (created_at)
    WHERE deleted_at IS NULL;

-- Covers: SELECT * FROM providers WHERE deleted_at IS NULL ORDER BY created_at ASC
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_providers_created_at_not_deleted
    ON providers (created_at)
    WHERE deleted_at IS NULL;
