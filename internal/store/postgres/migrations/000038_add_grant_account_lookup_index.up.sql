-- Grant list/count filters use LOWER(account_id), unlike the existing raw
-- account_id index used by previous-grant lookups. Retain both access paths.
CREATE INDEX CONCURRENTLY idx_grants_lower_account_status_resource
    ON grants (LOWER(account_id), status, resource_id)
    WHERE deleted_at IS NULL;
