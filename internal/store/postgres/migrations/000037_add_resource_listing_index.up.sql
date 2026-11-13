-- Keep is_deleted in the key: the repository binds it as a parameter, so a
-- predicate on is_deleted=false would not be usable by a generic prepared plan.
-- One concurrent index per migration; do not wrap this in a transaction.
CREATE INDEX CONCURRENTLY idx_resources_filter_global_urn
    ON resources (provider_type, type, is_deleted, global_urn)
    WHERE deleted_at IS NULL;
