-- Add labels_metadata column for rich metadata about each label
ALTER TABLE appeals ADD COLUMN IF NOT EXISTS labels_metadata JSONB;

-- Add GIN indexes for efficient label filtering
CREATE INDEX IF NOT EXISTS idx_appeals_labels ON appeals USING GIN (labels);
CREATE INDEX IF NOT EXISTS idx_appeals_labels_metadata ON appeals USING GIN (labels_metadata);

-- Add comments for documentation
COMMENT ON COLUMN appeals.labels IS 'System-generated and user-provided labels (namespaced key-value pairs)';
COMMENT ON COLUMN appeals.labels_metadata IS 'Rich metadata about each label including derivation, category, and attributes';
