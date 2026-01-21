-- Drop indexes
DROP INDEX IF EXISTS idx_appeals_labels;
DROP INDEX IF EXISTS idx_appeals_labels_metadata;

-- Drop labels_metadata column
-- Note: We don't drop the column to preserve data, just remove indexes
-- If you really want to drop the column, uncomment the line below:
-- ALTER TABLE appeals DROP COLUMN IF EXISTS labels_metadata;
