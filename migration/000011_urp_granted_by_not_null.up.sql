-- Migrate "system-issued grants" off the NULL anti-pattern onto the
-- explicit sentinel 'system'. Historically granted_by allowed NULL to
-- mean "non-user origin"; we now standardise on the literal 'system'.
UPDATE user_resource_permissions
   SET granted_by = 'system'
 WHERE granted_by IS NULL OR granted_by = '';

ALTER TABLE user_resource_permissions
    ALTER COLUMN granted_by SET DEFAULT 'system';

ALTER TABLE user_resource_permissions
    ALTER COLUMN granted_by SET NOT NULL;
