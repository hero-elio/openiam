ALTER TABLE user_resource_permissions
    ALTER COLUMN granted_by DROP NOT NULL;

ALTER TABLE user_resource_permissions
    ALTER COLUMN granted_by DROP DEFAULT;
