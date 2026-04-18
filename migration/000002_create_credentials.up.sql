CREATE TABLE credentials (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    app_id VARCHAR(36) NOT NULL,
    type VARCHAR(20) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    credential_subject VARCHAR(255) NOT NULL,
    secret TEXT,
    public_key TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (app_id, credential_subject, type)
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_app_id ON credentials(app_id);
CREATE INDEX idx_credentials_type ON credentials(type);
