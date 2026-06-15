-- Refresh sessions for MySocial wallet auth
CREATE TABLE refresh_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_identifier VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_token_hash ON refresh_sessions (refresh_token_hash);
CREATE INDEX idx_refresh_expires ON refresh_sessions (expires_at);

-- For reuse detection: store superseded token hashes
CREATE TABLE revoked_refresh_tokens (
    refresh_token_hash VARCHAR(64) PRIMARY KEY,
    user_identifier VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_revoked_user ON revoked_refresh_tokens (user_identifier);
