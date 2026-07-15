-- Bind refresh sessions to the platform and wallet identity needed to reissue
-- independently verifiable MySocial access tokens.
ALTER TABLE refresh_sessions
    ADD COLUMN wallet_address VARCHAR(66) NOT NULL DEFAULT '',
    ADD COLUMN provider VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN client_id VARCHAR(255) NOT NULL DEFAULT '';

CREATE INDEX idx_refresh_user_identifier ON refresh_sessions (user_identifier);
