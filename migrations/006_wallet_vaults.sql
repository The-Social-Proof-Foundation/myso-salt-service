-- Opaque encrypted wallet vaults. The service never stores a signing key.
CREATE TABLE wallet_vaults (
    user_identifier TEXT PRIMARY KEY,
    address VARCHAR(66) NOT NULL,
    version INTEGER NOT NULL,
    credential_id TEXT,
    prf_salt TEXT,
    prf_wrapped_wek TEXT,
    recovery_wrapped_wek TEXT NOT NULL,
    recovery_kdf_salt TEXT NOT NULL,
    vault TEXT NOT NULL,
    vault_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE wallet_vault_challenges (
    nonce TEXT PRIMARY KEY,
    user_identifier TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_wallet_vault_challenges_user ON wallet_vault_challenges (user_identifier);
