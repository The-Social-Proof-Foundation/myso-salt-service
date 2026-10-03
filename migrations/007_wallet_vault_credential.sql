CREATE UNIQUE INDEX IF NOT EXISTS wallet_vaults_credential_id_idx
    ON wallet_vaults (credential_id)
    WHERE credential_id IS NOT NULL;
