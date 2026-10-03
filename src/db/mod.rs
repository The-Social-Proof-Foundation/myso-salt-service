use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use chrono::Utc;
use uuid::Uuid;

use crate::models::RefreshSession;

#[derive(Clone)]
pub struct SaltStore {
    pool: PgPool,
}

impl SaltStore {
    /// Create a new SaltStore with database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { pool })
    }

    /// Get pool for migrations
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check rate limit for an identifier
    pub async fn check_rate_limit(&self, identifier: &str, window_minutes: i32, max_requests: i32) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM rate_limit_entries
            WHERE identifier = $1
              AND window_start > NOW() - INTERVAL '1 minute' * $2::float
            "#
        )
        .bind(identifier)
        .bind(window_minutes as f64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to check rate limit")?;

        if count >= max_requests as i64 {
            return Ok(false);
        }

        // Record the request
        sqlx::query(
            r#"
            INSERT INTO rate_limit_entries (identifier)
            VALUES ($1)
            "#
        )
        .bind(identifier)
        .execute(&self.pool)
        .await
        .context("Failed to record rate limit entry")?;

        Ok(true)
    }

    /// Clean up old rate limit entries
    pub async fn cleanup_rate_limits(&self, older_than_hours: i32) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM rate_limit_entries
            WHERE window_start < NOW() - INTERVAL '1 hour' * $1::float
            "#
        )
        .bind(older_than_hours as f64)
        .execute(&self.pool)
        .await
        .context("Failed to cleanup rate limits")?;

        Ok(result.rows_affected())
    }

    /// Store a refresh session (30 days TTL).
    pub async fn store_refresh_session(
        &self,
        user_identifier: &str,
        wallet_address: &str,
        provider: &str,
        client_id: &str,
        refresh_token_hash: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<Uuid> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO refresh_sessions
                (user_identifier, wallet_address, provider, client_id, refresh_token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(user_identifier)
        .bind(wallet_address)
        .bind(provider)
        .bind(client_id)
        .bind(refresh_token_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to store refresh session")?;

        Ok(row.0)
    }

    /// Get a refresh session by token hash if not expired.
    pub async fn get_refresh_session(&self, refresh_token_hash: &str) -> Result<Option<RefreshSession>> {
        let session = sqlx::query_as::<_, RefreshSession>(
            r#"
            SELECT id, user_identifier, wallet_address, provider, client_id,
                   refresh_token_hash, expires_at, created_at
            FROM refresh_sessions
            WHERE refresh_token_hash = $1 AND expires_at > NOW()
            "#,
        )
        .bind(refresh_token_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get refresh session")?;

        Ok(session)
    }

    /// Delete a refresh session by token hash.
    pub async fn delete_refresh_session(&self, refresh_token_hash: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM refresh_sessions WHERE refresh_token_hash = $1
            "#,
        )
        .bind(refresh_token_hash)
        .execute(&self.pool)
        .await
        .context("Failed to delete refresh session")?;

        Ok(result.rows_affected() > 0)
    }

    /// Atomically consume an active refresh token, record it as revoked, and
    /// replace it with a rotated token that keeps the original absolute expiry.
    pub async fn rotate_refresh_session(
        &self,
        old_refresh_token_hash: &str,
        new_refresh_token_hash: &str,
    ) -> Result<Option<RefreshSession>> {
        let mut tx = self.pool.begin().await.context("Failed to begin refresh rotation")?;
        let session = sqlx::query_as::<_, RefreshSession>(
            r#"
            SELECT id, user_identifier, wallet_address, provider, client_id,
                   refresh_token_hash, expires_at, created_at
            FROM refresh_sessions
            WHERE refresh_token_hash = $1 AND expires_at > NOW()
            FOR UPDATE
            "#,
        )
        .bind(old_refresh_token_hash)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to lock refresh session")?;

        let Some(session) = session else {
            tx.rollback().await.ok();
            return Ok(None);
        };

        sqlx::query("DELETE FROM refresh_sessions WHERE id = $1")
            .bind(session.id)
            .execute(&mut *tx)
            .await
            .context("Failed to consume refresh session")?;
        sqlx::query(
            r#"
            INSERT INTO revoked_refresh_tokens (refresh_token_hash, user_identifier)
            VALUES ($1, $2)
            ON CONFLICT (refresh_token_hash) DO NOTHING
            "#,
        )
        .bind(old_refresh_token_hash)
        .bind(&session.user_identifier)
        .execute(&mut *tx)
        .await
        .context("Failed to record rotated refresh token")?;
        sqlx::query(
            r#"
            INSERT INTO refresh_sessions
                (user_identifier, wallet_address, provider, client_id, refresh_token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&session.user_identifier)
        .bind(&session.wallet_address)
        .bind(&session.provider)
        .bind(&session.client_id)
        .bind(new_refresh_token_hash)
        .bind(session.expires_at)
        .execute(&mut *tx)
        .await
        .context("Failed to store rotated refresh session")?;
        tx.commit().await.context("Failed to commit refresh rotation")?;
        Ok(Some(session))
    }

    /// Revoke an active refresh token. Logout is idempotent when the token is
    /// already missing or revoked.
    pub async fn revoke_refresh_session(&self, refresh_token_hash: &str) -> Result<Option<String>> {
        let mut tx = self.pool.begin().await.context("Failed to begin refresh revocation")?;
        let user_identifier: Option<String> = sqlx::query_scalar(
            "SELECT user_identifier FROM refresh_sessions WHERE refresh_token_hash = $1 FOR UPDATE",
        )
        .bind(refresh_token_hash)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to lock refresh session for revocation")?;
        let Some(user_identifier) = user_identifier else {
            tx.rollback().await.ok();
            return Ok(None);
        };
        sqlx::query("DELETE FROM refresh_sessions WHERE refresh_token_hash = $1")
            .bind(refresh_token_hash)
            .execute(&mut *tx)
            .await
            .context("Failed to delete refresh session")?;
        sqlx::query(
            r#"
            INSERT INTO revoked_refresh_tokens (refresh_token_hash, user_identifier)
            VALUES ($1, $2)
            ON CONFLICT (refresh_token_hash) DO NOTHING
            "#,
        )
        .bind(refresh_token_hash)
        .bind(&user_identifier)
        .execute(&mut *tx)
        .await
        .context("Failed to persist refresh revocation")?;
        tx.commit().await.context("Failed to commit refresh revocation")?;
        Ok(Some(user_identifier))
    }

    pub async fn revoked_refresh_owner(&self, refresh_token_hash: &str) -> Result<Option<String>> {
        sqlx::query_scalar(
            "SELECT user_identifier FROM revoked_refresh_tokens WHERE refresh_token_hash = $1",
        )
        .bind(refresh_token_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to check revoked refresh token")
    }

    pub async fn delete_refresh_sessions_for_user(&self, user_identifier: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM refresh_sessions WHERE user_identifier = $1")
            .bind(user_identifier)
            .execute(&self.pool)
            .await
            .context("Failed to revoke refresh token family")?;
        Ok(result.rows_affected())
    }

    /// Clean up expired refresh sessions.
    pub async fn cleanup_expired_refresh_sessions(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM refresh_sessions WHERE expires_at <= NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to cleanup expired refresh sessions")?;

        Ok(result.rows_affected())
    }

    pub async fn insert_vault_challenge(
        &self,
        nonce: &str,
        user_identifier: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO wallet_vault_challenges (nonce, user_identifier, expires_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(nonce)
        .bind(user_identifier)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .context("Failed to store vault challenge")?;
        Ok(())
    }

    /// Marks a challenge used. Returns false when it is missing, expired, reused, or bound to another user.
    pub async fn consume_vault_challenge(&self, nonce: &str, user_identifier: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE wallet_vault_challenges
            SET used_at = NOW()
            WHERE nonce = $1
              AND user_identifier = $2
              AND used_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(nonce)
        .bind(user_identifier)
        .execute(&self.pool)
        .await
        .context("Failed to consume vault challenge")?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn get_wallet_vault(
        &self,
        user_identifier: &str,
    ) -> Result<Option<crate::models::WalletVaultRecord>> {
        sqlx::query_as::<_, crate::models::WalletVaultRecord>(
            r#"
            SELECT user_identifier, address, version, credential_id, prf_salt, prf_wrapped_wek,
                   recovery_wrapped_wek, recovery_kdf_salt, vault, vault_hash, updated_at
            FROM wallet_vaults
            WHERE user_identifier = $1
            "#,
        )
        .bind(user_identifier)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to load wallet vault")
    }

    pub async fn get_wallet_vault_by_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<crate::models::WalletVaultRecord>> {
        sqlx::query_as::<_, crate::models::WalletVaultRecord>(
            r#"
            SELECT user_identifier, address, version, credential_id, prf_salt, prf_wrapped_wek,
                   recovery_wrapped_wek, recovery_kdf_salt, vault, vault_hash, updated_at
            FROM wallet_vaults
            WHERE credential_id = $1
            "#,
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to load wallet vault by credential")
    }

    pub async fn upsert_wallet_vault(&self, record: &crate::models::WalletVaultRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO wallet_vaults (
                user_identifier, address, version, credential_id, prf_salt, prf_wrapped_wek,
                recovery_wrapped_wek, recovery_kdf_salt, vault, vault_hash, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ON CONFLICT (user_identifier) DO UPDATE SET
                address = EXCLUDED.address,
                version = EXCLUDED.version,
                credential_id = EXCLUDED.credential_id,
                prf_salt = EXCLUDED.prf_salt,
                prf_wrapped_wek = EXCLUDED.prf_wrapped_wek,
                recovery_wrapped_wek = EXCLUDED.recovery_wrapped_wek,
                recovery_kdf_salt = EXCLUDED.recovery_kdf_salt,
                vault = EXCLUDED.vault,
                vault_hash = EXCLUDED.vault_hash,
                updated_at = NOW()
            "#,
        )
        .bind(&record.user_identifier)
        .bind(&record.address)
        .bind(record.version)
        .bind(&record.credential_id)
        .bind(&record.prf_salt)
        .bind(&record.prf_wrapped_wek)
        .bind(&record.recovery_wrapped_wek)
        .bind(&record.recovery_kdf_salt)
        .bind(&record.vault)
        .bind(&record.vault_hash)
        .execute(&self.pool)
        .await
        .context("Failed to store wallet vault")?;
        Ok(())
    }

    pub async fn set_refresh_wallet_address(
        &self,
        user_identifier: &str,
        wallet_address: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_sessions SET wallet_address = $2 WHERE user_identifier = $1 AND expires_at > NOW()",
        )
        .bind(user_identifier)
        .bind(wallet_address)
        .execute(&self.pool)
        .await
        .context("Failed to attach wallet address to refresh sessions")?;
        Ok(())
    }

    pub async fn get_zklogin_salt(&self, user_identifier: &str) -> Result<Option<(String, String, String)>> {
        let row = sqlx::query_as::<_, (String, String, String)>(
            "SELECT salt, iss, aud FROM zklogin_salts WHERE user_identifier = $1",
        )
        .bind(user_identifier)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to load zkLogin salt")?;
        Ok(row)
    }

    pub async fn insert_zklogin_salt(
        &self,
        user_identifier: &str,
        salt: &str,
        iss: &str,
        aud: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO zklogin_salts (user_identifier, salt, iss, aud) VALUES ($1, $2, $3, $4) ON CONFLICT (user_identifier) DO NOTHING",
        )
        .bind(user_identifier)
        .bind(salt)
        .bind(iss)
        .bind(aud)
        .execute(&self.pool)
        .await
        .context("Failed to store zkLogin salt")?;
        Ok(result.rows_affected() == 1)
    }
}

// Integration tests for DB live under `tests/` and require a live database.
