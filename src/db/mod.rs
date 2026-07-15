use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use chrono::Utc;
use uuid::Uuid;

use crate::models::{ActionType, AuditLogEntry, JwtClaims, RefreshSession, UserSalt};
use crate::security::jwt::JwtValidator;

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

    /// Store encrypted salt for a user
    /// Returns the stored salt (newly inserted or existing if race condition occurred)
    /// Uses ON CONFLICT DO UPDATE with no-op to ensure RETURNING always returns a row
    pub async fn store_salt(
        &self,
        claims: &JwtClaims,
        encrypted_salt: &[u8],
    ) -> Result<UserSalt> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        // Try to insert, but return existing row if salt already exists
        // This prevents race conditions where two requests try to create a salt simultaneously
        // We use DO UPDATE with a no-op to ensure RETURNING always returns a row
        let result = sqlx::query_as::<_, UserSalt>(
            r#"
            INSERT INTO user_salts (user_identifier, iss, aud, sub, encrypted_salt, encryption_version)
            VALUES ($1, $2, $3, $4, $5, 1)
            ON CONFLICT (user_identifier) DO UPDATE
            SET user_identifier = EXCLUDED.user_identifier
            RETURNING 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at, 
                updated_at
            "#
        )
        .bind(&user_identifier)
        .bind(&claims.iss)
        .bind(&claims.aud)
        .bind(&claims.sub)
        .bind(encrypted_salt)
        .fetch_one(&self.pool)
        .await
        .context("Failed to store salt")?;

        Ok(result)
    }

    /// Retrieve encrypted salt for a user
    pub async fn get_salt(&self, claims: &JwtClaims) -> Result<Option<UserSalt>> {
        let user_identifier = JwtValidator::generate_user_identifier(claims);

        // Log the database query for debugging
        tracing::debug!(
            "Querying salt for user_identifier: {} (iss: {}, sub: {})",
            user_identifier,
            claims.iss,
            claims.sub
        );

        let salt = sqlx::query_as::<_, UserSalt>(
            r#"
            SELECT 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at, 
                updated_at
            FROM user_salts
            WHERE user_identifier = $1
            "#
        )
        .bind(&user_identifier)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to retrieve salt")?;

        Ok(salt)
    }

    /// Retrieve encrypted salt by user identifier (for MySocial JWT where sub = OAuth user_identifier).
    pub async fn get_salt_by_user_identifier(&self, user_identifier: &str) -> Result<Option<UserSalt>> {
        let salt = sqlx::query_as::<_, UserSalt>(
            r#"
            SELECT 
                id, 
                user_identifier, 
                iss, 
                aud, 
                sub, 
                encrypted_salt, 
                encryption_version, 
                created_at, 
                updated_at
            FROM user_salts
            WHERE user_identifier = $1
            "#
        )
        .bind(user_identifier)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to retrieve salt by user identifier")?;

        Ok(salt)
    }

    /// Log an audit entry
    pub async fn log_audit(
        &self,
        user_identifier: &str,
        action_type: ActionType,
        ip_address: Option<String>,
        user_agent: Option<String>,
        jwt_hash: Option<String>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO salt_audit_log 
            (user_identifier, action_type, ip_address, user_agent, jwt_hash, success, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(user_identifier)
        .bind(action_type.as_str())
        .bind(&ip_address)
        .bind(&user_agent)
        .bind(&jwt_hash)
        .bind(success)
        .bind(&error_message)
        .execute(&self.pool)
        .await
        .context("Failed to log audit entry")?;

        Ok(())
    }

    /// Get audit logs for a user
    pub async fn get_audit_logs(&self, user_identifier: &str) -> Result<Vec<AuditLogEntry>> {
        let logs = sqlx::query_as::<_, AuditLogEntry>(
            r#"
            SELECT 
                id, 
                user_identifier, 
                action_type, 
                ip_address, 
                user_agent, 
                jwt_hash, 
                success, 
                error_message, 
                created_at
            FROM salt_audit_log
            WHERE user_identifier = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#
        )
        .bind(user_identifier)
        .fetch_all(&self.pool)
        .await
        .context("Failed to retrieve audit logs")?;

        Ok(logs)
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
}

// Integration tests for DB live under `tests/` and require a live database.
