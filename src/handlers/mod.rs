use axum::{
    extract::{State, Json, ConnectInfo},
    http::{StatusCode, HeaderMap}
};
use std::net::SocketAddr;
use tracing::{error, warn};
use hex;

use chrono::Utc;

use crate::{
    config::resolve_oauth_redirect_uri_for_token_exchange,
    auth::exchange,
    models::{
        HealthCheckResponse, ActionType,
        AuthCallbackRequest, AuthCallbackResponse, LogoutRequest, RefreshRequest,
        RefreshResponse, WalletAuthRequest, PutWalletVaultRequest, WalletVaultRecord,
        WalletVaultResponse, VaultChallengeResponse,
    },
    security::{
        jwt::JwtValidator,
        hash_token_for_audit,
        session_token,
        wallet_signature,
    },
    state::AppState,
};

/// Resolve provider from request or infer from client_id.
fn resolve_provider(request: &AuthCallbackRequest, config: &crate::config::Config) -> Result<String, String> {
    if let Some(ref p) = request.provider {
        let s = p.trim().to_lowercase();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let cid = request.client_id.trim();
    if config.allowed_audience_google.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("google".to_string());
    }
    if config.allowed_audience_apple.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("apple".to_string());
    }
    if config.allowed_audience_facebook.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("facebook".to_string());
    }
    if config.allowed_audience_twitch.as_deref().map(|a| a == cid).unwrap_or(false) {
        return Ok("twitch".to_string());
    }
    Err("Could not determine provider. Set provider in request or use client_id that matches an ALLOWED_AUDIENCE_* value.".to_string())
}

/// Get the OAuth client_id to use for token exchange. The auth frontend uses the provider's
/// client ID (from env) for the OAuth request; we must use the same for the token exchange.
fn get_oauth_client_id_for_provider(
    provider: &str,
    _request_client_id: &str,
    config: &crate::config::Config,
) -> Result<String, String> {
    let provider_lower = provider.to_lowercase();
    match provider_lower.as_str() {
        "google" => config
            .allowed_audience_google
            .clone()
            .ok_or_else(|| "ALLOWED_AUDIENCE_GOOGLE not configured".to_string()),
        "apple" => config
            .allowed_audience_apple
            .clone()
            .ok_or_else(|| "ALLOWED_AUDIENCE_APPLE not configured".to_string()),
        "facebook" => config
            .allowed_audience_facebook
            .clone()
            .or_else(|| config.facebook_app_id.clone())
            .ok_or_else(|| "ALLOWED_AUDIENCE_FACEBOOK or FACEBOOK_APP_ID not configured".to_string()),
        "twitch" => config
            .allowed_audience_twitch
            .clone()
            .or_else(|| config.twitch_client_id.clone())
            .ok_or_else(|| "ALLOWED_AUDIENCE_TWITCH or TWITCH_CLIENT_ID not configured".to_string()),
        _ => Err(format!("Unknown provider: {}", provider)),
    }
}

/// Health check endpoint
pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<HealthCheckResponse>, StatusCode> {
    // Check database connectivity
    match sqlx::query("SELECT 1 as check")
        .fetch_one(state.store.pool())
        .await
    {
        Ok(_) => Ok(Json(HealthCheckResponse {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })),
        Err(e) => {
            error!("Health check failed: {}", e);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Get audit logs for a user (admin endpoint)
// pub async fn get_audit_logs(
//     State(state): State<AppState>,
//     user_identifier: String,
// ) -> Result<impl IntoResponse, StatusCode> {
//     match state.store.get_audit_logs(&user_identifier).await {
//         Ok(logs) => Ok(Json(logs)),
//         Err(e) => {
//             error!("Failed to retrieve audit logs: {}", e);
//             Err(StatusCode::INTERNAL_SERVER_ERROR)
//         }
//     }
// }


pub async fn auth_provider_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<AuthCallbackRequest>,
) -> Result<Json<AuthCallbackResponse>, (StatusCode, String)> {
    let ip_address = addr.ip().to_string();
    let rate_limit_ok = state
        .store
        .check_rate_limit(&ip_address, 1, state.config.rate_limit_per_minute)
        .await
        .map_err(|e| {
            error!("Rate limit check failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    if !rate_limit_ok {
        warn!("Rate limit exceeded for IP: {}", ip_address);
        state.metrics.increment_rate_limit();
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }

    let client_meta = state
        .config
        .allowed_clients
        .iter()
        .find(|c| c.client_id == request.client_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Unknown client".to_string(),
        ))?;

    let provider = resolve_provider(&request, &state.config)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let oauth_client_id = get_oauth_client_id_for_provider(&provider, &request.client_id, &state.config)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let oauth_redirect_uri = resolve_oauth_redirect_uri_for_token_exchange(
        request.redirect_uri.as_deref(),
        client_meta,
        state.config.auth_callback_url.as_deref(),
    )
    .map_err(|e| {
        let status = if e.starts_with("redirect_uri mismatch:") {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, e)
    })?;

    let tokens = exchange::exchange_code_for_tokens(
        &state.http_client,
        &provider,
        &request.code,
        oauth_redirect_uri.as_str(),
        &oauth_client_id,
        request.code_verifier.as_deref(),
        &state.config,
    )
    .await
    .map_err(|e| {
        error!("Token exchange failed: {}", e);
        (StatusCode::BAD_GATEWAY, format!("Auth exchange failed: {}", e))
    })?;

    let (claims, token_hash) = if let Some(ref id_token) = tokens.id_token {
        match state.jwt_validator.validate(id_token).await {
            Ok(c) => {
                let hash = hash_token_for_audit(id_token);
                (c, hash)
            }
            Err(e) => {
                error!("JWT validation failed after exchange: {}", e);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid JWT: {}", e),
                ));
            }
        }
    } else if let Some(ref access_token) = tokens.access_token {
        let provider = tokens
            .user
            .as_ref()
            .and_then(|u| {
                u.get("provider")
                    .or_else(|| u.get("iss"))
                    .and_then(|v| v.as_str())
            })
            .map(|s| {
                if s.contains("facebook") {
                    "facebook"
                } else if s.contains("twitch") {
                    "twitch"
                } else {
                    s
                }
            })
            .unwrap_or("unknown");
        let provider_lower = provider.to_lowercase();
        if provider_lower == "apple" || provider_lower == "google" {
            return Err((
                StatusCode::BAD_REQUEST,
                "id_token required for Google/Apple".to_string(),
            ));
        }
        match state
            .access_token_validator
            .extract_claims_from_token(provider, access_token)
            .await
        {
            Ok(c) => {
                let hash = hash_token_for_audit(access_token);
                (c, hash)
            }
            Err(e) => {
                error!("Access token validation failed: {}", e);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid token for provider {}: {}", provider, e),
                ));
            }
        }
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Auth response missing id_token and access_token".to_string(),
        ));
    };

    if provider == "google" || provider == "apple" {
        let expected_nonce = request
            .nonce
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or((StatusCode::BAD_REQUEST, "nonce is required".to_string()))?;
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err((StatusCode::UNAUTHORIZED, "Invalid nonce".to_string()));
        }
    }

    let user_identifier = JwtValidator::generate_user_identifier(&claims);
    tracing::debug!(
        "Auth callback for user {} (iss: {}, sub: {})",
        user_identifier, claims.iss, claims.sub
    );

    let registered_address = state
        .store
        .get_wallet_vault(&user_identifier)
        .await
        .map_err(|e| {
            error!("Failed to load wallet vault: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
        })?
        .map(|record| record.address);

    let _ = state.store.log_audit(
        &user_identifier,
        ActionType::Read,
        Some(addr.ip().to_string()),
        None,
        Some(token_hash),
        true,
        None,
    ).await;

    let code = tokens
        .id_token
        .clone()
        .or(tokens.access_token.clone())
        .unwrap_or_default();

    let mut user_obj = serde_json::Map::new();
    if let Some(ref wallet_address) = registered_address {
        user_obj.insert(
            "address".to_string(),
            serde_json::Value::String(wallet_address.clone()),
        );
    }
    user_obj.insert("sub".to_string(), serde_json::Value::String(claims.sub.clone()));
    if let Some(ref email) = claims.email {
        user_obj.insert("email".to_string(), serde_json::Value::String(email.clone()));
    }
    let user = Some(serde_json::Value::Object(user_obj));

    if state.config.jwt_signing_key.is_none() || state.config.jwt_issuer.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MySocial session signing is not configured".to_string(),
        ));
    }

    let (session_access_token, refresh_token, expires_in) =
        if let (Some(ref key_b64), Some(ref issuer)) =
            (&state.config.jwt_signing_key, &state.config.jwt_issuer)
        {
            let access_token = session_token::issue_access_token(
                &user_identifier,
                registered_address.as_deref(),
                &provider,
                &request.client_id,
                issuer,
                key_b64,
                &state.config.jwt_key_id,
            )
                .map_err(|e| {
                    error!("Failed to issue access token: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Token issuance failed".to_string())
                })?;

            let (refresh_opaque, refresh_hash) = session_token::generate_refresh_token()
                .map_err(|e| {
                    error!("Failed to generate refresh token: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string())
                })?;

            let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
            state
                .store
                .store_refresh_session(
                    &user_identifier,
                    registered_address.as_deref().unwrap_or(""),
                    &provider,
                    &request.client_id,
                    &refresh_hash,
                    expires_at,
                )
                .await
                .map_err(|e| {
                    error!("Failed to store refresh session: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Session storage failed".to_string())
                })?;

            (
                Some(access_token),
                Some(refresh_opaque),
                Some(1800u64),
            )
        } else {
            (None, None, None)
        };

    Ok(Json(AuthCallbackResponse {
        code,
        id_token: tokens.id_token.clone(),
        user,
        access_token: tokens.access_token,
        session_access_token,
        refresh_token,
        expires_in,
    }))
}

/// Wallet authentication callback. Accepts address + Ed25519 signature, verifies ownership,
/// creates session, and returns tokens when JWT_SIGNING_KEY is configured.
pub async fn auth_wallet_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<WalletAuthRequest>,
) -> Result<Json<AuthCallbackResponse>, (StatusCode, String)> {
    let ip_address = addr.ip().to_string();
    let rate_limit_ok = state
        .store
        .check_rate_limit(&ip_address, 1, state.config.rate_limit_per_minute)
        .await
        .map_err(|e| {
            error!("Rate limit check failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    if !rate_limit_ok {
        warn!("Rate limit exceeded for IP: {}", ip_address);
        state.metrics.increment_rate_limit();
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }

    let _client = state
        .config
        .allowed_clients
        .iter()
        .find(|c| c.client_id == request.client_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Unknown client".to_string(),
        ))?;

    wallet_signature::verify_wallet_signature(&request.address, &request.message, &request.signature)
        .map_err(|e| {
            error!("Wallet signature verification failed: {}", e);
            (StatusCode::UNAUTHORIZED, "Invalid signature".to_string())
        })?;

    let user_identifier = format!("wallet:{}", request.address);

    let _ = state.store.log_audit(
        &user_identifier,
        ActionType::Read,
        Some(ip_address),
        None,
        Some(hash_token_for_audit(&request.signature)),
        true,
        None,
    )
    .await;

    let mut user_obj = serde_json::Map::new();
    user_obj.insert("address".to_string(), serde_json::Value::String(request.address.clone()));

    if state.config.jwt_signing_key.is_none() || state.config.jwt_issuer.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MySocial session signing is not configured".to_string(),
        ));
    }

    let (session_access_token, refresh_token, expires_in) =
        if let (Some(ref key_b64), Some(ref issuer)) =
            (&state.config.jwt_signing_key, &state.config.jwt_issuer)
        {
            let access_token = session_token::issue_access_token(
                &user_identifier,
                Some(&request.address),
                "wallet",
                &request.client_id,
                issuer,
                key_b64,
                &state.config.jwt_key_id,
            )
                .map_err(|e| {
                    error!("Failed to issue access token: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Token issuance failed".to_string())
                })?;

            let (refresh_opaque, refresh_hash) = session_token::generate_refresh_token()
                .map_err(|e| {
                    error!("Failed to generate refresh token: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string())
                })?;

            let expires_at = Utc::now() + chrono::Duration::days(30);
            state
                .store
                .store_refresh_session(
                    &user_identifier,
                    &request.address,
                    "wallet",
                    &request.client_id,
                    &refresh_hash,
                    expires_at,
                )
                .await
                .map_err(|e| {
                    error!("Failed to store refresh session: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Session storage failed".to_string())
                })?;

            (
                Some(access_token),
                Some(refresh_opaque),
                Some(1800u64),
            )
        } else {
            (None, None, None)
        };

    Ok(Json(AuthCallbackResponse {
        code: request.address.clone(),
        id_token: None,
        user: Some(serde_json::Value::Object(user_obj)),
        access_token: None,
        session_access_token,
        refresh_token,
        expires_in,
    }))
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    if request.refresh_token.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "refresh_token is required".to_string()));
    }
    let ip_address = addr.ip().to_string();
    let allowed = state
        .store
        .check_rate_limit(&format!("refresh:{ip_address}"), 1, 10)
        .await
        .map_err(|e| {
            error!("Refresh rate limit check failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    if !allowed {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
    }

    let old_hash = session_token::hash_refresh_token(&request.refresh_token);
    if let Some(user_identifier) = state
        .store
        .revoked_refresh_owner(&old_hash)
        .await
        .map_err(|e| {
            error!("Failed to check refresh reuse: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?
    {
        state
            .store
            .delete_refresh_sessions_for_user(&user_identifier)
            .await
            .map_err(|e| {
                error!("Failed to revoke replayed refresh family: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
            })?;
        return Err((StatusCode::UNAUTHORIZED, "Refresh token revoked".to_string()));
    }

    let (new_refresh_token, new_refresh_hash) = session_token::generate_refresh_token()
        .map_err(|e| {
            error!("Failed to generate refresh token: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string())
        })?;
    let session = state
        .store
        .rotate_refresh_session(&old_hash, &new_refresh_hash)
        .await
        .map_err(|e| {
            error!("Refresh rotation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session rotation failed".to_string())
        })?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid refresh token".to_string()))?;

    let key = state
        .config
        .jwt_signing_key
        .as_deref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Session signing unavailable".to_string()))?;
    let issuer = state
        .config
        .jwt_issuer
        .as_deref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Session issuer unavailable".to_string()))?;
    let wallet_address = session.wallet_address.trim();
    let access_token = session_token::issue_access_token(
        &session.user_identifier,
        if wallet_address.is_empty() { None } else { Some(wallet_address) },
        &session.provider,
        &session.client_id,
        issuer,
        key,
        &state.config.jwt_key_id,
    )
    .map_err(|e| {
        error!("Failed to issue refreshed access token: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Token issuance failed".to_string())
    })?;

    Ok(Json(RefreshResponse {
        access_token: access_token.clone(),
        session_access_token: access_token,
        refresh_token: new_refresh_token,
        expires_in: session_token::ACCESS_TOKEN_EXPIRY_SECS as u64,
        user: if wallet_address.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "address": wallet_address })
        },
    }))
}

pub async fn auth_logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if request.refresh_token.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "refresh_token is required".to_string()));
    }
    let refresh_hash = session_token::hash_refresh_token(&request.refresh_token);
    state
        .store
        .revoke_refresh_session(&refresh_hash)
        .await
        .map_err(|e| {
            error!("Refresh revocation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session revocation failed".to_string())
        })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn session_jwks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let key = state
        .config
        .jwt_signing_key
        .as_deref()
        .ok_or((StatusCode::NOT_FOUND, "JWKS unavailable".to_string()))?;
    session_token::jwks(key, &state.config.jwt_key_id)
        .map(Json)
        .map_err(|e| {
            error!("Failed to build JWKS: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "JWKS unavailable".to_string())
        })
}

/// Get service metrics
pub async fn get_metrics(
    State(state): State<AppState>,
) -> Json<crate::monitoring::MetricsSnapshot> {
    Json(state.metrics.get_stats())
}

const MAX_VAULT_FIELD: usize = 16_384;

fn bearer_session_token(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    token
        .map(str::to_string)
        .ok_or((StatusCode::UNAUTHORIZED, "Bearer token required".to_string()))
}

async fn authenticated_subject(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let token = bearer_session_token(headers)?;
    let key = state.config.jwt_signing_key.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Session signing unavailable".to_string(),
    ))?;
    let claims = session_token::verify_access_token(&token, key).map_err(|e| {
        error!("Vault session verification failed: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid session".to_string())
    })?;
    Ok(claims.sub)
}

fn bounded(value: &str, label: &str) -> Result<(), (StatusCode, String)> {
    if value.len() > MAX_VAULT_FIELD {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} is too large"),
        ));
    }
    Ok(())
}

fn is_wallet_address(value: &str) -> bool {
    let rest = value.strip_prefix("0x").unwrap_or("");
    rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn wallet_vault_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VaultChallengeResponse>, (StatusCode, String)> {
    let subject = authenticated_subject(&state, &headers).await?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    state
        .store
        .insert_vault_challenge(&nonce, &subject, expires_at)
        .await
        .map_err(|e| {
            error!("Failed to store vault challenge: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Challenge storage failed".to_string())
        })?;
    Ok(Json(VaultChallengeResponse {
        nonce,
        expires_in: 300,
    }))
}

pub async fn get_wallet_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletVaultResponse>, (StatusCode, String)> {
    let subject = authenticated_subject(&state, &headers).await?;
    let record = state
        .store
        .get_wallet_vault(&subject)
        .await
        .map_err(|e| {
            error!("Failed to load wallet vault: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
        })?
        .ok_or((StatusCode::NOT_FOUND, "No wallet vault".to_string()))?;
    Ok(Json(vault_response(record)))
}

pub async fn put_wallet_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PutWalletVaultRequest>,
) -> Result<Json<WalletVaultResponse>, (StatusCode, String)> {
    let subject = authenticated_subject(&state, &headers).await?;
    if request.version != 1 {
        return Err((StatusCode::BAD_REQUEST, "Unsupported vault version".to_string()));
    }
    if !is_wallet_address(&request.address) {
        return Err((StatusCode::BAD_REQUEST, "Invalid wallet address".to_string()));
    }
    for (label, value) in [
        ("vault", request.vault.as_str()),
        ("recoveryWrappedWek", request.recovery_wrapped_wek.as_str()),
        ("recoveryKdfSalt", request.recovery_kdf_salt.as_str()),
        ("signature", request.signature.as_str()),
        ("nonce", request.nonce.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, format!("{label} is required")));
        }
        bounded(value, label)?;
    }
    if let Some(value) = request.credential_id.as_deref() {
        bounded(value, "credentialId")?;
    }
    if let Some(value) = request.prf_salt.as_deref() {
        bounded(value, "prfSalt")?;
    }
    if let Some(value) = request.prf_wrapped_wek.as_deref() {
        bounded(value, "prfWrappedWek")?;
    }

    let vault_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(request.vault.as_bytes()))
    };
    let message = session_token::vault_possession_message(
        &subject,
        &request.address,
        &vault_hash,
        &request.nonce,
    );
    wallet_signature::verify_wallet_signature(&request.address, &message, &request.signature)
        .map_err(|e| {
            error!("Vault proof of possession failed: {}", e);
            (StatusCode::UNAUTHORIZED, "Invalid vault signature".to_string())
        })?;

    let consumed = state
        .store
        .consume_vault_challenge(&request.nonce, &subject)
        .await
        .map_err(|e| {
            error!("Failed to consume vault challenge: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Challenge check failed".to_string())
        })?;
    if !consumed {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Vault challenge is invalid or already used".to_string(),
        ));
    }

    let address = request.address.trim().to_lowercase();
    let record = WalletVaultRecord {
        user_identifier: subject.clone(),
        address: address.clone(),
        version: request.version,
        credential_id: request.credential_id,
        prf_salt: request.prf_salt,
        prf_wrapped_wek: request.prf_wrapped_wek,
        recovery_wrapped_wek: request.recovery_wrapped_wek,
        recovery_kdf_salt: request.recovery_kdf_salt,
        vault: request.vault,
        vault_hash,
        updated_at: chrono::Utc::now(),
    };
    state.store.upsert_wallet_vault(&record).await.map_err(|e| {
        error!("Failed to store wallet vault: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Vault storage failed".to_string())
    })?;
    state
        .store
        .set_refresh_wallet_address(&subject, &address)
        .await
        .map_err(|e| {
            error!("Failed to update session wallet address: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session update failed".to_string())
        })?;
    Ok(Json(vault_response(record)))
}

fn vault_response(record: WalletVaultRecord) -> WalletVaultResponse {
    WalletVaultResponse {
        address: record.address,
        version: record.version,
        credential_id: record.credential_id,
        prf_salt: record.prf_salt,
        prf_wrapped_wek: record.prf_wrapped_wek,
        recovery_wrapped_wek: record.recovery_wrapped_wek,
        recovery_kdf_salt: record.recovery_kdf_salt,
        vault: record.vault,
        vault_hash: record.vault_hash,
    }
}
