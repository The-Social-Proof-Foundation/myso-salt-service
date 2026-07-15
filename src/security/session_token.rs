//! MySocial session token issuance.
//!
//! Access tokens are EdDSA JWTs with a public JWKS. Refresh tokens are random
//! opaque values and only their SHA-256 hashes are persisted.

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ACCESS_TOKEN_EXPIRY_SECS: i64 = 1800;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub wallet_address: String,
    pub provider: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

fn signing_key(signing_key_base64: &str) -> Result<SigningKey> {
    let bytes = general_purpose::STANDARD
        .decode(signing_key_base64)
        .context("Invalid JWT_SIGNING_KEY base64")?;
    let seed: [u8; 32] = bytes
        .get(..32)
        .context("JWT_SIGNING_KEY must contain at least 32 bytes")?
        .try_into()
        .context("Invalid Ed25519 signing seed")?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn issue_access_token(
    user_identifier: &str,
    wallet_address: &str,
    provider: &str,
    client_id: &str,
    issuer: &str,
    signing_key_base64: &str,
    key_id: &str,
) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = SessionClaims {
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        sub: user_identifier.to_string(),
        wallet_address: wallet_address.to_lowercase(),
        provider: provider.to_string(),
        iat: now,
        exp: now + ACCESS_TOKEN_EXPIRY_SECS,
        jti: Uuid::new_v4().to_string(),
    };
    let header = JwtHeader {
        alg: "EdDSA",
        typ: "JWT",
        kid: key_id,
    };
    let header = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{claims}");
    let signature = signing_key(signing_key_base64)?.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

pub fn jwks(signing_key_base64: &str, key_id: &str) -> Result<serde_json::Value> {
    let public_key = signing_key(signing_key_base64)?.verifying_key();
    Ok(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": key_id,
            "x": general_purpose::URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
        }]
    }))
}

pub fn generate_refresh_token() -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let opaque = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&opaque);
    Ok((opaque, hash))
}

pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn issued_token_matches_published_jwk() {
        let seed = general_purpose::STANDARD.encode([7u8; 32]);
        let token = issue_access_token(
            "https://accounts.google.com:user",
            "0x1234",
            "google",
            "dripdrop",
            "https://salt.testnet.mysocial.network",
            &seed,
            "test-key",
        )
        .unwrap();
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        let key = signing_key(&seed).unwrap().verifying_key();
        key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert_eq!(jwks(&seed, "test-key").unwrap()["keys"][0]["kid"], "test-key");
    }
}
