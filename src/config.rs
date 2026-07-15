use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedClient {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub master_seed_base64: String,
    pub port: u16,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_minute: i32,
    pub log_level: String,
    pub twitch_client_id: Option<String>,
    pub twitch_client_secret: Option<String>,
    pub facebook_app_secret: Option<String>,
    pub facebook_app_id: Option<String>,
    /// Canonical aud for Google JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_google: Option<String>,
    /// Google client secret for token exchange.
    pub google_client_secret: Option<String>,
    /// Canonical aud for Apple JWT validation. Web and iOS must use same client ID.
    pub allowed_audience_apple: Option<String>,
    /// Apple Team ID for JWT client assertion.
    pub apple_team_id: Option<String>,
    /// Apple Key Identifier for JWT client assertion.
    pub apple_key_identifier: Option<String>,
    /// Apple private key (PEM) for JWT client assertion.
    pub apple_private_key: Option<String>,
    /// Canonical aud for Facebook access-token flow.
    pub allowed_audience_facebook: Option<String>,
    /// Canonical aud for Twitch access-token flow.
    pub allowed_audience_twitch: Option<String>,
    /// Auth frontend OAuth callback URL (where Google/Apple redirect after login). Used for token exchange fallback when a client has no `redirect_uri`.
    pub auth_callback_url: Option<String>,
    /// OAuth clients from `ALLOWED_CLIENTS` env JSON (merged with indexer in `main` when indexer URL is set).
    pub allowed_clients_env: Vec<AllowedClient>,
    /// Final allowlist after merging indexer platforms with `allowed_clients_env` (env wins on duplicate `client_id`).
    pub allowed_clients: Vec<AllowedClient>,
    /// My indexer GraphQL HTTP endpoint. When set, platforms are fetched at startup and merged with env.
    pub myso_indexer_graphql_url: Option<String>,
    pub indexer_platforms_page_limit: u32,
    /// If true, skip indexer platforms with no URL under `platform_links_redirect_keys` in `links`.
    pub require_redirect_uri_from_links: bool,
    pub platform_status_allowlist: Option<Vec<String>>,
    pub platform_status_denylist: Vec<String>,
    pub platform_links_redirect_keys: Vec<String>,
    /// MySocial Auth issuer (e.g. https://auth.testnet.mysocial.network).
    pub mysocial_auth_issuer: Option<String>,
    /// MySocial Auth JWKS URI for JWT validation.
    pub mysocial_auth_jwks_uri: Option<String>,
    /// Canonical aud for MySocial Auth JWT validation (optional).
    pub allowed_audience_mysocial: Option<String>,
    /// Base64-encoded Ed25519 signing seed for session access tokens (at least 32 bytes).
    /// When set, auth callbacks return session_access_token and refresh_token.
    pub jwt_signing_key: Option<String>,
    /// Public key identifier included in session JWTs and the published JWKS.
    pub jwt_key_id: String,
    /// Issuer claim for session JWTs (e.g. https://salt.mysocial.network).
    pub jwt_issuer: Option<String>,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            master_seed_base64: env::var("MASTER_SEED")
                .context("MASTER_SEED not set")?,
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .context("Invalid PORT")?,
            allowed_origins: env::var("ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "https://mysocial.network,http://localhost:3000".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            rate_limit_per_minute: env::var("RATE_LIMIT")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .context("Invalid RATE_LIMIT")?,
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            twitch_client_id: env::var("TWITCH_CLIENT_ID").ok(),
            twitch_client_secret: env::var("TWITCH_CLIENT_SECRET").ok(),
            facebook_app_secret: env::var("FACEBOOK_APP_SECRET").ok(),
            facebook_app_id: env::var("FACEBOOK_APP_ID").ok(),
            allowed_audience_google: env::var("ALLOWED_AUDIENCE_GOOGLE").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            allowed_audience_apple: env::var("ALLOWED_AUDIENCE_APPLE").ok(),
            apple_team_id: env::var("APPLE_TEAM_ID").ok(),
            apple_key_identifier: env::var("APPLE_KEY_IDENTIFIER").ok(),
            apple_private_key: env::var("APPLE_PRIVATE_KEY").ok(),
            allowed_audience_facebook: env::var("ALLOWED_AUDIENCE_FACEBOOK").ok(),
            allowed_audience_twitch: env::var("ALLOWED_AUDIENCE_TWITCH").ok(),
            auth_callback_url: env::var("AUTH_CALLBACK_URL").ok(),
            allowed_clients_env: parse_allowed_clients_for_auth()?,
            allowed_clients: Vec::new(),
            myso_indexer_graphql_url: env::var("MYSO_INDEXER_GRAPHQL_URL").ok(),
            indexer_platforms_page_limit: env::var("INDEXER_PLATFORMS_PAGE_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200),
            require_redirect_uri_from_links: env::var("REQUIRE_REDIRECT_URI_FROM_LINKS")
                .ok()
                .map(|s| {
                    matches!(
                        s.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes"
                    )
                })
                .unwrap_or(false),
            platform_status_allowlist: parse_comma_list_opt(env::var("PLATFORM_STATUS_ALLOWLIST").ok())?,
            platform_status_denylist: parse_comma_list_with_default(
                env::var("PLATFORM_STATUS_DENYLIST").ok(),
                "Shutdown,Sunset",
            )?,
            platform_links_redirect_keys: parse_comma_list_with_default(
                env::var("PLATFORM_LINKS_REDIRECT_KEYS").ok(),
                "website,url",
            )?,
            mysocial_auth_issuer: env::var("MYSOCIAL_AUTH_ISSUER").ok(),
            mysocial_auth_jwks_uri: env::var("MYSOCIAL_AUTH_JWKS_URI").ok(),
            allowed_audience_mysocial: env::var("ALLOWED_AUDIENCE_MYSOCIAL").ok(),
            jwt_signing_key: env::var("JWT_SIGNING_KEY").ok(),
            jwt_key_id: env::var("JWT_KEY_ID")
                .unwrap_or_else(|_| "mysocial-salt".to_string()),
            jwt_issuer: env::var("JWT_ISSUER")
                .ok()
                .or_else(|| Some("https://salt.testnet.mysocial.network".to_string())),
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate master seed
        let seed = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.master_seed_base64
        ).context("Invalid MASTER_SEED base64")?;

        if seed.len() < 32 {
            anyhow::bail!("MASTER_SEED must be at least 32 bytes");
        }

        let signing_key = self
            .jwt_signing_key
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .context("JWT_SIGNING_KEY must be set so every authentication returns a MySocial session")?;
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            signing_key,
        )
        .context("Invalid JWT_SIGNING_KEY base64")?;
        if decoded.len() < 32 {
            anyhow::bail!("JWT_SIGNING_KEY must decode to at least 32 bytes");
        }
        if self.jwt_key_id.trim().is_empty() {
            anyhow::bail!("JWT_KEY_ID must not be empty");
        }
        if self
            .jwt_issuer
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            anyhow::bail!("JWT_ISSUER must not be empty");
        }

        // Validate database URL
        if !self.database_url.starts_with("postgresql://") && !self.database_url.starts_with("postgres://") {
            anyhow::bail!("DATABASE_URL must be a PostgreSQL connection string");
        }

        // Require allowed audiences for JWT providers (Google, Apple)
        if self.allowed_audience_google.is_none() || self.allowed_audience_google.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            anyhow::bail!("ALLOWED_AUDIENCE_GOOGLE must be set for JWT validation");
        }
        if self.allowed_audience_apple.is_none() || self.allowed_audience_apple.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            anyhow::bail!("ALLOWED_AUDIENCE_APPLE must be set for JWT validation");
        }

        // Require allowed audiences for access-token providers when configured
        if self.facebook_app_id.is_some() && (self.allowed_audience_facebook.is_none() || self.allowed_audience_facebook.as_ref().map(|s| s.is_empty()).unwrap_or(true)) {
            anyhow::bail!("ALLOWED_AUDIENCE_FACEBOOK must be set when FACEBOOK_APP_ID is configured");
        }
        if self.twitch_client_id.is_some() && (self.allowed_audience_twitch.is_none() || self.allowed_audience_twitch.as_ref().map(|s| s.is_empty()).unwrap_or(true)) {
            anyhow::bail!("ALLOWED_AUDIENCE_TWITCH must be set when TWITCH_CLIENT_ID is configured");
        }

        if !self.allowed_clients.is_empty() {
            let global_cb = self
                .auth_callback_url
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if !global_cb {
                for c in &self.allowed_clients {
                    if c.redirect_uri.trim().is_empty() {
                        anyhow::bail!(
                            "Each allowed client must have redirect_uri (from ALLOWED_CLIENTS or indexer `links`), or set AUTH_CALLBACK_URL as a global fallback (client_id {:?} has empty redirect_uri)",
                            c.client_id
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

fn parse_allowed_clients_for_auth() -> Result<Vec<AllowedClient>> {
    let s = env::var("ALLOWED_CLIENTS").ok();
    let s = match s {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    let clients: Vec<AllowedClient> = serde_json::from_str(&s).context("Invalid ALLOWED_CLIENTS JSON")?;
    Ok(clients)
}

fn parse_comma_list_opt(raw: Option<String>) -> Result<Option<Vec<String>>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let v: Vec<String> = s
        .split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect();
    Ok(Some(v).filter(|x| !x.is_empty()))
}

fn parse_comma_list_with_default(raw: Option<String>, default: &str) -> Result<Vec<String>> {
    let s = raw
        .filter(|x| !x.trim().is_empty())
        .unwrap_or_else(|| default.to_string());
    Ok(s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect())
}

/// OAuth `redirect_uri` for token exchange: prefer per-client URL, else global auth callback.
pub fn oauth_redirect_uri_for_exchange<'a>(
    client: &'a AllowedClient,
    auth_callback_url: Option<&'a str>,
) -> Option<&'a str> {
    let u = client.redirect_uri.trim();
    if !u.is_empty() {
        return Some(u);
    }
    auth_callback_url.map(str::trim).filter(|s| !s.is_empty())
}

fn trim_oauth_redirect_uri(s: &str) -> &str {
    s.trim().trim_end_matches('/')
}

/// Google/Apple token exchange must use the same `redirect_uri` as the authorize step.
/// The auth frontend sends it in the JSON body. Falls back to [`oauth_redirect_uri_for_exchange`]
/// when omitted (legacy clients).
pub fn resolve_oauth_redirect_uri_for_token_exchange(
    request_redirect_uri: Option<&str>,
    client: &AllowedClient,
    auth_callback_url: Option<&str>,
) -> Result<String, String> {
    let body = request_redirect_uri
        .map(trim_oauth_redirect_uri)
        .filter(|s| !s.is_empty());
    match body {
        Some(uri) => {
            if let Some(ac) = auth_callback_url
                .map(trim_oauth_redirect_uri)
                .filter(|s| !s.is_empty())
            {
                if uri != ac {
                    return Err(format!(
                        "redirect_uri mismatch: must match AUTH_CALLBACK_URL for token exchange (got {uri}, expected {ac})"
                    ));
                }
            }
            Ok(uri.to_string())
        }
        None => oauth_redirect_uri_for_exchange(client, auth_callback_url)
            .map(trim_oauth_redirect_uri)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                "AUTH_CALLBACK_URL not configured and client has no redirect_uri".to_string()
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn minimal_config(mut c: Config) -> Config {
        c.master_seed_base64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        c.database_url = "postgresql://localhost/db".into();
        c.allowed_audience_google = Some("g".into());
        c.allowed_audience_apple = Some("a".into());
        c.jwt_signing_key = Some(
            base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
        );
        c.jwt_issuer = Some("https://salt.test.example".into());
        c
    }

    #[test]
    fn validate_allows_empty_redirect_when_global_callback_set() {
        let c = minimal_config(Config {
            allowed_clients: vec![AllowedClient {
                client_id: "p1".into(),
                redirect_uri: "".into(),
            }],
            auth_callback_url: Some("https://auth.example/callback".into()),
            ..empty_shell()
        });
        c.validate().unwrap();
    }

    #[test]
    fn validate_requires_per_client_redirect_without_global() {
        let c = minimal_config(Config {
            allowed_clients: vec![AllowedClient {
                client_id: "p1".into(),
                redirect_uri: "".into(),
            }],
            auth_callback_url: None,
            ..empty_shell()
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_requires_session_signing() {
        let mut c = minimal_config(empty_shell());
        c.jwt_signing_key = None;
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("JWT_SIGNING_KEY must be set"));
    }

    #[test]
    fn oauth_redirect_prefers_client_uri() {
        let client = AllowedClient {
            client_id: "x".into(),
            redirect_uri: "https://app/cb".into(),
        };
        assert_eq!(
            oauth_redirect_uri_for_exchange(&client, Some("https://global/cb")),
            Some("https://app/cb")
        );
    }

    #[test]
    fn oauth_redirect_falls_back_to_global() {
        let client = AllowedClient {
            client_id: "x".into(),
            redirect_uri: "".into(),
        };
        assert_eq!(
            oauth_redirect_uri_for_exchange(&client, Some("https://global/cb")),
            Some("https://global/cb")
        );
    }

    #[test]
    fn resolve_prefers_request_body_when_matches_auth_callback() {
        let client = AllowedClient {
            client_id: "x".into(),
            redirect_uri: "https://consumer.app/cb".into(),
        };
        assert_eq!(
            resolve_oauth_redirect_uri_for_token_exchange(
                Some("https://auth.example/callback"),
                &client,
                Some("https://auth.example/callback"),
            ),
            Ok("https://auth.example/callback".into())
        );
    }

    #[test]
    fn resolve_rejects_body_when_auth_callback_differs() {
        let client = AllowedClient {
            client_id: "x".into(),
            redirect_uri: "https://consumer.app/cb".into(),
        };
        assert!(resolve_oauth_redirect_uri_for_token_exchange(
            Some("https://auth.example/callback"),
            &client,
            Some("https://other/callback"),
        )
        .unwrap_err()
        .starts_with("redirect_uri mismatch:"));
    }

    #[test]
    fn resolve_accepts_body_when_no_global_callback_configured() {
        let client = AllowedClient {
            client_id: "x".into(),
            redirect_uri: "https://consumer.app/cb".into(),
        };
        assert_eq!(
            resolve_oauth_redirect_uri_for_token_exchange(
                Some("https://auth.example/callback"),
                &client,
                None,
            ),
            Ok("https://auth.example/callback".into())
        );
    }

    fn empty_shell() -> Config {
        Config {
            database_url: String::new(),
            master_seed_base64: String::new(),
            port: 3000,
            allowed_origins: vec![],
            rate_limit_per_minute: 60,
            log_level: "info".into(),
            twitch_client_id: None,
            twitch_client_secret: None,
            facebook_app_secret: None,
            facebook_app_id: None,
            allowed_audience_google: None,
            google_client_secret: None,
            allowed_audience_apple: None,
            apple_team_id: None,
            apple_key_identifier: None,
            apple_private_key: None,
            allowed_audience_facebook: None,
            allowed_audience_twitch: None,
            auth_callback_url: None,
            allowed_clients_env: vec![],
            allowed_clients: vec![],
            myso_indexer_graphql_url: None,
            indexer_platforms_page_limit: 200,
            require_redirect_uri_from_links: false,
            platform_status_allowlist: None,
            platform_status_denylist: vec![],
            platform_links_redirect_keys: vec![],
            mysocial_auth_issuer: None,
            mysocial_auth_jwks_uri: None,
            allowed_audience_mysocial: None,
            jwt_signing_key: None,
            jwt_key_id: "mysocial-salt".into(),
            jwt_issuer: None,
        }
    }
}
