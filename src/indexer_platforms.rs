//! MySo indexer GraphQL: load allowlisted OAuth clients from `platforms`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::{AllowedClient, Config};

const ACTIVE_PLATFORMS_QUERY: &str = r#"query ActivePlatforms($limit: Int, $offset: Int) {
  platforms(approvedOnly: true, limit: $limit, offset: $offset) {
    platformId
    statusText
    redirectUri
    links
  }
}"#;

#[derive(Debug, Deserialize)]
struct GraphqlError {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphqlEnvelope<T> {
    data: Option<T>,
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Debug, Deserialize)]
struct PlatformsData {
    #[serde(rename = "platforms")]
    platforms: Option<Vec<PlatformRow>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlatformRow {
    platform_id: Option<String>,
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    developer_address: Option<String>,
    status_text: Option<String>,
    #[allow(dead_code)]
    redirect_uri: Option<String>,
    #[allow(dead_code)]
    shutdown_date: Option<serde_json::Value>,
    links: Option<serde_json::Value>,
}

/// Merge indexer clients with env `ALLOWED_CLIENTS`. Env wins on duplicate `client_id`.
pub fn merge_allowed_clients(indexer: Vec<AllowedClient>, env: Vec<AllowedClient>) -> Vec<AllowedClient> {
    use std::collections::HashMap;
    let mut map: HashMap<String, AllowedClient> =
        indexer.into_iter().map(|c| (c.client_id.clone(), c)).collect();
    for c in env {
        map.insert(c.client_id.clone(), c);
    }
    let mut out: Vec<_> = map.into_values().collect();
    out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    out
}

pub(crate) fn platform_passes_status_filter(
    status_text: Option<&str>,
    allowlist: &Option<Vec<String>>,
    denylist: &[String],
) -> bool {
    let status = status_text.map(str::trim).filter(|s| !s.is_empty());
    let Some(s) = status else {
        return false;
    };
    if let Some(allowed) = allowlist {
        if !allowed.is_empty() {
            return allowed.iter().any(|a| a.trim() == s);
        }
    }
    !denylist.iter().any(|d| d.trim() == s)
}

pub fn redirect_uri_from_links(links: Option<&serde_json::Value>, keys: &[String]) -> Option<String> {
    let links = links?;
    if keys.is_empty() {
        return None;
    }
    let obj = links.as_object()?;
    for key in keys {
        let k = key.trim();
        if k.is_empty() {
            continue;
        }
        if let Some(v) = obj.get(k) {
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

pub fn resolve_platform_redirect_uri(
    redirect_uri: Option<&str>,
    links: Option<&serde_json::Value>,
    keys: &[String],
) -> Option<String> {
    if let Some(uri) = redirect_uri {
        let trimmed = uri.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    redirect_uri_from_links(links, keys)
}

pub async fn fetch_allowed_clients_from_indexer(
    http: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<AllowedClient>> {
    let url = cfg
        .myso_indexer_graphql_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("indexer GraphQL URL missing")?;

    let limit = cfg.indexer_platforms_page_limit.max(1);
    let mut offset: i64 = 0;
    let mut out = Vec::new();

    loop {
        let body = serde_json::json!({
            "query": ACTIVE_PLATFORMS_QUERY,
            "variables": {
                "limit": limit as i64,
                "offset": offset,
            }
        });

        let resp = http
            .post(url)
            .json(&body)
            .send()
            .await
            .context("indexer GraphQL request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("indexer GraphQL HTTP {}: {}", status, text);
        }

        let parsed: GraphqlEnvelope<PlatformsData> = resp
            .json()
            .await
            .context("indexer GraphQL response is not valid JSON")?;

        if let Some(errs) = parsed.errors {
            if !errs.is_empty() {
                let msg = errs
                    .iter()
                    .filter_map(|e| e.message.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ");
                if !msg.is_empty() {
                    anyhow::bail!("indexer GraphQL errors: {}", msg);
                }
            }
        }

        let platforms = parsed
            .data
            .and_then(|d| d.platforms)
            .unwrap_or_default();

        let page_len = platforms.len();
        if page_len == 0 {
            break;
        }

        for row in platforms {
            if !platform_passes_status_filter(
                row.status_text.as_deref(),
                &cfg.platform_status_allowlist,
                &cfg.platform_status_denylist,
            ) {
                tracing::debug!(
                    platform_id = ?row.platform_id,
                    status = ?row.status_text,
                    "skipping platform (status filter)"
                );
                continue;
            }

            let redirect = resolve_platform_redirect_uri(
                row.redirect_uri.as_deref(),
                row.links.as_ref(),
                &cfg.platform_links_redirect_keys,
            );
            if cfg.require_redirect_uri_from_links && redirect.is_none() {
                tracing::debug!(
                    platform_id = ?row.platform_id,
                    "skipping platform (no redirect URL in links for configured keys)"
                );
                continue;
            }

            let has_global_callback = cfg
                .auth_callback_url
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if redirect.is_none() && !has_global_callback {
                tracing::debug!(
                    platform_id = ?row.platform_id,
                    "skipping platform (no redirect URI and AUTH_CALLBACK_URL not configured)"
                );
                continue;
            }

            let redirect_uri = redirect.unwrap_or_default();
            let Some(pid) = row.platform_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            let client_id = pid.to_string();

            out.push(AllowedClient {
                client_id,
                redirect_uri,
            });
        }

        if (page_len as u32) < limit {
            break;
        }
        offset += i64::from(limit);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_env_overrides_indexer() {
        let indexer = vec![
            AllowedClient {
                client_id: "a".into(),
                redirect_uri: "https://a.example/cb".into(),
            },
            AllowedClient {
                client_id: "b".into(),
                redirect_uri: "https://b.example/cb".into(),
            },
        ];
        let env = vec![AllowedClient {
            client_id: "a".into(),
            redirect_uri: "https://override/cb".into(),
        }];
        let m = merge_allowed_clients(indexer, env);
        assert_eq!(m.len(), 2);
        let a = m.iter().find(|c| c.client_id == "a").unwrap();
        assert_eq!(a.redirect_uri, "https://override/cb");
    }

    #[test]
    fn status_allowlist() {
        let allow = Some(vec!["Live".to_string()]);
        assert!(platform_passes_status_filter(Some("Live"), &allow, &[]));
        assert!(!platform_passes_status_filter(Some("Beta"), &allow, &[]));
        assert!(!platform_passes_status_filter(None, &allow, &[]));
    }

    #[test]
    fn status_denylist_when_no_allowlist() {
        let deny = vec!["Shutdown".to_string(), "Sunset".to_string()];
        assert!(platform_passes_status_filter(Some("Live"), &None, &deny));
        assert!(!platform_passes_status_filter(Some("Sunset"), &None, &deny));
    }

    #[test]
    fn empty_allowlist_falls_back_to_denylist() {
        let allow = Some(vec![]);
        let deny = vec!["Shutdown".to_string()];
        assert!(platform_passes_status_filter(Some("Live"), &allow, &deny));
        assert!(!platform_passes_status_filter(Some("Shutdown"), &allow, &deny));
    }

    #[test]
    fn redirect_from_on_chain_field() {
        let links = serde_json::json!({ "website": "https://links.example/cb" });
        let keys = vec!["website".into()];
        assert_eq!(
            resolve_platform_redirect_uri(
                Some("https://onchain.example/cb"),
                Some(&links),
                &keys,
            )
            .as_deref(),
            Some("https://onchain.example/cb")
        );
    }

    #[test]
    fn redirect_falls_back_to_links_when_on_chain_missing() {
        let links = serde_json::json!({ "website": "https://links.example/cb" });
        let keys = vec!["website".into()];
        assert_eq!(
            resolve_platform_redirect_uri(None, Some(&links), &keys).as_deref(),
            Some("https://links.example/cb")
        );
    }

    #[test]
    fn redirect_from_links_ordered_keys() {
        let links = serde_json::json!({
            "website": "https://one.test/callback",
            "url": "https://two.test/cb"
        });
        let keys = vec!["missing".into(), "url".into(), "website".into()];
        assert_eq!(
            redirect_uri_from_links(Some(&links), &keys).as_deref(),
            Some("https://two.test/cb")
        );
    }

    fn test_config(auth_callback_url: Option<&str>) -> Config {
        Config {
            database_url: "postgresql://localhost/db".into(),
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
            auth_callback_url: auth_callback_url.map(str::to_string),
            allowed_clients_env: vec![],
            allowed_clients: vec![],
            myso_indexer_graphql_url: Some("http://indexer.test/graphql".into()),
            indexer_platforms_page_limit: 200,
            require_redirect_uri_from_links: false,
            platform_status_allowlist: None,
            platform_status_denylist: vec!["Shutdown".into(), "Sunset".into()],
            platform_links_redirect_keys: vec!["website".into(), "url".into()],
            mysocial_auth_issuer: None,
            mysocial_auth_jwks_uri: None,
            allowed_audience_mysocial: None,
            jwt_signing_key: None,
            jwt_key_id: "mysocial-salt".into(),
            jwt_issuer: None,
        }
    }

    #[test]
    fn skips_platform_without_redirect_when_no_global_callback() {
        let row = PlatformRow {
            platform_id: Some("platform-1".into()),
            name: None,
            developer_address: None,
            status_text: Some("Live".into()),
            redirect_uri: None,
            shutdown_date: None,
            links: None,
        };
        let cfg = test_config(None);
        let redirect = resolve_platform_redirect_uri(
            row.redirect_uri.as_deref(),
            row.links.as_ref(),
            &cfg.platform_links_redirect_keys,
        );
        let has_global_callback = cfg
            .auth_callback_url
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        assert!(redirect.is_none());
        assert!(!has_global_callback);
    }
}
