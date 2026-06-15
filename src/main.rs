use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post},
    http::{header, Method},
};
use base64::{Engine as _, engine::general_purpose};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use myso_salt_service::{
    config::Config,
    db::SaltStore,
    indexer_platforms::{self, merge_allowed_clients},
    monitoring::Metrics,
    state::AppState,
    security::{SaltManager, jwt::JwtValidator, access_token::AccessTokenValidator},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting the MySocial Salt Service");

    // Load configuration
    let mut config = Config::from_env()?;

    let http_for_indexer = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client for indexer")?;

    let indexer_url_set = config
        .myso_indexer_graphql_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();

    if indexer_url_set {
        match indexer_platforms::fetch_allowed_clients_from_indexer(&http_for_indexer, &config).await {
            Ok(from_indexer) => {
                let env_clients = std::mem::take(&mut config.allowed_clients_env);
                config.allowed_clients = merge_allowed_clients(from_indexer, env_clients);
                info!(
                    count = config.allowed_clients.len(),
                    "Merged allowed clients from indexer and ALLOWED_CLIENTS"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Indexer platform fetch failed; continuing with ALLOWED_CLIENTS env only (indexer DB may be behind — e.g. missing cover_photo column)"
                );
                config.allowed_clients = std::mem::take(&mut config.allowed_clients_env);
            }
        }
    } else {
        config.allowed_clients = std::mem::take(&mut config.allowed_clients_env);
    }

    config.validate()?;

    let config = Arc::new(config);
    info!("Configuration loaded successfully");

    // Decode master seed
    let master_seed = general_purpose::STANDARD
        .decode(&config.master_seed_base64)
        .context("Failed to decode master seed")?;

    // Initialize components
    let store = SaltStore::new(&config.database_url).await?;
    info!("Database connection established");

    // Run migrations
    run_migrations(&store).await?;
    info!("Database migrations completed");

    let salt_manager = Arc::new(SaltManager::new(master_seed)?);
    let jwt_validator = Arc::new(JwtValidator::new(
        config.allowed_audience_google.clone(),
        config.allowed_audience_apple.clone(),
        config.mysocial_auth_issuer.clone(),
        config.mysocial_auth_jwks_uri.clone(),
        config.allowed_audience_mysocial.clone(),
    ));
    let access_token_validator = Arc::new(AccessTokenValidator::new(
        config.twitch_client_id.clone(),
        config.facebook_app_secret.clone(),
        config.facebook_app_id.clone(),
        config.allowed_audience_facebook.clone(),
        config.allowed_audience_twitch.clone(),
    ));
    let metrics = Arc::new(Metrics::new());
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client")?;

    let state = AppState {
        config: config.clone(),
        store,
        salt_manager,
        jwt_validator,
        access_token_validator,
        metrics,
        http_client,
    };

    // Build router
    let app = build_router(state.clone(), &config.allowed_origins);

    // Start background tasks
    tokio::spawn(cleanup_task(state.store.clone()));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(state: AppState, allowed_origins: &[String]) -> Router {
    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|o| {
            o.trim()
                .parse()
                .map_err(|e| {
                    error!("Invalid ALLOWED_ORIGINS entry {:?}: {}", o, e);
                })
                .ok()
        })
        .collect();

    let cors = if origins.is_empty() {
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    };

    let mut router = Router::new()
        .route("/health", get(myso_salt_service::handlers::health_check))
        .route("/salt", post(myso_salt_service::handlers::get_salt))
        .route("/salt/check", get(myso_salt_service::handlers::salt_check))
        .route("/salt/test", post(myso_salt_service::handlers::get_salt_test))
        .route("/metrics", get(myso_salt_service::handlers::get_metrics));

    if !state.config.allowed_clients.is_empty() {
        router = router
            .route(
                "/auth/provider/callback",
                post(myso_salt_service::handlers::auth_provider_callback),
            )
            .route(
                "/auth/wallet/callback",
                post(myso_salt_service::handlers::auth_wallet_callback),
            );
    }

    router
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

async fn run_migrations(store: &SaltStore) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(store.pool())
        .await
        .context("Failed to run migrations")?;
    Ok(())
}

async fn cleanup_task(store: SaltStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1 hour

    loop {
        interval.tick().await;

        match store.cleanup_rate_limits(24).await {
            Ok(count) => {
                if count > 0 {
                    info!("Cleaned up {} old rate limit entries", count);
                }
            }
            Err(e) => {
                error!("Failed to cleanup rate limits: {}", e);
            }
        }

        match store.cleanup_expired_refresh_sessions().await {
            Ok(count) => {
                if count > 0 {
                    info!("Cleaned up {} expired refresh sessions", count);
                }
            }
            Err(e) => {
                error!("Failed to cleanup expired refresh sessions: {}", e);
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}
