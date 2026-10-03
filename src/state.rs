use std::sync::Arc;

use crate::config::Config;
use crate::db::SaltStore;
use crate::monitoring::Metrics;
use crate::security::{jwt::JwtValidator, access_token::AccessTokenValidator};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: SaltStore,
    pub jwt_validator: Arc<JwtValidator>,
    pub access_token_validator: Arc<AccessTokenValidator>,
    pub metrics: Arc<Metrics>,
    pub http_client: reqwest::Client,
}

