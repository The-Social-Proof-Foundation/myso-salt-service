use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Metrics {
    pub requests_total: Arc<AtomicU64>,
    pub requests_success: Arc<AtomicU64>,
    pub requests_failed: Arc<AtomicU64>,
    pub jwt_validations_failed: Arc<AtomicU64>,
    pub rate_limits_hit: Arc<AtomicU64>,
    pub start_time: DateTime<Utc>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_success: Arc::new(AtomicU64::new(0)),
            requests_failed: Arc::new(AtomicU64::new(0)),
            jwt_validations_failed: Arc::new(AtomicU64::new(0)),
            rate_limits_hit: Arc::new(AtomicU64::new(0)),
            start_time: Utc::now(),
        }
    }

    pub fn increment_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_jwt_failed(&self) {
        self.jwt_validations_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_rate_limit(&self) {
        self.rate_limits_hit.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        let uptime = Utc::now().signed_duration_since(self.start_time);
        
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            jwt_validations_failed: self.jwt_validations_failed.load(Ordering::Relaxed),
            rate_limits_hit: self.rate_limits_hit.load(Ordering::Relaxed),
            uptime_seconds: uptime.num_seconds(),
            start_time: self.start_time,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub jwt_validations_failed: u64,
    pub rate_limits_hit: u64,
    pub uptime_seconds: i64,
    pub start_time: DateTime<Utc>,
} 