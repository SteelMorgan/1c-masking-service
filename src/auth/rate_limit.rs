use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub per_minute: usize,
    pub per_hour: usize,
    pub max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 5,
            per_hour: 20,
            max_keys: 10_000,
        }
    }
}

#[derive(Default)]
struct Attempts {
    values: Vec<Instant>,
    last_seen: Option<Instant>,
}

pub struct LoginRateLimiter {
    config: RateLimitConfig,
    attempts: Mutex<HashMap<String, Attempts>>,
}

impl LoginRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_record(&self, key: &str, now: Instant) -> bool {
        let Ok(mut all) = self.attempts.lock() else {
            return false;
        };
        if all.len() >= self.config.max_keys && !all.contains_key(key) {
            if let Some(oldest) = all
                .iter()
                .min_by_key(|(_, attempts)| attempts.last_seen)
                .map(|(key, _)| key.clone())
            {
                all.remove(&oldest);
            }
        }

        let attempts = all.entry(key.to_owned()).or_default();
        attempts
            .values
            .retain(|at| now.saturating_duration_since(*at) < Duration::from_secs(3600));
        let minute = attempts
            .values
            .iter()
            .filter(|at| now.saturating_duration_since(**at) < Duration::from_secs(60))
            .count();
        let allowed =
            minute < self.config.per_minute && attempts.values.len() < self.config.per_hour;
        attempts.values.push(now);
        attempts.last_seen = Some(now);
        allowed
    }
}
