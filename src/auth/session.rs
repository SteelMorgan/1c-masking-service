use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::{AuthError, AuthStore, NewSession, Principal, UserStatus};

#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub token: String,
    pub csrf_token: String,
    pub principal: Principal,
    pub absolute_expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum SessionValidationError {
    #[error("session is invalid")]
    Invalid,
    #[error("authentication storage is unavailable")]
    Unavailable,
}

pub struct SessionService {
    store: Arc<dyn AuthStore>,
    idle_ttl: Duration,
    absolute_ttl: Duration,
}

impl SessionService {
    pub fn new(store: Arc<dyn AuthStore>) -> Self {
        Self {
            store,
            idle_ttl: Duration::from_secs(30 * 60),
            absolute_ttl: Duration::from_secs(8 * 60 * 60),
        }
    }

    pub fn with_ttls(
        store: Arc<dyn AuthStore>,
        idle_ttl: Duration,
        absolute_ttl: Duration,
    ) -> Self {
        Self {
            store,
            idle_ttl,
            absolute_ttl,
        }
    }

    pub fn issue(
        &self,
        principal: Principal,
        now: DateTime<Utc>,
    ) -> Result<IssuedSession, AuthError> {
        let token = random_token();
        //++agent TASK-224 [24.09.2026]
        // Б11: CSRF детерминированно выводится из хеша сессионного токена —
        // GET /session может вернуть его существующей сессии без хранения
        // открытым текстом и без инвалидации других вкладок той же сессии.
        let token_hash = hash_token(&token);
        let csrf_token = derive_csrf_token(&token_hash);
        //--agent TASK-224
        let idle_expires_at = add_duration(now, self.idle_ttl)?;
        let absolute_expires_at = add_duration(now, self.absolute_ttl)?;
        self.store.insert_session(NewSession {
            token_hash,
            csrf_hash: hash_token(&csrf_token),
            user_id: principal.user_id,
            auth_epoch: principal.auth_epoch,
            idle_expires_at,
            absolute_expires_at,
            last_seen_at: now,
        })?;
        Ok(IssuedSession {
            token,
            csrf_token,
            principal,
            absolute_expires_at,
        })
    }

    pub fn validate(
        &self,
        token: &str,
        csrf_token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Principal, SessionValidationError> {
        let token_hash = hash_token(token);
        let record = self
            .store
            .find_session(&token_hash)
            .map_err(|_| SessionValidationError::Unavailable)?
            .ok_or(SessionValidationError::Invalid)?;
        if record.revoked_at.is_some()
            || record.user_status != UserStatus::Active
            || record.auth_epoch != record.current_auth_epoch
            || now >= record.idle_expires_at
            || now >= record.absolute_expires_at
        {
            return Err(SessionValidationError::Invalid);
        }
        if let Some(csrf) = csrf_token {
            if !bool::from(record.csrf_hash.ct_eq(&hash_token(csrf))) {
                return Err(SessionValidationError::Invalid);
            }
        }

        let next_idle = add_duration(now, self.idle_ttl)
            .map_err(|_| SessionValidationError::Unavailable)?
            .min(record.absolute_expires_at);
        self.store
            .touch_session(&token_hash, next_idle, now)
            .map_err(|_| SessionValidationError::Unavailable)?;
        Ok(Principal {
            user_id: record.user_id,
            role: record.role,
            auth_epoch: record.current_auth_epoch,
        })
    }

    pub fn revoke(&self, token: &str, now: DateTime<Utc>) -> Result<(), AuthError> {
        self.store.revoke_session(&hash_token(token), now)
    }

    //++agent TASK-224 [24.09.2026]
    /// CSRF-токен, привязанный к живой сессии (Б11): тот же, что выдан при
    /// login/activate/change_password. Детерминирован от token_hash — утечка
    /// БД не даёт ни cookie, ни способа подделать запрос без неё.
    pub fn csrf_for_session_token(&self, token: &str) -> String {
        derive_csrf_token(&hash_token(token))
    }
    //--agent TASK-224
}

//++agent TASK-224 [24.09.2026]
fn derive_csrf_token(token_hash: &[u8; 32]) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(token_hash).expect("HMAC accepts keys of any length");
    mac.update(b"human-csrf-v1");
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
//--agent TASK-224

fn add_duration(now: DateTime<Utc>, duration: Duration) -> Result<DateTime<Utc>, AuthError> {
    let delta = TimeDelta::from_std(duration).map_err(|_| AuthError::Unavailable)?;
    now.checked_add_signed(delta).ok_or(AuthError::Unavailable)
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
