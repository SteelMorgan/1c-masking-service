use std::{sync::Arc, time::Instant};

use chrono::{Duration, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::{
    session::{hash_token, random_token},
    ActivationCapability, AuthError, AuthStore, LoginRateLimiter, PasswordError, PasswordService,
    Principal, RateLimitConfig, Role, UserAccount, UserStatus,
};

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("credentials were rejected")]
    Rejected,
    #[error("too many authentication attempts")]
    RateLimited,
    #[error("authentication is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum ChangePasswordError {
    #[error("credentials were rejected")]
    Rejected,
    #[error("too many authentication attempts")]
    RateLimited,
    #[error("the new password does not satisfy policy")]
    InvalidNewPassword,
    #[error("authentication is unavailable")]
    Unavailable,
}

pub trait AuthProvider: Send + Sync {
    fn authenticate(
        &self,
        source: &str,
        login: &str,
        password: &str,
    ) -> Result<Principal, LoginError>;
}

pub struct LocalAuthProvider {
    store: Arc<dyn AuthStore>,
    passwords: PasswordService,
    limiter: LoginRateLimiter,
    dummy_hash: String,
}

impl LocalAuthProvider {
    pub fn new(store: Arc<dyn AuthStore>) -> Result<Self, PasswordError> {
        let passwords = PasswordService::new();
        let dummy_hash = passwords.dummy_hash()?;
        Ok(Self {
            store,
            passwords,
            limiter: LoginRateLimiter::new(RateLimitConfig::default()),
            dummy_hash,
        })
    }

    pub fn initialize(&self) -> Result<UserAccount, AuthError> {
        self.store.ensure_initial_admin()
    }

    /// This method is intended only for the mode-0600 local control socket.
    pub fn bootstrap_admin_password(&self, password: &str) -> Result<(), AuthError> {
        if !self
            .limiter
            .check_and_record("local-bootstrap\0admin", Instant::now())
        {
            return Err(AuthError::Conflict);
        }
        let hash = self
            .passwords
            .hash(password)
            .map_err(|_| AuthError::Conflict)?;
        self.store.complete_initial_admin_bootstrap(&hash)
    }

    pub fn create_user(
        &self,
        actor: &Principal,
        display_login: &str,
        role: Role,
        correlation_id: Uuid,
    ) -> Result<(UserAccount, String), AuthError> {
        if actor.role != Role::Admin {
            return Err(AuthError::Conflict);
        }
        let normalized = normalize_login(display_login).ok_or(AuthError::Conflict)?;
        let token = random_token();
        let capability = ActivationCapability {
            token_hash: hash_token(&token),
            user_id: Uuid::new_v4(),
            expires_at: Utc::now() + Duration::minutes(15),
            consumed_at: None,
        };
        let user = self.store.create_user_with_activation(
            display_login,
            &normalized,
            role,
            capability,
            actor.user_id,
            correlation_id,
        )?;
        Ok((user, token))
    }

    pub fn activate(&self, token: &str, password: &str) -> Result<(), AuthError> {
        let hash = self
            .passwords
            .hash(password)
            .map_err(|_| AuthError::Conflict)?;
        self.store
            .activate_user(&hash_token(token), Utc::now(), &hash)
    }

    pub fn list_users(&self) -> Result<Vec<UserAccount>, AuthError> {
        self.store.list_users()
    }

    pub fn update_user_access(
        &self,
        actor: &Principal,
        user_id: Uuid,
        role: Role,
        status: UserStatus,
        correlation_id: Uuid,
    ) -> Result<(), AuthError> {
        if actor.role != Role::Admin {
            return Err(AuthError::Conflict);
        }
        self.store
            .update_user_access(user_id, role, status, actor.user_id, correlation_id)
    }

    pub fn change_password(
        &self,
        source: &str,
        principal: &Principal,
        current_password: &str,
        new_password: &str,
        correlation_id: Uuid,
    ) -> Result<Principal, ChangePasswordError> {
        let rate_key = format!("password-change\0{source}\0{}", principal.user_id);
        if !self.limiter.check_and_record(&rate_key, Instant::now()) {
            return Err(ChangePasswordError::RateLimited);
        }

        let user = self
            .store
            .find_user_by_id(principal.user_id)
            .map_err(|_| ChangePasswordError::Unavailable)?
            .ok_or(ChangePasswordError::Rejected)?;
        let candidate_hash = user.password_hash.as_deref().unwrap_or(&self.dummy_hash);
        if user.status != UserStatus::Active
            || user.auth_epoch != principal.auth_epoch
            || user.password_hash.is_none()
            || !self.passwords.verify(current_password, candidate_hash)
        {
            return Err(ChangePasswordError::Rejected);
        }
        PasswordService::validate(new_password)
            .map_err(|_| ChangePasswordError::InvalidNewPassword)?;
        if self.passwords.verify(new_password, candidate_hash) {
            return Err(ChangePasswordError::Rejected);
        }
        let replacement = self
            .passwords
            .hash(new_password)
            .map_err(|error| match error {
                PasswordError::InvalidPassword => ChangePasswordError::InvalidNewPassword,
                PasswordError::HashingFailed => ChangePasswordError::Unavailable,
            })?;
        let auth_epoch = self
            .store
            .change_password(
                user.id,
                principal.auth_epoch,
                &replacement,
                Utc::now(),
                correlation_id,
            )
            .map_err(|error| match error {
                AuthError::Conflict | AuthError::NotFound => ChangePasswordError::Rejected,
                AuthError::Unavailable => ChangePasswordError::Unavailable,
            })?;
        Ok(Principal {
            user_id: user.id,
            role: user.role,
            auth_epoch,
        })
    }
}

impl AuthProvider for LocalAuthProvider {
    fn authenticate(
        &self,
        source: &str,
        login: &str,
        password: &str,
    ) -> Result<Principal, LoginError> {
        let normalized = normalize_login(login).unwrap_or_default();
        let rate_key = format!("{source}\0{normalized}");
        if !self.limiter.check_and_record(&rate_key, Instant::now()) {
            return Err(LoginError::RateLimited);
        }

        let user = self
            .store
            .find_user_by_login(&normalized)
            .map_err(|_| LoginError::Unavailable)?;
        let candidate_hash = user
            .as_ref()
            .and_then(|account| account.password_hash.as_deref())
            .unwrap_or(&self.dummy_hash)
            .to_owned();
        let password_matches = self.passwords.verify(password, &candidate_hash);
        let Some(user) = user else {
            return Err(LoginError::Rejected);
        };
        if !password_matches || user.password_hash.is_none() || user.status != UserStatus::Active {
            return Err(LoginError::Rejected);
        }
        if self.passwords.needs_rehash(&candidate_hash) {
            let replacement = self
                .passwords
                .hash(password)
                .map_err(|_| LoginError::Unavailable)?;
            self.store
                .rehash_password(user.id, user.auth_epoch, &replacement)
                .map_err(|_| LoginError::Unavailable)?;
        }
        Ok(Principal {
            user_id: user.id,
            role: user.role,
            auth_epoch: user.auth_epoch,
        })
    }
}

pub fn normalize_login(login: &str) -> Option<String> {
    let trimmed = login.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 128 || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_lowercase())
}
