use std::{sync::Arc, time::Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::{
    session::{hash_token, random_token},
    ActivationCapability, AuthError, AuthStore, LoginRateLimiter, PasswordError, PasswordService,
    PendingActivation, Principal, RateLimitConfig, Role, UserAccount, UserListEntry, UserStatus,
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

//++agent TASK-224 [24.09.2026]
/// Ошибки активации разделены (Б8): слабый пароль при действительном коде —
/// `PasswordPolicy`, а не общий отказ; перебор кодов ограничен `RateLimited` (Б10).
#[derive(Debug, Error)]
pub enum ActivationError {
    #[error("activation capability is invalid, expired or consumed")]
    Invalid,
    #[error("too many activation attempts")]
    RateLimited,
    #[error("the password does not satisfy policy")]
    PasswordPolicy,
    #[error("authentication is unavailable")]
    Unavailable,
}
//--agent TASK-224

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
    //++agent TASK-224 [25.09.2026] ревью R2: широкое ведро на весь
    // endpoint активации — per-token ключ (в `limiter`) режет перебор
    // одного кода, а этот общий лимит — распыление попыток по множеству
    // токенов; при этом один атакующий не исчерпывает лимит за всех.
    activation_endpoint_limiter: LoginRateLimiter,
    //--agent TASK-224
    dummy_hash: String,
}

//++agent TASK-224 [25.09.2026] ревью R2
/// Общий лимит endpoint'а активации — заметно шире per-token (5/мин):
/// массовая выдача приглашений не должна упираться в него, а вал попыток
/// с разными кодами — отсекаться до исчерпания per-token вёдер.
const ACTIVATION_ENDPOINT_LIMIT: RateLimitConfig = RateLimitConfig {
    per_minute: 60,
    per_hour: 600,
    max_keys: 128,
};
//--agent TASK-224

impl LocalAuthProvider {
    pub fn new(store: Arc<dyn AuthStore>) -> Result<Self, PasswordError> {
        let passwords = PasswordService::new();
        let dummy_hash = passwords.dummy_hash()?;
        Ok(Self {
            store,
            passwords,
            limiter: LoginRateLimiter::new(RateLimitConfig::default()),
            activation_endpoint_limiter: LoginRateLimiter::new(ACTIVATION_ENDPOINT_LIMIT),
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

    //++agent TASK-224 [24.09.2026]
    /// Активация (Б3/Б8/Б10): сначала дешёвая проверка кода, затем политика
    /// пароля и только потом дорогой Argon2 — иначе ошибка политики сливалась
    /// бы с «код недействителен», а перебор грузил бы CPU.
    pub fn activate(
        &self,
        source: &str,
        token: &str,
        password: &str,
    ) -> Result<Principal, ActivationError> {
        //++agent TASK-224 [25.09.2026] ревью R2: per-token ключ — по хэшу
        // кода (сырые токены в ключи лимитера не попадают); endpoint-ведро
        // проверяется вторым, чтобы спам одним кодом не ел общий лимит.
        let now = Instant::now();
        let token_key = format!(
            "activation\0{source}\0{}",
            URL_SAFE_NO_PAD.encode(hash_token(token))
        );
        if !self.limiter.check_and_record(&token_key, now)
            || !self
                .activation_endpoint_limiter
                .check_and_record(&format!("activation\0{source}"), now)
        {
            return Err(ActivationError::RateLimited);
        }
        //--agent TASK-224
        self.store
            .find_pending_activation(&hash_token(token), Utc::now())
            .map_err(|_| ActivationError::Unavailable)?
            .ok_or(ActivationError::Invalid)?;
        PasswordService::validate(password).map_err(|_| ActivationError::PasswordPolicy)?;
        let hash = self
            .passwords
            .hash(password)
            .map_err(|_| ActivationError::Unavailable)?;
        // Гонка «код погасили между предпроверкой и записью» остаётся Invalid.
        self.store
            .activate_user(&hash_token(token), Utc::now(), &hash)
            .map_err(|error| match error {
                AuthError::Unavailable => ActivationError::Unavailable,
                //++agent TASK-224 [08.10.2026] UserDisabled здесь недостижим:
                // pending-capability фильтрует status='active' — недостижимый
                // вариант сводится к Invalid, не открывая нового пути.
                AuthError::Conflict | AuthError::NotFound | AuthError::UserDisabled => {
                    ActivationError::Invalid
                } //--agent TASK-224
            })
    }

    /// Предпроверка кода приглашения (Б2): логин и срок без изменения состояния.
    pub fn pending_activation(&self, token: &str) -> Result<Option<PendingActivation>, AuthError> {
        self.store
            .find_pending_activation(&hash_token(token), Utc::now())
    }

    /// Перевыпуск приглашения (Б1): новый код показывается один раз в ответе.
    pub fn reissue_invitation(
        &self,
        actor: &Principal,
        user_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(UserAccount, String), AuthError> {
        if actor.role != Role::Admin {
            return Err(AuthError::Conflict);
        }
        let token = random_token();
        let capability = ActivationCapability {
            token_hash: hash_token(&token),
            user_id,
            expires_at: Utc::now() + Duration::minutes(15),
            consumed_at: None,
        };
        let user =
            self.store
                .reissue_activation(user_id, capability, actor.user_id, correlation_id)?;
        Ok((user, token))
    }

    /// Сброс пароля администратором (Б5): пользователь заново проходит
    /// приглашение; старый пароль и сессии уничтожаются в той же транзакции.
    pub fn reset_user_password(
        &self,
        actor: &Principal,
        user_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(UserAccount, String), AuthError> {
        if actor.role != Role::Admin {
            return Err(AuthError::Conflict);
        }
        let token = random_token();
        let capability = ActivationCapability {
            token_hash: hash_token(&token),
            user_id,
            expires_at: Utc::now() + Duration::minutes(15),
            consumed_at: None,
        };
        let user =
            self.store
                .reset_user_password(user_id, capability, actor.user_id, correlation_id)?;
        Ok((user, token))
    }

    /// Удаление пользователя, ни разу не входившего (Б6), освобождает логин.
    pub fn delete_user(
        &self,
        actor: &Principal,
        user_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError> {
        if actor.role != Role::Admin {
            return Err(AuthError::Conflict);
        }
        self.store
            .delete_user(user_id, actor.user_id, correlation_id)
    }

    /// Б9: сервис ещё не инициализирован первым администратором.
    pub fn bootstrap_pending(&self) -> Result<bool, AuthError> {
        self.store.bootstrap_pending()
    }

    /// Логин для подписи в UI (меню профиля); безопасно показывать владельцу
    /// сессии — это его собственная учётная запись.
    pub fn display_login(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        Ok(self
            .store
            .find_user_by_id(user_id)?
            .map(|user| user.display_login))
    }
    //--agent TASK-224

    pub fn list_users(&self) -> Result<Vec<UserListEntry>, AuthError> {
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
                AuthError::Conflict | AuthError::NotFound | AuthError::UserDisabled => {
                    ChangePasswordError::Rejected
                }
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
