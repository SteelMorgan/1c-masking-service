use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Полные права, включая пользователей и назначение доступа к базам;
    /// набор баз всегда «все» (включая будущие) и не хранится.
    SuperAdmin,
    /// Управление только явно назначенными базами.
    Admin,
    /// Просмотр истории только назначенных баз. Ступень точная:
    /// просмотр осознанно не наследуется администраторами — разделение
    /// обязанностей между Admin и Viewer сделано намеренно.
    Viewer,
}

/// Область видимости баз для principal: `All` — все базы без перечисления
/// (только SuperAdmin), `Only` — явный набор из `user_database_access`.
/// Пустой `Only` допустим и ничего не открывает (fail-closed).
#[derive(Debug, Clone)]
pub enum DatabaseScope {
    All,
    Only(std::collections::HashSet<Uuid>),
}

impl DatabaseScope {
    pub fn contains(&self, database_id: Uuid) -> bool {
        match self {
            Self::All => true,
            Self::Only(ids) => ids.contains(&database_id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct UserAccount {
    pub id: Uuid,
    pub normalized_login: String,
    pub display_login: String,
    pub password_hash: Option<String>,
    pub role: Role,
    pub status: UserStatus,
    pub auth_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    pub user_id: Uuid,
    pub role: Role,
    pub auth_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ActivationCapability {
    pub token_hash: [u8; 32],
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

//++agent TASK-224 [24.09.2026]
/// Валидная (не погашенная, не истёкшая) пригласительная capability:
/// отдаётся наружу для предпроверки кода — логин показывается до ввода пароля.
#[derive(Debug, Clone)]
pub struct PendingActivation {
    pub user_id: Uuid,
    pub display_login: String,
    pub expires_at: DateTime<Utc>,
}

/// Строка списка пользователей для Admin UI: аккаунт + агрегаты приглашения
/// и последнего входа (нужны состояниям «Ожидает/Истекло» и колонке входа).
#[derive(Debug, Clone)]
pub struct UserListEntry {
    pub account: UserAccount,
    pub invitation_expires_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    /// Явно выданные базы из `user_database_access`; у SuperAdmin пусто —
    /// его набор не хранится (всегда «все»).
    pub database_ids: Vec<Uuid>,
}
//--agent TASK-224

#[derive(Debug, Clone)]
pub struct NewSession {
    pub token_hash: [u8; 32],
    pub csrf_hash: [u8; 32],
    pub user_id: Uuid,
    pub auth_epoch: u64,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub token_hash: [u8; 32],
    pub csrf_hash: [u8; 32],
    pub user_id: Uuid,
    pub role: Role,
    pub auth_epoch: u64,
    pub current_auth_epoch: u64,
    pub user_status: UserStatus,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authentication storage is unavailable")]
    Unavailable,
    #[error("authentication state conflicts with the requested operation")]
    Conflict,
    #[error("authentication record was not found")]
    NotFound,
    //++agent TASK-224 [08.10.2026] итерация 4
    /// Целевой пользователь отключён: приглашение и сброс пароля для него
    /// запрещены до включения — иначе у отключённой учётной записи
    /// появился бы свежий путь входа.
    #[error("target user is disabled")]
    UserDisabled,
    //--agent TASK-224
    /// Цель назначения доступа — SuperAdmin: его набор баз всегда «все»
    /// и явно не задаётся (на API — 409 SUPERADMIN_HAS_ALL).
    #[error("super admin database scope is implicit")]
    SuperAdminScope,
    /// В назначаемом наборе указан несуществующий database_id.
    #[error("unknown database id in access set")]
    UnknownDatabase,
}

/// Persistence boundary for local human identities. Implementations must make
/// password/bootstrap mutations and their session revocation atomic.
pub trait AuthStore: Send + Sync {
    fn ensure_initial_admin(&self) -> Result<UserAccount, AuthError>;
    fn find_user_by_login(&self, normalized_login: &str) -> Result<Option<UserAccount>, AuthError>;
    fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserAccount>, AuthError>;
    /// Список для Admin UI (Б7): аккаунт + invitation_expires_at/last_login_at.
    fn list_users(&self) -> Result<Vec<UserListEntry>, AuthError>;

    /// Permanently completes first-admin bootstrap. It must succeed only once,
    /// only for login `Admin`, and only while its password hash is NULL.
    fn complete_initial_admin_bootstrap(&self, password_hash: &str) -> Result<(), AuthError>;

    /// Creates a user with a NULL password and stores only the activation-token
    /// hash. `database_ids` — начальный набор доступа (Admin/Viewer); вставка
    /// и аудит выдачи идут в той же транзакции, чтобы не существовало
    /// промежуточного состояния. Несуществующий id → `UnknownDatabase`.
    #[allow(clippy::too_many_arguments)]
    fn create_user_with_activation(
        &self,
        display_login: &str,
        normalized_login: &str,
        role: Role,
        database_ids: &[Uuid],
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError>;

    /// Consumes the capability, stores the password hash, increments auth_epoch,
    /// and revokes all user sessions in one transaction. Returns the activated
    /// principal so the caller can issue a session (auto-login, TASK-224/Б3).
    fn activate_user(
        &self,
        token_hash: &[u8; 32],
        now: DateTime<Utc>,
        password_hash: &str,
    ) -> Result<Principal, AuthError>;

    //++agent TASK-224 [24.09.2026]
    /// Возвращает pending-активацию по хешу кода: capability не погашена, не
    /// истекла, пользователь активен и ещё без пароля. Используется и
    /// предпроверкой (Б2), и самой активацией (Б8), чтобы слабый пароль не
    /// маскировался под «код недействителен».
    fn find_pending_activation(
        &self,
        token_hash: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<Option<PendingActivation>, AuthError>;

    /// Перевыпуск приглашения (Б1): гасит все pending-capability пользователя
    /// и ставит новую. Только для активного пользователя без пароля.
    fn reissue_activation(
        &self,
        user_id: Uuid,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError>;

    /// Сброс пароля администратором (Б5): обнуляет пароль, увеличивает
    /// auth_epoch, отзывает сессии, гасит pending-capability и ставит новую —
    /// атомарно, иначе пользователь остался бы без способа войти.
    fn reset_user_password(
        &self,
        user_id: Uuid,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError>;

    /// Удаление пользователя (Б6), который ни разу не входил (пароль NULL и
    /// ни одной сессии). Последний активный SuperAdmin не удаляется — защита
    /// от полной потери административного доступа.
    fn delete_user(
        &self,
        user_id: Uuid,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError>;

    /// Б9: true, пока bootstrap первого администратора не завершён.
    fn bootstrap_pending(&self) -> Result<bool, AuthError>;
    //--agent TASK-224

    /// Явно выданные базы пользователя (Admin/Viewer). У SuperAdmin
    /// строк нет — возвращается пустой список, доступ «все» неявный.
    fn list_database_access(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError>;

    /// Полная замена набора доступа в одной транзакции: diff с текущим
    /// набором пишет по событию аудита `access.grant`/`access.revoke` на
    /// каждую пару (user, database) — `database_id` и `target_user_id`
    /// заполняются отдельными полями. `auth_epoch` НЕ инкрементируется:
    /// scope считывается на каждый запрос, сессии инвалидировать не нужно.
    /// Ошибки: цель-SuperAdmin → `SuperAdminScope`; несуществующий
    /// database_id → `UnknownDatabase`; нет пользователя → `NotFound`.
    fn set_database_access(
        &self,
        user_id: Uuid,
        database_ids: &[Uuid],
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError>;

    /// Область видимости баз вызывающего: SuperAdmin → `All` (включая
    /// будущие базы авторегистрации), остальные — `Only` явного набора.
    /// Выполняется на каждый запрос — отзыв действует немедленно.
    fn accessible_databases(&self, principal: &Principal) -> Result<DatabaseScope, AuthError>;

    /// Updates role/status, increments auth_epoch, and revokes all sessions atomically.
    fn update_user_access(
        &self,
        user_id: Uuid,
        role: Role,
        status: UserStatus,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError>;

    /// Replaces an obsolete PHC encoding after successful verification without
    /// changing the security principal or invalidating the new login.
    fn rehash_password(
        &self,
        user_id: Uuid,
        expected_auth_epoch: u64,
        password_hash: &str,
    ) -> Result<(), AuthError>;

    /// Changes the password, advances auth_epoch, revokes all prior sessions,
    /// and records the successful security event in one transaction.
    fn change_password(
        &self,
        user_id: Uuid,
        expected_auth_epoch: u64,
        password_hash: &str,
        now: DateTime<Utc>,
        correlation_id: Uuid,
    ) -> Result<u64, AuthError>;

    fn insert_session(&self, session: NewSession) -> Result<(), AuthError>;
    fn find_session(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, AuthError>;
    fn touch_session(
        &self,
        token_hash: &[u8; 32],
        idle_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    fn revoke_session(&self, token_hash: &[u8; 32], now: DateTime<Utc>) -> Result<(), AuthError>;
}
