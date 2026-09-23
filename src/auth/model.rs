use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Viewer,
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
}

/// Persistence boundary for local human identities. Implementations must make
/// password/bootstrap mutations and their session revocation atomic.
pub trait AuthStore: Send + Sync {
    fn ensure_initial_admin(&self) -> Result<UserAccount, AuthError>;
    fn find_user_by_login(&self, normalized_login: &str) -> Result<Option<UserAccount>, AuthError>;
    fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserAccount>, AuthError>;
    fn list_users(&self) -> Result<Vec<UserAccount>, AuthError>;

    /// Permanently completes first-admin bootstrap. It must succeed only once,
    /// only for login `Admin`, and only while its password hash is NULL.
    fn complete_initial_admin_bootstrap(&self, password_hash: &str) -> Result<(), AuthError>;

    /// Creates a user with a NULL password and stores only the activation-token hash.
    fn create_user_with_activation(
        &self,
        display_login: &str,
        normalized_login: &str,
        role: Role,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError>;

    /// Consumes the capability, stores the password hash, increments auth_epoch,
    /// and revokes all user sessions in one transaction.
    fn activate_user(
        &self,
        token_hash: &[u8; 32],
        now: DateTime<Utc>,
        password_hash: &str,
    ) -> Result<(), AuthError>;

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
