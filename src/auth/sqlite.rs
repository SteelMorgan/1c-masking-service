use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::storage::SqliteStorage;

use super::{
    ActivationCapability, AuthError, AuthStore, NewSession, Role, SessionRecord, UserAccount,
    UserStatus,
};

impl AuthStore for SqliteStorage {
    fn ensure_initial_admin(&self) -> Result<UserAccount, AuthError> {
        self.with_connection(|connection| {
            load_user_by_login(connection, "admin")?.ok_or(rusqlite::Error::QueryReturnedNoRows)
        })
        .map_err(map_error)
    }

    fn find_user_by_login(&self, normalized_login: &str) -> Result<Option<UserAccount>, AuthError> {
        self.with_connection(|connection| load_user_by_login(connection, normalized_login))
            .map_err(map_error)
    }

    fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserAccount>, AuthError> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT id,normalized_login,display_login,password_hash,role,status,auth_epoch FROM users WHERE id=?1",
                [user_id.to_string()],
                read_user,
            ).optional()
        }).map_err(map_error)
    }

    fn list_users(&self) -> Result<Vec<UserAccount>, AuthError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,normalized_login,display_login,password_hash,role,status,auth_epoch FROM users ORDER BY normalized_login",
            )?;
            let rows = statement.query_map([], read_user)?.collect();
            rows
        }).map_err(map_error)
    }

    fn complete_initial_admin_bootstrap(&self, password_hash: &str) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let completed: Option<String> = transaction.query_row(
                "SELECT bootstrap_completed_at FROM service_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if completed.is_some() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let now = Utc::now().to_rfc3339();
            let changed = transaction.execute(
                "UPDATE users SET password_hash=?1,auth_epoch=auth_epoch+1,updated_at=?2
                 WHERE normalized_login='admin' AND role='Admin' AND status='active' AND password_hash IS NULL",
                params![password_hash, now],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            transaction.execute(
                "UPDATE service_state SET bootstrap_completed_at=?1 WHERE singleton=1 AND bootstrap_completed_at IS NULL",
                [&now],
            )?;
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=(SELECT id FROM users WHERE normalized_login='admin') AND revoked_at IS NULL",
                [&now],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
    }

    fn create_user_with_activation(
        &self,
        display_login: &str,
        normalized_login: &str,
        role: Role,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO users(id,normalized_login,display_login,password_hash,role,status,auth_epoch,created_at,updated_at)
                 VALUES (?1,?2,?3,NULL,?4,'active',0,?5,?5)",
                params![capability.user_id.to_string(), normalized_login, display_login, role_text(role), now],
            )?;
            transaction.execute(
                "INSERT INTO activation_capabilities(id,token_hash,user_id,purpose,expires_at,consumed_at,created_at)
                 VALUES (?1,?2,?3,'initial_password',?4,NULL,?5)",
                params![Uuid::new_v4().to_string(), &capability.token_hash[..], capability.user_id.to_string(), capability.expires_at.to_rfc3339(), now],
            )?;
            let audit_code = format!(
                "target_user_id={};role={};status=active",
                capability.user_id,
                role_text(role)
            );
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,correlation_id,created_at)
                 VALUES ('human',?1,'user.create','success',?2,?3,?4)",
                params![actor_id.to_string(), audit_code, correlation_id.to_string(), now],
            )?;
            transaction.commit()?;
            Ok(UserAccount {
                id: capability.user_id,
                normalized_login: normalized_login.to_owned(),
                display_login: display_login.to_owned(),
                password_hash: None,
                role,
                status: UserStatus::Active,
                auth_epoch: 0,
            })
        }).map_err(|error| if is_constraint(&error) { AuthError::Conflict } else { map_error(error) })
    }

    fn activate_user(
        &self,
        token_hash: &[u8; 32],
        now: DateTime<Utc>,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now_text = now.to_rfc3339();
            let user_id: Option<String> = transaction.query_row(
                "SELECT user_id FROM activation_capabilities
                 WHERE token_hash=?1 AND purpose='initial_password' AND consumed_at IS NULL AND expires_at>?2",
                params![&token_hash[..], now_text],
                |row| row.get(0),
            ).optional()?;
            let Some(user_id) = user_id else {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            };
            let changed = transaction.execute(
                "UPDATE users SET password_hash=?1,auth_epoch=auth_epoch+1,updated_at=?2
                 WHERE id=?3 AND status='active' AND password_hash IS NULL",
                params![password_hash, now_text, user_id],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            transaction.execute(
                "UPDATE activation_capabilities SET consumed_at=?1 WHERE token_hash=?2 AND consumed_at IS NULL",
                params![now_text, &token_hash[..]],
            )?;
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
                params![now_text, user_id],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
    }

    fn update_user_access(
        &self,
        user_id: Uuid,
        role: Role,
        status: UserStatus,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let target_is_active_admin: Option<bool> = transaction.query_row(
                "SELECT role='Admin' AND status='active' FROM users WHERE id=?1",
                [user_id.to_string()],
                |row| row.get(0),
            ).optional()?;
            let Some(target_is_active_admin) = target_is_active_admin else {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            };
            if target_is_active_admin && (role != Role::Admin || status != UserStatus::Active) {
                let active_admins: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM users WHERE role='Admin' AND status='active'",
                    [],
                    |row| row.get(0),
                )?;
                if active_admins <= 1 {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
            }
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "UPDATE users SET role=?1,status=?2,auth_epoch=auth_epoch+1,updated_at=?3 WHERE id=?4",
                params![role_text(role), status_text(status), now, user_id.to_string()],
            )?;
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
                params![now, user_id.to_string()],
            )?;
            let audit_code = format!(
                "target_user_id={};role={};status={}",
                user_id,
                role_text(role),
                status_text(status)
            );
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,correlation_id,created_at)
                 VALUES ('human',?1,'user.update','success',?2,?3,?4)",
                params![actor_id.to_string(), audit_code, correlation_id.to_string(), now],
            )?;
            transaction.commit()
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
    }

    fn rehash_password(
        &self,
        user_id: Uuid,
        expected_auth_epoch: u64,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE users SET password_hash=?1,updated_at=?2 WHERE id=?3 AND auth_epoch=?4 AND status='active'",
                params![password_hash, Utc::now().to_rfc3339(), user_id.to_string(), expected_auth_epoch as i64],
            )?;
            if changed == 1 { Ok(()) } else { Err(rusqlite::Error::QueryReturnedNoRows) }
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
    }

    fn change_password(
        &self,
        user_id: Uuid,
        expected_auth_epoch: u64,
        password_hash: &str,
        now: DateTime<Utc>,
        correlation_id: Uuid,
    ) -> Result<u64, AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now_text = now.to_rfc3339();
            let changed = transaction.execute(
                "UPDATE users SET password_hash=?1,auth_epoch=auth_epoch+1,updated_at=?2
                 WHERE id=?3 AND auth_epoch=?4 AND status='active' AND password_hash IS NOT NULL",
                params![password_hash, now_text, user_id.to_string(), expected_auth_epoch as i64],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
                params![now_text, user_id.to_string()],
            )?;
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,correlation_id,created_at)
                 VALUES ('human',?1,'password_change','success','PASSWORD_CHANGED',?2,?3)",
                params![user_id.to_string(), correlation_id.to_string(), now_text],
            )?;
            transaction.commit()?;
            expected_auth_epoch
                .checked_add(1)
                .ok_or(rusqlite::Error::InvalidQuery)
        })
        .map_err(|error| {
            if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                AuthError::Conflict
            } else {
                map_error(error)
            }
        })
    }

    fn insert_session(&self, session: NewSession) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_hash,idle_expires_at,absolute_expires_at,last_seen_at,revoked_at,auth_epoch,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,NULL,?7,?6)",
                params![&session.token_hash[..], session.user_id.to_string(), &session.csrf_hash[..], session.idle_expires_at.to_rfc3339(), session.absolute_expires_at.to_rfc3339(), session.last_seen_at.to_rfc3339(), session.auth_epoch as i64],
            )?;
            Ok(())
        }).map_err(map_error)
    }

    fn find_session(&self, token_hash: &[u8; 32]) -> Result<Option<SessionRecord>, AuthError> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT s.token_hash,s.csrf_hash,s.user_id,u.role,s.auth_epoch,u.auth_epoch,u.status,s.idle_expires_at,s.absolute_expires_at,s.revoked_at
                 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?1",
                [&token_hash[..]],
                |row| {
                    Ok(SessionRecord {
                        token_hash: blob32(row.get::<_, Vec<u8>>(0)?)?,
                        csrf_hash: blob32(row.get::<_, Vec<u8>>(1)?)?,
                        user_id: parse_uuid(row.get::<_, String>(2)?)?,
                        role: parse_role(&row.get::<_, String>(3)?)?,
                        auth_epoch: row.get::<_, i64>(4)?.max(0) as u64,
                        current_auth_epoch: row.get::<_, i64>(5)?.max(0) as u64,
                        user_status: parse_status(&row.get::<_, String>(6)?)?,
                        idle_expires_at: parse_time(row.get::<_, String>(7)?)?,
                        absolute_expires_at: parse_time(row.get::<_, String>(8)?)?,
                        revoked_at: row.get::<_, Option<String>>(9)?.map(parse_time).transpose()?,
                    })
                },
            ).optional()
        }).map_err(map_error)
    }

    fn touch_session(
        &self,
        token_hash: &[u8; 32],
        idle_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE sessions SET idle_expires_at=?1,last_seen_at=?2 WHERE token_hash=?3 AND revoked_at IS NULL",
                params![idle_expires_at.to_rfc3339(), now.to_rfc3339(), &token_hash[..]],
            )?;
            Ok(())
        }).map_err(map_error)
    }

    fn revoke_session(&self, token_hash: &[u8; 32], now: DateTime<Utc>) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            connection.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE token_hash=?2 AND revoked_at IS NULL",
                params![now.to_rfc3339(), &token_hash[..]],
            )?;
            Ok(())
        })
        .map_err(map_error)
    }
}

fn load_user_by_login(
    connection: &rusqlite::Connection,
    login: &str,
) -> rusqlite::Result<Option<UserAccount>> {
    connection.query_row(
        "SELECT id,normalized_login,display_login,password_hash,role,status,auth_epoch FROM users WHERE normalized_login=?1",
        [login],
        read_user,
    ).optional()
}

fn read_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserAccount> {
    Ok(UserAccount {
        id: parse_uuid(row.get(0)?)?,
        normalized_login: row.get(1)?,
        display_login: row.get(2)?,
        password_hash: row.get(3)?,
        role: parse_role(&row.get::<_, String>(4)?)?,
        status: parse_status(&row.get::<_, String>(5)?)?,
        auth_epoch: row.get::<_, i64>(6)?.max(0) as u64,
    })
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_time(value: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn blob32(value: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn role_text(role: Role) -> &'static str {
    match role {
        Role::Admin => "Admin",
        Role::Viewer => "Viewer",
    }
}
fn status_text(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
    }
}
fn parse_role(value: &str) -> rusqlite::Result<Role> {
    match value {
        "Admin" => Ok(Role::Admin),
        "Viewer" => Ok(Role::Viewer),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn parse_status(value: &str) -> rusqlite::Result<UserStatus> {
    match value {
        "active" => Ok(UserStatus::Active),
        "disabled" => Ok(UserStatus::Disabled),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn map_error(_: rusqlite::Error) -> AuthError {
    AuthError::Unavailable
}
fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(inner, _) if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE || inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}
