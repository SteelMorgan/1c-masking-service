use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::storage::SqliteStorage;

use super::{
    ActivationCapability, AuthError, AuthStore, NewSession, PendingActivation, Principal, Role,
    SessionRecord, UserAccount, UserListEntry, UserStatus,
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

    //++agent TASK-224 [24.09.2026]
    // Б7: одним запросом тянем агрегаты — срок ближайшего pending-приглашения
    // (истёкший тоже показываем: состояние «Приглашение истекло» считает UI)
    // и время последнего входа (MAX sessions.created_at).
    fn list_users(&self) -> Result<Vec<UserListEntry>, AuthError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT u.id,u.normalized_login,u.display_login,u.password_hash,u.role,u.status,u.auth_epoch,
                        (SELECT MAX(c.expires_at) FROM activation_capabilities c
                          WHERE c.user_id=u.id AND c.purpose='initial_password' AND c.consumed_at IS NULL),
                        (SELECT MAX(s.created_at) FROM sessions s WHERE s.user_id=u.id)
                 FROM users u ORDER BY u.normalized_login",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok(UserListEntry {
                        account: read_user(row)?,
                        invitation_expires_at: row
                            .get::<_, Option<String>>(7)?
                            .map(parse_time)
                            .transpose()?,
                        last_login_at: row
                            .get::<_, Option<String>>(8)?
                            .map(parse_time)
                            .transpose()?,
                    })
                })?
                .collect();
            rows
        }).map_err(map_error)
    }
    //--agent TASK-224

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
    ) -> Result<Principal, AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now_text = now.to_rfc3339();
            //++agent TASK-224 [24.09.2026]
            // Б3: возвращаем principal — авто-вход после активации выдаёт сессию
            // без повторной аутентификации, epoch берём уже увеличенный.
            let target: Option<(String, String, i64)> = transaction.query_row(
                "SELECT c.user_id,u.role,u.auth_epoch FROM activation_capabilities c
                 JOIN users u ON u.id=c.user_id
                 WHERE c.token_hash=?1 AND c.purpose='initial_password' AND c.consumed_at IS NULL AND c.expires_at>?2",
                params![&token_hash[..], now_text],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let Some((user_id, role_text_value, auth_epoch)) = target else {
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
            transaction.commit()?;
            Ok(Principal {
                user_id: parse_uuid(user_id)?,
                role: parse_role(&role_text_value)?,
                auth_epoch: auth_epoch.max(0) as u64 + 1,
            })
            //--agent TASK-224
        }).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
    }

    //++agent TASK-224 [24.09.2026]
    fn find_pending_activation(
        &self,
        token_hash: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<Option<PendingActivation>, AuthError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT u.id,u.display_login,c.expires_at FROM activation_capabilities c
                 JOIN users u ON u.id=c.user_id
                 WHERE c.token_hash=?1 AND c.purpose='initial_password' AND c.consumed_at IS NULL
                   AND c.expires_at>?2 AND u.status='active' AND u.password_hash IS NULL",
                    params![&token_hash[..], now.to_rfc3339()],
                    |row| {
                        Ok(PendingActivation {
                            user_id: parse_uuid(row.get::<_, String>(0)?)?,
                            display_login: row.get(1)?,
                            expires_at: parse_time(row.get::<_, String>(2)?)?,
                        })
                    },
                )
                .optional()
        })
        .map_err(map_error)
    }

    fn reissue_activation(
        &self,
        user_id: Uuid,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let user = load_user_by_id(&transaction, user_id)?;
            //++agent TASK-224 [08.10.2026] итерация 4: disabled — отдельный
            // код USER_DISABLED, чтобы UI объяснил «сначала включите»,
            // а не generic conflict.
            if user.status == UserStatus::Disabled {
                return Err(disabled_user());
            }
            //--agent TASK-224
            // Перевыпуск только для «ожидает активации»: активный и без пароля.
            if user.status != UserStatus::Active || user.password_hash.is_some() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "UPDATE activation_capabilities SET consumed_at=?1 WHERE user_id=?2 AND consumed_at IS NULL",
                params![now, user_id.to_string()],
            )?;
            insert_capability(&transaction, &capability, &now)?;
            audit_user(&transaction, actor_id, "user.invitation", user_id, correlation_id, &now)?;
            transaction.commit()?;
            Ok(user)
        }).map_err(map_user_error)
    }

    fn reset_user_password(
        &self,
        user_id: Uuid,
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let user = load_user_by_id(&transaction, user_id)?;
            //++agent TASK-224 [08.10.2026] итерация 4
            if user.status == UserStatus::Disabled {
                return Err(disabled_user());
            }
            //--agent TASK-224
            // Сброс — только для уже активированных; ожидающим нужен reissue.
            if user.password_hash.is_none() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "UPDATE users SET password_hash=NULL,auth_epoch=auth_epoch+1,updated_at=?1 WHERE id=?2",
                params![now, user_id.to_string()],
            )?;
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
                params![now, user_id.to_string()],
            )?;
            transaction.execute(
                "UPDATE activation_capabilities SET consumed_at=?1 WHERE user_id=?2 AND consumed_at IS NULL",
                params![now, user_id.to_string()],
            )?;
            insert_capability(&transaction, &capability, &now)?;
            audit_user(&transaction, actor_id, "user.password_reset", user_id, correlation_id, &now)?;
            transaction.commit()?;
            Ok(user)
        }).map_err(map_user_error)
    }

    fn delete_user(
        &self,
        user_id: Uuid,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let user = load_user_by_id(&transaction, user_id)?;
            let had_sessions: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=?1)",
                [user_id.to_string()],
                |row| row.get(0),
            )?;
            // «Никогда не входивший» = без пароля и без хоть одной сессии.
            if user.password_hash.is_some() || had_sessions {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            if user.role == Role::Admin && user.status == UserStatus::Active {
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
            transaction.execute("DELETE FROM users WHERE id=?1", [user_id.to_string()])?;
            audit_user(
                &transaction,
                actor_id,
                "user.delete",
                user_id,
                correlation_id,
                &now,
            )?;
            transaction.commit()
        })
        .map_err(|error| {
            if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                AuthError::Conflict
            } else {
                map_error(error)
            }
        })
    }

    fn bootstrap_pending(&self) -> Result<bool, AuthError> {
        self.with_connection(|connection| {
            connection.query_row(
                "SELECT bootstrap_completed_at IS NULL FROM service_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
        })
        .map_err(map_error)
    }
    //--agent TASK-224

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

//++agent TASK-224 [24.09.2026]
/// Загрузка по PK внутри транзакции; отсутствие записи → QueryReturnedNoRows,
/// что вызывающий код единообразно сводит к Conflict.
fn load_user_by_id(
    connection: &rusqlite::Connection,
    user_id: Uuid,
) -> rusqlite::Result<UserAccount> {
    connection.query_row(
        "SELECT id,normalized_login,display_login,password_hash,role,status,auth_epoch FROM users WHERE id=?1",
        [user_id.to_string()],
        read_user,
    )
}

/// Постановка пригласительной capability — общая для create/reissue/reset.
fn insert_capability(
    connection: &rusqlite::Connection,
    capability: &ActivationCapability,
    now: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO activation_capabilities(id,token_hash,user_id,purpose,expires_at,consumed_at,created_at)
         VALUES (?1,?2,?3,'initial_password',?4,NULL,?5)",
        params![
            Uuid::new_v4().to_string(),
            &capability.token_hash[..],
            capability.user_id.to_string(),
            capability.expires_at.to_rfc3339(),
            now
        ],
    )?;
    Ok(())
}

/// Аудит админ-мутации пользователя без секретов: только id цели.
fn audit_user(
    connection: &rusqlite::Connection,
    actor_id: Uuid,
    action: &str,
    target_user_id: Uuid,
    correlation_id: Uuid,
    now: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,correlation_id,created_at)
         VALUES ('human',?1,?2,'success',?3,?4,?5)",
        params![
            actor_id.to_string(),
            action,
            format!("target_user_id={target_user_id}"),
            correlation_id.to_string(),
            now
        ],
    )?;
    Ok(())
}
//--agent TASK-224

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
//++agent TASK-224 [08.10.2026] итерация 4
/// Маркер «пользователь отключён» внутри rusqlite-транзакции: статус
/// проверяется на момент commit, а до AuthError добираемся через downcast.
#[derive(Debug)]
struct UserDisabledMarker;
impl std::fmt::Display for UserDisabledMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("user disabled")
    }
}
impl std::error::Error for UserDisabledMarker {}

fn disabled_user() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(UserDisabledMarker))
}

fn is_disabled_user(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::ToSqlConversionFailure(e) if e.is::<UserDisabledMarker>())
}

/// Маппинг для мутаций, различающих «отключён» от прочего конфликта
/// (reissue/reset): disabled → USER_DISABLED, нет строки → Conflict.
fn map_user_error(error: rusqlite::Error) -> AuthError {
    if is_disabled_user(&error) {
        AuthError::UserDisabled
    } else if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
        AuthError::Conflict
    } else {
        map_error(error)
    }
}
//--agent TASK-224
fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(inner, _) if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE || inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}
