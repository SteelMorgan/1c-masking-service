use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::storage::SqliteStorage;

use super::{
    ActivationCapability, AuthError, AuthStore, DatabaseScope, NewSession, PendingActivation,
    Principal, Role, SessionRecord, UserAccount, UserListEntry, UserStatus,
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
                        database_ids: Vec::new(),
                    })
                })?
                .collect::<rusqlite::Result<Vec<UserListEntry>>>();
            let mut rows = rows?;
            // Выданные базы одним запросом — не N+1 по пользователям.
            let mut access = connection.prepare(
                "SELECT user_id,database_id FROM user_database_access ORDER BY database_id",
            )?;
            let grants = access.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for grant in grants {
                let (user_id, database_id) = grant?;
                if let Some(entry) = rows
                    .iter_mut()
                    .find(|entry| entry.account.id.to_string() == user_id)
                {
                    entry.database_ids.push(parse_uuid(database_id)?);
                }
            }
            Ok(rows)
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
                 WHERE normalized_login='admin' AND role='SuperAdmin' AND status='active' AND password_hash IS NULL",
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
        database_ids: &[Uuid],
        capability: ActivationCapability,
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<UserAccount, AuthError> {
        self.with_connection(|connection| {
            // Защита в глубину (проверка есть и в провайдере): у SuperAdmin
            // хранимого набора нет — переданные строки стали бы мёртвыми
            // грантами, которые «оживут» при последующем понижении роли.
            if role == Role::SuperAdmin && !database_ids.is_empty() {
                return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                    SuperAdminScopeMarker,
                )));
            }
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
            // Стартовый набор баз — в той же транзакции: состояния
            // «Admin без баз» на проводе не возникает.
            insert_access_grants(
                &transaction,
                capability.user_id,
                database_ids,
                actor_id,
                correlation_id,
                &now,
            )?;
            let audit_code = format!(
                "target_user_id={};role={};status=active",
                capability.user_id,
                role_text(role)
            );
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,target_user_id,correlation_id,created_at)
                 VALUES ('human',?1,'user.create','success',?2,?3,?4,?5)",
                params![actor_id.to_string(), audit_code, capability.user_id.to_string(), correlation_id.to_string(), now],
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
        }).map_err(|error| if is_constraint(&error) { AuthError::Conflict } else if is_unknown_database(&error) { AuthError::UnknownDatabase } else if is_superadmin_scope(&error) { AuthError::SuperAdminScope } else { map_error(error) })
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
            let user = load_user_by_id(&transaction, user_id)
                .map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { user_not_found() } else { error })?;
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
            let user = load_user_by_id(&transaction, user_id)
                .map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { user_not_found() } else { error })?;
            //++agent TASK-224 [08.10.2026] итерация 4
            if user.status == UserStatus::Disabled {
                return Err(disabled_user());
            }
            //--agent TASK-224
            // Сброс — только для уже активированных; ожидающим нужен reissue.
            if user.password_hash.is_none() {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            // Инвариант «последний функциональный SuperAdmin»: сброс
            // обнуляет пароль и гасит сессии — цель перестаёт быть
            // входоспособной до активации по одноразовому токену.
            // Если других входоспособных SuperAdmin нет, управление
            // теряется — блокируем как понижение/удаление.
            if user.role == Role::SuperAdmin {
                let functional: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM users
                     WHERE role='SuperAdmin' AND status='active' AND password_hash IS NOT NULL",
                    [],
                    |row| row.get(0),
                )?;
                if functional <= 1 {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
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
            let user = load_user_by_id(&transaction, user_id)
                .map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { user_not_found() } else { error })?;
            let had_sessions: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=?1)",
                [user_id.to_string()],
                |row| row.get(0),
            )?;
            // «Никогда не входивший» = без пароля и без хоть одной сессии.
            if user.password_hash.is_some() || had_sessions {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            // Инвариант последнего SuperAdmin здесь не проверяется: к этой
            // точке цель гарантированно без пароля, то есть невходоспособна —
            // её удаление счёт функциональных администраторов не меняет.
            let now = Utc::now().to_rfc3339();
            // Гранты уходят FK-каскадом — фиксируем revoke явно, иначе
            // в аудит-следе остаётся только «пользователь удалён».
            {
                let mut statement = transaction.prepare(
                    "SELECT database_id FROM user_database_access WHERE user_id=?1 ORDER BY database_id",
                )?;
                let granted: Vec<String> = statement
                    .query_map([user_id.to_string()], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                drop(statement);
                for database_id in granted {
                    transaction.execute(
                        "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,target_user_id,correlation_id,created_at)
                         VALUES ('human',?1,'access.revoke',?2,'success',?3,?4,?5)",
                        params![
                            actor_id.to_string(),
                            database_id,
                            user_id.to_string(),
                            correlation_id.to_string(),
                            now
                        ],
                    )?;
                }
            }
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
            if is_user_not_found(&error) {
                AuthError::NotFound
            } else if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
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

    fn list_database_access(&self, user_id: Uuid) -> Result<Vec<Uuid>, AuthError> {
        self.with_connection(|connection| {
            // Отсутствие пользователя отличаем от пустого набора —
            // иначе GET на удалённый id выглядел бы как «нет доступов».
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1)",
                [user_id.to_string()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let mut statement = connection.prepare(
                "SELECT database_id FROM user_database_access WHERE user_id=?1 ORDER BY database_id",
            )?;
            let rows = statement.query_map([user_id.to_string()], |row| {
                let value: String = row.get(0)?;
                parse_uuid(value)
            })?;
            rows.collect()
        })
        .map_err(|error| {
            if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                AuthError::NotFound
            } else {
                map_error(error)
            }
        })
    }

    fn set_database_access(
        &self,
        user_id: Uuid,
        database_ids: &[Uuid],
        actor_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<(), AuthError> {
        self.with_connection(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let user = load_user_by_id(&transaction, user_id)
                .map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { user_not_found() } else { error })?;
            // У SuperAdmin набора нет: «все базы» неявно и не снимается —
            // явная запись выглядела бы как ограничение, которым не является.
            if user.role == Role::SuperAdmin {
                return Err(superadmin_scope());
            }
            let mut statement = transaction.prepare(
                "SELECT database_id FROM user_database_access WHERE user_id=?1",
            )?;
            let current: std::collections::BTreeSet<String> = statement
                .query_map([user_id.to_string()], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);
            // BTreeSet — детерминированный порядок grant/revoke в аудите:
            // журнал читается людьми, недетерминированный порядок — шум.
            let wanted: std::collections::BTreeSet<String> = database_ids
                .iter()
                .map(Uuid::to_string)
                .collect();
            let now = Utc::now().to_rfc3339();
            for database_id in current.difference(&wanted) {
                transaction.execute(
                    "DELETE FROM user_database_access WHERE user_id=?1 AND database_id=?2",
                    params![user_id.to_string(), database_id],
                )?;
                transaction.execute(
                    "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,target_user_id,correlation_id,created_at)
                     VALUES ('human',?1,'access.revoke',?2,'success',?3,?4,?5)",
                    params![actor_id.to_string(), database_id, user_id.to_string(), correlation_id.to_string(), now],
                )?;
            }
            for database_id in wanted.difference(&current) {
                let exists: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM databases WHERE id=?1)",
                    [database_id],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(unknown_database());
                }
                transaction.execute(
                    "INSERT INTO user_database_access(user_id,database_id,granted_by,granted_at) VALUES (?1,?2,?3,?4)",
                    params![user_id.to_string(), database_id, actor_id.to_string(), now],
                )?;
                transaction.execute(
                    "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,target_user_id,correlation_id,created_at)
                     VALUES ('human',?1,'access.grant',?2,'success',?3,?4,?5)",
                    params![actor_id.to_string(), database_id, user_id.to_string(), correlation_id.to_string(), now],
                )?;
            }
            transaction.commit()
        })
        .map_err(|error| {
            if is_user_not_found(&error) {
                AuthError::NotFound
            } else if is_unknown_database(&error) {
                AuthError::UnknownDatabase
            } else if is_superadmin_scope(&error) {
                AuthError::SuperAdminScope
            } else if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                AuthError::NotFound
            } else {
                map_error(error)
            }
        })
    }

    fn accessible_databases(&self, principal: &Principal) -> Result<DatabaseScope, AuthError> {
        if principal.role == Role::SuperAdmin {
            return Ok(DatabaseScope::All);
        }
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT database_id FROM user_database_access WHERE user_id=?1",
            )?;
            let rows = statement.query_map([principal.user_id.to_string()], |row| {
                let value: String = row.get(0)?;
                parse_uuid(value)
            })?;
            rows.collect::<rusqlite::Result<std::collections::HashSet<Uuid>>>()
                .map(DatabaseScope::Only)
        })
        .map_err(map_error)
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
            let target: Option<(String, String, bool)> = transaction.query_row(
                "SELECT role,status,password_hash IS NOT NULL FROM users WHERE id=?1",
                [user_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let Some((old_role, old_status, old_has_password)) = target else {
                return Err(user_not_found());
            };
            // Инвариант «последний функциональный SuperAdmin» — понижение и
            // отключение блокируются, иначе теряется управление доступами.
            // Считаются только входоспособные (с паролем): ожидающий
            // активации инвариант реально не удерживает — и сам не является
            // его опорой, поэтому гард на pending-цель не распространяется.
            let target_is_active_super =
                old_role == "SuperAdmin" && old_status == "active" && old_has_password;
            if target_is_active_super
                && (role != Role::SuperAdmin || status != UserStatus::Active)
            {
                let active_admins: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM users
                     WHERE role='SuperAdmin' AND status='active' AND password_hash IS NOT NULL",
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
            // У SuperAdmin хранимого набора нет (доступ ко всем базам
            // неявный) — строки доступа снимаются, чтобы после понижения
            // не воскрес устаревший контур; снятие аудируется revoke.
            if role == Role::SuperAdmin {
                let mut statement = transaction.prepare(
                    "SELECT database_id FROM user_database_access WHERE user_id=?1 ORDER BY database_id",
                )?;
                let granted: Vec<String> = statement
                    .query_map([user_id.to_string()], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                drop(statement);
                transaction.execute(
                    "DELETE FROM user_database_access WHERE user_id=?1",
                    [user_id.to_string()],
                )?;
                for database_id in granted {
                    transaction.execute(
                        "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,target_user_id,correlation_id,created_at)
                         VALUES ('human',?1,'access.revoke',?2,'success',?3,?4,?5)",
                        params![
                            actor_id.to_string(),
                            database_id,
                            user_id.to_string(),
                            correlation_id.to_string(),
                            now
                        ],
                    )?;
                }
            }
            transaction.execute(
                "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
                params![now, user_id.to_string()],
            )?;
            // target_user_id — отдельной колонкой (миграция 0017) и первым
            // полем code для совместимости с существующими потребителями.
            let audit_code = format!(
                "target_user_id={};role={};status={}",
                user_id,
                role_text(role),
                status_text(status)
            );
            transaction.execute(
                "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,target_user_id,correlation_id,created_at)
                 VALUES ('human',?1,'user.update','success',?2,?3,?4,?5)",
                params![actor_id.to_string(), audit_code, user_id.to_string(), correlation_id.to_string(), now],
            )?;
            transaction.commit()
        }).map_err(|error| if is_user_not_found(&error) { AuthError::NotFound } else if matches!(error, rusqlite::Error::QueryReturnedNoRows) { AuthError::Conflict } else { map_error(error) })
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

/// Аудит админ-мутации пользователя без секретов: id цели — и префиксом
/// free-form code (совместимость со старыми потребителями журнала), и
/// отдельной колонкой target_user_id (миграция 0017).
fn audit_user(
    connection: &rusqlite::Connection,
    actor_id: Uuid,
    action: &str,
    target_user_id: Uuid,
    correlation_id: Uuid,
    now: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO audit_events(actor_kind,actor_id,action,outcome,code,target_user_id,correlation_id,created_at)
         VALUES ('human',?1,?2,'success',?3,?4,?5,?6)",
        params![
            actor_id.to_string(),
            action,
            format!("target_user_id={target_user_id}"),
            target_user_id.to_string(),
            correlation_id.to_string(),
            now
        ],
    )?;
    Ok(())
}
//--agent TASK-224

/// Проверка существования баз и вставка строк доступа с аудитом
/// `access.grant` на каждую пару — общая для create_user и set_access.
/// Несуществующий database_id — marker-ошибка, сводится к UnknownDatabase.
fn insert_access_grants(
    connection: &rusqlite::Connection,
    user_id: Uuid,
    database_ids: &[Uuid],
    actor_id: Uuid,
    correlation_id: Uuid,
    now: &str,
) -> rusqlite::Result<()> {
    // Дедупликация до вставки: POST /admin/users с повторным id не должен
    // отличаться от PUT …/databases (там набор — Set); BTreeSet заодно даёт
    // детерминированный порядок audit-строк.
    let unique: std::collections::BTreeSet<Uuid> = database_ids.iter().copied().collect();
    for database_id in unique {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM databases WHERE id=?1)",
            [database_id.to_string()],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(unknown_database());
        }
        connection.execute(
            "INSERT INTO user_database_access(user_id,database_id,granted_by,granted_at) VALUES (?1,?2,?3,?4)",
            params![user_id.to_string(), database_id.to_string(), actor_id.to_string(), now],
        )?;
        connection.execute(
            "INSERT INTO audit_events(actor_kind,actor_id,action,database_id,outcome,target_user_id,correlation_id,created_at)
             VALUES ('human',?1,'access.grant',?2,'success',?3,?4,?5)",
            params![actor_id.to_string(), database_id.to_string(), user_id.to_string(), correlation_id.to_string(), now],
        )?;
    }
    Ok(())
}

/// Маркер «несуществующий database_id» внутри транзакции — по аналогии
/// с UserDisabledMarker: до AuthError добираемся через downcast.
#[derive(Debug)]
struct UnknownDatabaseMarker;
impl std::fmt::Display for UnknownDatabaseMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown database id")
    }
}
impl std::error::Error for UnknownDatabaseMarker {}

fn unknown_database() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(UnknownDatabaseMarker))
}

fn is_unknown_database(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::ToSqlConversionFailure(e) if e.is::<UnknownDatabaseMarker>())
}

/// Маркер «пользователь не найден» внутри транзакции — отличает промах
/// по id от конфликта инварианта (оба раньше сводились к 409).
#[derive(Debug)]
struct UserNotFoundMarker;
impl std::fmt::Display for UserNotFoundMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("user not found")
    }
}
impl std::error::Error for UserNotFoundMarker {}

fn user_not_found() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(UserNotFoundMarker))
}

fn is_user_not_found(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::ToSqlConversionFailure(e) if e.is::<UserNotFoundMarker>())
}

/// Маркер «цель — SuperAdmin» внутри транзакции: доступ ему не назначается.
#[derive(Debug)]
struct SuperAdminScopeMarker;
impl std::fmt::Display for SuperAdminScopeMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("super admin scope is implicit")
    }
}
impl std::error::Error for SuperAdminScopeMarker {}

fn superadmin_scope() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(SuperAdminScopeMarker))
}

fn is_superadmin_scope(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::ToSqlConversionFailure(e) if e.is::<SuperAdminScopeMarker>())
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
        Role::SuperAdmin => "SuperAdmin",
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
        "SuperAdmin" => Ok(Role::SuperAdmin),
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
    if is_user_not_found(&error) {
        AuthError::NotFound
    } else if is_disabled_user(&error) {
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
