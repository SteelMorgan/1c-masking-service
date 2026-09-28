mod common;
use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use onec_masking_service::{
    api::human::{
        self, CreatePolicyRequest, DictionaryConfig, DictionarySelectorConfig, HumanDataError,
        HumanDataStore, HumanState, PolicyRuleInput, SqliteHumanDataStore, ToolClassificationPatch,
    },
    auth::{
        AuthProvider, AuthStore, ChangePasswordError, LocalAuthProvider, LoginError, Role,
        SessionService, UserStatus,
    },
    domain::{ErrorCode, MaskingService, PreflightRequest, SCHEMA_VERSION},
    SqliteStorage,
};
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://masking.test";
const ADMIN_PASSWORD: &str = "correct horse battery staple";
const VIEWER_PASSWORD: &str = "viewer passphrase is unique";
const CHANGED_ADMIN_PASSWORD: &str = "new correct horse battery staple";
const CHANGED_VIEWER_PASSWORD: &str = "new viewer passphrase is unique";

fn auth_fixture() -> (
    Arc<SqliteStorage>,
    Arc<LocalAuthProvider>,
    Arc<SessionService>,
) {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let store: Arc<dyn AuthStore> = storage.clone();
    let auth = Arc::new(LocalAuthProvider::new(store.clone()).unwrap());
    let sessions = Arc::new(SessionService::new(store));
    (storage, auth, sessions)
}

#[test]
fn initial_admin_cannot_login_until_one_time_bootstrap() {
    let (storage, auth, _) = auth_fixture();
    let admin = auth.initialize().unwrap();
    assert_eq!(admin.display_login, "Admin");
    assert_eq!(admin.role, Role::SuperAdmin);
    assert!(admin.password_hash.is_none());
    assert!(matches!(
        auth.authenticate("test", "Admin", ""),
        Err(LoginError::Rejected)
    ));

    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    assert!(auth
        .bootstrap_admin_password("another long password")
        .is_err());
    let principal = auth
        .authenticate("new-source", "admin", ADMIN_PASSWORD)
        .unwrap();
    assert_eq!(principal.role, Role::SuperAdmin);

    let (phc, bootstrap_completed): (String, Option<String>) = storage
        .with_connection(|connection| {
            let hash = connection.query_row(
                "SELECT password_hash FROM users WHERE normalized_login='admin'",
                [],
                |row| row.get(0),
            )?;
            let completed = connection.query_row(
                "SELECT bootstrap_completed_at FROM service_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            Ok((hash, completed))
        })
        .unwrap();
    assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    assert!(!phc.contains(ADMIN_PASSWORD));
    assert!(bootstrap_completed.is_some());
}

#[test]
fn activation_is_hashed_single_use_and_user_sets_own_password() {
    let (storage, auth, _) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("activation-admin", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (viewer, token) = auth
        .create_user(&admin, "Viewer One", Role::Viewer, &[], Uuid::new_v4())
        .unwrap();
    assert!(matches!(
        auth.authenticate("before-activation", "viewer one", VIEWER_PASSWORD),
        Err(LoginError::Rejected)
    ));

    let stored_token: Vec<u8> = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT token_hash FROM activation_capabilities WHERE user_id=?1",
                [viewer.id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_ne!(stored_token, token.as_bytes());
    assert_eq!(stored_token.len(), 32);

    auth.activate("test", &token, VIEWER_PASSWORD).unwrap();
    assert!(auth
        .activate("test", &token, "replacement password value")
        .is_err());
    let principal = auth
        .authenticate("after-activation", "VIEWER ONE", VIEWER_PASSWORD)
        .unwrap();
    assert_eq!(principal.role, Role::Viewer);
}

#[test]
fn csrf_epoch_and_revocation_protect_sessions() {
    let (_, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let principal = auth
        .authenticate("session-source", "admin", ADMIN_PASSWORD)
        .unwrap();
    let issued = sessions.issue(principal.clone(), Utc::now()).unwrap();

    assert!(sessions
        .validate(&issued.token, Some("wrong-csrf"), Utc::now())
        .is_err());
    assert!(sessions
        .validate(&issued.token, Some(&issued.csrf_token), Utc::now())
        .is_ok());
    // A role/status mutation increments auth_epoch and revokes every existing session.
    // The only active Admin cannot be demoted or disabled, preventing lockout.
    assert!(auth
        .update_user_access(
            &principal,
            principal.user_id,
            Role::Viewer,
            UserStatus::Active,
            Uuid::new_v4(),
        )
        .is_err());
    sessions.revoke(&issued.token, Utc::now()).unwrap();
    assert!(sessions.validate(&issued.token, None, Utc::now()).is_err());
}

#[test]
fn repeated_password_change_failures_are_rate_limited_without_changing_credentials() {
    let (_, auth, _) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let principal = auth
        .authenticate("rate-limit-login", "admin", ADMIN_PASSWORD)
        .unwrap();

    for _ in 0..5 {
        assert!(matches!(
            auth.change_password(
                "rate-limit-test",
                &principal,
                "deliberately wrong current password",
                CHANGED_ADMIN_PASSWORD,
                Uuid::new_v4(),
            ),
            Err(ChangePasswordError::Rejected)
        ));
    }
    assert!(matches!(
        auth.change_password(
            "rate-limit-test",
            &principal,
            "deliberately wrong current password",
            CHANGED_ADMIN_PASSWORD,
            Uuid::new_v4(),
        ),
        Err(ChangePasswordError::RateLimited)
    ));
    assert!(auth
        .authenticate("rate-limit-after", "admin", ADMIN_PASSWORD)
        .is_ok());
}

#[tokio::test]
async fn roles_are_checked_server_side_for_reveal_and_admin_routes() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("admin-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let admin_session = sessions.issue(admin.clone(), Utc::now()).unwrap();

    let (_, activation) = auth
        .create_user(&admin, "viewer", Role::Viewer, &[], Uuid::new_v4())
        .unwrap();
    auth.activate("test", &activation, VIEWER_PASSWORD).unwrap();
    let viewer = auth
        .authenticate("viewer-api", "viewer", VIEWER_PASSWORD)
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();

    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));

    let reveal = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/history/{}/reveal", Uuid::new_v4()))
        .header("origin", ORIGIN)
        .header(
            "cookie",
            format!("__Host-mask_session={}", admin_session.token),
        )
        .header("x-csrf-token", admin_session.csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(reveal).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let admin_list = Request::builder()
        .uri("/api/v1/admin/users")
        .header(
            "cookie",
            format!("__Host-mask_session={}", viewer_session.token),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(admin_list).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn admin_user_create_and_access_update_are_audited_without_secrets() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("admin-user-audit", "admin", ADMIN_PASSWORD)
        .unwrap();
    let admin_session = sessions.issue(admin.clone(), Utc::now()).unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));

    let create = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/users")
        .header("origin", ORIGIN)
        .header(
            "cookie",
            format!("__Host-mask_session={}", admin_session.token),
        )
        .header("x-csrf-token", &admin_session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"login":"audit-viewer","role":"Viewer"}).to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = Uuid::parse_str(created["user_id"].as_str().unwrap()).unwrap();
    let activation_token = created["activation_token"].as_str().unwrap();

    let update = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/admin/users/{user_id}"))
        .header("origin", ORIGIN)
        .header(
            "cookie",
            format!("__Host-mask_session={}", admin_session.token),
        )
        .header("x-csrf-token", &admin_session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"role":"Admin","status":"disabled"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(update).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let audit_rows: Vec<(String, String, String, String, String, String)> = storage
        .with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT action,actor_id,outcome,code,correlation_id,created_at
                 FROM audit_events WHERE action IN ('user.create','user.update') ORDER BY id",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect();
            rows
        })
        .unwrap();
    assert_eq!(audit_rows.len(), 2);
    assert_eq!(audit_rows[0].0, "user.create");
    assert_eq!(audit_rows[1].0, "user.update");
    assert!(audit_rows
        .iter()
        .all(|row| row.1 == admin.user_id.to_string() && row.2 == "success"));
    assert_eq!(
        audit_rows[0].3,
        format!("target_user_id={user_id};role=Viewer;status=active")
    );
    assert_eq!(
        audit_rows[1].3,
        format!("target_user_id={user_id};role=Admin;status=disabled")
    );
    for row in &audit_rows {
        Uuid::parse_str(&row.4).unwrap();
        chrono::DateTime::parse_from_rfc3339(&row.5).unwrap();
    }
    let serialized_audit = serde_json::to_string(&audit_rows).unwrap();
    assert!(!serialized_audit.contains("audit-viewer"));
    assert!(!serialized_audit.contains(activation_token));
    assert!(!serialized_audit.contains(ADMIN_PASSWORD));
}

#[tokio::test]
async fn admin_and_viewer_can_change_own_password_and_rotate_all_sessions() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("password-setup-admin", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin, "viewer", Role::Viewer, &[], Uuid::new_v4())
        .unwrap();
    auth.activate("test", &activation, VIEWER_PASSWORD).unwrap();

    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking));
    let app = human::router(Arc::new(HumanState {
        auth: auth.clone(),
        sessions: sessions.clone(),
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));

    for (login, old_password, new_password) in [
        ("admin", ADMIN_PASSWORD, CHANGED_ADMIN_PASSWORD),
        ("viewer", VIEWER_PASSWORD, CHANGED_VIEWER_PASSWORD),
    ] {
        let principal = auth
            .authenticate(&format!("change-{login}"), login, old_password)
            .unwrap();
        let current = sessions.issue(principal.clone(), Utc::now()).unwrap();
        let other = sessions.issue(principal, Utc::now()).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("origin", ORIGIN)
            .header("cookie", format!("__Host-mask_session={}", current.token))
            .header("x-csrf-token", current.csrf_token)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "current_password": old_password,
                    "new_password": new_password,
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rotated_cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(session["csrf_token"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));

        assert!(sessions.validate(&current.token, None, Utc::now()).is_err());
        assert!(sessions.validate(&other.token, None, Utc::now()).is_err());
        assert!(matches!(
            auth.authenticate(&format!("old-{login}"), login, old_password),
            Err(LoginError::Rejected)
        ));
        assert!(auth
            .authenticate(&format!("new-{login}"), login, new_password)
            .is_ok());

        let current_session = Request::builder()
            .uri("/api/v1/session")
            .header("cookie", rotated_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(current_session).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let password_audit_count: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE actor_kind='human' AND action='password_change' AND outcome='success'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(password_audit_count, 2);
}

#[tokio::test]
async fn password_change_requires_origin_csrf_current_password_and_strong_distinct_password() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let principal = auth
        .authenticate("change-validation", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(principal, Utc::now()).unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    let app = human::router(Arc::new(HumanState {
        auth: auth.clone(),
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));

    for (origin, csrf, current_password, new_password, expected) in [
        (
            "https://wrong-origin.test",
            session.csrf_token.as_str(),
            ADMIN_PASSWORD,
            CHANGED_ADMIN_PASSWORD,
            StatusCode::FORBIDDEN,
        ),
        (
            ORIGIN,
            "wrong-csrf",
            ADMIN_PASSWORD,
            CHANGED_ADMIN_PASSWORD,
            StatusCode::UNAUTHORIZED,
        ),
        (
            ORIGIN,
            session.csrf_token.as_str(),
            "wrong current password",
            CHANGED_ADMIN_PASSWORD,
            StatusCode::UNAUTHORIZED,
        ),
        (
            ORIGIN,
            session.csrf_token.as_str(),
            ADMIN_PASSWORD,
            "too short",
            StatusCode::BAD_REQUEST,
        ),
        (
            ORIGIN,
            session.csrf_token.as_str(),
            ADMIN_PASSWORD,
            ADMIN_PASSWORD,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/session/password")
            .header("origin", origin)
            .header("cookie", format!("__Host-mask_session={}", session.token))
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "current_password": current_password,
                    "new_password": new_password,
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }

    assert!(auth
        .authenticate("unchanged", "admin", ADMIN_PASSWORD)
        .is_ok());
}

#[tokio::test]
async fn admin_configuration_is_typed_validated_and_audited() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = SqliteHumanDataStore::new(storage.clone(), masking);
    let actor = onec_masking_service::auth::Principal {
        user_id: Uuid::new_v4(),
        role: Role::Admin,
        auth_epoch: 1,
    };

    data.update_tool_classification(
        &actor,
        database_id,
        "execute_query",
        ToolClassificationPatch {
            class: "data-mask".into(),
            confirm_bypass: false,
        },
        Uuid::new_v4(),
    )
    .unwrap();
    assert!(data
        .update_tool_classification(
            &actor,
            database_id,
            "unsafe_tool",
            ToolClassificationPatch {
                class: "allow-all".into(),
                confirm_bypass: false,
            },
            Uuid::new_v4(),
        )
        .is_err());

    let policy = data
        .create_policy(
            &actor,
            database_id,
            CreatePolicyRequest {
                rules: vec![PolicyRuleInput {
                    selector_kind: "regex".into(),
                    selector_value: "Иванов".into(),
                    action: "mask".into(),
                    category: "FIO".into(),
                    priority: 10,

                    rule_id: None,
                }],
            },
            Uuid::new_v4(),
        )
        .unwrap();
    data.activate_policy(&actor, database_id, policy.id, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(data.list_policies(database_id).unwrap()[0].status, "active");

    let dictionary = DictionaryConfig {
        id: Uuid::new_v4(),
        mode: "part".into(),
        selectors: vec![DictionarySelectorConfig {
            source_path: "Справочник.Контрагенты.Наименование".into(),
            category: "FIO".into(),
            filter_ast: Some(
                serde_json::json!({"op":"eq","field":"ПометкаУдаления","value":false}),
            ),
        }],
    };
    //++agent TASK-225 [26.09.2026] M-4: legacy PUT dictionaries пишет в
    // черновик-копию активной (draft_version в ответе) — активная
    // версия при этом не меняется (§4 legacy-маршруты).
    let draft_version = data
        .put_dictionary_config(&actor, database_id, dictionary, Uuid::new_v4())
        .unwrap();
    assert!(draft_version >= 1);
    let persisted_json: String = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT dictionary_json FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(persisted_json.contains("\"category\":\"FIO\""));

    let too_many = DictionaryConfig {
        id: Uuid::new_v4(),
        mode: "part".into(),
        selectors: (0..101)
            .map(|index| DictionarySelectorConfig {
                source_path: format!("Catalog.Item.Field{index}"),
                category: "FIO".into(),
                filter_ast: None,
            })
            .collect(),
    };
    assert!(data
        .put_dictionary_config(&actor, database_id, too_many, Uuid::new_v4())
        .is_err());

    let audit_count: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE actor_kind='human' AND actor_id=?1",
                [actor.user_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(audit_count >= 3);
}

#[tokio::test]
async fn activating_policy_before_first_pull_does_not_make_enabled_database_ready() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    storage
        .set_database_mode(
            database_id,
            onec_masking_service::domain::DatabaseMode::Enabled,
        )
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = SqliteHumanDataStore::new(storage, masking.clone());
    let actor = onec_masking_service::auth::Principal {
        user_id: Uuid::new_v4(),
        role: Role::Admin,
        auth_epoch: 1,
    };
    let policy = data
        .create_policy(
            &actor,
            database_id,
            CreatePolicyRequest {
                rules: vec![PolicyRuleInput {
                    selector_kind: "name".into(),
                    selector_value: "ФИО".into(),
                    action: "mask".into(),
                    category: "FIO".into(),
                    priority: 10,

                    rule_id: None,
                }],
            },
            Uuid::new_v4(),
        )
        .unwrap();
    data.activate_policy(&actor, database_id, policy.id, Uuid::new_v4())
        .await
        .unwrap();

    assert!(!masking.database_ready(database_id).await);
    let error = masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            identity: common::test_identity(database_id),
            caller: Some("policy-before-pull".to_owned()),
            tool_name: "execute_query".to_owned(),
            arguments: serde_json::json!({"query":"SELECT 1"}),
        })
        .await
        .unwrap_err();
    //++agent TASK-225 [26.09.2026] фаза-2 C: снимка ещё нет и pull
    // запланирован — это прогрев (SERVICE_WARMING_UP + retry_after_s),
    // а не безликий SERVICE_NOT_READY.
    assert_eq!(error.code, ErrorCode::ServiceWarmingUp);
    assert!(error.retry_after_s.unwrap_or(0) >= 5);
    //++agent TASK-225
}

//++agent TASK-221 2026-09-23
#[tokio::test]
async fn configurable_secret_rules_cannot_be_activated_without_premanager_policy() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    //++agent TASK-225 [26.09.2026] storage нужен в цикле для ensure_database.
    //++agent TASK-225
    let data = SqliteHumanDataStore::new(storage.clone(), masking);
    let actor = onec_masking_service::auth::Principal {
        user_id: Uuid::new_v4(),
        role: Role::Admin,
        auth_epoch: 1,
    };
    for (selector_kind, selector_value) in [
        ("source_path", "Catalog.Person.Secret"),
        ("name", "Secret"),
        ("type", "String"),
        ("dictionary", "FIO"),
        ("regex", "synthetic-secret"),
    ] {
        //++agent TASK-225 [26.09.2026]
        // §2.2: максимум один draft на базу — каждая итерация получает
        // свою базу (раньше тест складывал пять черновиков в одну).
        //++agent TASK-225
        let database_id = Uuid::new_v4();
        storage
            .insert_database(database_id, &common::test_identity(database_id))
            .unwrap();
        let policy = data
            .create_policy(
                &actor,
                database_id,
                CreatePolicyRequest {
                    rules: vec![PolicyRuleInput {
                        selector_kind: selector_kind.into(),
                        selector_value: selector_value.into(),
                        action: "secret".into(),
                        category: "SECRET".into(),
                        priority: 1,

                        rule_id: None,
                    }],
                },
                Uuid::new_v4(),
            )
            .unwrap();
        assert!(matches!(
            data.activate_policy(&actor, database_id, policy.id, Uuid::new_v4())
                .await,
            Err(HumanDataError::SecretPolicyUnsupported)
        ));
        assert_eq!(
            data.list_policies(database_id)
                .unwrap()
                .iter()
                .find(|item| item.id == policy.id)
                .unwrap()
                .status,
            "draft"
        );
    }
}

#[tokio::test]
async fn secret_policy_activation_http_returns_stable_conflict_code() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let actor = auth
        .authenticate("synthetic-policy-admin", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(actor.clone(), Utc::now()).unwrap();
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    let policy = data
        .create_policy(
            &actor,
            database_id,
            CreatePolicyRequest {
                rules: vec![PolicyRuleInput {
                    selector_kind: "regex".into(),
                    selector_value: "synthetic-pattern".into(),
                    action: "secret".into(),
                    category: "SECRET".into(),
                    priority: 1,

                    rule_id: None,
                }],
            },
            Uuid::new_v4(),
        )
        .unwrap();
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/databases/{database_id}/policies/{}/activate",
            policy.id
        ))
        .header("origin", ORIGIN)
        .header("cookie", format!("__Host-mask_session={}", session.token))
        .header("x-csrf-token", &session.csrf_token)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"]["code"], "SECRET_POLICY_UNSUPPORTED");
}
//--agent TASK-221

//++agent TASK-224 [24.09.2026]
// Тесты доработок Б1-Б12 редизайна UI.

fn test_app(
    storage: Arc<SqliteStorage>,
    auth: Arc<LocalAuthProvider>,
    sessions: Arc<SessionService>,
) -> axum::Router {
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }))
}

fn session_cookie_header(token: &str) -> String {
    format!("__Host-mask_session={token}")
}

fn json_post(
    uri: &str,
    session: &onec_masking_service::auth::IssuedSession,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn json_get(uri: &str, session: &onec_masking_service::auth::IssuedSession) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("cookie", session_cookie_header(&session.token))
        .body(Body::empty())
        .unwrap()
}

async fn admin_session() -> (
    Arc<SqliteStorage>,
    Arc<LocalAuthProvider>,
    Arc<SessionService>,
    axum::Router,
    onec_masking_service::auth::IssuedSession,
) {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("admin-224", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(admin, Utc::now()).unwrap();
    let app = test_app(storage.clone(), auth.clone(), sessions.clone());
    (storage, auth, sessions, app, session)
}

/// Б1+Б2+Б3+Б4: перевыпуск гасит старый код, предпроверка показывает логин,
/// сервер собирает ссылку, активация сразу выдаёт сессию.
#[tokio::test]
async fn invitation_reissue_precheck_url_and_auto_login() {
    let (_, auth, _, app, admin) = admin_session().await;

    let create = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"invite-viewer","role":"Viewer"}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = created["user_id"].as_str().unwrap().to_owned();
    let token = created["activation_token"].as_str().unwrap().to_owned();
    // Б4: сервер собирает каноническую ссылку из expected_origin.
    assert_eq!(
        created["activation_url"].as_str().unwrap(),
        format!("{ORIGIN}/activate/{token}")
    );

    // Б2: предпроверка кода возвращает логин и срок (ревью R3: no-store —
    // ответ не должен оседать в кэше прокси/браузера).
    let precheck = Request::builder()
        .uri(format!("/auth/activate/{token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(precheck).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(info["login"], "invite-viewer");
    assert!(info["expires_at"].as_str().is_some());

    // Б1: перевыпуск — старый код мёртв, новый работает.
    let reissue = json_post(
        &format!("/api/v1/admin/users/{user_id}/invitation"),
        &admin,
        "",
    );
    let response = app.clone().oneshot(reissue).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let reissued: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_token = reissued["activation_token"].as_str().unwrap().to_owned();
    assert_ne!(new_token, token);

    let stale = Request::builder()
        .uri(format!("/auth/activate/{token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(stale).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    // Б3: активация по новому коду возвращает 200 + cookie + csrf и сразу входит.
    let activate = Request::builder()
        .method("POST")
        .uri(format!("/auth/activate/{new_token}"))
        .header("origin", ORIGIN)
        .header("x-csrf-token", &new_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"password": VIEWER_PASSWORD}).to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(activate).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("__Host-mask_session="));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["role"], "Viewer");
    assert!(session["csrf_token"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));

    // Сессия из активации рабочая: GET /session отвечает 200.
    let check = Request::builder()
        .uri("/api/v1/session")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(check).await.unwrap().status(), StatusCode::OK);
    let _ = auth;
}

/// Б8+Б10: слабый пароль при валидном коде — PASSWORD_POLICY, код не сгорает;
/// активация ограничена rate limit 429.
#[tokio::test]
async fn activation_distinguishes_password_policy_and_is_rate_limited() {
    let (_, _, _, app, admin) = admin_session().await;

    let create = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"policy-viewer","role":"Viewer"}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = created["activation_token"].as_str().unwrap().to_owned();

    let activate_with = |password: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/auth/activate/{token}"))
            .header("origin", ORIGIN)
            .header("x-csrf-token", &token)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"password": password}).to_string(),
            ))
            .unwrap()
    };

    // Б8: короткий пароль при живом коде → 400 PASSWORD_POLICY.
    let response = app.clone().oneshot(activate_with("short")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"]["code"],
        "PASSWORD_POLICY"
    );
    // Код остался действителен.
    let precheck = Request::builder()
        .uri(format!("/auth/activate/{token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(precheck).await.unwrap().status(),
        StatusCode::OK
    );

    // Б10 (ревью R2): лимит 5/мин — на ключ токена, не на весь endpoint:
    // шестая попытка по тому же коду отклоняется 429, а другой код свой
    // лимит не делит — попытка по нему проходит до проверки кода (400).
    let bogus = "x".repeat(43);
    let attempt = |token: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/auth/activate/{token}"))
            .header("origin", ORIGIN)
            .header("x-csrf-token", token)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"password": "any long password value"}).to_string(),
            ))
            .unwrap()
    };
    for _ in 0..5 {
        assert_eq!(
            app.clone().oneshot(attempt(&bogus)).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        app.clone().oneshot(attempt(&bogus)).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = "y".repeat(43);
    assert_eq!(
        app.clone().oneshot(attempt(&other)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

/// Б11: GET /session отдаёт привязанный CSRF существующей сессии — мутация с
/// ним проходит без повторного логина.
#[tokio::test]
async fn session_endpoint_returns_bound_csrf_for_existing_session() {
    let (_, _, _, app, admin) = admin_session().await;

    let check = Request::builder()
        .uri("/api/v1/session")
        .header("cookie", session_cookie_header(&admin.token))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(check).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let session_info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Детерминированный CSRF совпадает с выданным при login/issue.
    assert_eq!(
        session_info["csrf_token"].as_str().unwrap(),
        admin.csrf_token
    );
    assert_eq!(session_info["login"], "Admin");

    // CSRF из GET /session авторизует мутацию (перевыпуск чужого приглашения).
    let create = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"csrf-viewer","role":"Viewer"}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let user_id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reissue = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/users/{user_id}/invitation"))
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&admin.token))
        .header("x-csrf-token", session_info["csrf_token"].as_str().unwrap())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(reissue).await.unwrap().status(),
        StatusCode::CREATED
    );
}

/// Б9: публичный статус показывает незавершённый bootstrap и закрывается после.
#[tokio::test]
async fn status_reports_pending_bootstrap_until_completed() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    let app = test_app(storage, auth.clone(), sessions);

    let status = Request::builder()
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(status).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["bootstrap_required"], true);
    assert!(payload["version"].as_str().is_some_and(|v| !v.is_empty()));

    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let status = Request::builder()
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(status).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["bootstrap_required"],
        false
    );
}

/// Б5+Б6+Б7: сброс пароля отзывает доступ и выдаёт новое приглашение; удаление
/// освобождает логин только у «никогда не входивших»; список несёт агрегаты.
#[tokio::test]
async fn admin_reset_delete_and_user_list_aggregates() {
    let (_, auth, _, app, admin) = admin_session().await;

    // Ожидающий пользователь: invitation_expires_at есть, last_login_at нет.
    let create = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"pending-user","role":"Viewer"}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pending_id = created["user_id"].as_str().unwrap().to_owned();
    let pending_token = created["activation_token"].as_str().unwrap().to_owned();

    let list = json_get("/api/v1/admin/users", &admin);
    let response = app.clone().oneshot(list).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let users: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pending = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["login"] == "pending-user")
        .unwrap();
    assert_eq!(pending["activated"], false);
    assert!(pending["invitation_expires_at"].as_str().is_some());
    assert!(pending["last_login_at"].is_null());
    let admin_row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["login"] == "Admin")
        .unwrap();
    assert_eq!(admin_row["activated"], true);
    assert!(admin_row["invitation_expires_at"].is_null());
    assert!(admin_row["last_login_at"].as_str().is_some());

    // Б5: сброс пароля → старый пароль не работает, новое приглашение активирует.
    let activated_id = {
        let create = json_post(
            "/api/v1/admin/users",
            &admin,
            &serde_json::json!({"login":"reset-me","role":"Viewer"}).to_string(),
        );
        let response = app.clone().oneshot(create).await.unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = created["activation_token"].as_str().unwrap().to_owned();
        let activate = Request::builder()
            .method("POST")
            .uri(format!("/auth/activate/{token}"))
            .header("origin", ORIGIN)
            .header("x-csrf-token", &token)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"password": VIEWER_PASSWORD}).to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(activate).await.unwrap().status(),
            StatusCode::OK
        );
        created["user_id"].as_str().unwrap().to_owned()
    };
    let reset = json_post(
        &format!("/api/v1/admin/users/{activated_id}/password-reset"),
        &admin,
        "",
    );
    let response = app.clone().oneshot(reset).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let reset_token = serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        ["activation_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(matches!(
        auth.authenticate("after-reset", "reset-me", VIEWER_PASSWORD),
        Err(LoginError::Rejected)
    ));
    let activate = Request::builder()
        .method("POST")
        .uri(format!("/auth/activate/{reset_token}"))
        .header("origin", ORIGIN)
        .header("x-csrf-token", &reset_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"password": CHANGED_VIEWER_PASSWORD}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(activate).await.unwrap().status(),
        StatusCode::OK
    );

    // Б6: активированного удалить нельзя, «никогда не входившего» — можно.
    let delete_activated = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/users/{activated_id}"))
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(delete_activated)
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let delete_pending = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/users/{pending_id}"))
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(delete_pending).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // Логин освобождён — повторное создание проходит, старый код мёртв.
    let create_again = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"pending-user","role":"Viewer"}).to_string(),
    );
    assert_eq!(
        app.clone().oneshot(create_again).await.unwrap().status(),
        StatusCode::CREATED
    );
    let stale = Request::builder()
        .uri(format!("/auth/activate/{pending_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(stale).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    // Последний активный Admin защищён от удаления.
    let delete_admin = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/users/{}", admin.principal.user_id))
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(delete_admin).await.unwrap().status(),
        StatusCode::CONFLICT
    );
}

/// Б12: страницы /viewer и /admin охраняются сессией и ролью; статика нового
/// UI отдаётся; / редиректит авторизованного в его раздел.
#[tokio::test]
async fn pages_are_session_guarded_and_static_served() {
    let (_, auth, sessions, app, admin) = admin_session().await;
    let (_, token) = auth
        .create_user(
            &admin.principal,
            "page-viewer",
            Role::Viewer, &[],
            Uuid::new_v4(),
        )
        .unwrap();
    auth.activate("page-test", &token, VIEWER_PASSWORD).unwrap();
    let viewer = auth
        .authenticate("page-viewer", "page-viewer", VIEWER_PASSWORD)
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();

    let get = |uri: &str, cookie: Option<&str>| {
        let mut builder = Request::builder().uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        builder.body(Body::empty()).unwrap()
    };

    // Без сессии рабочие страницы редиректят на вход.
    for uri in ["/viewer", "/admin"] {
        let response = app.clone().oneshot(get(uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/");
    }
    // Чужая роль → редирект в собственный раздел.
    let response = app
        .clone()
        .oneshot(get("/viewer", Some(&session_cookie_header(&admin.token))))
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/admin");
    let response = app
        .clone()
        .oneshot(get(
            "/admin",
            Some(&session_cookie_header(&viewer_session.token)),
        ))
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/viewer");
    // Своя роль → 200 HTML.
    for (uri, token) in [("/viewer", &viewer_session.token), ("/admin", &admin.token)] {
        let response = app
            .clone()
            .oneshot(get(uri, Some(&session_cookie_header(token))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Живая сессия на / → в раздел.
    let response = app
        .clone()
        .oneshot(get("/", Some(&session_cookie_header(&admin.token))))
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/admin");
    // Статика нового UI.
    for uri in ["/app.js", "/app.css", "/grid.js"] {
        let response = app.clone().oneshot(get(uri, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(
        app.oneshot(get("/favicon.ico", None))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
}
//--agent TASK-224

//++agent TASK-224 [24.09.2026]
// Итерация 3: reveal автоматический при открытии записи и потому НЕ аудируется
// (решение пользователя) — строки 'history.reveal' в audit_events быть не должно.
#[tokio::test]
async fn reveal_returns_report_and_writes_no_audit_event() {
    let (storage, auth, sessions, app, admin) = admin_session().await;
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let viewer = viewer_session_for(&auth, &sessions, &admin.principal, "reveal-viewer", &[database_id]);

    //++agent TASK-224 [08.10.2026] итерация 4: канонический формат отчёта —
    // title (текст запроса) + masked-флаг колонки.
    let report = serde_json::json!({
        "version":1,
        "title":"SELECT Имя FROM Справочник.Люди",
        "blocks":[{
            "kind":"table",
            "columns":[{"id":"name","label":"Имя","type":"string","masked":true}],
            "rows":[["[MASK:v1:FIO:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]"],["Петров Петр"]]
        }]
    });
    //--agent TASK-224
    let inserted = storage
        .write_history(
            database_id,
            Some("chat-r"),
            Uuid::new_v4(),
            "execute_query",
            "tool_result",
            &serde_json::json!({"content":[{"type":"text","text":"ok"}],"is_error":false}),
            &report,
            1,
            &[],
            86_400,
            None,
            Uuid::new_v4(),
            None,
        )
        .unwrap();
    let history_id = match inserted {
        onec_masking_service::storage::HistoryWrite::Inserted(id) => id,
        _ => panic!("history row must be inserted"),
    };

    let response = app
        .clone()
        .oneshot(json_post(
            &format!("/api/v1/history/{history_id}/reveal"),
            &viewer,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let revealed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(revealed, report);

    let audit_count: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='history.reveal'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(audit_count, 0);

    // Viewer-scope по-прежнему enforced: чужая запись — 404.
    let foreign = app
        .oneshot(json_post(
            &format!("/api/v1/history/{}/reveal", Uuid::new_v4()),
            &viewer,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}
//--agent TASK-224

//++agent TASK-224 [24.09.2026]
// Итерация 2: display_label/rename, ленивое дерево метаданных, in_manifest.

fn viewer_session_for(
    auth: &Arc<LocalAuthProvider>,
    sessions: &Arc<SessionService>,
    admin: &onec_masking_service::auth::Principal,
    login: &str,
    database_ids: &[Uuid],
) -> onec_masking_service::auth::IssuedSession {
    let (_, activation) = auth
        .create_user(admin, login, Role::Viewer, database_ids, Uuid::new_v4())
        .unwrap();
    auth.activate("test", &activation, VIEWER_PASSWORD).unwrap();
    let viewer = auth.authenticate("test", login, VIEWER_PASSWORD).unwrap();
    sessions.issue(viewer, Utc::now()).unwrap()
}

fn json_patch(
    uri: &str,
    session: &onec_masking_service::auth::IssuedSession,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn database_display_label_renamed_cleared_and_validated() {
    let (storage, auth, sessions, app, admin) = admin_session().await;
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();

    let uri = format!("/api/v1/admin/databases/{database_id}");
    // Новое имя.
    let response = app
        .clone()
        .oneshot(json_patch(
            &uri,
            &admin,
            r#"{"display_label":"Торговля (прод)"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(json_get("/api/v1/admin/databases", &admin))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list[0]["display_label"], "Торговля (прод)");
    assert_eq!(list[0]["label"], "Торговля (прод)");
    assert_eq!(list[0]["id"], database_id.to_string());

    // Пустая строка и null — сброс имени (тот же PATCH-контракт).
    for body_str in [r#"{"display_label":"  "}"#, r#"{"display_label":null}"#] {
        let response = app
            .clone()
            .oneshot(json_patch(&uri, &admin, body_str))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(json_get("/api/v1/admin/databases", &admin))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(list[0]["display_label"].is_null());
        assert_eq!(list[0]["label"], database_id.to_string());
    }

    // Слишком длинное имя и управляющие символы → 400.
    let long = "x".repeat(200);
    for body_str in [
        serde_json::json!({"display_label": long}).to_string(),
        r#"{"display_label":"bad\u{7}name"}"#.to_owned(),
    ] {
        let response = app
            .clone()
            .oneshot(json_patch(&uri, &admin, &body_str))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // PATCH без полей не затирает имя.
    app.clone()
        .oneshot(json_patch(&uri, &admin, r#"{"display_label":"Имя"}"#))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(json_patch(&uri, &admin, r#"{"mode":"enabled"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let stored: Option<String> = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT display_label FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(stored.as_deref(), Some("Имя"));
    let _ = (auth, sessions);
}

#[tokio::test]
async fn metadata_route_requires_admin_and_db() {
    let (storage, auth, sessions, app, admin) = admin_session().await;
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let admin_principal = auth
        .authenticate("meta-check", "admin", ADMIN_PASSWORD)
        .unwrap();
    let viewer = viewer_session_for(&auth, &sessions, &admin_principal, "meta-viewer", &[]);

    let uri = format!("/api/v1/admin/databases/{database_id}/metadata");
    // Viewer → 403, аноним → 401.
    assert_eq!(
        app.clone()
            .oneshot(json_get(&uri, &viewer))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let anon = Request::builder().uri(&uri).body(Body::empty()).unwrap();
    assert_eq!(
        app.clone().oneshot(anon).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // Несуществующая база → 404.
    let missing = format!("/api/v1/admin/databases/{}/metadata", Uuid::new_v4());
    assert_eq!(
        app.clone()
            .oneshot(json_get(&missing, &admin))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    // Admin → 200.
    assert_eq!(
        app.clone()
            .oneshot(json_get(&uri, &admin))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn metadata_route_reports_empty_manifest_and_tree_levels() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("meta-admin", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(admin, Utc::now()).unwrap();

    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking.clone()));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));
    let uri = format!("/api/v1/admin/databases/{database_id}/metadata");

    // Manifest не получен → валидный ответ с manifest_ready:false.
    let response = app.clone().oneshot(json_get(&uri, &session)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["manifest_ready"], false);
    assert!(page["nodes"].as_array().unwrap().is_empty());

    // Посев manifest: дерево по уровням.
    assert!(masking.seed_metadata_manifest(
        database_id,
        vec![
            onec_masking_service::domain::FeedMetadataItem {
                source_path: "Справочник.Контрагенты.ИНН".into(),
                field_name: "ИНН".into(),
                field_type: "String(12)".into(),
                password_mode: false,
            },
            onec_masking_service::domain::FeedMetadataItem {
                source_path: "Справочник.Контрагенты.Наименование".into(),
                field_name: "Наименование".into(),
                field_type: "String(150)".into(),
                password_mode: false,
            },
            onec_masking_service::domain::FeedMetadataItem {
                source_path: "Справочник.Пользователи.Пароль".into(),
                field_name: "Пароль".into(),
                field_type: "String".into(),
                password_mode: true,
            },
            onec_masking_service::domain::FeedMetadataItem {
                source_path: "Документ.Продажа.Товары.Цена".into(),
                field_name: "Цена".into(),
                field_type: "Number".into(),
                password_mode: false,
            },
        ],
    ));

    // Корень — классы.
    let response = app.clone().oneshot(json_get(&uri, &session)).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["manifest_ready"], true);
    let nodes = page["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0]["name"], "Документ");
    assert_eq!(nodes[0]["kind"], "group");
    assert_eq!(nodes[1]["name"], "Справочник");
    assert_eq!(nodes[1]["field_count"], 3);
    assert_eq!(nodes[1]["password_count"], 1);

    // Уровень объекта → поля; парольное поле помечено.
    let response = app
        .clone()
        .oneshot(json_get(
            &format!("{uri}?path=%D0%A1%D0%BF%D1%80%D0%B0%D0%B2%D0%BE%D1%87%D0%BD%D0%B8%D0%BA.%D0%9F%D0%BE%D0%BB%D1%8C%D0%B7%D0%BE%D0%B2%D0%B0%D1%82%D0%B5%D0%BB%D0%B8"),
            &session,
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let nodes = page["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["kind"], "field");
    assert_eq!(nodes[0]["name"], "Пароль");
    assert_eq!(nodes[0]["field_type"], "String");
    assert_eq!(nodes[0]["password_mode"], true);

    // Поиск по имени поля — плоский список листьев.
    let response = app
        .clone()
        .oneshot(json_get(&format!("{uri}?q=%D0%98%D0%9D%D0%9D"), &session))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let nodes = page["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["path"], "Справочник.Контрагенты.ИНН");

    // Поиск по классу: «Справочник» матчится в трёх source_path.
    let response = app
        .clone()
        .oneshot(json_get(
            &format!("{uri}?q=%D0%A1%D0%BF%D1%80%D0%B0%D0%B2%D0%BE%D1%87%D0%BD%D0%B8%D0%BA"),
            &session,
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["nodes"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn metadata_route_bounds_inputs_and_search_output() {
    let (storage, auth, sessions) = auth_fixture();
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let admin = auth
        .authenticate("meta-limits", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(admin, Utc::now()).unwrap();

    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let setup = human::setup::SetupService::new(storage.clone(), masking.clone());
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking.clone()));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
        setup,
    }));
    let uri = format!("/api/v1/admin/databases/{database_id}/metadata");

    // 250 полей под одним объектом — выдача поиска ограничена 200.
    let items: Vec<onec_masking_service::domain::FeedMetadataItem> = (0..250)
        .map(|i| onec_masking_service::domain::FeedMetadataItem {
            source_path: format!("Справочник.Товары.Поле{i:04}"),
            field_name: format!("Поле{i:04}"),
            field_type: "String".into(),
            password_mode: false,
        })
        .collect();
    assert!(masking.seed_metadata_manifest(database_id, items));

    let response = app
        .clone()
        .oneshot(json_get(&format!("{uri}?q=Поле"), &session))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["nodes"].as_array().unwrap().len(), 200);
    assert_eq!(page["truncated"], true);

    // Детские узлы уровня — 1 группа, лимит дерева не срабатывает.
    let response = app.clone().oneshot(json_get(&uri, &session)).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(page["truncated"], false);

    // Слишком длинные входы → 400 до обращения к store.
    let long_path = "a".repeat(600);
    let long_q = "q".repeat(200);
    for bad in [
        format!("{uri}?path={long_path}"),
        format!("{uri}?q={long_q}"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(json_get(&bad, &session))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn dictionary_configs_mark_stale_selectors_via_manifest() {
    let (storage, _, _) = auth_fixture();
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = SqliteHumanDataStore::new(storage.clone(), masking.clone());
    let actor = onec_masking_service::auth::Principal {
        user_id: Uuid::new_v4(),
        role: Role::Admin,
        auth_epoch: 1,
    };

    // Без manifest — in_manifest=null (состояние неизвестно).
    let config = DictionaryConfig {
        id: Uuid::new_v4(),
        mode: "part".into(),
        selectors: vec![
            DictionarySelectorConfig {
                source_path: "Справочник.Контрагенты.ИНН".into(),
                category: "INN".into(),
                filter_ast: None,
            },
            DictionarySelectorConfig {
                source_path: "Справочник.Удалённый.Поле".into(),
                category: "X".into(),
                filter_ast: None,
            },
        ],
    };
    data.put_dictionary_config(&actor, database_id, config, Uuid::new_v4())
        .unwrap();
    //++agent TASK-225 [26.09.2026] M-4: PUT пишет в черновик — для
    // проверки in_manifest активируем его (list читает активную, §2.5).
    let draft_id = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT id FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| row.get::<_, String>(0),
            )
        })
        .map(|id| Uuid::parse_str(&id).unwrap())
        .unwrap();
    data.activate_policy(&actor, database_id, draft_id, Uuid::new_v4())
        .await
        .unwrap();
    //++agent TASK-225
    let configs = data.list_dictionary_configs(database_id).unwrap();
    assert!(configs[0].selectors.iter().all(|s| s.in_manifest.is_none()));

    // С manifest — точная проверка пути: в конфигурации/нет в конфигурации.
    assert!(masking.seed_metadata_manifest(
        database_id,
        vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Справочник.Контрагенты.ИНН".into(),
            field_name: "ИНН".into(),
            field_type: "String(12)".into(),
            password_mode: false,
        }],
    ));
    let configs = data.list_dictionary_configs(database_id).unwrap();
    assert_eq!(configs[0].selectors[0].in_manifest, Some(true));
    assert_eq!(configs[0].selectors[1].in_manifest, Some(false));
    // Вычисляемое поле не протекает в durable JSON.
    let persisted: String = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT source_paths_json FROM dictionary_configs WHERE database_id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(!persisted.contains("in_manifest"));
}
//--agent TASK-224

//++agent TASK-224 [08.10.2026] итерация 4
// Приглашение и сброс пароля отключённого пользователя — явный
// 409 USER_DISABLED, а не generic conflict: UI должен объяснить,
// что учётную запись сначала нужно включить.
#[tokio::test]
async fn disabled_user_invitation_and_reset_return_user_disabled() {
    let (_storage, _auth, _sessions, app, admin) = admin_session().await;

    let create = json_post(
        "/api/v1/admin/users",
        &admin,
        &serde_json::json!({"login":"disabled-target","role":"Viewer"}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = created["user_id"].as_str().unwrap().to_owned();

    let patch = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/admin/users/{user_id}"))
        .header("origin", ORIGIN)
        .header("cookie", session_cookie_header(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"role":"Viewer","status":"disabled"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(patch).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    for uri in [
        format!("/api/v1/admin/users/{user_id}/invitation"),
        format!("/api/v1/admin/users/{user_id}/password-reset"),
    ] {
        let response = app
            .clone()
            .oneshot(json_post(&uri, &admin, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], "USER_DISABLED", "{uri}");
    }
}
//--agent TASK-224
