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
    assert_eq!(admin.role, Role::Admin);
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
    assert_eq!(principal.role, Role::Admin);

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
        .create_user(&admin, "Viewer One", Role::Viewer, Uuid::new_v4())
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

    auth.activate(&token, VIEWER_PASSWORD).unwrap();
    assert!(auth.activate(&token, "replacement password value").is_err());
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
        .create_user(&admin, "viewer", Role::Viewer, Uuid::new_v4())
        .unwrap();
    auth.activate(&activation, VIEWER_PASSWORD).unwrap();
    let viewer = auth
        .authenticate("viewer-api", "viewer", VIEWER_PASSWORD)
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();

    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
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
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking));
    let app = human::router(Arc::new(HumanState {
        auth,
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
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
        .create_user(&admin, "viewer", Role::Viewer, Uuid::new_v4())
        .unwrap();
    auth.activate(&activation, VIEWER_PASSWORD).unwrap();

    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = Arc::new(SqliteHumanDataStore::new(storage.clone(), masking));
    let app = human::router(Arc::new(HumanState {
        auth: auth.clone(),
        sessions: sessions.clone(),
        data,
        expected_origin: ORIGIN.to_owned(),
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
    let data = Arc::new(SqliteHumanDataStore::new(storage, masking));
    let app = human::router(Arc::new(HumanState {
        auth: auth.clone(),
        sessions,
        data,
        expected_origin: ORIGIN.to_owned(),
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
    storage.ensure_database(database_id).unwrap();
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
                class: "allow-all".into()
            },
            Uuid::new_v4(),
        )
        .is_err());

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
    data.put_dictionary_config(&actor, database_id, dictionary, Uuid::new_v4())
        .unwrap();
    let stored_configs = data.list_dictionary_configs(database_id).unwrap();
    assert_eq!(stored_configs.len(), 1);
    assert_eq!(stored_configs[0].selectors[0].category, "FIO");
    let persisted_json: String = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT source_paths_json FROM dictionary_configs WHERE database_id=?1",
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
                }],
            },
            Uuid::new_v4(),
        )
        .unwrap();
    data.activate_policy(&actor, database_id, policy.id, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(data.list_policies(database_id).unwrap()[0].status, "active");

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
async fn activating_policy_before_first_feed_does_not_make_enabled_database_ready() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
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
            database_id,
            chat_id: "policy-before-feed".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: serde_json::json!({"query":"SELECT 1"}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ServiceNotReady);
}

//++agent TASK-221 2026-09-23
#[tokio::test]
async fn configurable_secret_rules_cannot_be_activated_without_premanager_policy() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let data = SqliteHumanDataStore::new(storage, masking);
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
    storage.ensure_database(database_id).unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
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
