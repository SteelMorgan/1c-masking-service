//! B7: контурные тесты per-database RBAC (T1–T11 дизайна RBAC).
//! Прогон — in-memory SQLite + реальный axum Router; миграция T8 — на
//! файловой БД с унаследованным CHECK ролей.

mod common;

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use onec_masking_service::{
    api::human::{self, HumanState, SqliteHumanDataStore},
    auth::{
        AuthProvider, AuthStore, IssuedSession, LocalAuthProvider, Role, SessionService,
    },
    domain::MaskingService,
    SqliteStorage,
};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://masking.test";
const ADMIN_PASSWORD: &str = "correct horse battery staple";
const USER_PASSWORD: &str = "user passphrase is unique";

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

/// Полный контур: storage + auth + sessions + router + сессия SuperAdmin
/// (bootstrap-пользователь всегда SuperAdmin после миграции 0017).
async fn ctx() -> (
    Arc<SqliteStorage>,
    Arc<LocalAuthProvider>,
    Arc<SessionService>,
    axum::Router,
    IssuedSession,
) {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let store: Arc<dyn AuthStore> = storage.clone();
    let auth = Arc::new(LocalAuthProvider::new(store.clone()).unwrap());
    let sessions = Arc::new(SessionService::new(store));
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let principal = auth
        .authenticate("rbac", "admin", ADMIN_PASSWORD)
        .unwrap();
    assert_eq!(principal.role, Role::SuperAdmin);
    let session = sessions.issue(principal, Utc::now()).unwrap();
    let app = test_app(storage.clone(), auth.clone(), sessions.clone());
    (storage, auth, sessions, app, session)
}

/// Создание + активация + вход пользователя с набором баз.
fn user_session(
    auth: &Arc<LocalAuthProvider>,
    sessions: &Arc<SessionService>,
    admin_login_source: &str,
    login: &str,
    role: Role,
    database_ids: &[Uuid],
) -> IssuedSession {
    let admin = auth
        .authenticate(admin_login_source, "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin, login, role, database_ids, Uuid::new_v4())
        .unwrap();
    auth.activate(login, &activation, USER_PASSWORD).unwrap();
    let principal = auth.authenticate(login, login, USER_PASSWORD).unwrap();
    sessions.issue(principal, Utc::now()).unwrap()
}

fn cookie(token: &str) -> String {
    format!("__Host-mask_session={token}")
}

fn get(uri: &str, session: &IssuedSession) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("cookie", cookie(&session.token))
        .body(Body::empty())
        .unwrap()
}

fn write(
    method: &str,
    uri: &str,
    session: &IssuedSession,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn seed_db(storage: &SqliteStorage, database_id: Uuid) {
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

// -------------------------------------------------------------------
// T1: SuperAdmin видит все базы и управляет пользователями/доступами.
// -------------------------------------------------------------------
#[tokio::test]
async fn t1_superadmin_sees_all_and_manages_users() {
    let (storage, _auth, _sessions, app, admin) = ctx().await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, a);
    seed_db(&storage, b);

    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/databases", &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&a.to_string().as_str()) && ids.contains(&b.to_string().as_str()));

    // Управление пользователями и наборами доступа.
    let response = app
        .clone()
        .oneshot(get("/api/v1/admin/users", &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let create = write(
        "POST",
        "/api/v1/admin/users",
        &admin,
        &json!({"login":"limited","role":"Admin","database_ids":[a]}).to_string(),
    );
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json_body(response).await["user_id"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/users/{user_id}/databases"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["database_ids"], json!([a]));

    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/users/{user_id}/databases"),
            &admin,
            &json!({"database_ids":[a, b]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// -------------------------------------------------------------------
// T2: ограниченный Admin видит и меняет только назначенные базы; чужая —
// 404 DATABASE_NOT_FOUND (также и несуществующая — ответы не различимы).
// -------------------------------------------------------------------
#[tokio::test]
async fn t2_limited_admin_scoped_and_foreign_is_404() {
    let (storage, auth, sessions, app, _) = ctx().await;
    let (own, foreign, missing) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, own);
    seed_db(&storage, foreign);
    let admin = user_session(&auth, &sessions, "t2", "adm", Role::Admin, &[own]);

    // Список — только назначенная база.
    let body = json_body(
        app.clone()
            .oneshot(get("/api/v1/admin/databases", &admin))
            .await
            .unwrap(),
    )
    .await;
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![own.to_string().as_str()]);

    // Мутация своей базы — доступна; чужой и несуществующей — одинаковый 404.
    let own_patch = write(
        "PATCH",
        &format!("/api/v1/admin/databases/{own}"),
        &admin,
        &json!({"display_label":"mine"}).to_string(),
    );
    assert_eq!(
        app.clone().oneshot(own_patch).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    for id in [foreign, missing] {
        let response = app
            .clone()
            .oneshot(write(
                "PATCH",
                &format!("/api/v1/admin/databases/{id}"),
                &admin,
                &json!({"display_label":"x"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await["error"]["code"], "DATABASE_NOT_FOUND");
        // Чтение метаданных чужой базы — тот же 404.
        let response = app
            .clone()
            .oneshot(get(
                &format!("/api/v1/admin/databases/{id}/metadata"),
                &admin,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

// -------------------------------------------------------------------
// T3: свой id базы + чужой policy_id / версия — 404, чужая база не
// мутирует.
// -------------------------------------------------------------------
#[tokio::test]
async fn t3_foreign_resource_ids_do_not_cross_databases() {
    let (storage, auth, sessions, app, _) = ctx().await;
    let (own, foreign) = (Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, own);
    seed_db(&storage, foreign);
    let admin = user_session(&auth, &sessions, "t3", "adm3", Role::Admin, &[own]);

    // В чужой базе — политика с версией 1.
    let foreign_policy = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO policies(id,database_id,version,status,created_at)
                 VALUES (?1,?2,1,'draft','t')",
                rusqlite::params![foreign_policy.to_string(), foreign.to_string()],
            )?;
            Ok(())
        })
        .unwrap();

    // Активация чужой политики на своей базе — 404, политика чужой базы
    // остаётся черновиком.
    let response = app
        .clone()
        .oneshot(write(
            "POST",
            &format!("/api/v1/admin/databases/{own}/policies/{foreign_policy}/activate"),
            &admin,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let status: String = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT status FROM policies WHERE id=?1",
                [foreign_policy.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(status, "draft");

    // Чтение версии чужой базы под своим id — 404 (у своей базы версий нет).
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{own}/setup/versions/1"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // T11-часть: назначение классификации инструмента разрешено только на
    // своей базе; на чужой — 404.
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/databases/{own}/tools/execute_query"),
            &admin,
            &json!({"class":"no-mask","confirm_bypass":true}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Снимок чужой записи до попытки — PUT по чужому id обязан её не тронуть.
    let before: (String, Option<String>, String) = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT class, reviewer, updated_at FROM tool_classifications
                 WHERE database_id=?1 AND tool_name='execute_query'",
                [foreign.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
        })
        .unwrap();
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/databases/{foreign}/tools/execute_query"),
            &admin,
            &json!({"class":"no-mask","confirm_bypass":true}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let after: (String, Option<String>, String) = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT class, reviewer, updated_at FROM tool_classifications
                 WHERE database_id=?1 AND tool_name='execute_query'",
                [foreign.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
        })
        .unwrap();
    assert_eq!(before, after);
}

// -------------------------------------------------------------------
// T4: reveal и reasons по записи истории чужой базы — 404; своя — как
// раньше.
// -------------------------------------------------------------------
#[tokio::test]
async fn t4_history_of_foreign_database_is_not_found() {
    let (storage, auth, sessions, app, _) = ctx().await;
    let (own, foreign) = (Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, own);
    seed_db(&storage, foreign);
    let viewer = user_session(&auth, &sessions, "t4", "vw", Role::Viewer, &[own]);

    let seed_history = |database_id: Uuid| -> Uuid {
        let inserted = storage
            .write_history(
                database_id,
                "chat",
                Uuid::new_v4(),
                "execute_query",
                "tool_result",
                &json!({"content":[{"type":"text","text":"ok"}],"is_error":false}),
                &json!({"version":1,"title":"t","blocks":[]}),
                1,
                &[],
                86_400,
                None,
                Uuid::new_v4(),
                None,
            )
            .unwrap();
        match inserted {
            onec_masking_service::storage::HistoryWrite::Inserted(id) => id,
            _ => panic!("history row expected"),
        }
    };
    let (own_history, foreign_history) = (seed_history(own), seed_history(foreign));

    for (history_id, expected) in
        [(own_history, StatusCode::OK), (foreign_history, StatusCode::NOT_FOUND)]
    {
        let response = app
            .clone()
            .oneshot(write(
                "POST",
                &format!("/api/v1/history/{history_id}/reveal"),
                &viewer,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let response = app
            .clone()
            .oneshot(get(
                &format!("/api/v1/history/{history_id}/reasons"),
                &viewer,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

// -------------------------------------------------------------------
// T5: ограниченный Admin получает 403 на всех /admin/users* и на
// DELETE /admin/databases/{id} — даже своей базы.
// -------------------------------------------------------------------
#[tokio::test]
async fn t5_limited_admin_forbidden_on_user_management_and_db_delete() {
    let (storage, auth, sessions, app, admin_session) = ctx().await;
    let own = Uuid::new_v4();
    seed_db(&storage, own);
    let admin = user_session(&auth, &sessions, "t5", "adm5", Role::Admin, &[own]);
    let target = auth
        .authenticate("t5", "adm5", USER_PASSWORD)
        .unwrap()
        .user_id;

    for request in [
        get("/api/v1/admin/users", &admin),
        write("POST", "/api/v1/admin/users", &admin, r#"{"login":"x","role":"Viewer"}"#),
        get(
            &format!("/api/v1/admin/users/{target}/databases"),
            &admin,
        ),
        write(
            "PUT",
            &format!("/api/v1/admin/users/{target}/databases"),
            &admin,
            r#"{"database_ids":[]}"#,
        ),
        write(
            "PATCH",
            &format!("/api/v1/admin/users/{target}"),
            &admin,
            r#"{"role":"Viewer","status":"active"}"#,
        ),
        write(
            "DELETE",
            &format!("/api/v1/admin/databases/{own}"),
            &admin,
            "",
        ),
        // Перевыпуск/сброс/удаление пользователя — тоже только SuperAdmin.
        write(
            "POST",
            &format!("/api/v1/admin/users/{target}/invitation"),
            &admin,
            "",
        ),
        write(
            "POST",
            &format!("/api/v1/admin/users/{target}/password-reset"),
            &admin,
            "",
        ),
        write("DELETE", &format!("/api/v1/admin/users/{target}"), &admin, ""),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    // SuperAdmin для контраста может удалить базу.
    let response = app
        .clone()
        .oneshot(write(
            "DELETE",
            &format!("/api/v1/admin/databases/{own}"),
            &admin_session,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// -------------------------------------------------------------------
// T6: /databases (Viewer) и /admin/databases (Admin) показывают только
// назначенные; SuperAdmin видит базу, зарегистрированную после выдачи.
// -------------------------------------------------------------------
#[tokio::test]
async fn t6_lists_are_scoped_and_superadmin_sees_late_databases() {
    let (storage, auth, sessions, app, admin_session) = ctx().await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, a);
    seed_db(&storage, b);
    let viewer = user_session(&auth, &sessions, "t6", "vw6", Role::Viewer, &[a]);
    let admin = user_session(&auth, &sessions, "t6a", "adm6", Role::Admin, &[a]);

    for (session, uri) in [
        (&viewer, "/api/v1/databases"),
        (&admin, "/api/v1/admin/databases"),
    ] {
        let body = json_body(app.clone().oneshot(get(uri, session)).await.unwrap()).await;
        let ids: Vec<String> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ids, vec![a.to_string()]);
    }

    // База, появившаяся ПОСЛЕ выдачи доступа, видна SuperAdmin автоматически.
    let late = Uuid::new_v4();
    seed_db(&storage, late);
    let body = json_body(
        app.clone()
            .oneshot(get("/api/v1/admin/databases", &admin_session))
            .await
            .unwrap(),
    )
    .await;
    let ids: Vec<String> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect();
    for expected in [a, b, late] {
        assert!(ids.contains(&expected.to_string()));
    }
    // А у ограниченного Admin — по-прежнему одна назначенная.
    let body = json_body(
        app.clone()
            .oneshot(get("/api/v1/admin/databases", &admin))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}

// -------------------------------------------------------------------
// T7: отзыв доступа действует на следующий запрос той же сессии.
// -------------------------------------------------------------------
#[tokio::test]
async fn t7_revoke_takes_effect_on_next_request() {
    let (storage, auth, sessions, app, admin) = ctx().await;
    let a = Uuid::new_v4();
    seed_db(&storage, a);
    let viewer = user_session(&auth, &sessions, "t7", "vw7", Role::Viewer, &[a]);
    let viewer_id = auth
        .authenticate("t7-id", "vw7", USER_PASSWORD)
        .unwrap()
        .user_id;

    // Пока доступ есть — чат-лист базы отдаёт 200.
    let uri = format!("/api/v1/chats?database_id={a}");
    assert_eq!(
        app.clone()
            .oneshot(get(&uri, &viewer))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // Отзыв (полная замена набора пустым) — той же сессией админа.
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/users/{viewer_id}/databases"),
            &admin,
            r#"{"database_ids":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Следующий запрос той же viewer-сессии — уже 404, перелогин не нужен.
    assert_eq!(
        app.clone()
            .oneshot(get(&uri, &viewer))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json_body(
            app.clone()
                .oneshot(get("/api/v1/databases", &viewer))
                .await
                .unwrap()
        )
        .await
        .as_array()
        .unwrap()
        .len(),
        0
    );
}

// -------------------------------------------------------------------
// T8: миграция базы с Admin/Viewer и живой сессией — Admin → SuperAdmin,
// сессия валидна, Viewer получает все существующие базы; повторный запуск
// идемпотентен.
// -------------------------------------------------------------------
#[test]
fn t8_migration_promotes_admin_grants_viewer_and_is_idempotent() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let (admin_id, viewer_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (db_a, db_b) = (Uuid::new_v4(), Uuid::new_v4());
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        for file in [
            "0001_core.sql",
            "0002_terminal_history.sql",
            "0003_v2_call_receipts.sql",
            "0004_v2_active_snapshots.sql",
            "0005_v2_feed_leases.sql",
            "0006_v2_feed_completion_proof.sql",
            "0007_v2_refresh_intents.sql",
            "0008_drop_v2_feed.sql",
            "0009_call_contexts.sql",
            "0010_setup_versions.sql",
            "0011_tool_auto_classification.sql",
            "0012_strict_mode.sql",
            "0013_refresh_backoff.sql",
            "0014_mask_token_flag.sql",
            "0015_no_mask_rename.sql",
            "0016_database_identity.sql",
        ] {
            let sql = std::fs::read_to_string(format!("migrations/{file}")).unwrap();
            // 0011+ повторяют ADD COLUMN'ы 0010 — настоящий runner применяет
            // их поколоночно с пропуском существующих; в фикстуре то же —
            // постатейно, дубли колонок игнорируются (как legacy_database_14).
            if file.starts_with("001") {
                // ';' встречается и внутри комментариев — сначала их снимаем,
                // иначе разрез ломает текст на середине '-- initialize; ...'.
                let without_comments = sql
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .collect::<Vec<_>>()
                    .join("\n");
                for statement in without_comments.split(';') {
                    let statement = statement.trim();
                    if statement.is_empty() {
                        continue;
                    }
                    match connection.execute_batch(statement) {
                        Ok(()) => {}
                        Err(error) if error.to_string().contains("duplicate column name") => {}
                        Err(error) => panic!("{file}: {error}"),
                    }
                }
            } else {
                connection.execute_batch(&sql).unwrap();
            }
        }
        for version in 1..=16i64 {
            connection
                .execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 'x')",
                    [version],
                )
                .unwrap();
        }
        // Откат CHECK роли к до-0017 виду — имитация базы, созданной
        // до этой миграции (новый 0001 уже содержит SuperAdmin).
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_master SET sql=replace(sql,'''SuperAdmin'', ','')
                 WHERE type='table' AND name='users'",
                [],
            )
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();
        let users_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!users_sql.contains("SuperAdmin"), "{users_sql}");

        for (id, login, role) in [
            (admin_id, "adm", "Admin"),
            (viewer_id, "vw", "Viewer"),
        ] {
            connection
                .execute(
                    "INSERT INTO users(id,normalized_login,display_login,password_hash,role,status,auth_epoch,created_at,updated_at)
                     VALUES (?1,?2,?2,NULL,?3,'active',0,'t','t')",
                    rusqlite::params![id.to_string(), login, role],
                )
                .unwrap();
        }
        for database_id in [db_a, db_b] {
            connection
                .execute(
                    "INSERT INTO databases(id,instance_id,display_label,mode,created_at,updated_at)
                     VALUES (?1,?1,'db','enabled','t','t')",
                    [database_id.to_string()],
                )
                .unwrap();
        }
        // Живая сессия Admin: token_hash = sha256(token), epoch 0.
        let token_hash: [u8; 32] = Sha256::digest(b"legacy-session").into();
        connection
            .execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_hash,idle_expires_at,absolute_expires_at,last_seen_at,auth_epoch,created_at)
                 VALUES (?1,?2,?3,'2999-01-01T00:00:00Z','2999-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'2026-01-01T00:00:00Z')",
                rusqlite::params![
                    token_hash.as_slice(),
                    admin_id.to_string(),
                    Sha256::digest(b"csrf").as_slice()
                ],
            )
            .unwrap();
    }

    let storage = Arc::new(SqliteStorage::open(&path).unwrap());
    let roles: Vec<(String, String)> = storage
        .with_connection(|c| {
            let mut st = c.prepare("SELECT normalized_login, role FROM users ORDER BY 1")?;
            let rows = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(
        roles,
        vec![
            ("adm".to_owned(), "SuperAdmin".to_owned()),
            ("vw".to_owned(), "Viewer".to_owned())
        ]
    );

    // Viewer получил все существующие базы (миграционная выдача, granted_by NULL).
    let grants: Vec<(String, Option<String>)> = storage
        .with_connection(|c| {
            let mut st = c.prepare(
                "SELECT database_id, granted_by FROM user_database_access WHERE user_id=?1 ORDER BY 1",
            )?;
            let rows = st
                .query_map([viewer_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().all(|(_, by)| by.is_none()));

    // Колонка аудита появилась.
    let has_column: bool = storage
        .with_connection(|c| {
            let mut st = c.prepare("PRAGMA table_info(audit_events)")?;
            let names = st
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names.iter().any(|name| name == "target_user_id"))
        })
        .unwrap();
    assert!(has_column);

    // Сессия пережила пересоздание users и остаётся валидной.
    let store: Arc<dyn AuthStore> = storage.clone();
    let sessions = SessionService::new(store);
    let principal = sessions
        .validate("legacy-session", None, Utc::now())
        .unwrap();
    assert_eq!(principal.role, Role::SuperAdmin);

    // Повторный запуск — идемпотентен.
    drop(sessions);
    drop(storage);
    let storage = SqliteStorage::open(&path).unwrap();
    let count: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM user_database_access WHERE user_id=?1",
                [viewer_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(count, 2);
}

// -------------------------------------------------------------------
// T9: последнего активного SuperAdmin нельзя понизить, отключить или
// удалить — 409.
// -------------------------------------------------------------------
#[tokio::test]
async fn t9_last_superadmin_cannot_be_demoted_disabled_or_deleted() {
    let (_storage, auth, sessions, app, admin) = ctx().await;
    let admin_id = auth
        .authenticate("t9", "admin", ADMIN_PASSWORD)
        .unwrap()
        .user_id;

    for (method, body) in [
        ("PATCH", r#"{"role":"Admin","status":"active"}"#),
        ("PATCH", r#"{"role":"SuperAdmin","status":"disabled"}"#),
        ("DELETE", ""),
    ] {
        let response = app
            .clone()
            .oneshot(write(
                method,
                &format!("/api/v1/admin/users/{admin_id}"),
                &admin,
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{method} {body}");
    }

    // Ожидающий активации SuperAdmin инвариант НЕ снимает: без пароля
    // он не входоспособен, а приглашение показывается один раз и могло
    // истечь — иначе понижение последнего реального супера прошло бы
    // через «виртуальный» счётчик.
    let (_pending_user, _pending_activation) = auth
        .create_user(
            &auth
                .authenticate("t9b", "admin", ADMIN_PASSWORD)
                .unwrap(),
            "pending-super",
            Role::SuperAdmin,
            &[],
            Uuid::new_v4(),
        )
        .unwrap();
    let response = app
        .clone()
        .oneshot(write(
            "PATCH",
            &format!("/api/v1/admin/users/{admin_id}"),
            &admin,
            r#"{"role":"Admin","status":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "pending SuperAdmin не считается в инварианте"
    );

    // Обратная сторона: сам pending-SuperAdmin свободно понижается и
    // удаляется — счёт функциональных администраторов он не меняет,
    // гард на него не распространяется (иначе логин «зависал» бы навсегда).
    let pending_id = _pending_user.id;
    let response = app
        .clone()
        .oneshot(write(
            "PATCH",
            &format!("/api/v1/admin/users/{pending_id}"),
            &admin,
            r#"{"role":"Viewer","status":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .clone()
        .oneshot(write(
            "DELETE",
            &format!("/api/v1/admin/users/{pending_id}"),
            &admin,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Сброс пароля последнего функционального SuperAdmin тоже под
    // инвариантом: цель обнулила бы пароль и перестала быть
    // входоспособной до активации по одноразовому токену.
    let response = app
        .clone()
        .oneshot(write(
            "POST",
            &format!("/api/v1/admin/users/{admin_id}/password-reset"),
            &admin,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Активированный второй SuperAdmin снимает ограничение — понижение
    // допустимо.
    let _second = user_session(
        &auth,
        &sessions,
        "t9c",
        "second-super",
        Role::SuperAdmin,
        &[],
    );
    let response = app
        .clone()
        .oneshot(write(
            "PATCH",
            &format!("/api/v1/admin/users/{admin_id}"),
            &admin,
            r#"{"role":"Admin","status":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// -------------------------------------------------------------------
// T10: grant/revoke пишут audit с database_id, actor_id и отдельной
// колонкой target_user_id.
// -------------------------------------------------------------------
#[tokio::test]
async fn t10_access_changes_write_audited_columns() {
    let (storage, auth, sessions, app, admin) = ctx().await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    seed_db(&storage, a);
    seed_db(&storage, b);
    let admin_id = auth
        .authenticate("t10", "admin", ADMIN_PASSWORD)
        .unwrap()
        .user_id;
    let viewer = user_session(&auth, &sessions, "t10", "vw10", Role::Viewer, &[a]);
    let viewer_id = auth
        .authenticate("t10-id", "vw10", USER_PASSWORD)
        .unwrap()
        .user_id;
    let _ = viewer;

    // Grant a уже был при создании; добавляем b и снимаем a одной заменой.
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/users/{viewer_id}/databases"),
            &admin,
            &json!({"database_ids":[b]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let rows: Vec<(String, String, String, String)> = storage
        .with_connection(|c| {
            let mut st = c.prepare(
                "SELECT action, database_id, actor_id, target_user_id
                 FROM audit_events
                 WHERE action IN ('access.grant','access.revoke')
                 ORDER BY id",
            )?;
            let rows = st
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .unwrap();
    // Создание с набором [a] дало grant(a); замена — revoke(a)+grant(b).
    assert_eq!(
        rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        vec!["access.grant", "access.revoke", "access.grant"]
    );
    assert_eq!(rows[0].1, a.to_string());
    assert_eq!(rows[1].1, a.to_string());
    assert_eq!(rows[2].1, b.to_string());
    for row in &rows {
        assert_eq!(row.2, admin_id.to_string(), "actor_id — выдавший");
        assert_eq!(row.3, viewer_id.to_string(), "target_user_id — цель");
    }

    // Повышение до SuperAdmin снимает хранимые гранты — revoke в аудите,
    // а не молчаливый DELETE.
    let response = app
        .clone()
        .oneshot(write(
            "PATCH",
            &format!("/api/v1/admin/users/{viewer_id}"),
            &admin,
            r#"{"role":"SuperAdmin","status":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Удаление пользователя с грантами — revoke в аудите (иначе след
    // «кому был доступ» уходит каскадом незамеченным).
    let (_pending, _act) = auth
        .create_user(
            &auth
                .authenticate("t10b", "admin", ADMIN_PASSWORD)
                .unwrap(),
            "t10-pending",
            Role::Viewer,
            &[a],
            Uuid::new_v4(),
        )
        .unwrap();
    let pending_id = _pending.id;
    let response = app
        .clone()
        .oneshot(write(
            "DELETE",
            &format!("/api/v1/admin/users/{pending_id}"),
            &admin,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let rows: Vec<(String, String, String)> = storage
        .with_connection(|c| {
            let mut st = c.prepare(
                "SELECT action, database_id, target_user_id FROM audit_events
                 WHERE action='access.revoke' ORDER BY id",
            )?;
            let rows = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .unwrap();
    // revoke(a) из PUT-диффа, revoke(b) при повышении, revoke(a) при удалении.
    assert_eq!(
        rows.iter()
            .map(|r| (r.1.clone(), r.2.clone()))
            .collect::<Vec<_>>(),
        vec![
            (a.to_string(), viewer_id.to_string()),
            (b.to_string(), viewer_id.to_string()),
            (a.to_string(), pending_id.to_string()),
        ]
    );
}

// -------------------------------------------------------------------
// T5-доп: Viewer тоже не управляет пользователями (ступень не наследуется).
// -------------------------------------------------------------------
#[tokio::test]
async fn t5b_viewer_forbidden_on_user_management() {
    let (storage, auth, sessions, app, _) = ctx().await;
    let a = Uuid::new_v4();
    seed_db(&storage, a);
    let viewer = user_session(&auth, &sessions, "t5v", "vw5", Role::Viewer, &[a]);
    assert_eq!(
        app.clone()
            .oneshot(get("/api/v1/admin/users", &viewer))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

// -------------------------------------------------------------------
// T11: контракт ошибок эндпоинтов доступа — несуществующая база → 400,
// набор у SuperAdmin-цели → 409 SUPERADMIN_HAS_ALL и GET → "all",
// несуществующий пользователь → 404 USER_NOT_FOUND, дубли id при
// создании не отличаются от уникальных (как PUT-семантика Set).
// -------------------------------------------------------------------
#[tokio::test]
async fn t11_access_endpoint_error_contract() {
    let (storage, auth, sessions, app, admin) = ctx().await;
    let a = Uuid::new_v4();
    seed_db(&storage, a);
    let admin_id = auth
        .authenticate("t11", "admin", ADMIN_PASSWORD)
        .unwrap()
        .user_id;
    let viewer = user_session(&auth, &sessions, "t11", "vw11", Role::Viewer, &[a]);
    let viewer_id = auth
        .authenticate("t11-id", "vw11", USER_PASSWORD)
        .unwrap()
        .user_id;
    let _ = viewer;

    // Несуществующий database_id → 400 (а не 500/409).
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/users/{viewer_id}/databases"),
            &admin,
            &json!({"database_ids":[a, Uuid::new_v4()]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Цель-SuperAdmin: PUT → 409 SUPERADMIN_HAS_ALL, GET → "all".
    let response = app
        .clone()
        .oneshot(write(
            "PUT",
            &format!("/api/v1/admin/users/{admin_id}/databases"),
            &admin,
            &json!({"database_ids":[a]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["error"]["code"], "SUPERADMIN_HAS_ALL");

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/users/{admin_id}/databases"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["database_ids"], "all");

    // Несуществующий пользователь → 404 USER_NOT_FOUND на обеих операциях.
    let missing = Uuid::new_v4();
    for request in [
        get(
            &format!("/api/v1/admin/users/{missing}/databases"),
            &admin,
        ),
        write(
            "PUT",
            &format!("/api/v1/admin/users/{missing}/databases"),
            &admin,
            &json!({"database_ids":[a]}).to_string(),
        ),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await["error"]["code"], "USER_NOT_FOUND");
    }

    // POST /admin/users: SuperAdmin с явным набором → 409 SUPERADMIN_HAS_ALL;
    // дубли database_ids у обычной роли — как уникальный набор, без UNIQUE-ошибки.
    let response = app
        .clone()
        .oneshot(write(
            "POST",
            "/api/v1/admin/users",
            &admin,
            &json!({"login":"sa2","role":"SuperAdmin","database_ids":[a]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response).await["error"]["code"], "SUPERADMIN_HAS_ALL");

    let response = app
        .clone()
        .oneshot(write(
            "POST",
            "/api/v1/admin/users",
            &admin,
            &json!({"login":"vw-dup","role":"Viewer","database_ids":[a, a]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "дубли id дедуплицируются как в PUT-семантике"
    );
    let created = json_body(response).await;
    let created_id = created["user_id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/users/{created_id}/databases"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(response).await["database_ids"], json!([a]));
}

// T12 (DEV-инцидент): база с чужой записью schema_migrations version=17
// от ранней сборки — user_database_access и audit_events.target_user_id
// отсутствуют, роли уже SuperAdmin (фаза 1 прошла). initialize обязан
// достроить схему по фактическому состоянию, не теряя чужую запись.
#[test]
fn t12_foreign_version17_record_does_not_block_schema_repair() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign17.db");
    let viewer_id = Uuid::new_v4();
    let (db_a, db_b) = (Uuid::new_v4(), Uuid::new_v4());
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        for file in [
            "0001_core.sql",
            "0002_terminal_history.sql",
            "0003_v2_call_receipts.sql",
            "0004_v2_active_snapshots.sql",
            "0005_v2_feed_leases.sql",
            "0006_v2_feed_completion_proof.sql",
            "0007_v2_refresh_intents.sql",
            "0008_drop_v2_feed.sql",
            "0009_call_contexts.sql",
            "0010_setup_versions.sql",
            "0011_tool_auto_classification.sql",
            "0012_strict_mode.sql",
            "0013_refresh_backoff.sql",
            "0014_mask_token_flag.sql",
            "0015_no_mask_rename.sql",
            "0016_database_identity.sql",
        ] {
            let sql = std::fs::read_to_string(format!("migrations/{file}")).unwrap();
            let without_comments = sql
                .lines()
                .filter(|line| !line.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            for statement in without_comments.split(';') {
                let statement = statement.trim();
                if statement.is_empty() {
                    continue;
                }
                match connection.execute_batch(statement) {
                    Ok(()) => {}
                    Err(error) if error.to_string().contains("duplicate column name") => {}
                    Err(error) => panic!("{file}: {error}"),
                }
            }
        }
        for version in 1..=16i64 {
            connection
                .execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 'x')",
                    [version],
                )
                .unwrap();
        }
        // Чужая запись version=17 от сборки без фазы 2 — её timestamp
        // обязан сохраниться (INSERT OR IGNORE), а не перезаписаться.
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (17, '2026-09-26T13:58:00Z')",
                [],
            )
            .unwrap();
        // Состояние «фаза 1 прошла»: users уже с новым CHECK (свежий
        // 0001), роли переименованы; user_database_access и
        // audit_events.target_user_id — отсутствуют.
        for (id, login, role) in [
            (Uuid::new_v4(), "adm", "SuperAdmin"),
            (viewer_id, "vw", "Viewer"),
        ] {
            connection
                .execute(
                    "INSERT INTO users(id,normalized_login,display_login,password_hash,role,status,auth_epoch,created_at,updated_at)
                     VALUES (?1,?2,?2,NULL,?3,'active',0,'t','t')",
                    rusqlite::params![id.to_string(), login, role],
                )
                .unwrap();
        }
        for database_id in [db_a, db_b] {
            connection
                .execute(
                    "INSERT INTO databases(id,instance_id,display_label,mode,created_at,updated_at)
                     VALUES (?1,?1,'db','enabled','t','t')",
                    [database_id.to_string()],
                )
                .unwrap();
        }
        let has_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_database_access')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!has_table);
    }

    let storage = Arc::new(SqliteStorage::open(&path).unwrap());
    let (has_table, grants, has_column, applied_at): (bool, usize, bool, String) = storage
        .with_connection(|c| {
            let has_table: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_database_access')",
                [],
                |r| r.get(0),
            )?;
            let grants: usize = c.query_row(
                "SELECT COUNT(*) FROM user_database_access WHERE user_id=?1 AND granted_by IS NULL",
                [viewer_id.to_string()],
                |r| r.get(0),
            )?;
            let mut st = c.prepare("PRAGMA table_info(audit_events)")?;
            let names = st
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_column = names.iter().any(|name| name == "target_user_id");
            let applied_at: String = c.query_row(
                "SELECT applied_at FROM schema_migrations WHERE version=17",
                [],
                |r| r.get(0),
            )?;
            Ok((has_table, grants, has_column, applied_at))
        })
        .unwrap();
    assert!(has_table, "user_database_access не создана");
    assert_eq!(grants, 2, "Viewer не получил существующие базы");
    assert!(has_column, "audit_events.target_user_id не добавлена");
    assert_eq!(applied_at, "2026-09-26T13:58:00Z", "чужая запись version=17 перезаписана");

    // Повторный старт — идемпотентен.
    drop(storage);
    let storage = SqliteStorage::open(&path).unwrap();
    let grants: usize = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM user_database_access WHERE user_id=?1",
                [viewer_id.to_string()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(grants, 2);
}
