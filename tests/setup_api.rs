//++agent TASK-225 [26.09.2026]
//! B-4: HTTP-тесты setup/* маршрутов (спека §9) + по тесту на каждый
//! дефект UI-исполнителя D1–D5 (D6 — сторона t226).
//! Прогон — in-memory SQLite + реальный axum Router (сессия Admin).
//--agent TASK-225

mod common;

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chrono::Utc;
use onec_masking_service::{
    api::human::{self, HumanState, SqliteHumanDataStore},
    auth::{AuthProvider, AuthStore, IssuedSession, LocalAuthProvider, Role, SessionService},
    domain::MaskingService,
    SqliteStorage,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://masking.test";
const ADMIN_PASSWORD: &str = "correct horse battery staple";

fn test_app(
    storage: Arc<SqliteStorage>,
    auth: Arc<LocalAuthProvider>,
    sessions: Arc<SessionService>,
    masking: Arc<MaskingService>,
) -> axum::Router {
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

/// База + приложение + Admin-сессия (display_login пользователя — "Admin").
async fn fixture() -> (
    Arc<SqliteStorage>,
    Arc<LocalAuthProvider>,
    Arc<SessionService>,
    Arc<MaskingService>,
    axum::Router,
    IssuedSession,
    Uuid,
) {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let store: Arc<dyn AuthStore> = storage.clone();
    let auth = Arc::new(LocalAuthProvider::new(store.clone()).unwrap());
    let sessions = Arc::new(SessionService::new(store));
    auth.initialize().unwrap();
    auth.bootstrap_admin_password(ADMIN_PASSWORD).unwrap();
    let principal = auth
        .authenticate("setup-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let session = sessions.issue(principal, Utc::now()).unwrap();
    let masking = Arc::new(MaskingService::new(storage.clone()));
    let app = test_app(
        storage.clone(),
        auth.clone(),
        sessions.clone(),
        masking.clone(),
    );
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    (storage, auth, sessions, masking, app, session, database_id)
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

fn post(uri: &str, session: &IssuedSession, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn put(uri: &str, session: &IssuedSession, if_match: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .header("content-type", "application/json")
        .header(header::IF_MATCH, if_match.to_owned())
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn journal_count(storage: &SqliteStorage, database_id: Uuid) -> i64 {
    storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM setup_journal WHERE database_id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap()
}

/// Активная версия v1: словарь `part` с одним источником + правила,
/// заданные JSON-массивом `rules` (`policy_rules` со всеми NOT NULL
/// колонками — включая `created_at`; именно его пропуск давал D4=503).
fn seed_active(
    storage: &SqliteStorage,
    database_id: Uuid,
    rules: &[Value],
    dictionary: Value,
) -> Uuid {
    let policy_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO policies(id,database_id,version,status,dictionary_json,origin,created_at,updated_at,activated_at)
                 VALUES (?1,?2,1,'active',?3,'seed','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                rusqlite::params![
                    policy_id.to_string(),
                    database_id.to_string(),
                    serde_json::to_string(&dictionary).unwrap(),
                ],
            )?;
            c.execute(
                "UPDATE databases SET active_policy_id=?2 WHERE id=?1",
                rusqlite::params![database_id.to_string(), policy_id.to_string()],
            )?;
            for (index, rule) in rules.iter().enumerate() {
                c.execute(
                    "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,priority,enabled,reason,created_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'2026-01-01T00:00:00Z')",
                    rusqlite::params![
                        Uuid::new_v4().to_string(),
                        policy_id.to_string(),
                        rule["selector"].as_str().unwrap(),
                        rule["value"].as_str().unwrap(),
                        rule["action"].as_str().unwrap(),
                        rule["category"].as_str().unwrap(),
                        rule["priority"].as_i64().unwrap_or(index as i64),
                        rule["enabled"].as_bool().unwrap_or(true) as i64,
                        rule["reason"].as_str().unwrap_or("seed"),
                    ],
                )?;
            }
            Ok(())
        })
        .unwrap();
    policy_id
}

fn sample_source(path: &str, reason: &str) -> Value {
    json!({"source_path": path, "category": "pii", "reason": reason})
}

fn sample_rule(value: &str) -> Value {
    json!({
        "selector": "regex",
        "value": value,
        "action": "mask",
        "category": "pii",
        "priority": 10,
        "enabled": true,
        "reason": "тест",
        "tests": {"match": [value]},
    })
}

fn setup_file(database_id: Uuid, dictionary: Value, rules: Value) -> Value {
    json!({
        "schema": "masking-setup/v1",
        "generated_at": "2026-09-26T00:00:00Z",
        "generated_by": {"kind": "human", "name": "тест"},
        "database_hint": {"id": database_id.to_string()},
        "dictionary": dictionary,
        "rules": rules,
    })
}

// ------------------------------------------------------------------
// D4: черновик из активной / импорт / откат — с правилами НЕ 503.
// Регресс: write_version_content не писал created_at и копировал id.
// ------------------------------------------------------------------
#[tokio::test]
async fn d4_draft_import_rollback_with_rules_do_not_503() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[sample_rule("Иванов"), sample_rule("Петров")],
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","контрагенты")]}),
    );

    // Черновик-копия активной (два правила копируются — свежие id,
    // created_at заполнен).
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    let draft_version = body["draft_version"].as_i64().unwrap();
    assert_eq!(draft_version, 2);

    // Скопированные правила: id свежие (≠ исходным), created_at проставлен.
    storage
        .with_connection(|c| {
            let (count, fresh, created): (i64, i64, i64) = c.query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(r.id NOT IN (SELECT pr.id FROM policy_rules pr
                                                  JOIN policies p2 ON p2.id=pr.policy_id
                                                  WHERE p2.status='active')),0),
                        COALESCE(SUM(r.created_at IS NOT NULL),0)
                 FROM policy_rules r
                 JOIN policies p ON p.id=r.policy_id
                 WHERE p.database_id=?1 AND p.status='draft'",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(count, 2);
            assert_eq!(fresh, 2, "id скопированных правил должны быть новыми");
            assert_eq!(created, 2, "created_at обязателен (NOT NULL)");
            Ok(())
        })
        .unwrap();

    // Импорт файла с правилами → replace_draft → тоже 201, не 503.
    // Содержимое идентично v1 — последующая активация без ослаблений.
    let file = setup_file(
        database_id,
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","контрагенты")]}),
        json!([sample_rule("Иванов"), sample_rule("Петров")]),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports?replace_draft=1"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Откат возможен только с НЕактивной версии: активируем импортированный
    // черновик (v3) — v1 с правилами уходит в retired.
    let body = body_json(response).await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/activate"),
            &admin,
            &json!({
                "version": body["draft_version"].as_i64().unwrap(),
                "draft_hash": body["draft_hash"].as_str().unwrap(),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Откат retired v1 в черновик (правила копируются) — 201, не 503.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/rollback"),
            &admin,
            &json!({"version": 1, "replace_draft": true}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Правила из retired v1 снова скопированы — свежие id, created_at.
    storage
        .with_connection(|c| {
            let (count, fresh, created): (i64, i64, i64) = c.query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(r.id NOT IN (SELECT pr.id FROM policy_rules pr
                                                  JOIN policies p2 ON p2.id=pr.policy_id
                                                  WHERE p2.status IN ('active','retired'))),0),
                        COALESCE(SUM(r.created_at IS NOT NULL),0)
                 FROM policy_rules r
                 JOIN policies p ON p.id=r.policy_id
                 WHERE p.database_id=?1 AND p.status='draft'",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(count, 2);
            assert_eq!(fresh, 2, "id скопированных правил должны быть новыми");
            assert_eq!(created, 2);
            Ok(())
        })
        .unwrap();
}

// ------------------------------------------------------------------
// D5: PUT setup/draft/{dictionary|rules|tools} — полный §1-каркас
// синтетического файла: все области 200, а не 400 SETUP_INVALID.
// ------------------------------------------------------------------
#[tokio::test]
async fn d5_put_draft_areas_accept_valid_bodies() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    let draft = body_json(response).await;
    let mut hash = draft["draft_hash"].as_str().unwrap().to_owned();

    let base = format!("/api/v1/admin/databases/{database_id}/setup/draft");
    // dictionary
    let response = app
        .clone()
        .oneshot(put(
            &format!("{base}/dictionary"),
            &admin,
            &hash,
            &json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","D5")]})
                .to_string(),
        ))
        .await
        .unwrap();
    let status = response.status();
    let put_body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {put_body}");
    hash = put_body["draft_hash"].as_str().unwrap().to_owned();

    // rules
    let response = app
        .clone()
        .oneshot(put(
            &format!("{base}/rules"),
            &admin,
            &hash,
            &json!({"rules":[sample_rule("Иванов")]}).to_string(),
        ))
        .await
        .unwrap();
    let status = response.status();
    let put_body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {put_body}");
    hash = put_body["draft_hash"].as_str().unwrap().to_owned();

    // tools
    let response = app
        .clone()
        .oneshot(put(
            &format!("{base}/tools"),
            &admin,
            &hash,
            &json!({"tools":[{"tool":"execute_query","mode":"data-mask","reason":"D5"}]})
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Содержимое черновика: все три области применены.
    let stored = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT dictionary_json,tools_json FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
        })
        .unwrap();
    assert!(stored.0.contains("Справочник.Контрагенты"));
    assert!(stored.1.unwrap().contains("execute_query"));
}

// ------------------------------------------------------------------
// D1: журнал — 200 и actor.login из users.display_login (не u.login).
// ------------------------------------------------------------------
#[tokio::test]
async fn d1_journal_returns_actor_login() {
    let (_storage, _, _, _, app, admin, database_id) = fixture().await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/journal"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let entries = body_json(response).await;
    let entries = entries.as_array().unwrap();
    assert!(!entries.is_empty());
    assert_eq!(entries[0]["action"], "draft_create");
    assert_eq!(entries[0]["actor"]["kind"], "human");
    assert_eq!(entries[0]["actor"]["login"], "Admin");
}

// ------------------------------------------------------------------
// D2: список версий (автор/дата) + чтение версии — без записи в журнал.
// ------------------------------------------------------------------
#[tokio::test]
async fn d2_version_list_and_read_do_not_journal() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let before = journal_count(&storage, database_id);

    // Список: версия, статус, автор, даты.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/versions"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list = body_json(response).await;
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1);
    let row = &list[0];
    assert_eq!(row["version"], 1);
    assert_eq!(row["status"], "draft");
    assert!(row["created_at"].as_str().is_some());
    assert!(row["updated_at"].as_str().is_some());
    assert_eq!(row["created_by"]["login"], "Admin");
    assert!(row["content_hash"].as_str().is_some_and(|s| !s.is_empty()));

    // Чтение конкретной версии: контент §1 + статус, без journal/audit.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/versions/1"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let file = body_json(response).await;
    assert_eq!(file["schema"], "masking-setup/v1");
    assert_eq!(file["status"], "draft");
    assert!(file["dictionary"].is_object());
    assert!(file["rules"].is_array());

    assert_eq!(
        journal_count(&storage, database_id),
        before,
        "просмотр версий не пишет журнал"
    );
    let audit_rows: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE database_id=?1 AND action LIKE 'setup.version%'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(audit_rows, 0, "просмотр версий не аудируется");
}

// ------------------------------------------------------------------
// D3: dry-run — маскированная сетка: координаты и статусы, без значений.
// ------------------------------------------------------------------
#[tokio::test]
async fn d3_dry_run_returns_masked_grid_without_values() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    // Активная v1 без правил; черновик добавляет mask regex «Иванов».
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let draft = body_json(response).await;
    let hash = draft["draft_hash"].as_str().unwrap().to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/rules"),
            &admin,
            &hash,
            &json!({"rules":[sample_rule("Иванов")]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Запись истории tool_result с lineage: открытое значение «Иванов».
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                        mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?4,'execute_query','tool_result',1,'[]',?3,'{}',
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,'{}')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    serde_json::to_string(&json!({
                        "content":[{"type":"json","json":{"rows":[["Иванов Петров"]],"columns":["fio"]}}]
                    }))
                    .unwrap(),
                    Uuid::new_v4().to_string(),
                ],
            )
        })
        .unwrap();

    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/dry-run"),
            &admin,
            &json!({"version":"draft"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(
        !serialized.contains("Иванов"),
        "dry-run не должен выдавать исходные значения: {serialized}"
    );
    assert!(body["version"].is_i64());
    assert!(body["timing"].is_object());
    assert!(body["dictionary_not_loaded"].is_array());
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    let grid = &records[0]["grid"];
    assert!(grid["columns"].is_array());
    let cells = grid["cells"].as_array().unwrap();
    assert!(!cells.is_empty(), "grid должен содержать ячейки");
    // Ячейки — только координаты и статусы: ни value, ни токена.
    for cell in cells {
        assert!(cell.get("value").is_none());
        assert!(cell.get("token").is_none());
        assert!(cell["before"].is_string() && cell["after"].is_string());
    }
    // «Иванов» открыт в активной и маскируется черновиком → became_masked.
    assert!(cells
        .iter()
        .any(|cell| cell["before"] == "open" && cell["after"] == "masked"));
    assert!(records[0]["became_masked"].as_u64().unwrap() >= 1);
}

// ------------------------------------------------------------------
// B-4/T1: импорт валидного файла → 201 + counts; невалидный → 400
// SETUP_INVALID без черновика; импорт при существующем → 409 DRAFT_EXISTS.
// ------------------------------------------------------------------
#[tokio::test]
async fn t1_import_valid_invalid_and_draft_exists() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let file = setup_file(
        database_id,
        json!({"mode":"part","sources":[
            sample_source("Справочник.Контрагенты","к1"),
            sample_source("Справочник.Пользователи","к2"),
        ]}),
        json!([
            sample_rule("Иванов"),
            sample_rule("Петров"),
            sample_rule("Сидоров")
        ]),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    assert_eq!(body["draft_version"], 1);
    assert_eq!(body["counts"]["sources"], 2);
    assert_eq!(body["counts"]["rules"], 3);
    assert!(body["sha256"].as_str().is_some_and(|s| s.len() == 64));

    // Повторный импорт без replace_draft → 409 DRAFT_EXISTS.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(response).await["error"]["code"], "DRAFT_EXISTS");

    // Невалидный файл → 400 SETUP_INVALID; черновик не создаётся.
    let bad = json!({
        "schema": "masking-setup/v1",
        "generated_at": "2026-09-26T00:00:00Z",
        "generated_by": {"kind":"user"},
        "dictionary": {"mode":"part","sources":[]},
        "rules": [{"selector":"bogus","value":"x","action":"mask","category":"c","priority":1,"enabled":true,"reason":"r"}],
    });
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports?replace_draft=1"),
            &admin,
            &serde_json::to_string(&bad).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "SETUP_INVALID");
    let drafts: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        drafts, 1,
        "старый черновик остаётся (импорт отклонён до записи)"
    );
}

// ------------------------------------------------------------------
// B-4/T3: diff — удалённый источник = weakening SOURCE_REMOVED.
// ------------------------------------------------------------------
#[tokio::test]
async fn t3_diff_marks_removed_source_weakening() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","a")]}),
    );
    // Черновик из активной + замена словаря на пустой → SOURCE_REMOVED.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/dictionary"),
            &admin,
            &hash,
            &json!({"mode":"part","sources":[]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let diff = body_json(response).await;
    assert_eq!(diff["from_version"], 1);
    assert_eq!(diff["counts"]["weakening"].as_u64().unwrap(), 1);
    let change = &diff["changes"][0];
    assert_eq!(change["kind"], "SOURCE_REMOVED");
    assert_eq!(change["class"], "weakening");
    assert!(change["id"].as_str().is_some_and(|s| !s.is_empty()));
}

// ------------------------------------------------------------------
// B-4/T4: активация — ослабления требуют confirmed_weakenings;
// неверный draft_hash → DRAFT_CHANGED; после подтверждения — 200.
// ------------------------------------------------------------------
#[tokio::test]
async fn t4_activate_confirms_weakenings_and_checks_hash() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","a")]}),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/dictionary"),
            &admin,
            &hash,
            &json!({"mode":"part","sources":[]}).to_string(),
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();

    // Без подтверждений → 409 WEAKENING_NOT_CONFIRMED {missing}.
    let activate_uri = format!("/api/v1/admin/databases/{database_id}/setup/activate");
    let response = app
        .clone()
        .oneshot(post(
            &activate_uri,
            &admin,
            &json!({"version": 2, "draft_hash": hash}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "WEAKENING_NOT_CONFIRMED");
    let missing = body["error"]["details"]["missing"].as_array().unwrap();
    assert_eq!(missing.len(), 1);

    // Неверный hash → 409 DRAFT_CHANGED.
    let response = app
        .clone()
        .oneshot(post(
            &activate_uri,
            &admin,
            &json!({
                "version": 2,
                "draft_hash": "0000",
                "confirmed_weakenings": missing,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(response).await["error"]["code"], "DRAFT_CHANGED");

    // С подтверждением → 200, прежняя версия уходит в retired.
    let response = app
        .clone()
        .oneshot(post(
            &activate_uri,
            &admin,
            &json!({
                "version": 2,
                "draft_hash": hash,
                "confirmed_weakenings": missing,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["active_version"], 2);
    let statuses: Vec<String> = storage
        .with_connection(|c| {
            let mut s =
                c.prepare("SELECT status FROM policies WHERE database_id=?1 ORDER BY version")?;
            let rows = s
                .query_map([database_id.to_string()], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(statuses, ["retired", "active"]);
}

// ------------------------------------------------------------------
// B-4/T4-11: PUT области без If-Match → 428; устаревший → 409+current_hash.
// ------------------------------------------------------------------
#[tokio::test]
async fn t4_11_if_match_required_and_stale_conflict() {
    let (_, _, _, _, app, admin, database_id) = fixture().await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let uri = format!("/api/v1/admin/databases/{database_id}/setup/draft/rules");

    // Без If-Match → 428 PRECONDITION_REQUIRED.
    let request = Request::builder()
        .method("PUT")
        .uri(&uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .header("content-type", "application/json")
        .body(Body::from(json!({"rules":[]}).to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

    // Устаревший hash → 409 с current_hash.
    let response = app
        .clone()
        .oneshot(put(
            &uri,
            &admin,
            "stale-hash",
            &json!({"rules":[]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(body["error"]["details"]["current_hash"], hash);
}

// ------------------------------------------------------------------
// B-4/T4-10: Viewer на изменяющих маршрутах → 403.
// ------------------------------------------------------------------
#[tokio::test]
async fn t4_10_viewer_forbidden_on_setup_mutations() {
    let (storage, auth, sessions, _, app, admin, database_id) = fixture().await;
    let (_, activation) = auth
        .create_user(
            &auth
                .authenticate("mk-viewer", "admin", ADMIN_PASSWORD)
                .unwrap(),
            "viewer-d2",
            Role::Viewer, &[],
            Uuid::new_v4(),
        )
        .unwrap();
    auth.activate("viewer-d2", &activation, "viewer passphrase unique")
        .unwrap();
    let viewer_principal = auth
        .authenticate("viewer-d2-login", "viewer-d2", "viewer passphrase unique")
        .unwrap();
    let viewer = sessions.issue(viewer_principal, Utc::now()).unwrap();

    for request in [
        post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &viewer,
            r#"{"from":"empty"}"#,
        ),
        post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &viewer,
            "{}",
        ),
        post(
            &format!("/api/v1/admin/databases/{database_id}/setup/dry-run"),
            &viewer,
            "{}",
        ),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let _ = storage;
    let _ = admin;
}

// ------------------------------------------------------------------
// M-4: legacy PUT dictionaries/{id} — правка уходит в черновик,
// ответ содержит draft_version; активная версия не трогается.
// ------------------------------------------------------------------
#[tokio::test]
async fn m4_legacy_put_dictionaries_writes_draft() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[sample_source("Справочник.Старое","s")]}),
    );
    let response = app
        .clone()
        .oneshot(put(
            &format!(
                "/api/v1/admin/databases/{database_id}/dictionaries/{}",
                Uuid::new_v4()
            ),
            &admin,
            "*",
            &json!({
                "id": Uuid::new_v4(),
                "mode": "part",
                "selectors": [{
                    "source_path": "Справочник.Новое",
                    "category": "pii",
                    "filter_ast": null,
                }],
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["draft_version"].as_i64().unwrap() >= 2);

    // Черновик — копия активной с новым словарём; активная не изменилась.
    let (active_dict, draft_dict): (String, String) = storage
        .with_connection(|c| {
            let active: String = c.query_row(
                "SELECT dictionary_json FROM policies WHERE database_id=?1 AND status='active'",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            let draft: String = c.query_row(
                "SELECT dictionary_json FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            Ok((active, draft))
        })
        .unwrap();
    assert!(active_dict.contains("Справочник.Старое"));
    assert!(draft_dict.contains("Справочник.Новое"));
    assert!(!draft_dict.contains("Справочник.Старое"));
}

// ------------------------------------------------------------------
// M-5: legacy POST policies/{id}/activate — только draft; retired → 409.
// ------------------------------------------------------------------
#[tokio::test]
async fn m5_legacy_activate_accepts_only_draft() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let retired_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO policies(id,database_id,version,status,dictionary_json,origin,created_at)
                 VALUES (?1,?2,9,'retired','{}','seed','2026-01-01T00:00:00Z')",
                rusqlite::params![retired_id.to_string(), database_id.to_string()],
            )
        })
        .unwrap();
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/policies/{retired_id}/activate"),
            &admin,
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ------------------------------------------------------------------
// B-4/T8-02: PUT tools no-mask без confirm_bypass → 400.
// ------------------------------------------------------------------
#[tokio::test]
async fn t8_tool_classification_bypass_requires_confirm() {
    let (_, _, _, _, app, admin, database_id) = fixture().await;
    let uri = format!("/api/v1/admin/databases/{database_id}/tools/execute_query");
    // no-mask без подтверждения → 400 BYPASS_NOT_CONFIRMED.
    let response = app
        .clone()
        .oneshot(put(
            &uri,
            &admin,
            "*",
            &json!({"class":"no-mask","confirm_bypass":false}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["error"]["code"],
        "BYPASS_NOT_CONFIRMED"
    );
    // data-mask — без подтверждения проходит.
    let response = app
        .clone()
        .oneshot(put(
            &uri,
            &admin,
            "*",
            &json!({"class":"data-mask","confirm_bypass":false}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// Review BLOCKER регрессия: GET history/{id}/reasons не должен
// дедлочить общее соединение (history_reasons_record берёт тот же
// мьютекс — вызов обязан идти ВНЕ with_connection-обёртки хендлера).
#[tokio::test]
async fn history_reasons_returns_row_and_does_not_deadlock() {
    let (storage, auth, sessions, _, app, _, database_id) = fixture().await;
    // Маршрут — Viewer-уровень: заводим отдельную viewer-сессию.
    let admin = auth
        .authenticate("setup-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin, "viewer", Role::Viewer, &[database_id], Uuid::new_v4())
        .unwrap();
    auth.activate("test", &activation, "viewer passphrase t225")
        .unwrap();
    let viewer = auth
        .authenticate("setup-api-viewer", "viewer", "viewer passphrase t225")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();
    let history_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                        mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?3,'execute_query','tool_result',1,
                        '[\"dictionary:ORG\"]','{}','{}',
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,'{}')",
                rusqlite::params![
                    history_id.to_string(),
                    database_id.to_string(),
                    Uuid::new_v4().to_string(),
                ],
            )
        })
        .unwrap();
    // Запрос под соединением в руках ничего не блокирует — отвечает 200.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/history/{history_id}/reasons"),
            &viewer_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["legacy_reasons"], json!(["dictionary:ORG"]), "{body}");

    // Отсутствующая запись — 404, не 503.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/history/{}/reasons", Uuid::new_v4()),
            &viewer_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ==================================================================
// Ревью-2: B-1 (legacy activate без активной версии), T4-03
// STALE_CONFIRMATION, T4-04a WARNING_NOT_EXCLUDABLE, T6 dry-run,
// T7 детальные причины.
// ==================================================================

// ------------------------------------------------------------------
// B-1: активной версии нет; черновик с keep-правилом = ослабление от
// empty_content → legacy /policies/{id}/activate отдаёт 409
// WEAKENING_NOT_CONFIRMED (барьер не отключается отсутствием активной).
// ------------------------------------------------------------------
#[tokio::test]
async fn b1_legacy_activate_rejects_weakening_without_active() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/rules"),
            &admin,
            &hash,
            &json!({"rules":[{
                "selector":"name","value":"ФИО","action":"keep",
                "category":"pii","priority":10,"enabled":true,"reason":"тест"
            }]})
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let draft_id: String = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT id FROM policies WHERE database_id=?1 AND status='draft'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();

    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/policies/{draft_id}/activate"),
            &admin,
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "WEAKENING_NOT_CONFIRMED");
    let missing = body["error"]["details"]["missing"].as_array().unwrap();
    assert!(!missing.is_empty(), "ослабление keep должно быть в missing");
}

// ------------------------------------------------------------------
// T4-03: id не из текущего diff в любом из трёх списков подтверждений →
// 409 STALE_CONFIRMATION {unknown}; проверка идёт до WEAKENING_NOT_CONFIRMED.
// ------------------------------------------------------------------
#[tokio::test]
async fn t4_03_stale_confirmation_for_unknown_ids() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    // Активная v1 с источником; черновик без источников → SOURCE_REMOVED
    // (реальное ослабление — показывает порядок проверок: STALE раньше WNC).
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","a")]}),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/dictionary"),
            &admin,
            &hash,
            &json!({"mode":"part","sources":[]}).to_string(),
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let activate_uri = format!("/api/v1/admin/databases/{database_id}/setup/activate");
    let post_activate = |body: Value| {
        let app = app.clone();
        let admin = admin.clone();
        let uri = activate_uri.clone();
        async move {
            let response = app
                .oneshot(post(&uri, &admin, &body.to_string()))
                .await
                .unwrap();
            (response.status(), body_json(response).await)
        }
    };

    // Чужой id в confirmed_weakenings → STALE {unknown}, а не WNC.
    let (status, body) =
        post_activate(json!({"version":2,"draft_hash":hash,"confirmed_weakenings":["c_bogus"]}))
            .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "STALE_CONFIRMATION");
    assert_eq!(body["error"]["details"]["unknown"], json!(["c_bogus"]));

    // Чужой id в accepted_strengthenings → тот же STALE.
    let (status, body) = post_activate(
        json!({"version":2,"draft_hash":hash,"accepted_strengthenings":["c_bogus2"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "STALE_CONFIRMATION");
    assert_eq!(body["error"]["details"]["unknown"], json!(["c_bogus2"]));

    // Чужой id в excluded_warnings → STALE (реальные предупреждения
    // есть — MANIFEST_UNAVAILABLE в тестовом окружении без manifest).
    let (status, body) =
        post_activate(json!({"version":2,"draft_hash":hash,"excluded_warnings":["w_bogus"]})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "STALE_CONFIRMATION");
    assert_eq!(body["error"]["details"]["unknown"], json!(["w_bogus"]));
}

// ------------------------------------------------------------------
// T4-04a: предупреждение без excludable → 400 WARNING_NOT_EXCLUDABLE;
// исключаемое (PATH_NOT_IN_MANIFEST) удаляет элемент из итогового
// содержимого → активация проходит и источника в активной нет.
// ------------------------------------------------------------------
#[tokio::test]
async fn t4_04a_warning_exclusion_semantics() {
    let (storage, _, _, masking, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    // Источник с путём вне manifest → после посева manifest это
    // PATH_NOT_IN_MANIFEST (excludable); до посева — только
    // MANIFEST_UNAVAILABLE (неисключаемое).
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/dictionary"),
            &admin,
            &hash,
            &json!({"mode":"part","sources":[
                sample_source("Справочник.НесуществующийОбъект","a")
            ]})
            .to_string(),
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();

    let diff = |app: axum::Router, admin: IssuedSession| async move {
        let response = app
            .oneshot(get(
                &format!("/api/v1/admin/databases/{database_id}/setup/diff"),
                &admin,
            ))
            .await
            .unwrap();
        body_json(response).await["warnings"]
            .as_array()
            .unwrap()
            .clone()
    };
    let warning_id = |warnings: &[Value], kind: &str| {
        warnings
            .iter()
            .find(|w| w["kind"] == kind)
            .unwrap_or_else(|| panic!("warning {kind} отсутствует: {warnings:?}"))["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // Фаза 1: manifest не засеян → единственное предупреждение
    // MANIFEST_UNAVAILABLE (excludable:false) → 400 WARNING_NOT_EXCLUDABLE.
    let warnings = diff(app.clone(), admin.clone()).await;
    assert!(warnings
        .iter()
        .any(|w| w["kind"] == "MANIFEST_UNAVAILABLE" && w["excludable"] == false));
    let manifest_unavailable = warning_id(&warnings, "MANIFEST_UNAVAILABLE");
    let activate_uri = format!("/api/v1/admin/databases/{database_id}/setup/activate");
    let response = app
        .clone()
        .oneshot(post(
            &activate_uri,
            &admin,
            &json!({
                "version":2,
                "draft_hash":hash,
                "excluded_warnings":[manifest_unavailable],
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "WARNING_NOT_EXCLUDABLE");

    // Фаза 2: manifest без пути источника → PATH_NOT_IN_MANIFEST
    // (excludable) → исключение убирает источник, активация проходит.
    assert!(masking.seed_metadata_manifest(
        database_id,
        vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Справочник.Контрагенты.ИНН".into(),
            field_name: "ИНН".into(),
            field_type: "String(12)".into(),
            password_mode: false,
        }],
    ));
    let warnings = diff(app.clone(), admin.clone()).await;
    assert!(warnings
        .iter()
        .any(|w| w["kind"] == "PATH_NOT_IN_MANIFEST" && w["excludable"] == true));
    let path_not_in_manifest = warning_id(&warnings, "PATH_NOT_IN_MANIFEST");
    let response = app
        .clone()
        .oneshot(post(
            &activate_uri,
            &admin,
            &json!({
                "version":2,
                "draft_hash":hash,
                "excluded_warnings":[path_not_in_manifest],
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sources: Vec<String> = storage
        .with_connection(|c| {
            let json: String = c.query_row(
                "SELECT dictionary_json FROM policies WHERE database_id=?1 AND status='active'",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(json)
        })
        .map(|text| {
            let value: Value = serde_json::from_str(&text).unwrap();
            value["sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["source_path"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap();
    assert!(
        !sources
            .iter()
            .any(|p| p == "Справочник.НесуществующийОбъект"),
        "исключённый источник не должен попасть в активную версию: {sources:?}"
    );
}

// ------------------------------------------------------------------
// T6-03: истории нет → history_empty:true + reason no_records; записи
// без lineage (field_sources_json NULL) → no_lineage.
// ------------------------------------------------------------------
#[tokio::test]
async fn t6_dry_run_empty_history_reasons() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let dry_run_uri = format!("/api/v1/admin/databases/{database_id}/setup/dry-run");

    let response = app
        .clone()
        .oneshot(post(
            &dry_run_uri,
            &admin,
            &json!({"version":"active"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["history_empty"], true);
    assert_eq!(body["reason"], "no_records");

    // Запись tool_result без field_sources → no_lineage.
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                        mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?4,'execute_query','tool_result',1,'[]','{}','{}',
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,NULL)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    "",
                    Uuid::new_v4().to_string(),
                ],
            )
        })
        .unwrap();
    let response = app
        .clone()
        .oneshot(post(
            &dry_run_uri,
            &admin,
            &json!({"version":"active"}).to_string(),
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert_eq!(body["history_empty"], true);
    assert_eq!(body["reason"], "no_lineage");
}

// ------------------------------------------------------------------
// T6-04/T6-05: запись с истёкшим mapping-батчем → skipped +
// reason mapping_expired; сухой прогон не пишет новых записей истории.
// ------------------------------------------------------------------
#[tokio::test]
async fn t6_dry_run_skips_expired_mapping_without_writes() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let history_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                        mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?4,'execute_query','tool_result',1,'[]',?3,'{}',
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',?5,'{}')",
                rusqlite::params![
                    history_id.to_string(),
                    database_id.to_string(),
                    serde_json::to_string(&json!({
                        "content":[{"type":"json","json":{"rows":[["[MASK:v1:FIO:abcdefghijklmnopqrstuvwxyz123456]"]],"columns":["fio"]}}]
                    }))
                    .unwrap(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                ],
            )
        })
        .unwrap();
    let history_count = |storage: &SqliteStorage| -> i64 {
        storage
            .with_connection(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM history WHERE database_id=?1",
                    [database_id.to_string()],
                    |row| row.get(0),
                )
            })
            .unwrap()
    };
    let before = history_count(&storage);

    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/dry-run"),
            &admin,
            &json!({"version":"active"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let skipped = body["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["history_id"], history_id.to_string());
    assert_eq!(skipped[0]["reason"], "mapping_expired");
    assert_eq!(body["checked"], 1);
    assert!(body["records"].as_array().unwrap().is_empty());
    // Сухой прогон не создаёт записей истории (§5.4: ни истории, ни
    // публикации токенов в боевой mapping).
    assert_eq!(history_count(&storage), before);
}

// ------------------------------------------------------------------
// T7-01/T7-03: запись с mask_detail → detailed:true; причины с idx,
// kind/code, rule_id, счётчиком cells; ячейки по (block,row,col) с
// именем колонки и отсортированными reason_idx; truncated проксируется.
// ------------------------------------------------------------------
#[tokio::test]
async fn t7_reasons_detailed_cells_and_rule_ids() {
    let (storage, auth, sessions, _, app, _, database_id) = fixture().await;
    // Маршрут — Viewer-уровень: заводим отдельную viewer-сессию.
    let admin_principal = auth
        .authenticate("setup-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin_principal, "viewer-t7", Role::Viewer, &[database_id], Uuid::new_v4())
        .unwrap();
    auth.activate("viewer-t7", &activation, "viewer passphrase t7")
        .unwrap();
    let viewer = auth
        .authenticate("viewer-t7-login", "viewer-t7", "viewer passphrase t7")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let history_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,mask_detail_json,public_result_json,report_json,
                        created_at,expires_at,mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?3,'execute_query','tool_result',1,'[]',?4,'{}',?5,
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,'{}')",
                rusqlite::params![
                    history_id.to_string(),
                    database_id.to_string(),
                    Uuid::new_v4().to_string(),
                    serde_json::to_string(&json!({
                        "reasons": [
                            {"kind":"rule","code":"mask","rule_id":"rule-abc","category":"pii",
                             "selector":"literal","pattern":"Иванов","cells":1},
                            {"kind":"dictionary","code":"dict_hit","source_path":"Справочник.Контрагенты.ИНН","cells":1},
                            {"kind":"secret","code":"embedded","cells":1}
                        ],
                        "cells": [[0,0,0,0],[0,0,1,1],[0,0,1,2]],
                        "truncated": true
                    }))
                    .unwrap(),
                    serde_json::to_string(&json!({
                        "blocks":[{"columns":[{"id":"fio"},{"id":"inn"}]}]
                    }))
                    .unwrap(),
                ],
            )
        })
        .unwrap();

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/history/{history_id}/reasons"),
            &viewer_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["detailed"], true);
    assert_eq!(body["truncated"], true);

    let reasons = body["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 3);
    assert_eq!(reasons[0]["idx"], 0);
    assert_eq!(reasons[0]["kind"], "rule");
    assert_eq!(reasons[0]["rule_id"], "rule-abc");
    assert_eq!(reasons[0]["cells"], 1);
    assert_eq!(reasons[1]["source_path"], "Справочник.Контрагенты.ИНН");
    for reason in reasons {
        assert!(reason["label"].is_string());
    }
    // link.admin_path: rule → по rule_id, dictionary → по source_path,
    // secret → null (§6.3).
    let rule_link = reasons[0]["link"]["admin_path"].as_str().unwrap();
    assert!(rule_link.contains("rule=rule-abc"), "{rule_link}");
    let dict_link = reasons[1]["link"]["admin_path"].as_str().unwrap();
    assert!(dict_link.contains("source="), "{dict_link}");
    assert!(reasons[2]["link"].is_null());

    let cells = body["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 2);
    assert_eq!(cells[0]["column"], "fio");
    assert_eq!(cells[0]["reasons"], json!([0]));
    assert_eq!(cells[1]["column"], "inn");
    assert_eq!(cells[1]["reasons"], json!([1, 2]));
}

// ------------------------------------------------------------------
// Ревью-2 N-4: legacy activate целевой версии не существует → 404,
// а не молчаливый проход барьера ослабления.
// ------------------------------------------------------------------
#[tokio::test]
async fn n4_legacy_activate_missing_version_returns_404() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let missing = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/policies/{missing}/activate"),
            &admin,
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Активная версия не тронута — барьер не пропускал активацию.
    let active: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM policies WHERE database_id=?1 AND status='active'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(active, 1);
}

// ------------------------------------------------------------------
// T6-01/T6-02/T6-06..T6-08: прогон ограничен limit'ом (50 из 55), keep
// в черновике → became_open, [SECRET_REMOVED] → unevaluable, сухой
// прогон не пишет историю и не публикует боевые токены, тайминги и
// top_sources присутствуют, исходные значения в ответ не попадают.
// ------------------------------------------------------------------
#[tokio::test]
async fn t6_dry_run_bounded_keep_secret_and_no_writes() {
    use onec_masking_service::domain::{
        DatabaseMode, FieldSources, FinalizeOutcome, FinalizeRequest, PolicyRule, PolicySnapshot,
        RuleAction, RuleSelector, SCHEMA_VERSION,
    };

    let (storage, _, _, masking, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    // Токены чеканятся только в режиме Enabled + ready-снимок политики
    // (ready публикует только pull — как в бою).
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    let _manager = common::FakeManager::spawn(common::empty_feed_responder);
    common::enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        masking
            .refresh_due_intents(&_manager.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(masking.database_ready(database_id).await);
    // Активная политика движка: name-правило маскирует колонку ИНН.
    masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                version: 1,
                ready: true,
                rules: vec![PolicyRule {
                    selector: RuleSelector::Name,
                    pattern: "ИНН".to_owned(),
                    action: RuleAction::Mask,
                    category: "pii".to_owned(),
                    priority: 10,
                    rule_id: None,
                }],
                ..PolicySnapshot::default()
            },
        )
        .await;

    // Реальная финализация → запись истории с токеном, батчем и
    // field_sources — dry-run сможет разрешить токен по батчу.
    let minted = masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            identity: common::test_identity(database_id),
            chat_id: "chat".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"data":[{"ИНН":"7707083893"}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":"ИНН","sources":["Справочник.Контрагенты.ИНН"]}]}),
                lineage: vec![json!({"column":"ИНН","source_path":"Справочник.Контрагенты.ИНН"})],
            },
        })
        .await
        .unwrap();
    assert!(serde_json::to_string(&minted.public_result)
        .unwrap()
        .contains("[MASK:v1:"));

    // Ещё 54 записи с lineage (итого 55 > limit 50) + одна с
    // [SECRET_REMOVED] — необратимая ячейка неоценима.
    storage
        .with_connection(|c| {
            for _ in 0..54 {
                c.execute(
                    "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                            mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                            mapping_batch_id,field_sources_json)
                     VALUES (?1,?2,'chat',?4,'execute_query','tool_result',1,'[]',?3,'{}',
                            '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,'{}')",
                    rusqlite::params![
                        Uuid::new_v4().to_string(),
                        database_id.to_string(),
                        serde_json::to_string(&json!({
                            "content":[{"type":"text","text":"{\"rows\":[[\"открыто\"]]}"}]
                        }))
                        .unwrap(),
                        Uuid::new_v4().to_string(),
                    ],
                )?;
            }
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,public_result_json,report_json,created_at,expires_at,
                        mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?4,'execute_query','tool_result',1,'[]',?3,'{}',
                        '2026-01-02T00:00:01Z','2999-01-01T00:00:00Z',NULL,'{}')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    serde_json::to_string(&json!({
                        "content":[{"type":"text","text":"{\"rows\":[[\"[SECRET_REMOVED]\"]]}"}]
                    }))
                    .unwrap(),
                    Uuid::new_v4().to_string(),
                ],
            )?;
            Ok(())
        })
        .unwrap();

    // Черновик: keep name-правило на ИНН → ячейка токена открывается.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/rules"),
            &admin,
            &hash,
            &json!({"rules":[{
                "selector":"name","value":"ИНН","action":"keep",
                "category":"pii","priority":10,"enabled":true,"reason":"keep"
            }]})
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let history_count = || -> i64 {
        storage
            .with_connection(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM history WHERE database_id=?1",
                    [database_id.to_string()],
                    |row| row.get(0),
                )
            })
            .unwrap()
    };
    let before_history = history_count();
    let before_mappings = masking.mapping_count().await;

    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/dry-run"),
            &admin,
            &json!({"version":"draft"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let text = body.to_string();

    // Ограничение прогона: 55 записей → 50 проверенных.
    assert_eq!(body["checked"], 50);
    assert_eq!(body["records"].as_array().unwrap().len(), 50);
    // keep открыл ячейку токена; [SECRET_REMOVED] необратим.
    assert!(
        body["totals"]["became_open"].as_u64().unwrap() >= 1,
        "{text}"
    );
    assert!(
        body["totals"]["unevaluable_cells"].as_u64().unwrap() >= 1,
        "{text}"
    );
    // Тайминги и топ источников присутствуют (§5).
    assert!(body["timing"]["budget_ms"].is_f64(), "{text}");
    assert!(body["timing"]["active"]["median_ms"].is_f64(), "{text}");
    assert!(body["timing"]["top_sources"].is_array(), "{text}");
    assert!(
        body["timing"]["dictionary_memory"]["active_bytes"].is_u64(),
        "{text}"
    );
    // Исходное значение не утекает в отчёт.
    assert!(!text.contains("7707083893"), "{text}");
    // Сухой прогон не пишет историю и не публикует токены.
    assert_eq!(history_count(), before_history);
    assert_eq!(masking.mapping_count().await, before_mappings);
}

// ------------------------------------------------------------------
// T7-02: запись без mask_detail (наследие до §6.1) → detailed:false и
// legacy_reasons из mask_reasons_json.
// ------------------------------------------------------------------
#[tokio::test]
async fn t7_reasons_legacy_row_returns_legacy_reasons() {
    let (storage, auth, sessions, _, app, _, database_id) = fixture().await;
    let admin_principal = auth
        .authenticate("setup-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin_principal, "viewer-t7l", Role::Viewer, &[database_id], Uuid::new_v4())
        .unwrap();
    auth.activate("viewer-t7l", &activation, "viewer passphrase t7l")
        .unwrap();
    let viewer = auth
        .authenticate("viewer-t7l-login", "viewer-t7l", "viewer passphrase t7l")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let history_id = Uuid::new_v4();
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                        mask_reasons_json,mask_detail_json,public_result_json,report_json,
                        created_at,expires_at,mapping_batch_id,field_sources_json)
                 VALUES (?1,?2,'chat',?3,'execute_query','tool_result',1,?4,NULL,'{}','{}',
                        '2026-01-02T00:00:00Z','2999-01-01T00:00:00Z',NULL,'{}')",
                rusqlite::params![
                    history_id.to_string(),
                    database_id.to_string(),
                    Uuid::new_v4().to_string(),
                    serde_json::to_string(&json!(["dictionary:pii","mandatory:fio:name"])).unwrap(),
                ],
            )
        })
        .unwrap();
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/history/{history_id}/reasons"),
            &viewer_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["detailed"], false);
    assert_eq!(
        body["legacy_reasons"],
        json!(["dictionary:pii", "mandatory:fio:name"])
    );
}

// ------------------------------------------------------------------
// D7: stored `"filter_ast":null` → экспорт без ключа filter, импорт
// того же файла принят (round-trip); явный `filter:null` в файле —
// тоже отсутствие фильтра.
// ------------------------------------------------------------------
#[tokio::test]
async fn d7_export_import_filter_null_round_trip() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[
            {"source_path":"Справочник.Контрагенты.ИНН","category":"inn",
             "filter_ast":null,"reason":"x"}
        ]}),
    );

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/export"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let file = body_json(response).await;
    let source = &file["dictionary"]["sources"][0];
    assert_eq!(source["source_path"], "Справочник.Контрагенты.ИНН");
    assert!(
        !source.as_object().unwrap().contains_key("filter"),
        "stored filter_ast:null не должен доезжать до экспорта: {source}"
    );

    // Импорт экспортированного файла без правок → принят.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &file.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Файл с явным `"filter":null` (внешний редактор/старая выгрузка) —
    // тот же round-trip, принят.
    let mut with_null = file;
    with_null["dictionary"]["sources"][0]
        .as_object_mut()
        .unwrap()
        .insert("filter".to_string(), Value::Null);
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports?replace_draft=1"),
            &admin,
            &with_null.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    // В черновике фильтр не появился.
    let draft_filter: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM policies p
                    WHERE p.database_id=?1 AND p.status='draft'
                      AND json_extract(p.dictionary_json,'$.sources[0].filter_ast') IS NOT NULL)",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(draft_filter, 0);
}

// ------------------------------------------------------------------
// D8a: `GET /setup/versions/{n}` — правила несут rule_id (связка с
// причинами B9); в файле экспорта id по-прежнему отсутствуют (§1.1).
// ------------------------------------------------------------------
#[tokio::test]
async fn d8_version_content_carries_rule_id() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let policy_id = seed_active(
        &storage,
        database_id,
        &[sample_rule("Иванов")],
        json!({"mode":"part","sources":[]}),
    );
    let db_rule_id: String = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT id FROM policy_rules WHERE policy_id=?1",
                [policy_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/versions/1"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["rules"][0]["rule_id"], db_rule_id);

    // Экспорт того же содержимого — без внутренних id.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/export"),
            &admin,
        ))
        .await
        .unwrap();
    let file = body_json(response).await;
    assert!(
        !file["rules"][0]
            .as_object()
            .unwrap()
            .contains_key("rule_id"),
        "§1.1: в файле внутренних id быть не должно: {}",
        file["rules"][0]
    );
}

// ------------------------------------------------------------------
// D8b: причина kind=dictionary несёт source_path источника (§6.3) —
// из FeedDictionaryValue.source_path при pull; link строится по пути.
// ------------------------------------------------------------------
#[tokio::test]
async fn d8_dictionary_reason_carries_source_path() {
    use onec_masking_service::domain::{
        DatabaseMode, FieldSources, FinalizeOutcome, FinalizeRequest, SCHEMA_VERSION,
    };

    let (storage, auth, sessions, masking, app, _, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[
            {"source_path":"Справочник.Контрагенты.ИНН","category":"inn","reason":"x"}
        ]}),
    );
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    // Pull со словарным значением — путь источника доезжает в снимок.
    let manager = common::FakeManager::spawn(|name, _| match name {
        common::METADATA_TOOL => Ok(common::metadata_page(
            vec![common::metadata_item(
                "Справочник.Контрагенты.ИНН",
                "ИНН",
                "String(12)",
                false,
            )],
            None,
            true,
        )),
        _ => Ok(common::dictionary_page(
            vec![common::dictionary_value(
                "Справочник.Контрагенты.ИНН",
                "inn",
                "7707083893",
            )],
            None,
            true,
        )),
    });
    common::enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        masking
            .refresh_due_intents(&manager.client(), 10)
            .await
            .unwrap(),
        1
    );

    let call_id = Uuid::new_v4();
    masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            identity: common::test_identity(database_id),
            chat_id: "chat".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"data":[{"ИНН":"7707083893"}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":"ИНН","sources":["Справочник.Контрагенты.ИНН"]}]}),
                lineage: vec![json!({"column":"ИНН","source_path":"Справочник.Контрагенты.ИНН"})],
            },
        })
        .await
        .unwrap();
    let history_id: String = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT id FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();

    let admin_principal = auth
        .authenticate("setup-api", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin_principal, "viewer-d8", Role::Viewer, &[database_id], Uuid::new_v4())
        .unwrap();
    auth.activate("viewer-d8", &activation, "viewer passphrase d8")
        .unwrap();
    let viewer = auth
        .authenticate("viewer-d8-login", "viewer-d8", "viewer passphrase d8")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/history/{history_id}/reasons"),
            &viewer_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let dict = body["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "dictionary")
        .unwrap_or_else(|| panic!("dictionary-причина отсутствует: {body}"));
    assert_eq!(dict["category"], "inn");
    assert_eq!(dict["source_path"], "Справочник.Контрагенты.ИНН");
    let link = dict["link"]["admin_path"].as_str().unwrap();
    assert!(link.contains("source="), "{link}");
}

// ------------------------------------------------------------------
// H (phase-decisions-2): DELETE tools/{tool} — снятие записи
// классификации. Admin-only + CSRF + аудит + 404.
// ------------------------------------------------------------------
fn delete_request(uri: &str, session: &IssuedSession) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&session.token))
        .header("x-csrf-token", &session.csrf_token)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn delete_tool_classification_removes_row_and_audits() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    let uri = format!("/api/v1/admin/databases/{database_id}/tools/execute_query");
    app.clone()
        .oneshot(put(
            &uri,
            &admin,
            "*",
            &json!({"class":"data-mask"}).to_string(),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(delete_request(&uri, &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Запись удалена из живого состояния.
    assert_eq!(tool_count(&storage, database_id, "execute_query"), 0);
    // Аудит-событие как у PUT — action=tool.delete; имя удалённого — в
    // code (R4-9).
    let audited: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='tool.delete' AND database_id=?1 AND code='execute_query'",
                [database_id.to_string()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(audited, 1);
    // Повторное удаление — 404.
    let response = app
        .clone()
        .oneshot(delete_request(&uri, &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_tool_classification_requires_admin_csrf_and_origin() {
    let (_, auth, sessions, _, app, admin, database_id) = fixture().await;
    let uri = format!("/api/v1/admin/databases/{database_id}/tools/execute_query");
    app.clone()
        .oneshot(put(
            &uri,
            &admin,
            "*",
            &json!({"class":"data-mask"}).to_string(),
        ))
        .await
        .unwrap();

    // Viewer — 403.
    let admin_principal = auth
        .authenticate("setup-api-h", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin_principal, "viewer-h", Role::Viewer, &[], Uuid::new_v4())
        .unwrap();
    auth.activate("viewer-h", &activation, "viewer passphrase h")
        .unwrap();
    let viewer = auth
        .authenticate("viewer-h-login", "viewer-h", "viewer passphrase h")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();
    let response = app
        .clone()
        .oneshot(delete_request(&uri, &viewer_session))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Без CSRF — 403; чужой origin — 403.
    let no_csrf = Request::builder()
        .method("DELETE")
        .uri(&uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&admin.token))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(no_csrf).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let foreign_origin = Request::builder()
        .method("DELETE")
        .uri(&uri)
        .header("origin", "https://evil.test")
        .header("cookie", cookie(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(foreign_origin).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Запись на месте — ни одна из попыток не прошла.
    let response = app
        .clone()
        .oneshot(delete_request(&uri, &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ------------------------------------------------------------------
// H.6: удаление инструментов через импорт — отказываемый TOOL_REMOVED.
// ------------------------------------------------------------------
fn seed_tool(storage: &SqliteStorage, database_id: Uuid, tool: &str, class: &str) {
    storage
        .with_connection(|c| {
            c.execute(
                "INSERT OR REPLACE INTO tool_classifications(database_id,tool_name,class,updated_at,auto_added)
                 VALUES (?1,?2,?3,'2026-09-26T00:00:00Z',0)",
                rusqlite::params![database_id.to_string(), tool, class],
            )
        })
        .unwrap();
}

fn tool_count(storage: &SqliteStorage, database_id: Uuid, tool: &str) -> i64 {
    storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM tool_classifications WHERE database_id=?1 AND tool_name=?2",
                rusqlite::params![database_id.to_string(), tool],
                |r| r.get(0),
            )
        })
        .unwrap()
}

fn diff_tool_removed_ids(diff: &Value) -> Vec<String> {
    diff["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "TOOL_REMOVED")
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn h6_file_with_tools_marks_missing_as_removable_tool_removed() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    seed_tool(&storage, database_id, "execute_query", "data-mask");
    seed_tool(&storage, database_id, "retired_tool", "no-mask");

    // Файл с секцией tools (execute_query остаётся, retired_tool нет).
    let mut file = setup_file(database_id, json!({"mode":"part","sources":[]}), json!([]));
    file["tools"] = json!([{"tool":"execute_query","mode":"data-mask","reason":"нужен"}]);
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    let diff = body_json(response).await;
    let removed = diff["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "TOOL_REMOVED")
        .collect::<Vec<_>>();
    // В файле только execute_query → удаляются 5 встроенных + retired_tool.
    assert_eq!(removed.len(), 6, "{diff}");
    let retired = removed
        .iter()
        .find(|c| c["subject"]["tool"] == "retired_tool")
        .unwrap();
    // Нейтральная категория — не ослабление и не усиление.
    assert_eq!(retired["class"], "neutral");
    assert_eq!(retired["before"]["mode"], "no-mask");
    assert!(removed.iter().all(|c| c["class"] == "neutral"));
    assert!(!removed
        .iter()
        .any(|c| c["subject"]["tool"] == "execute_query"));
}

#[tokio::test]
async fn h6_file_without_tools_removes_nothing() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    seed_tool(&storage, database_id, "execute_query", "data-mask");

    // Файл БЕЗ секции tools — удалений нет вообще.
    let file = setup_file(database_id, json!({"mode":"part","sources":[]}), json!([]));
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    let diff = body_json(response).await;
    assert!(diff_tool_removed_ids(&diff).is_empty(), "{diff}");

    // "tools": null ≡ ключа нет — тоже без удалений (уточнение H.6).
    let mut file = file;
    file["tools"] = Value::Null;
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports?replace_draft=1"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    let diff = body_json(response).await;
    assert!(diff_tool_removed_ids(&diff).is_empty(), "{diff}");
}

#[tokio::test]
async fn h6_activate_applies_accepted_removals_and_audits() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    seed_tool(&storage, database_id, "keep_me", "data-mask");
    seed_tool(&storage, database_id, "gone_a", "data-mask");
    seed_tool(&storage, database_id, "gone_b", "no-mask");

    // "tools": [] в файле = удаление ВСЕХ (keep_me не в файле тоже —
    // значит и он TOOL_REMOVED; оставим его через declined).
    let mut file = setup_file(database_id, json!({"mode":"part","sources":[]}), json!([]));
    file["tools"] = json!([]);
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &serde_json::to_string(&file).unwrap(),
        ))
        .await
        .unwrap();
    let body = body_json(response).await;
    let (version, hash) = (
        body["draft_version"].as_i64().unwrap(),
        body["draft_hash"].as_str().unwrap().to_string(),
    );

    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    let diff = body_json(response).await;
    let removals = diff["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "TOOL_REMOVED")
        .collect::<Vec<_>>();
    // "tools": [] = удалить все: 6 встроенных + 3 посеянных.
    assert_eq!(removals.len(), 9, "{diff}");
    let declined: Vec<String> = removals
        .iter()
        .filter(|c| c["subject"]["tool"] == "keep_me")
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(declined.len(), 1);

    // Сначала — stale: неизвестный id отказа → STALE_CONFIRMATION.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/activate"),
            &admin,
            &json!({
                "version": version, "draft_hash": hash,
                "declined_tool_removals": ["not-a-change"],
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(response).await["error"]["details"]["code"],
        "STALE_CONFIRMATION"
    );

    // Активация: gone_a/gone_b удалены + аудит, keep_me остался.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/activate"),
            &admin,
            &json!({
                "version": version, "draft_hash": hash,
                "declined_tool_removals": declined,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let removed: Vec<&str> = body["tool_removals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(removed.len(), 8, "{body}");
    assert!(removed.contains(&"gone_a") && removed.contains(&"gone_b"));

    assert_eq!(tool_count(&storage, database_id, "keep_me"), 1);
    assert_eq!(tool_count(&storage, database_id, "gone_a"), 0);
    assert_eq!(tool_count(&storage, database_id, "gone_b"), 0);
    assert_eq!(tool_count(&storage, database_id, "execute_query"), 0);
    let audited: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='tool.delete' AND database_id=?1 AND code IS NOT NULL",
                [database_id.to_string()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(audited, 8);
    // R4-9: имя удалённого инструмента — в audit_events.code.
    let named: i64 = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='tool.delete' AND database_id=?1 AND code='gone_a'",
                [database_id.to_string()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(named, 1);
}

// ------------------------------------------------------------------
// TASK-225 I: round-trip — пустой reason экспортируется плейсхолдером;
// импорт неизменённого файла → diff 0 изменений (нет шума
// REASON_CHANGED).
// ------------------------------------------------------------------
#[tokio::test]
async fn i_roundtrip_empty_reason_placeholder_is_silent() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[json!({
            "selector": "name",
            "value": "*ФИО*",
            "action": "mask",
            "category": "pii",
            "priority": 10,
            "enabled": true,
            "reason": ""
        })],
        json!({"mode":"part","sources":[
            {"source_path":"Справочник.Контрагенты","category":"pii","reason":""}
        ]}),
    );

    // Экспорт: пустые reason подставлены плейсхолдером.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/export"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let file = body_json(response).await;
    let placeholder = "не указано (создано до версионирования настройки)";
    assert_eq!(file["dictionary"]["sources"][0]["reason"], placeholder);
    assert_eq!(file["rules"][0]["reason"], placeholder);

    // Импорт файла без правок → черновик.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports"),
            &admin,
            &file.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Diff активной vs черновика — ноль изменений.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let diff = body_json(response).await;
    assert_eq!(
        diff["changes"].as_array().unwrap().len(),
        0,
        "round-trip должен молчать: {diff}"
    );
}

// ------------------------------------------------------------------
// J: первая версия базы — diff с пустой настройкой и активация.
// Регресс: раньше from=active без активной версии отдавал NO_DRAFT,
// мастер сообщал «у базы нет черновика» и активация была недоступна.
// ------------------------------------------------------------------
#[tokio::test]
async fn j_first_version_diffs_against_empty_and_activates() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;

    // Без черновика — по-прежнему 409 NO_DRAFT.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(response).await["error"]["code"], "NO_DRAFT");

    // Промах по from=draft — 404 VERSION_NOT_FOUND (NO_DRAFT — только
    // про отсутствие целевого черновика).
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=draft&to=active"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await["error"]["code"],
        "VERSION_NOT_FOUND"
    );

    // Импорт → черновик v1.
    let file = setup_file(
        database_id,
        json!({"mode":"part","sources":[sample_source("Справочник.Контрагенты","контрагенты")]}),
        json!([sample_rule("Иванов")]),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/imports?replace_draft=0"),
            &admin,
            &file.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let draft = body_json(response).await;
    assert_eq!(draft["draft_version"], 1);

    // from=active при отсутствии активной версии: 200, from_version=null,
    // все элементы — добавления/усиления.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=active&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let diff = body_json(response).await;
    assert_eq!(diff["from_version"], Value::Null);
    assert_eq!(diff["to_version"], 1);
    let changes = diff["changes"].as_array().unwrap();
    assert!(!changes.is_empty(), "первая версия должна давать изменения");
    assert!(
        changes
            .iter()
            .all(|change| change["class"] == "strengthening" || change["class"] == "neutral"),
        "против пустой настройки не может быть ослаблений: {diff}"
    );
    assert_eq!(diff["counts"]["weakening"], 0);

    // Несуществующий номер from по-прежнему — VERSION_NOT_FOUND.
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff?from=99&to=draft"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await["error"]["code"],
        "VERSION_NOT_FOUND"
    );

    // Активация без активной версии: все усиления приняты — 200.
    let accepted: Vec<Value> = changes
        .iter()
        .filter(|change| change["class"] == "strengthening")
        .map(|change| change["id"].clone())
        .collect();
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/activate"),
            &admin,
            &json!({
                "version": 1,
                "draft_hash": draft["draft_hash"],
                "accepted_strengthenings": accepted,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["active_version"], 1);
    let statuses: Vec<String> = storage
        .with_connection(|c| {
            let mut s =
                c.prepare("SELECT status FROM policies WHERE database_id=?1 ORDER BY version")?;
            let rows = s
                .query_map([database_id.to_string()], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(
        statuses,
        ["active"],
        "черновик стал активной v1: {statuses:?}"
    );
}

// ------------------------------------------------------------------
// TASK-225 L R4-2: TOOL_REMOVED эмитится только для версий, пришедших
// из импорта файла (origin=import). Черновик «из действующей»,
// legacy-черновик и откат наследуют ЧАСТИЧНЫЙ снимок tools — удалений
// по ним быть не должно.
// ------------------------------------------------------------------
fn seed_active_tools_json(storage: &SqliteStorage, database_id: Uuid, tools: Value) {
    storage
        .with_connection(|c| {
            c.execute(
                "UPDATE policies SET tools_json=?2 WHERE database_id=?1 AND status='active'",
                rusqlite::params![database_id.to_string(), tools.to_string()],
            )
        })
        .unwrap();
}

async fn fetch_diff(app: &axum::Router, admin: &IssuedSession, database_id: Uuid) -> Value {
    let response = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/admin/databases/{database_id}/setup/diff"),
            admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

// Ручной черновик (origin=manual — им покрыты и «из действующей», и
// legacy PUT): переходы режимов работают, удалений по отсутствующим в
// списке инструментам нет.
#[tokio::test]
async fn r4_manual_draft_put_tools_keeps_transitions_no_removals() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"empty"}"#,
        ))
        .await
        .unwrap();
    let hash = body_json(response).await["draft_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    // execute_query: data-mask → no-mask (ослабление должно остаться в
    // diff), остальные 5 встроенных вне списка — не удаляются.
    let response = app
        .clone()
        .oneshot(put(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft/tools"),
            &admin,
            &hash,
            &json!({"tools":[{"tool":"execute_query","mode":"no-mask","reason":"L"}]}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let diff = fetch_diff(&app, &admin, database_id).await;
    assert!(
        diff_tool_removed_ids(&diff).is_empty(),
        "ручной черновик не должен удалять классификации: {diff}"
    );
    let transition = diff["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "TOOL_NO_MASK")
        .expect("переход execute_query data-mask→no-mask обязан быть в diff");
    assert_eq!(transition["class"], "weakening");
}

// Откат версии — origin=rollback: снимок tools копируется, удалений нет.
#[tokio::test]
async fn r4_rollback_draft_emits_no_tool_removals() {
    let (storage, _, _, _, app, admin, database_id) = fixture().await;
    seed_active(
        &storage,
        database_id,
        &[],
        json!({"mode":"part","sources":[]}),
    );
    seed_active_tools_json(
        &storage,
        database_id,
        json!([{"tool":"execute_query","mode":"data-mask","reason":"snap"}]),
    );
    // Черновик v2 со снимком tools → откат на него даёт v3 origin=rollback.
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/draft"),
            &admin,
            r#"{"from":"active"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/admin/databases/{database_id}/setup/rollback"),
            &admin,
            &json!({"version": 2, "replace_draft": true}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let diff = fetch_diff(&app, &admin, database_id).await;
    assert!(
        diff_tool_removed_ids(&diff).is_empty(),
        "откат не должен удалять классификации: {diff}"
    );
}

// Импорт-сторона (origin=import → удаления есть) покрыта тестами
// H.6 выше (`h6_file_with_tools_marks_missing_as_removable_tool_removed`).

// ------------------------------------------------------------------
// T (phase-decisions-2): DELETE /admin/databases/{id} — каскадное
// снятие записи базы, audit database.delete, RBAC/CSRF, заново
// регистрируется unconfigured при повторном вызове.
//++agent TASK-225 [27.09.2026 00:00:00]

// Строки во всех таблицах с database_id, чтобы DELETE реально
// покрывал каскад, а не только пустую запись databases.
fn seed_database_relations(storage: &SqliteStorage, database_id: Uuid) {
    let database_id = database_id.to_string();
    let policy_id = Uuid::new_v4().to_string();
    storage
        .with_connection(|connection| {
            connection.execute(
                "UPDATE databases SET display_label='old-db' WHERE id=?1",
                [&database_id],
            )?;
            connection.execute(
                "INSERT INTO policies(id,database_id,version,status,created_at)
                 VALUES (?1,?2,1,'active','2026-01-01T00:00:00Z')",
                rusqlite::params![policy_id, database_id],
            )?;
            // База указывает на активную политику — edge FK без cascade.
            connection.execute(
                "UPDATE databases SET active_policy_id=?1 WHERE id=?2",
                rusqlite::params![policy_id, database_id],
            )?;
            connection.execute(
                "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,
                   action,category,priority,created_at)
                 VALUES (?1,?2,'source_path','Catalog.Номенклатура.Name','mask','PII',1,
                   '2026-01-01T00:00:00Z')",
                rusqlite::params![Uuid::new_v4().to_string(), policy_id],
            )?;
            connection.execute(
                "INSERT INTO tool_classifications(database_id,tool_name,class,updated_at)
                 VALUES (?1,'seed_tool','data-mask','2026-01-01T00:00:00Z')",
                [&database_id],
            )?;
            connection.execute(
                "INSERT INTO dictionary_configs(id,database_id,mode,updated_at)
                 VALUES (?1,?2,'all','2026-01-01T00:00:00Z')",
                rusqlite::params![Uuid::new_v4().to_string(), database_id],
            )?;
            connection.execute(
                "INSERT INTO cache_generations(database_id,version,digest,status,created_at,activated_at)
                 VALUES (?1,1,'d','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                [&database_id],
            )?;
            connection.execute(
                "INSERT INTO v2_refresh_intents(database_id,phase,reason,created_at)
                 VALUES (?1,'full','test','2026-01-01T00:00:00Z')",
                [&database_id],
            )?;
            connection.execute(
                "INSERT INTO setup_imports(id,database_id,actor_id,sha256,size_bytes,schema,result,created_at)
                 VALUES (?1,?2,?3,'s',1,'masking-setup/v1','accepted','2026-01-01T00:00:00Z')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id,
                    Uuid::new_v4().to_string()
                ],
            )?;
            connection.execute(
                "INSERT INTO setup_journal(database_id,at,actor_kind,action)
                 VALUES (?1,'2026-01-01T00:00:00Z','human','export')",
                [&database_id],
            )?;
            connection.execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,
                   policy_version,mask_reasons_json,public_result_json,report_json,
                   created_at,expires_at)
                 VALUES (?1,?2,'c',?3,'t','tool_result',1,'[]','{}','{}',
                   '2026-01-01T00:00:00Z','2999-01-01T00:00:00Z')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id,
                    Uuid::new_v4().to_string()
                ],
            )?;
            connection.execute(
                "INSERT INTO call_contexts(call_id,database_id,chat_id,tool_name,created_at,expires_at)
                 VALUES (?1,?2,'c','t','2026-01-01T00:00:00Z','2999-01-01T00:00:00Z')",
                rusqlite::params![Uuid::new_v4().to_string(), database_id],
            )?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn delete_database_cascades_all_rows_and_keeps_audit() {
    let (storage, _, _, masking, app, admin, database_id) = fixture().await;
    seed_database_relations(&storage, database_id);
    // RAM-снапшот manifest до удаления — после DELETE его быть не должно.
    assert!(masking.seed_metadata_manifest(
        database_id,
        vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Справочник.Контрагенты.ИНН".into(),
            field_name: "ИНН".into(),
            field_type: "String(12)".into(),
            password_mode: false,
        }],
    ));

    let response = app
        .clone()
        .oneshot(delete_request(
            &format!("/api/v1/admin/databases/{database_id}"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let database_id_s = database_id.to_string();
    let counts = storage
        .with_connection(|connection| {
            let count = |sql: &str| -> rusqlite::Result<i64> {
                connection.query_row(sql, [&database_id_s], |row| row.get(0))
            };
            Ok((
                count("SELECT COUNT(*) FROM databases WHERE id=?1")?,
                count("SELECT COUNT(*) FROM policies WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM tool_classifications WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM dictionary_configs WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM cache_generations WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM v2_refresh_intents WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM setup_imports WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM setup_journal WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM history WHERE database_id=?1")?,
                count("SELECT COUNT(*) FROM call_contexts WHERE database_id=?1")?,
                connection.query_row("SELECT COUNT(*) FROM policy_rules", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                count(
                    "SELECT COUNT(*) FROM audit_events
                     WHERE database_id=?1 AND action='database.delete'
                       AND actor_id IS NOT NULL AND code='old-db'",
                )?,
            ))
        })
        .unwrap();
    // Каждая каскадная таблица пуста, audit database.delete остался.
    assert_eq!(
        counts,
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
        "counts={counts:?}"
    );
    // RAM-состояние по базе сброшено.
    assert!(masking
        .metadata_manifest_view(database_id, |items| items.len())
        .is_none());

    // Повтор — 404.
    let response = app
        .oneshot(delete_request(
            &format!("/api/v1/admin/databases/{database_id}"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_database_requires_admin_csrf_and_origin() {
    let (_, auth, sessions, _, app, admin, database_id) = fixture().await;
    let uri = format!("/api/v1/admin/databases/{database_id}");

    // Viewer — 403.
    let admin_principal = auth
        .authenticate("setup-api-t", "admin", ADMIN_PASSWORD)
        .unwrap();
    let (_, activation) = auth
        .create_user(&admin_principal, "viewer-t", Role::Viewer, &[], Uuid::new_v4())
        .unwrap();
    auth.activate("viewer-t", &activation, "viewer passphrase t")
        .unwrap();
    let viewer = auth
        .authenticate("viewer-t-login", "viewer-t", "viewer passphrase t")
        .unwrap();
    let viewer_session = sessions.issue(viewer, Utc::now()).unwrap();
    let response = app
        .clone()
        .oneshot(delete_request(&uri, &viewer_session))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Без CSRF — 403; чужой origin — 403.
    let no_csrf = Request::builder()
        .method("DELETE")
        .uri(&uri)
        .header("origin", ORIGIN)
        .header("cookie", cookie(&admin.token))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(no_csrf).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let foreign_origin = Request::builder()
        .method("DELETE")
        .uri(&uri)
        .header("origin", "https://evil.test")
        .header("cookie", cookie(&admin.token))
        .header("x-csrf-token", &admin.csrf_token)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(foreign_origin).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Запись на месте — ни одна из попыток не прошла.
    let response = app
        .clone()
        .oneshot(delete_request(&uri, &admin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn deleted_database_re_registers_as_unconfigured_on_next_call() {
    use onec_masking_service::domain::{DatabaseMode, PreflightRequest, SCHEMA_VERSION};
    let (storage, _, _, masking, app, admin, database_id) = fixture().await;
    let response = app
        .oneshot(delete_request(
            &format!("/api/v1/admin/databases/{database_id}"),
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Та же личность делает вызов — авто-регистрация заново.
    let identity = common::test_identity(database_id);
    let response = masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            identity: identity.clone(),
            chat_id: "chat-t".to_owned(),
            tool_name: "get_metadata".to_owned(),
            arguments: json!({}),
        })
        .await
        .unwrap();
    assert_eq!(response.decision, "allow");

    // Запись создана заново — режим unconfigured.
    let (_new_id, settings) = storage
        .lookup_database(&identity)
        .unwrap()
        .expect("база должна перерегистрироваться");
    assert_eq!(settings.mode, DatabaseMode::Unconfigured);
}
//++agent TASK-225
