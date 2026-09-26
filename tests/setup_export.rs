//++agent TASK-225 [26.09.2026]
//! T5-04 / ОВ-2 (Б12): `GET /internal/v1/setup/export` — §1 тело активной
//! версии, аудит `setup.export` с actor_kind=`agent`, 404 NO_ACTIVE_VERSION.
//--agent TASK-225

mod common;

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode},
};
use onec_masking_service::{internal_api::UdsConnectInfo, internal_app, AppState, SqliteStorage};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

fn get_request(uri: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(UdsConnectInfo { uid: None }));
    request
}

/// База + активная версия (version=5) со словарём, правилом и классификацией.
fn seed_active_setup(storage: &SqliteStorage, database_id: Uuid) {
    storage
        .with_connection(|connection| {
            connection.execute(
                "INSERT INTO databases(id,instance_id,mode,display_label,created_at,updated_at)
                 VALUES (?1,?2,'enabled','Demo DB','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                rusqlite::params![database_id.to_string(), format!("inst-{database_id}")],
            )?;
            connection.execute(
                "INSERT INTO policies(id,database_id,version,status,dictionary_json,origin,created_at)
                 VALUES (?1,?2,5,'active',?3,'migration','2026-01-01T00:00:00Z')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    serde_json::to_string(&json!({
                        "mode": "part",
                        "sources": [{
                            "source_path": "Справочник.Контрагенты",
                            "category": "pii",
                            "filter_ast": {"op":"eq","field":"Тип","value":"ЮрЛицо"},
                            "reason": "контрагенты",
                            "estimated_values": 1500
                        }]
                    }))
                    .unwrap()
                ],
            )?;
            let policy_id: String = connection.query_row(
                "SELECT id FROM policies WHERE database_id=?1 AND status='active'",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            connection.execute(
                "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,
                        priority,enabled,reason,tests_json,created_at)
                 VALUES (?1,?2,'regex','(?i)token','mask','credentials',7,0,NULL,
                        '{\"match\":[\"abc\"]}','2026-01-01T00:00:00Z')",
                rusqlite::params![Uuid::new_v4().to_string(), policy_id],
            )?;
            connection.execute(
                "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at)
                 VALUES (?1,'execute_query','data-mask','admin','2026-01-01T00:00:00Z')",
                [database_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn setup_export_returns_active_version_and_audits_agent() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let app = internal_app(state);
    let database_id = Uuid::new_v4();
    seed_active_setup(&storage, database_id);

    let response = app
        .oneshot(get_request(&format!(
            "/internal/v1/setup/export?database_id={database_id}&include_tools=1"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();

    assert_eq!(body["schema"], "masking-setup/v1");
    assert_eq!(body["generated_by"]["kind"], "service");
    assert_eq!(body["database_hint"]["id"], database_id.to_string());
    assert_eq!(body["database_hint"]["label"], "Demo DB");
    assert_eq!(body["database_hint"]["source_version"], 5);
    // Словарь: stored filter_ast выходит как `filter` §1, reason сохраняется.
    let source = &body["dictionary"]["sources"][0];
    assert_eq!(source["source_path"], "Справочник.Контрагенты");
    assert_eq!(source["filter"]["op"], "eq");
    assert_eq!(source["estimated_values"], 1500);
    // Правило: reason NULL → константа §2.3.6; внутренний id не выходит.
    let rule = &body["rules"][0];
    assert_eq!(rule["selector"], "regex");
    assert_eq!(rule["enabled"], false);
    assert_eq!(rule["reason"], "не указано (создано до TASK-225)");
    assert!(rule.get("rule_id").is_none() && rule.get("id").is_none());
    assert_eq!(rule["tests"]["match"][0], "abc");
    // tools_json у версии нет → текущие tool_classifications.
    assert_eq!(body["tools"][0]["tool"], "execute_query");
    assert_eq!(body["tools"][0]["mode"], "data-mask");

    // Аудит: setup.export actor_kind=agent + журнал export с sha256.
    storage
        .with_connection(|connection| {
            let (audit_action, actor, journal): (String, String, i64) = connection.query_row(
                "SELECT a.action, a.actor_kind,
                        EXISTS(SELECT 1 FROM setup_journal j
                               WHERE j.database_id=a.database_id AND j.action='export'
                                     AND j.version=5 AND j.sha256 IS NOT NULL)
                 FROM audit_events a
                 WHERE a.database_id=?1 AND a.action='setup.export'",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(audit_action, "setup.export");
            assert_eq!(actor, "agent");
            assert_eq!(journal, 1, "setup_journal must carry export row");
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn setup_export_omits_tools_without_flag() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let app = internal_app(state);
    let database_id = Uuid::new_v4();
    seed_active_setup(&storage, database_id);

    let response = app
        .oneshot(get_request(&format!(
            "/internal/v1/setup/export?database_id={database_id}"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(body.get("tools").is_none());
}

#[tokio::test]
async fn setup_export_is_404_without_active_version() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let app = internal_app(state);

    // База существует, но версий нет вовсе.
    let database_id = Uuid::new_v4();
    storage
        .with_connection(|connection| {
            connection.execute(
                "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
                 VALUES (?1,?2,'enabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                rusqlite::params![database_id.to_string(), format!("inst-{database_id}")],
            )?;
            Ok(())
        })
        .unwrap();

    for id in [database_id, Uuid::new_v4()] {
        let response = app
            .clone()
            .oneshot(get_request(&format!(
                "/internal/v1/setup/export?database_id={id}"
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["error"]["code"], "NO_ACTIVE_VERSION");
    }
}
