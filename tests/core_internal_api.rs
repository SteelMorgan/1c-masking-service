mod common;

use std::{process::Command, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode},
};
use onec_masking_service::{
    domain::{
        DatabaseMode, ErrorCode, FieldSources, FinalizeOutcome, FinalizeRequest, PolicyRule,
        RuleAction, RuleSelector,
    },
    internal_api::UdsConnectInfo,
    internal_app, AppState, SqliteStorage,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use common::{
    dictionary_page, dictionary_value, empty_feed_responder, enqueue_refresh_intent, metadata_item,
    metadata_page, FakeManager, DICTIONARY_TOOL, METADATA_TOOL,
};

#[test]
fn existing_v1_database_is_migrated_without_losing_masked_history() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sqlite3");
    let database_id = Uuid::new_v4();
    let call_id = Uuid::new_v4();
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(include_str!("../migrations/0001_core.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES (1,'2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
                 VALUES (?1,?1,'disabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                [database_id.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                                     mask_reasons_json,public_result_json,report_json,created_at,expires_at)
                 VALUES (?1,?2,'chat',?3,'execute_query','tool_result',1,'[]',?4,?5,
                         '2026-01-01T00:00:00Z','2099-01-01T00:00:00')",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    database_id.to_string(),
                    call_id.to_string(),
                    json!({"content":[{"type":"text","text":"[MASK:v1:FIO:test]"}],"is_error":false}).to_string(),
                    json!({"version":1,"blocks":[]}).to_string()
                ],
            )
            .unwrap();
    }

    let storage = SqliteStorage::open(&path).unwrap();
    storage
        .with_connection(|connection| {
            let migration_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version IN (1,2)",
                [],
                |row| row.get(0),
            )?;
            let history_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            let ledger_exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='unscoped_terminal_events'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!((migration_count, history_count, ledger_exists), (2, 1, 1));
            let dropped_feed_tables: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
                 ('feed_jobs','v2_call_receipts','v2_active_snapshots','v2_feed_leases')",
                [],
                |row| row.get(0),
            )?;
            //++agent TASK-222: транспортные таблицы v1 feed/v2 удалены
            // миграцией 0008, durable intent и журнал прогонов остаются.
            assert_eq!(dropped_feed_tables, 0);
            for name in ["v2_refresh_intents", "cache_generations"] {
                let exists: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |row| row.get(0),
                )?;
                assert_eq!(exists, 1, "table {name} must survive migration 0008");
            }
            //++agent TASK-222
            Ok(())
        })
        .unwrap();
}

fn json_request(uri: &str, value: Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&value).unwrap()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(UdsConnectInfo { uid: None }));
    request
}

//++agent TASK-221 [23.09.2026 20:14:00]
#[tokio::test]
async fn internal_router_respects_configured_body_limit_before_handler() {
    const CHILD_FLAG: &str = "MASKING_TEST_222_BODY_LIMIT_CHILD";
    const CANARY: &str = "SYNTHETIC_BODY_CANARY_222";
    if std::env::var_os(CHILD_FLAG).is_none() {
        // Изолированный процесс не меняет переменную окружения параллельных tests.
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("internal_router_respects_configured_body_limit_before_handler")
            .arg("--nocapture")
            .env(CHILD_FLAG, "1")
            .env("MASKING_MAX_BODY_BYTES", "1024")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated HTTP limit test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "isolated HTTP limit test was not selected"
        );
        return;
    }

    assert_eq!(std::env::var("MASKING_MAX_BODY_BYTES").unwrap(), "1024");
    let peer_uid = 222;
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new_with_peer_uid(storage, "https://masking.test", peer_uid);
    let app = internal_app(state);
    let database_id = Uuid::new_v4();
    let preflight = json!({
        "schema_version":1,
        "call_id":Uuid::new_v4(),
        "correlation_id":Uuid::new_v4(),
        "cluster_server":common::TEST_CLUSTER_SERVER,
        "infobase_name":common::test_infobase_name(database_id),
        "instance_id":format!("ras:{}:{}",database_id,common::test_infobase_guid(database_id)),

        "chat_id":"synthetic-chat",
        "tool_name":"execute_query",
        "arguments":{"query":"SELECT 1"}
    });
    let finalize = json!({
        "schema_version":1,
        "call_id":Uuid::new_v4(),
        "correlation_id":Uuid::new_v4(),
        "cluster_server":common::TEST_CLUSTER_SERVER,
        "infobase_name":common::test_infobase_name(database_id),
        "instance_id":format!("ras:{}:{}",database_id,common::test_infobase_guid(database_id)),

        "chat_id":"synthetic-chat",
        "tool_name":"execute_query",
        "outcome":{"kind":"transport_error","error":{"message":"synthetic-timeout"}}
    });

    for (route, small, large) in [
        ("/internal/v1/calls/preflight", preflight.clone(), {
            let mut payload = preflight;
            payload["arguments"]["padding"] = json!(format!("{CANARY}{}", "x".repeat(1_500)));
            payload
        }),
        ("/internal/v1/calls/finalize", finalize.clone(), {
            let mut payload = finalize;
            payload["chat_id"] = json!(format!("{CANARY}{}", "x".repeat(1_500)));
            payload
        }),
    ] {
        let mut small_request = json_request(route, small);
        small_request
            .extensions_mut()
            .insert(ConnectInfo(UdsConnectInfo {
                uid: Some(peer_uid),
            }));
        let small_response = app.clone().oneshot(small_request).await.unwrap();
        // Limit отпускает маленькое тело до handler: неизвестная БД —
        // ACTION_REQUIRED (CONFLICT), не отказ уровня transport.
        assert_eq!(small_response.status(), StatusCode::CONFLICT);

        let serialized = serde_json::to_vec(&large).unwrap();
        assert!(serialized.len() > 1_024 && serialized.len() < 8 * 1024 * 1024);
        let mut large_request = json_request(route, large);
        large_request
            .extensions_mut()
            .insert(ConnectInfo(UdsConnectInfo {
                uid: Some(peer_uid),
            }));
        let response = app.clone().oneshot(large_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response_body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&response_body).contains(CANARY));
    }
}
//++agent TASK-221

#[tokio::test]
async fn unverified_terminal_events_use_an_unscoped_idempotent_retained_ledger() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let app = internal_app(state.clone());
    let call_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let event = json!({
        "schema_version":1,
        "call_id":call_id,
        "correlation_id":correlation_id,
        "tool_name":"execute_query",
        "error_code":"CHAT_IDENTITY_REQUIRED",
        "scope":{"kind":"unverified"}
    });

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(json_request("/internal/v1/calls/terminal", event.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body, json!({"schema_version":1,"status":"recorded"}));
    }

    let attributed = json!({
        "schema_version":1,
        "call_id":Uuid::new_v4(),
        "correlation_id":Uuid::new_v4(),
        "tool_name":"execute_query",
        "error_code":"CHAT_IDENTITY_REQUIRED",
        "scope":{"kind":"unverified","cluster_server":"test-srv","chat_id":"candidate"}
    });
    assert_eq!(
        app.clone()
            .oneshot(json_request("/internal/v1/calls/terminal", attributed))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let mismatch = json!({
        "schema_version":1,
        "call_id":call_id,
        "correlation_id":correlation_id,
        "tool_name":"execute_query",
        "error_code":"DATABASE_IDENTITY_UNVERIFIED",
        "scope":{"kind":"unverified"}
    });
    let mismatch_response = app
        .oneshot(json_request("/internal/v1/calls/terminal", mismatch))
        .await
        .unwrap();
    assert_eq!(mismatch_response.status(), StatusCode::CONFLICT);
    let mismatch_body: Value = serde_json::from_slice(
        &to_bytes(mismatch_response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(mismatch_body["error"]["code"], "TERMINAL_ALREADY_RECORDED");

    storage
        .with_connection(|connection| {
            let (ledger_count, audit_count, scoped_count): (i64, i64, i64) =
                connection.query_row(
                    "SELECT COUNT(*),
                            (SELECT COUNT(*) FROM audit_events WHERE action='call.terminal.unscoped'),
                            (SELECT COUNT(*) FROM history)
                     FROM unscoped_terminal_events WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
            assert_eq!((ledger_count, audit_count, scoped_count), (1, 1, 0));
            connection.execute(
                "UPDATE unscoped_terminal_events SET expires_at='1970-01-01T00:00:00Z' WHERE call_id=?1",
                [call_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
    let candidate_database_id = Uuid::new_v4();
    storage
        .insert_database(
            candidate_database_id,
            &common::test_identity(candidate_database_id),
        )
        .unwrap();
    storage
        .set_database_mode(candidate_database_id, DatabaseMode::Disabled)
        .unwrap();
    let attributed_finalize = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id,
            identity: common::test_identity(candidate_database_id),
            chat_id: "candidate-chat".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"content":[{"type":"text","text":"must-not-be-attributed"}],"is_error":false}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(attributed_finalize.code, ErrorCode::TerminalAlreadyRecorded);
    let scoped_after_finalize: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(scoped_after_finalize, 0);
    let (_, terminal, _, _) = state.masking.maintenance_tick().await.unwrap();
    assert_eq!(terminal, 1);
    let remaining: i64 = storage
        .with_connection(|connection| {
            connection.query_row("SELECT COUNT(*) FROM unscoped_terminal_events", [], |row| {
                row.get(0)
            })
        })
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn internal_http_contract_fails_closed_then_masks_all_result_copies() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let app = internal_app(state.clone());
    let database_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let denied_call_id = Uuid::new_v4();

    let response = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/preflight",
            json!({
                "schema_version":1,
                "call_id":denied_call_id,
                "correlation_id":correlation_id,
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(database_id),
                "instance_id":format!("ras:{}:{}",database_id,common::test_infobase_guid(database_id)),

                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "arguments":{"query":"SELECT 1"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(body["error"]["code"], "ACTION_REQUIRED");
    assert_eq!(body["error"]["correlation_id"], correlation_id.to_string());

    let lost_response_fallback = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/terminal",
            json!({
                "schema_version":1,
                "call_id":denied_call_id,
                "correlation_id":correlation_id,
                "tool_name":"execute_query",
                "error_code":"SERVICE_NOT_READY",
                "scope":{"kind":"verified","cluster_server":common::TEST_CLUSTER_SERVER,"infobase_name":common::test_infobase_name(database_id),"instance_id":format!("ras:{}:{}",database_id,common::test_infobase_guid(database_id)),"chat_id":"trusted-conversation"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(lost_response_fallback.status(), StatusCode::CONFLICT);
    let lost_response_body: Value = serde_json::from_slice(
        &to_bytes(lost_response_fallback.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        lost_response_body["error"]["code"],
        "TERMINAL_ALREADY_RECORDED"
    );
    storage
        .with_connection(|connection| {
            let (history_count, action_required, service_not_ready): (i64, i64, i64) = connection
                .query_row(
                "SELECT COUNT(*),
                            SUM(instr(public_result_json,'ACTION_REQUIRED')>0),
                            SUM(instr(public_result_json,'SERVICE_NOT_READY')>0)
                     FROM history WHERE call_id=?1",
                [denied_call_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(
                (history_count, action_required, service_not_ready),
                (1, 1, 0)
            );
            Ok(())
        })
        .unwrap();

    //++agent TASK-225 [26.09.2026] N: авто-регистрация создаёт запись с
    // собственным id — резолвим его по identity для дальнейших assert'ов.
    let identity_seed = database_id;
    let (database_id, _) = storage
        .lookup_database(&common::test_identity(identity_seed))
        .unwrap()
        .unwrap();
    //++agent TASK-225
    assert!(storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap());
    assert!(!state.masking.database_ready(database_id).await);

    let not_ready_call_id = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/preflight",
            json!({
                "schema_version":1,
                "call_id":not_ready_call_id,
                "correlation_id":Uuid::new_v4(),
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(identity_seed),
                "instance_id":format!("ras:{}:{}",identity_seed,common::test_infobase_guid(identity_seed)),

                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "arguments":{"query":"SELECT 1"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(body["error"]["code"], "SERVICE_NOT_READY");
    let not_ready_history: String = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT public_result_json || report_json FROM history WHERE call_id=?1",
                [not_ready_call_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(not_ready_history.contains("SERVICE_NOT_READY"));

    let response = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/finalize",
            json!({
                "schema_version":1,
                "call_id":Uuid::new_v4(),
                "correlation_id":Uuid::new_v4(),
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(identity_seed),
                "instance_id":format!("ras:{}:{}",identity_seed,common::test_infobase_guid(identity_seed)),

                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "outcome":{"kind":"tool_result","result":{
                    "content":[{"type":"text","text":"must-not-run-before-cache"}],
                    "is_error":false
                }},
                "field_sources":{}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/finalize",
            json!({
                "schema_version":1,
                "call_id":Uuid::new_v4(),
                "correlation_id":Uuid::new_v4(),
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(identity_seed),
                "instance_id":format!("ras:{}:{}",identity_seed,common::test_infobase_guid(identity_seed)),

                "chat_id":"trusted-conversation",
                "tool_name":"get_metadata",
                "outcome":{"kind":"tool_result","result":{
                    "content":[{"type":"json","json":{"password":"never-publish"}}],
                    "is_error":false
                }},
                "field_sources":{}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert!(!body.to_string().contains("never-publish"));
    assert!(body.to_string().contains("[SECRET_REMOVED]"));

    //++agent TASK-222: готовность получается pull'ом через manager UDS —
    // durable intent → pull worker → internal feed tools → snapshot swap.
    let fake = FakeManager::spawn(empty_feed_responder);
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(state.masking.database_ready(database_id).await);

    let raw = "Иванов Иван Иванович";
    let call_id = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(json_request(
            "/internal/v1/calls/finalize",
            json!({
                "schema_version":1,
                "call_id":call_id,
                "correlation_id":Uuid::new_v4(),
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(identity_seed),
                "instance_id":format!("ras:{}:{}",identity_seed,common::test_infobase_guid(identity_seed)),

                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                //++agent TASK-222: контракт Р2 — непрозрачный бизнес-result;
                // маскированное значение уходит агенту в content[0].text.
                "outcome":{"kind":"tool_result","result":{
                    "success":true,
                    "data":[{"ФИО":raw}]
                }},
                "field_sources":{
                    "schema":{"columns":[{"name":"ФИО","sources":["Справочник.People.FullName"]}]},
                    "lineage":[{"column":"ФИО","source_path":"Справочник.People.FullName"}]
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let rendered = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!rendered.contains(raw));
    assert_eq!(rendered.matches("[MASK:v1:FIO:").count(), 1);
    // data не теряется: masked-значение живёт в JSON внутри content[0].text.
    let public: Value = serde_json::from_slice(&bytes).unwrap();
    let public_text = public["public_result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let masked_result: Value = serde_json::from_str(public_text).unwrap();
    assert!(masked_result["data"][0]["ФИО"]
        .as_str()
        .unwrap()
        .starts_with("[MASK:v1:FIO:"));
    assert_eq!(masked_result["success"], true);

    let persisted: String = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT public_result_json || report_json FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(!persisted.contains(raw));

    let malformed_call_id = Uuid::new_v4();
    let malformed_raw = "raw-value-that-must-not-be-persisted";
    let response = app
        .oneshot(json_request(
            "/internal/v1/calls/finalize",
            json!({
                "schema_version":1,
                "call_id":malformed_call_id,
                "correlation_id":Uuid::new_v4(),
                "cluster_server":common::TEST_CLUSTER_SERVER,
                "infobase_name":common::test_infobase_name(identity_seed),
                "instance_id":format!("ras:{}:{}",identity_seed,common::test_infobase_guid(identity_seed)),

                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "outcome":{"kind":"tool_result","result":{
                    "content":[{"type":"json","json":{"html":malformed_raw}}],
                    "is_error":false
                }}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sanitized: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(sanitized["public_result"]["is_error"], true);
    assert!(!sanitized.to_string().contains(malformed_raw));
    let stored: String = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT public_result_json || report_json FROM history WHERE call_id=?1",
                [malformed_call_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(!stored.contains(malformed_raw));
}

//++agent TASK-222 [05.10.2026]
// Холодный старт all-режима в pull-модели: сначала metadata manifest,
// затем dictionary-вызовы уже по явным source_path (никакого "*" на проводе).
#[tokio::test]
async fn all_mode_cold_start_expands_wildcard_selectors_after_metadata_pull() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage
        .insert_database(database_id, &common::test_identity(database_id))
        .unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    storage
        .install_policy(
            database_id,
            11,
            &[PolicyRule {
                selector: RuleSelector::SourcePath,
                pattern: "Catalog.Organizations.Description".to_owned(),
                action: RuleAction::Mask,
                category: "ORG".to_owned(),
                priority: 0,
                rule_id: None,
            }],
        )
        .unwrap();
    storage
        .set_dictionary_config(
            database_id,
            "all",
            &[json!({"source_path":"*","category":"ORG","filter_ast":null})],
        )
        .unwrap();
    let state = AppState::new(storage.clone(), "https://masking.test");

    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Organizations.Description",
                "Description",
                "String",
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(
            vec![dictionary_value(
                "Catalog.Organizations.Description",
                "ORG",
                "ООО Вектор",
            )],
            None,
            true,
        )),
    });
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(state.masking.database_ready(database_id).await);

    let dictionary_calls = fake.calls_for(DICTIONARY_TOOL);
    assert_eq!(dictionary_calls.len(), 1);
    let selector = &dictionary_calls[0]["selector"];
    assert_eq!(selector["source_path"], "Catalog.Organizations.Description");
    assert_ne!(selector["source_path"], "*");

    let finalized = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            identity: common::test_identity(database_id),
            chat_id: "chat-all-mode".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "content":[{"type":"text","text":"Контрагент ООО Вектор"}],"is_error":false
                }),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&finalized.public_result).unwrap();
    assert!(!rendered.contains("ООО Вектор"));
    assert!(rendered.contains("[MASK:v1:ORG:"));
}
//++agent TASK-222
