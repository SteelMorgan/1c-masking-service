use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode},
};
use onec_masking_service::{
    domain::{
        DatabaseMode, ErrorCode, FinalizeOutcome, FinalizeRequest, MaskingEvidence, PolicyRule,
        RuleAction, RuleSelector,
    },
    internal_api::UdsConnectInfo,
    internal_app, AppState, SqliteStorage,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

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
                         '2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
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

fn get_request(uri: &str) -> Request<Body> {
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(UdsConnectInfo { uid: None }));
    request
}

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
        "scope":{"kind":"unverified","database_id":Uuid::new_v4(),"chat_id":"candidate"}
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
    storage.ensure_database(candidate_database_id).unwrap();
    storage
        .set_database_mode(candidate_database_id, DatabaseMode::Disabled)
        .unwrap();
    let attributed_finalize = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id,
            database_id: candidate_database_id,
            chat_id: "candidate-chat".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"content":[{"type":"text","text":"must-not-be-attributed"}],"is_error":false}),
            },
            evidence: MaskingEvidence::default(),
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
                "database_id":database_id,
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
                "scope":{"kind":"verified","database_id":database_id,"chat_id":"trusted-conversation"}
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
                "database_id":database_id,
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
                "database_id":database_id,
                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "outcome":{"kind":"tool_result","result":{
                    "content":[{"type":"text","text":"must-not-run-before-cache"}],
                    "is_error":false
                }},
                "evidence":{}
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
                "database_id":database_id,
                "chat_id":"trusted-conversation",
                "tool_name":"get_metadata",
                "outcome":{"kind":"tool_result","result":{
                    "content":[{"type":"json","json":{"password":"never-publish"}}],
                    "is_error":false
                }},
                "evidence":{}
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

    let job_id = storage.enqueue_feed_job(database_id, 1).unwrap();
    state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap();
    let payload = onec_masking_service::domain::FeedPayload {
        selection_id: None,
        page_index: 0,
        metadata: Vec::new(),
        dictionary_values: Vec::new(),
        final_chunk: true,
    };
    let digest = canonical_digest(&serde_json::to_value(&payload).unwrap());
    state
        .masking
        .upload_feed_chunk(
            job_id,
            0,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&digest),
                payload,
            },
        )
        .unwrap();
    let aggregate: [u8; 32] = Sha256::digest(digest).into();
    state
        .masking
        .activate_feed(
            job_id,
            onec_masking_service::domain::FeedActivateRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                expected_chunks: 1,
                expected_metadata_count: 0,
                expected_dictionary_count: 0,
                aggregate_digest: hex(&aggregate),
            },
        )
        .await
        .unwrap();
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
                "database_id":database_id,
                "chat_id":"trusted-conversation",
                "tool_name":"execute_query",
                "outcome":{"kind":"tool_result","result":{
                    "content":[
                        {"type":"text","text":raw},
                        {"type":"json","json":{"ФИО":raw}}
                    ],
                    "structured_content":{"rows":[{"ФИО":raw}]},
                    "is_error":false
                }},
                "evidence":{}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let rendered = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!rendered.contains(raw));
    assert_eq!(rendered.matches("[MASK:v1:FIO:").count(), 3);

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
                "database_id":database_id,
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

#[tokio::test]
async fn all_mode_cold_start_uses_metadata_stage_then_explicit_selector_follow_up() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
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
    storage.enqueue_feed_job(database_id, 2).unwrap();
    let state = AppState::new(storage, "https://masking.test");
    let app = internal_app(state.clone());

    let response = app
        .clone()
        .oneshot(get_request("/internal/v1/feed/jobs?limit=10"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let jobs: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let stage_one = &jobs["jobs"][0];
    assert_eq!(stage_one["dictionary_selectors"], json!([]));
    let job_id = stage_one["job_id"].as_str().unwrap();
    let payload = json!({
        "selection_id":null,
        "page_index":0,
        "metadata":[{
            "source_path":"Catalog.Organizations.Description",
            "field_name":"Description",
            "field_type":"String",
            "password_mode":false
        }],
        "dictionary_values":[],
        "final_chunk":true
    });
    let digest = canonical_digest(&payload);
    let response = app
        .clone()
        .oneshot(json_request(
            &format!("/internal/v1/feed/jobs/{job_id}/chunks/0"),
            json!({
                "schema_version":1,
                "correlation_id":Uuid::new_v4(),
                "chunk_digest":hex(&digest),
                "payload":payload
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let aggregate: [u8; 32] = Sha256::digest(digest).into();
    let response = app
        .clone()
        .oneshot(json_request(
            &format!("/internal/v1/feed/jobs/{job_id}/activate"),
            json!({
                "schema_version":1,
                "correlation_id":Uuid::new_v4(),
                "expected_chunks":1,
                "expected_metadata_count":1,
                "expected_dictionary_count":0,
                "aggregate_digest":hex(&aggregate)
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let activation: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(
        activation,
        json!({"schema_version":1,"cache_version":2,"status":"active"})
    );
    assert!(!state.masking.database_ready(database_id).await);

    let response = app
        .oneshot(get_request("/internal/v1/feed/jobs?limit=10"))
        .await
        .unwrap();
    let jobs: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let selectors = jobs["jobs"][0]["dictionary_selectors"].as_array().unwrap();
    assert_eq!(selectors.len(), 1);
    assert_eq!(
        selectors[0]["source_path"],
        "Catalog.Organizations.Description"
    );
    assert_ne!(selectors[0]["source_path"], "*");
}

fn canonical_digest(value: &Value) -> [u8; 32] {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect(),
            ),
            Value::Array(array) => Value::Array(array.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    Sha256::digest(serde_json::to_vec(&sort(value)).unwrap()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
