use std::sync::Arc;

use axum::{
    extract::{
        connect_info::{ConnectInfo, Connected},
        rejection::JsonRejection,
        DefaultBodyLimit, Query, Request, State,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::UnixListener;
use uuid::Uuid;

use crate::{
    domain::{
        FinalizeRequest, FinalizeResponse, PreflightRequest, PreflightResponse, ServiceError,
        TerminalEventRequest, TerminalEventResponse,
    },
    AppState,
};

pub fn router(state: Arc<AppState>) -> Router {
    let expected_peer_uid = state.expected_peer_uid;
    Router::new()
        .route("/internal/v1/calls/preflight", post(preflight))
        .route("/internal/v1/calls/finalize", post(finalize))
        .route("/internal/v1/calls/terminal", post(terminal))
        //++agent TASK-225 [26.09.2026]
        // ОВ-2/Б12: read-only экспорт настройки для MCP-инструмента
        // менеджера — JSON §1 активной версии, без значений словаря.
        .route("/internal/v1/setup/export", get(setup_export))
        //--agent TASK-225
        .route("/internal/v1/health/live", get(live))
        .route("/internal/v1/health/ready", get(ready))
        .layer(DefaultBodyLimit::max(bounded_env_usize(
            "MASKING_MAX_BODY_BYTES",
            8 * 1024 * 1024,
            1024,
            64 * 1024 * 1024,
        )))
        .layer(middleware::from_fn_with_state(
            expected_peer_uid,
            peer_uid_gate,
        ))
        .with_state(state)
}

#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub uid: Option<u32>,
}

impl Connected<axum::serve::IncomingStream<'_, UnixListener>> for UdsConnectInfo {
    fn connect_info(stream: axum::serve::IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream
                .io()
                .peer_cred()
                .ok()
                .map(|credentials| credentials.uid()),
        }
    }
}

async fn peer_uid_gate(
    State(expected): State<Option<u32>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<UdsConnectInfo>>() else {
        return ServiceError::unauthorized(Uuid::nil()).into_response();
    };
    if expected.is_some_and(|uid| peer.uid != Some(uid)) {
        return ServiceError::unauthorized(Uuid::nil()).into_response();
    }
    next.run(request).await
}

async fn preflight(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<PreflightRequest>, JsonRejection>,
) -> Result<Json<PreflightResponse>, ServiceError> {
    let Json(request) = bounded_json(payload)?;
    let correlation_id = request.correlation_id;
    //++agent TASK-225 [25.09.2026]
    // Точечный request-лог: только идентификаторы и решение — аргументы
    // и результаты вызовов в лог не идут (там могут быть данные до маскирования).
    tracing::info!(
        event = "call_preflight",
        %correlation_id,
        cluster_server = %request.identity.cluster_server,
        infobase_name = %request.identity.infobase_name,
        tool = %request.tool_name,
    );
    //++agent TASK-225
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(bounded_env_u64(
            "MASKING_PREFLIGHT_TIMEOUT_SECONDS",
            3,
            1,
            60,
        )),
        state.masking.preflight(request),
    )
    .await
    .map_err(|_| ServiceError::new(crate::domain::ErrorCode::MaskingTimeout, correlation_id))??;
    tracing::info!(
        event = "call_preflight_done",
        %correlation_id,
        decision = response.decision,
    );
    Ok(Json(response))
}

async fn finalize(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<FinalizeRequest>, JsonRejection>,
) -> Result<Json<FinalizeResponse>, ServiceError> {
    let Json(request) = bounded_json(payload)?;
    let correlation_id = request.correlation_id;
    //++agent TASK-225 [25.09.2026]
    let outcome_kind = match &request.outcome {
        crate::domain::FinalizeOutcome::ToolResult { .. } => "tool_result",
        crate::domain::FinalizeOutcome::TransportError { .. } => "transport_error",
    };
    tracing::info!(
        event = "call_finalize",
        %correlation_id,
        cluster_server = %request.identity.cluster_server,
        infobase_name = %request.identity.infobase_name,
        tool = %request.tool_name,
        outcome = outcome_kind,
    );
    //++agent TASK-225
    tokio::time::timeout(
        std::time::Duration::from_secs(bounded_env_u64(
            "MASKING_FINALIZE_TIMEOUT_SECONDS",
            15,
            1,
            300,
        )),
        state.masking.finalize(request),
    )
    .await
    .map_err(|_| ServiceError::new(crate::domain::ErrorCode::MaskingTimeout, correlation_id))?
    .map(Json)
}

async fn terminal(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<TerminalEventRequest>, JsonRejection>,
) -> Result<Json<TerminalEventResponse>, ServiceError> {
    let Json(request) = bounded_json(payload)?;
    //++agent TASK-225 [25.09.2026]
    tracing::info!(
        event = "call_terminal",
        correlation_id = %request.correlation_id,
        tool = %request.tool_name,
        error_code = %request.error_code,
    );
    //++agent TASK-225
    state.masking.record_terminal_event(request).map(Json)
}

fn bounded_json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<Json<T>, ServiceError> {
    payload.map_err(|rejection| {
        let status = rejection.status();
        let reason = match status {
            axum::http::StatusCode::PAYLOAD_TOO_LARGE => "JSON_PAYLOAD_TOO_LARGE",
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE => "JSON_CONTENT_TYPE_REJECTED",
            axum::http::StatusCode::UNPROCESSABLE_ENTITY => "JSON_DATA_REJECTED",
            axum::http::StatusCode::BAD_REQUEST => "JSON_SYNTAX_REJECTED",
            _ => "JSON_REQUEST_REJECTED",
        };
        tracing::warn!(reason, status = status.as_u16(), "bounded JSON rejected");
        let code = if status == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
            crate::domain::ErrorCode::ResultLimitExceeded
        } else {
            crate::domain::ErrorCode::DatabaseIdentityUnverified
        };
        ServiceError::new(code, Uuid::nil())
    })
}

//++agent TASK-225 [26.09.2026]
/// ОВ-2/Б12: параметры `GET /internal/v1/setup/export` — база обязательна,
/// `include_tools=1` добавляет секцию tools (снимок версии либо текущие
/// классификации). Параметра версии нет: агент видит только активную.
#[derive(Deserialize)]
struct SetupExportQuery {
    database_id: Uuid,
    include_tools: Option<u8>,
}

/// ОВ-2/Б12: сборка и аудит экспорта. Отказ при отсутствии базы/активной
/// версии — `NO_ACTIVE_VERSION` (404), при сбое хранилища — `SERVICE_NOT_READY`.
async fn setup_export(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SetupExportQuery>,
) -> Result<Json<Value>, ServiceError> {
    let correlation_id = Uuid::new_v4();
    let database_id = query.database_id;
    let include_tools = query.include_tools.unwrap_or(0) != 0;
    tracing::info!(
        event = "setup_export",
        %correlation_id,
        %database_id,
        include_tools,
    );
    let exported = state
        .storage
        .with_connection(|connection| {
            setup_export_body(connection, database_id, include_tools, correlation_id)
        })
        .map_err(|error| {
            tracing::warn!(event = "setup_export_failed", %correlation_id, %database_id, %error);
            ServiceError::new(crate::domain::ErrorCode::ServiceNotReady, correlation_id)
        })?;
    exported
        .map(Json)
        .ok_or_else(|| ServiceError::new(crate::domain::ErrorCode::NoActiveVersion, correlation_id))
}

/// Тело §1 активной версии + строки аудита (`setup.export` с actor_kind
/// `agent`) и setup_journal (`export`, version, sha256 выгрузки) в одной
/// транзакции. `Ok(None)` — базы или активной версии нет.
fn setup_export_body(
    connection: &mut rusqlite::Connection,
    database_id: Uuid,
    include_tools: bool,
    correlation_id: Uuid,
) -> rusqlite::Result<Option<Value>> {
    use crate::storage::setup::{
        current_tools, journal_insert, load_version, stored_version_content, VersionRef,
    };
    use rusqlite::OptionalExtension;
    use sha2::Digest;

    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let database: Option<Option<String>> = transaction
        .query_row(
            "SELECT display_label FROM databases WHERE id=?1",
            [database_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(label) = database else {
        return Ok(None);
    };
    let Some(version) = load_version(&transaction, database_id, &VersionRef::Active)? else {
        return Ok(None);
    };
    let content = stored_version_content(&version);
    //++agent TASK-225 [26.09.2026] MINOR-2: тело §1-файла собирает общая
    // export_file_json (та же, что у human-экспорта) — формы больше не
    // расходятся. Снимок tools_json у версии может отсутствовать
    // (версии до 0010) — тогда отдаём текущие классификации.
    let tools = if include_tools {
        match &content.tools {
            Some(specs) => Some(specs.clone()),
            None => Some(current_tools(&transaction, database_id)?),
        }
    } else {
        None
    };
    let body = crate::api::human::setup::export_file_json(
        &content,
        database_id,
        label.as_deref(),
        version.version,
        tools,
        &chrono::Utc::now().to_rfc3339(),
    );
    // sha256 — от сериализованного тела ответа (те же байты, что уйдут
    // клиенту): serde_json::to_string детерминирован для json!-макроса.
    let serialized = serde_json::to_string(&body).unwrap_or_default();
    let sha256 = format!("{:x}", sha2::Sha256::digest(serialized.as_bytes()));
    let now = chrono::Utc::now().to_rfc3339();
    transaction.execute(
        "INSERT INTO audit_events(actor_kind,action,database_id,outcome,code,correlation_id,created_at)
         VALUES ('agent','setup.export',?1,'success',?2,?3,?4)",
        rusqlite::params![
            database_id.to_string(),
            format!("version={} sha256={sha256}", version.version),
            correlation_id.to_string(),
            now,
        ],
    )?;
    journal_insert(
        &transaction,
        database_id,
        "agent",
        None,
        "export",
        Some(version.version),
        None,
        Some(&sha256),
        None,
        &now,
    )?;
    transaction.commit()?;
    Ok(Some(body))
}
//--agent TASK-225

async fn live() -> Json<Value> {
    Json(json!({"status":"live"}))
}

#[derive(Deserialize)]
struct ReadyQuery {
    database_id: Option<Uuid>,
}

async fn ready(State(state): State<Arc<AppState>>, Query(query): Query<ReadyQuery>) -> Json<Value> {
    let sqlite_ready = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=1)",
                [],
                |row| row.get::<_, bool>(0),
            )
        })
        .unwrap_or(false);
    let database = if let Some(database_id) = query.database_id {
        Some(
            json!({"database_id":database_id,"ready":sqlite_ready && state.masking.database_ready(database_id).await}),
        )
    } else {
        None
    };
    Json(
        json!({"status": if sqlite_ready { "ready" } else { "not_ready" }, "sqlite": sqlite_ready, "database":database}),
    )
}

fn bounded_env_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}

fn bounded_env_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}
