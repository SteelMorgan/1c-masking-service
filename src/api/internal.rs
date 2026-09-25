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
        database_id = %request.database_id,
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
        database_id = %request.database_id,
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
