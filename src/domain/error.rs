use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("bounded processing failed")]
pub struct ProcessingError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    ActionRequired,
    DatabaseIdentityUnverified,
    ToolPendingReview,
    MaskTokenInvalid,
    ServiceNotReady,
    PolicyInvalid,
    ResultLimitExceeded,
    MaskingTimeout,
    MaskingFailed,
    HistoryUnavailable,
    MappingUnavailable,
    TerminalAlreadyRecorded,
    CallConflict,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActionRequired => "ACTION_REQUIRED",
            Self::DatabaseIdentityUnverified => "DATABASE_IDENTITY_UNVERIFIED",
            Self::ToolPendingReview => "TOOL_PENDING_REVIEW",
            Self::MaskTokenInvalid => "MASK_TOKEN_INVALID",
            Self::ServiceNotReady => "SERVICE_NOT_READY",
            Self::PolicyInvalid => "POLICY_INVALID",
            Self::ResultLimitExceeded => "RESULT_LIMIT_EXCEEDED",
            Self::MaskingTimeout => "MASKING_TIMEOUT",
            Self::MaskingFailed => "MASKING_FAILED",
            Self::HistoryUnavailable => "HISTORY_UNAVAILABLE",
            Self::MappingUnavailable => "MAPPING_UNAVAILABLE",
            Self::TerminalAlreadyRecorded => "TERMINAL_ALREADY_RECORDED",
            Self::CallConflict => "CALL_CONFLICT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceError {
    pub code: ErrorCode,
    pub correlation_id: Uuid,
    pub status: StatusCode,
    pub retryable: bool,
}

impl ServiceError {
    pub fn new(code: ErrorCode, correlation_id: Uuid) -> Self {
        let (status, retryable) = match code {
            ErrorCode::ActionRequired
            | ErrorCode::ToolPendingReview
            | ErrorCode::MaskTokenInvalid
            | ErrorCode::CallConflict
            | ErrorCode::TerminalAlreadyRecorded => (StatusCode::CONFLICT, false),
            ErrorCode::DatabaseIdentityUnverified => (StatusCode::BAD_REQUEST, false),
            ErrorCode::PolicyInvalid => (StatusCode::UNPROCESSABLE_ENTITY, false),
            ErrorCode::ResultLimitExceeded => (StatusCode::PAYLOAD_TOO_LARGE, false),
            ErrorCode::MaskingTimeout | ErrorCode::ServiceNotReady => {
                (StatusCode::SERVICE_UNAVAILABLE, true)
            }
            ErrorCode::MaskingFailed
            | ErrorCode::HistoryUnavailable
            | ErrorCode::MappingUnavailable => (StatusCode::SERVICE_UNAVAILABLE, false),
        };
        Self {
            code,
            correlation_id,
            status,
            retryable,
        }
    }

    pub fn unauthorized(correlation_id: Uuid) -> Self {
        Self {
            code: ErrorCode::DatabaseIdentityUnverified,
            correlation_id,
            status: StatusCode::UNAUTHORIZED,
            retryable: false,
        }
    }

    fn message(&self) -> &'static str {
        match self.code {
            ErrorCode::ActionRequired => "База требует настройки пользователем",
            ErrorCode::ToolPendingReview => "Инструмент ожидает проверки",
            ErrorCode::MaskTokenInvalid => "Значение недоступно",
            ErrorCode::DatabaseIdentityUnverified => "Идентичность базы не подтверждена",
            ErrorCode::ResultLimitExceeded => "Размер результата превышает допустимый предел",
            ErrorCode::TerminalAlreadyRecorded => "Завершение вызова уже зафиксировано",
            _ => "Операция временно недоступна",
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl std::error::Error for ServiceError {}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    correlation_id: Uuid,
    retryable: bool,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        //++agent TASK-225 [25.09.2026]
        // Единая точка error-логирования: все ответы-ошибки сервиса видны
        // в журнале по correlation_id без дополнительной инструментации
        // каждого обработчика.
        tracing::warn!(
            event = "service_error",
            code = self.code.as_str(),
            status = %self.status.as_u16(),
            correlation_id = %self.correlation_id,
        );
        //++agent TASK-225
        let envelope = ErrorEnvelope {
            error: ErrorBody {
                code: self.code.as_str(),
                message: self.message(),
                correlation_id: self.correlation_id,
                retryable: self.retryable,
            },
        };
        (self.status, Json(envelope)).into_response()
    }
}
