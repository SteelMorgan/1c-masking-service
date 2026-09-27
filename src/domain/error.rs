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
    //++agent TASK-225 [26.09.2026]
    /// ОВ-2/Б12: у базы нет активной версии настройки (404).
    NoActiveVersion,
    /// §5.7: повторный сухой прогон базы, пока идёт текущий (409).
    DryRunBusy,
    /// Фаза-2 C: индекс словаря прогревается (pull запланирован/идёт) —
    /// ответ несёт `retry_after_s`, через сколько повторить вызов.
    ServiceWarmingUp,
    //--agent TASK-225
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
            //++agent TASK-225
            Self::NoActiveVersion => "NO_ACTIVE_VERSION",
            Self::DryRunBusy => "DRY_RUN_BUSY",
            Self::ServiceWarmingUp => "SERVICE_WARMING_UP",
            //--agent TASK-225
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceError {
    pub code: ErrorCode,
    pub correlation_id: Uuid,
    pub status: StatusCode,
    pub retryable: bool,
    //++agent TASK-225 [26.09.2026] фаза-2 C
    /// Оценка «повторить через N с» — только у SERVICE_WARMING_UP.
    pub retry_after_s: Option<u64>,
    //++agent TASK-225
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
            //++agent TASK-225
            ErrorCode::NoActiveVersion => (StatusCode::NOT_FOUND, false),
            ErrorCode::DryRunBusy => (StatusCode::CONFLICT, false),
            //--agent TASK-225
            ErrorCode::PolicyInvalid => (StatusCode::UNPROCESSABLE_ENTITY, false),
            ErrorCode::ResultLimitExceeded => (StatusCode::PAYLOAD_TOO_LARGE, false),
            //++agent TASK-225 [26.09.2026] фаза-2 C: прогрев —
            // retryable 503, как у ServiceNotReady; точная оценка
            // приходит через `warming_up` (текст и `retry_after_s`).
            ErrorCode::MaskingTimeout
            | ErrorCode::ServiceNotReady
            | ErrorCode::ServiceWarmingUp => (StatusCode::SERVICE_UNAVAILABLE, true),
            ErrorCode::MaskingFailed
            | ErrorCode::HistoryUnavailable
            | ErrorCode::MappingUnavailable => (StatusCode::SERVICE_UNAVAILABLE, false),
        };
        Self {
            code,
            correlation_id,
            status,
            retryable,
            retry_after_s: None,
        }
    }

    //++agent TASK-225 [26.09.2026] фаза-2 C
    /// Прогрев словаря: 503 + retryable + `retry_after_s` (оценка по
    /// числу значений прошлого pull, минимум 5с). В MCP-ответе
    /// менеджера — isError с этим текстом, не transport_error.
    pub fn warming_up(correlation_id: Uuid, retry_after_s: u64) -> Self {
        Self {
            code: ErrorCode::ServiceWarmingUp,
            correlation_id,
            status: StatusCode::SERVICE_UNAVAILABLE,
            retryable: true,
            retry_after_s: Some(retry_after_s.max(5)),
        }
    }
    //++agent TASK-225

    pub fn unauthorized(correlation_id: Uuid) -> Self {
        Self {
            code: ErrorCode::DatabaseIdentityUnverified,
            correlation_id,
            status: StatusCode::UNAUTHORIZED,
            retryable: false,
            retry_after_s: None,
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
            //++agent TASK-225
            ErrorCode::NoActiveVersion => "Активная версия настройки не найдена",
            //--agent TASK-225
            _ => "Операция временно недоступна",
        }
    }

    //++agent TASK-225 [26.09.2026] фаза-2 C
    /// Текст для пользователя/агента. У SERVICE_WARMING_UP динамический
    /// — включает оценку `retry_after_s`.
    fn user_message(&self) -> std::borrow::Cow<'_, str> {
        if self.code == ErrorCode::ServiceWarmingUp {
            return std::borrow::Cow::Owned(format!(
                "Сервис маскирования прогревает словарь, повторите через {} с",
                // `warming_up` — единственный конструктор кода — всегда
                // ставит retry_after_s (≥5).
                self.retry_after_s.unwrap_or_default()
            ));
        }
        std::borrow::Cow::Borrowed(self.message())
    }
    //++agent TASK-225
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
    message: std::borrow::Cow<'a, str>,
    correlation_id: Uuid,
    retryable: bool,
    //++agent TASK-225 [26.09.2026] фаза-2 C
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_s: Option<u64>,
    //++agent TASK-225
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
                message: self.user_message(),
                correlation_id: self.correlation_id,
                retryable: self.retryable,
                retry_after_s: self.retry_after_s,
            },
        };
        (self.status, Json(envelope)).into_response()
    }
}
