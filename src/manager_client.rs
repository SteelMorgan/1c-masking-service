//++agent TASK-222 [05.10.2026]
//! Клиент к v8-session-manager по Unix domain socket: единственный вызов —
//! `POST /internal/v1/tools/call` для internal feed-инструментов
//! (metadata/dictionary pull). Это не универсальный MCP-клиент: сервис не
//! ходит на `/mcp` и не использует Ed25519-assertions — внутренний endpoint
//! защищён peer-UID на стороне менеджера.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::UnixStream;

/// Request bound: selector+cursor — маленький фиксированный JSON.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Response bound совпадает с internal-body конвенцией сервиса: feed-страница
/// ограничена producer-стороной ~1 МиБ, запас до 8 МиБ оставляет headroom.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const TOOLS_CALL_PATH: &str = "/internal/v1/tools/call";

#[derive(Debug, thiserror::Error)]
pub enum ManagerClientError {
    /// Сокет недоступен / HTTP handshake / IO — transient, pull повторится.
    #[error("manager transport unavailable")]
    Transport,
    #[error("manager call deadline exceeded")]
    Timeout,
    /// Не-JSON, не-200 без error-конверта, битая структура ответа.
    #[error("manager returned an invalid response")]
    InvalidResponse,
    /// `{"success":false,"error":{"code":...}}` — отказ уровня вызова.
    #[error("internal tool call rejected: {code}")]
    Rejected { code: String },
}

/// Типизированный HTTP/1.1 клиент к manager UDS.
#[derive(Debug, Clone)]
pub struct ManagerClient {
    socket_path: PathBuf,
    /// Ожидаемый UID владельца сокета (`MASKING_MANAGER_UID`) — защита от
    /// подключения к чужому сокету; `None` отключает проверку (тесты).
    expected_uid: Option<u32>,
    call_timeout: Duration,
}

impl ManagerClient {
    pub fn new(socket_path: PathBuf, expected_uid: Option<u32>) -> Self {
        Self {
            socket_path,
            expected_uid,
            call_timeout: Duration::from_secs(bounded_env_u64(
                "MASKING_MANAGER_CALL_TIMEOUT_SECONDS",
                30,
                1,
                120,
            )),
        }
    }

    /// `POST /internal/v1/tools/call` `{instance_id,name,arguments}` →
    /// `result` успешного ответа. Семантика ошибок различает отказ вызова
    /// (`Rejected`) и недоступность транспорта — pull-runner маппит их
    /// по-разному на судьбу durable intent.
    //++agent TASK-225 [26.09.2026] O2: маршрут к базе — точный ключ
    // `instance_id`, менеджер сопоставляет сессию только по нему.
    pub async fn call_tool(
        &self,
        identity: &crate::domain::DatabaseIdentity,
        name: &str,
        arguments: &Value,
    ) -> Result<Value, ManagerClientError> {
        let body = json!({
            "instance_id": identity.instance_id,
            "name": name,
            "arguments": arguments,
        });
        let body = serde_json::to_vec(&body).map_err(|_| ManagerClientError::InvalidResponse)?;
        let attempt = request_bytes(&self.socket_path, self.expected_uid, TOOLS_CALL_PATH, body);
        let response = tokio::time::timeout(self.call_timeout, attempt)
            .await
            .map_err(|_| ManagerClientError::Timeout)??;
        parse_call_response(&response)
    }
}

async fn request_bytes(
    socket_path: &Path,
    expected_uid: Option<u32>,
    path: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, ManagerClientError> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ManagerClientError::InvalidResponse);
    }
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|_| ManagerClientError::Transport)?;
    if let Some(expected) = expected_uid {
        let uid = stream
            .peer_cred()
            .map_err(|_| ManagerClientError::Transport)?
            .uid();
        if uid != expected {
            return Err(ManagerClientError::Transport);
        }
    }
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| ManagerClientError::Transport)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(hyper::header::HOST, "v8-session-manager")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| ManagerClientError::InvalidResponse)?;
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|_| ManagerClientError::Transport)?;
    let ok_status = response.status().is_success();
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| ManagerClientError::Transport)?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > MAX_RESPONSE_BYTES {
                return Err(ManagerClientError::InvalidResponse);
            }
            bytes.extend_from_slice(&data);
        }
    }
    //++agent TASK-225 [26.09.2026]
    // K: менеджер отдаёт отказы уровня вызова не-2xx статусом
    // (503 `no_target`, 404 `method_not_found`…) —
    // код конверта важнее статуса: иначе «база не привязана» неотличима
    // от «менеджер не отвечает». Неразборчивый ответ — по-прежнему
    // InvalidResponse.
    if !ok_status {
        return match parse_call_response(&bytes) {
            Err(rejected @ ManagerClientError::Rejected { .. }) => Err(rejected),
            _ => Err(ManagerClientError::InvalidResponse),
        };
    }
    //++agent TASK-225
    Ok(bytes)
}

#[derive(Deserialize)]
struct CallEnvelope {
    success: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Option<CallErrorBody>,
}

#[derive(Deserialize)]
struct CallErrorBody {
    code: String,
}

fn parse_call_response(bytes: &[u8]) -> Result<Value, ManagerClientError> {
    let envelope: CallEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ManagerClientError::InvalidResponse)?;
    if envelope.success {
        return Ok(envelope.result);
    }
    let code = envelope
        .error
        .map(|error| error.code)
        .filter(|code| !code.is_empty() && code.len() <= 128)
        .unwrap_or_else(|| "UNKNOWN".to_owned());
    Err(ManagerClientError::Rejected { code })
}

fn bounded_env_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}
//++agent TASK-222
