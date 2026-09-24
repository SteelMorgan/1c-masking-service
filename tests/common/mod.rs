//++agent TASK-222 [05.10.2026]
//! Общие тестовые примитивы pull-модели: фейковый v8-session-manager на
//! Unix domain socket (HTTP/1.1 `POST /internal/v1/tools/call`) и хелперы
//! постановки durable refresh intent + прогон pull worker.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use onec_masking_service::{
    domain::{FeedDictionaryValue, FeedMetadataItem},
    manager_client::ManagerClient,
    AppState, SqliteStorage,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    task::JoinHandle,
};
use uuid::Uuid;

pub const METADATA_TOOL: &str = "mcp_internal_masking_metadata_feed";
pub const DICTIONARY_TOOL: &str = "mcp_internal_masking_dictionary_feed";

/// Одна запись вызова internal tool: `(tool_name, arguments)`.
pub type ToolCall = (String, Value);

/// Ответ фейкового менеджера: `Ok(result)` → `{"success":true,"result":..}`,
/// `Err(code)` → `{"success":false,"error":{"code":..}}` — отказ вызова
/// уровня `/internal/v1/tools/call` (не путать со страничным `success:false`).
pub type Responder = Arc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;

/// Фейковый менеджер: принимает HTTP/1.1 запросы на UDS, маршрутизирует по
/// `name` в замыкании-ответчике и записывает все вызовы для assertions.
pub struct FakeManager {
    socket_path: PathBuf,
    calls: Arc<Mutex<Vec<ToolCall>>>,
    _dir: tempfile::TempDir,
    _task: JoinHandle<()>,
}

impl FakeManager {
    pub fn spawn(
        responder: impl Fn(&str, &Value) -> Result<Value, String> + Send + Sync + 'static,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("manager.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let calls: Arc<Mutex<Vec<ToolCall>>> = Arc::new(Mutex::new(Vec::new()));
        let task_calls = calls.clone();
        let responder: Responder = Arc::new(responder);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let calls = task_calls.clone();
                let responder = responder.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, calls, responder).await;
                });
            }
        });
        Self {
            socket_path,
            calls,
            _dir: dir,
            _task: task,
        }
    }

    pub fn client(&self) -> ManagerClient {
        ManagerClient::new(self.socket_path.clone(), None)
    }

    /// Зафиксированные вызовы `(name, arguments)` в порядке поступления.
    pub fn calls(&self) -> Vec<ToolCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Вызовы одного инструмента.
    pub fn calls_for(&self, tool: &str) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|(name, _)| name == tool)
            .map(|(_, arguments)| arguments)
            .collect()
    }
}

async fn serve(
    stream: tokio::net::UnixStream,
    calls: Arc<Mutex<Vec<ToolCall>>>,
    responder: Responder,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = Vec::new();
    let mut header_end = None;
    while header_end.is_none() {
        let mut chunk = [0u8; 8192];
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        header_end = find_subslice(&buffer, b"\r\n\r\n").map(|pos| pos + 4);
    }
    let header_end = header_end.unwrap();
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_lowercase();
    let content_length: usize = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .and_then(|value| value.trim().parse().ok())
        })
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let mut chunk = [0u8; 8192];
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body: Value = serde_json::from_slice(&buffer[header_end..header_end + content_length])
        .unwrap_or(Value::Null);
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    let arguments = body["arguments"].clone();
    calls
        .lock()
        .unwrap()
        .push((name.clone(), arguments.clone()));
    let payload = match responder(&name, &arguments) {
        Ok(result) => json!({"success": true, "result": result}),
        Err(code) => json!({"success": false, "error": {"code": code, "message": code}}),
    };
    let payload = serde_json::to_vec(&payload).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    );
    writer.write_all(response.as_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.shutdown().await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Страница metadata feed (форма совпадает с BSL `РезультатFeed` —
/// `manifest_digest` BSL не отдаёт, решение Р1(а)).
pub fn metadata_page(
    items: Vec<FeedMetadataItem>,
    next_cursor: Option<&str>,
    final_chunk: bool,
) -> Value {
    json!({
        "success": true,
        "metadata": items,
        "dictionary_values": [],
        "next_cursor": next_cursor,
        "final_chunk": final_chunk
    })
}

/// Страница dictionary feed.
pub fn dictionary_page(
    values: Vec<FeedDictionaryValue>,
    next_cursor: Option<&str>,
    final_chunk: bool,
) -> Value {
    json!({
        "success": true,
        "metadata": [],
        "dictionary_values": values,
        "next_cursor": next_cursor,
        "final_chunk": final_chunk
    })
}

/// Страничный отказ (`success:false` внутри `result`) — отличается от
/// отказа вызова `Err(code)` в Responder.
pub fn failed_page(code: &str) -> Value {
    json!({
        "success": false,
        "metadata": [],
        "dictionary_values": [],
        "next_cursor": null,
        "final_chunk": true,
        "error": code
    })
}

pub fn metadata_item(
    source_path: &str,
    field_name: &str,
    field_type: &str,
    password_mode: bool,
) -> FeedMetadataItem {
    FeedMetadataItem {
        source_path: source_path.to_owned(),
        field_name: field_name.to_owned(),
        field_type: field_type.to_owned(),
        password_mode,
    }
}

pub fn dictionary_value(source_path: &str, category: &str, value: &str) -> FeedDictionaryValue {
    FeedDictionaryValue {
        source_path: source_path.to_owned(),
        category: category.to_owned(),
        value: value.to_owned(),
    }
}

/// Стандартный responder пустого словаря: один безопасный metadata item,
/// dictionary всегда пустая. Покрывает большинство finalize-тестов —
/// snapshot ready без словарных значений.
pub fn empty_feed_responder(name: &str, _: &Value) -> Result<Value, String> {
    match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Справочник.Test.Name",
                "Name",
                "String(50)",
                false,
            )],
            None,
            true,
        )),
        DICTIONARY_TOOL => Ok(dictionary_page(Vec::new(), None, true)),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    }
}

/// Durable refresh intent 'full' — тот же INSERT, что Admin-мутации/startup.
pub fn enqueue_refresh_intent(storage: &SqliteStorage, database_id: Uuid) {
    storage
        .with_connection(|connection| {
            connection.execute(
                "INSERT INTO v2_refresh_intents(database_id,phase,reason,actor_id,created_at)
                 VALUES (?1,'full','test',NULL,?2) ON CONFLICT(database_id) DO UPDATE SET
                 created_at=excluded.created_at",
                rusqlite::params![database_id.to_string(), chrono::Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
        .unwrap();
}

pub fn pending_intent_count(storage: &SqliteStorage, database_id: Uuid) -> i64 {
    storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap()
}

/// Включает базу и прогоняет pull через фейковый менеджер: ready-snapshot
/// получается тем же путём, что и в бою (intent → worker → manager → swap).
pub async fn pull_empty_cache(state: &AppState, database_id: Uuid) -> FakeManager {
    let fake = FakeManager::spawn(empty_feed_responder);
    enqueue_refresh_intent(&state.storage, database_id);
    let completed = state
        .masking
        .refresh_due_intents(&fake.client(), 10)
        .await
        .unwrap();
    assert_eq!(completed, 1, "initial pull must publish a ready snapshot");
    assert!(state.masking.database_ready(database_id).await);
    fake
}
//++agent TASK-222
