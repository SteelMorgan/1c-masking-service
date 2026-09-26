//++agent TASK-225 [25.09.2026]
//! §8 устойчивость refresh: backoff transient-неудач pull, аудит без шума,
//! поле `refresh` в B2 (T9-01..T9-05).
mod common;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use chrono::{DateTime, Utc};
use onec_masking_service::{
    api::human::{HumanDataStore, SqliteHumanDataStore},
    auth::{Principal, Role},
    domain::{DatabaseMode, MaskingService},
    manager_client::ManagerClient,
    AppState, SqliteStorage,
};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use uuid::Uuid;

use common::{empty_feed_responder, enqueue_refresh_intent, FakeManager};

/// Клиент к несуществующему UDS — каждый pull падает
/// `MANAGER_UNAVAILABLE` (Transient) до первой страницы.
fn dead_client() -> ManagerClient {
    ManagerClient::new("/nonexistent/masked-manager.sock".into(), None)
}

fn admin() -> Principal {
    Principal {
        user_id: Uuid::new_v4(),
        role: Role::Admin,
        auth_epoch: 1,
    }
}

fn enabled_database(storage: &SqliteStorage) -> Uuid {
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    assert!(storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap());
    database_id
}

/// Строка intent как кортеж (attempts, state, next_attempt_at,
/// last_error_at, first_failed_at).
fn intent_row(
    storage: &SqliteStorage,
    database_id: Uuid,
) -> (i64, String, Option<String>, Option<String>, Option<String>) {
    storage
        .with_connection(|c| {
            c.query_row(
                "SELECT attempts,state,next_attempt_at,last_error_at,first_failed_at FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
        })
        .unwrap()
}

fn audit_count(storage: &SqliteStorage, database_id: Uuid, action: &str, outcome: &str) -> i64 {
    storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE database_id=?1 AND action=?2 AND outcome=?3",
                params![database_id.to_string(), action, outcome],
                |row| row.get(0),
            )
        })
        .unwrap()
}

/// Повтор «наступил»: следующий тик воркера подхватит intent без ожидания
/// реального backoff-интервала.
fn force_due(storage: &SqliteStorage, database_id: Uuid) {
    storage
        .with_connection(|c| {
            c.execute(
                "UPDATE v2_refresh_intents SET next_attempt_at=NULL WHERE database_id=?1",
                [database_id.to_string()],
            )
        })
        .unwrap();
}

fn rfc3339(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

// T9-01: серия MANAGER_UNAVAILABLE — attempts растёт, next_attempt_at
// отстаёт по экспоненте (base=10с: задержки 1..3-й попыток лежат в
// непересекающихся диапазонах jitter ±20%: [8,12], [16,24], [32,48]).
#[tokio::test]
async fn transient_failures_schedule_growing_backoff() {
    // Детерминированная задержка: джиттер выключен до создания AppState
    // (jitter_span читается один раз в PullRetryPolicy::from_env). Другие
    // тесты бинаря от этого только стабильнее — span=0 лишь убирает шум.
    unsafe {
        std::env::set_var("MASKING_PULL_RETRY_JITTER_SPAN", "0");
    }
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = enabled_database(&storage);
    let state = AppState::new(storage.clone(), "https://masking.test");
    let client = dead_client();

    // Без джиттера задержка точная: base·2^(n-1). Замер по меткам
    // next_attempt_at − last_error_at: обе секундной точности
    // (rfc3339), расхождение — доли секунды между двумя Utc::now().
    let expected = [10.0_f64, 20.0, 40.0];
    for (attempt, want) in expected.iter().enumerate() {
        force_due(&storage, database_id);
        let completed = state
            .masking
            .refresh_due_intents(&client, 10)
            .await
            .unwrap();
        assert_eq!(completed, 0);
        let (attempts, st, next_at, last_err_at, first_failed_at) =
            intent_row(&storage, database_id);
        assert_eq!(attempts, attempt as i64 + 1);
        assert_eq!(st, "pending");
        assert!(first_failed_at.is_some());
        let delay = rfc3339(&next_at.unwrap()) - rfc3339(&last_err_at.unwrap());
        let seconds = delay.num_milliseconds() as f64 / 1000.0;
        assert!(
            (*want - 1.0..=*want).contains(&seconds),
            "attempt {attempts}: delay {seconds}s, want {want}"
        );
    }
    // §8.2: аудируется только первая неудача серии.
    assert_eq!(audit_count(&storage, database_id, "feed.pull", "failed"), 1);
}

// T9-02: 8 неудач (дефолтный max_attempts) → needs_attention, воркер
// intent больше не берёт, audit-строк ровно 2 (первая + переход).
#[tokio::test]
async fn max_attempts_moves_intent_to_needs_attention() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = enabled_database(&storage);
    let state = AppState::new(storage.clone(), "https://masking.test");
    let client = dead_client();

    for _ in 0..8 {
        force_due(&storage, database_id);
        state
            .masking
            .refresh_due_intents(&client, 10)
            .await
            .unwrap();
    }
    let (attempts, st, _, _, _) = intent_row(&storage, database_id);
    assert_eq!(attempts, 8);
    assert_eq!(st, "needs_attention");

    // needs_attention не выбирается воркером — тик пустой.
    let completed = state
        .masking
        .refresh_due_intents(&client, 10)
        .await
        .unwrap();
    assert_eq!(completed, 0);
    assert_eq!(intent_row(&storage, database_id).0, 8);
    assert_eq!(audit_count(&storage, database_id, "feed.pull", "failed"), 2);
}

// T9-03: POST /refresh (admin_refresh intent) сбрасывает серию; успех
// после неудач пишет feed.pull.recovered и last_refresh_ok_at.
#[tokio::test]
async fn admin_refresh_resets_and_recovery_is_audited() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = enabled_database(&storage);
    let state = AppState::new(storage.clone(), "https://masking.test");
    let fail = Arc::new(AtomicBool::new(true));
    let responder_fail = fail.clone();
    let fake = FakeManager::spawn(move |name, _| {
        if responder_fail.load(Ordering::SeqCst) {
            Err("INTERNAL_TOOL_FAILED".to_owned())
        } else {
            empty_feed_responder(name, &Value::Null)
        }
    });

    // Две transient-неудачи — серия остаётся pending.
    for _ in 0..2 {
        force_due(&storage, database_id);
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap();
    }
    assert_eq!(intent_row(&storage, database_id).0, 2);

    // Явный refresh Admin-ом = новая серия.
    let data = SqliteHumanDataStore::new(storage.clone(), state.masking.clone());
    data.refresh_database(&admin(), database_id, Uuid::new_v4())
        .unwrap();
    let (attempts, st, next_at, _, _) = intent_row(&storage, database_id);
    assert_eq!((attempts, st.as_str(), next_at), (0, "pending", None));

    // Успешный pull удаляет intent и фиксирует recovered-аудит… но после
    // сброса attempts=0 recovered не пишется — проверяем отдельной серией:
    // две неудачи → успех без сброса.
    for _ in 0..2 {
        force_due(&storage, database_id);
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap();
    }
    fail.store(false, Ordering::SeqCst);
    force_due(&storage, database_id);
    let completed = state
        .masking
        .refresh_due_intents(&fake.client(), 10)
        .await
        .unwrap();
    assert_eq!(completed, 1);
    storage
        .with_connection(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|count| assert_eq!(count, 0, "intent must be deleted after success"))
        .unwrap();
    let recovered: Option<String> = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT code FROM audit_events WHERE database_id=?1 AND action='feed.pull.recovered' AND outcome='success'",
                [database_id.to_string()],
                |row| row.get(0),
            )
            .optional()
        })
        .unwrap();
    assert_eq!(recovered.as_deref(), Some("attempts=2"));
    let (ok_at, err_code): (Option<String>, Option<String>) = storage
        .with_connection(|c| {
            c.query_row(
                "SELECT last_refresh_ok_at,last_refresh_error_code FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert!(ok_at.is_some());
    assert!(err_code.is_none(), "success clears terminal error state");
}

// T9-04: старт сервиса возвращает needs_attention в работу.
#[tokio::test]
async fn startup_rewinds_needs_attention() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = enabled_database(&storage);
    enqueue_refresh_intent(&storage, database_id);
    storage
        .with_connection(|c| {
            c.execute(
                "UPDATE v2_refresh_intents SET state='needs_attention',attempts=8,next_attempt_at=?2 WHERE database_id=?1",
                params![database_id.to_string(), Utc::now().to_rfc3339()],
            )
        })
        .unwrap();
    // MaskingService::new → enqueue_startup_pull_intents.
    let _service = MaskingService::new(storage.clone());
    let (attempts, st, next_at, _, _) = intent_row(&storage, database_id);
    assert_eq!((attempts, st.as_str(), next_at), (0, "pending", None));
}

// T9-05: B2 отдаёт refresh.state/last_error_text по §8.3/§8.4.
#[tokio::test]
async fn b2_reports_refresh_state_and_error_text() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = enabled_database(&storage);
    let state = AppState::new(storage.clone(), "https://masking.test");
    let data = SqliteHumanDataStore::new(storage.clone(), state.masking.clone());

    // idle: нет intent, нет ошибок — сначала снимаем startup-intent.
    storage
        .with_connection(|c| {
            c.execute(
                "DELETE FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
            )
        })
        .unwrap();
    let refresh = data
        .list_databases()
        .unwrap()
        .into_iter()
        .find(|db| db.id == database_id)
        .unwrap()
        .refresh;
    assert_eq!(refresh.state, "idle");
    assert!(refresh.last_error_code.is_none());

    // running: intent поставлен и ждёт ближайший тик.
    enqueue_refresh_intent(&storage, database_id);
    let refresh = data
        .list_databases()
        .unwrap()
        .into_iter()
        .find(|db| db.id == database_id)
        .unwrap()
        .refresh;
    assert_eq!(refresh.state, "running");

    // retrying + текст MANAGER_UNAVAILABLE после первой неудачи.
    state
        .masking
        .refresh_due_intents(&dead_client(), 10)
        .await
        .unwrap();
    let refresh = data
        .list_databases()
        .unwrap()
        .into_iter()
        .find(|db| db.id == database_id)
        .unwrap()
        .refresh;
    assert_eq!(refresh.state, "retrying");
    assert_eq!(refresh.attempts, 1);
    assert_eq!(
        refresh.last_error_code.as_deref(),
        Some("MANAGER_UNAVAILABLE")
    );
    assert!(refresh
        .last_error_text
        .as_deref()
        .unwrap_or_default()
        .contains("Менеджер MCP недоступен"));
    assert!(refresh.first_failed_at.is_some());

    // needs_attention: префикс §8.3.
    storage
        .with_connection(|c| {
            c.execute(
                "UPDATE v2_refresh_intents SET state='needs_attention',attempts=8 WHERE database_id=?1",
                [database_id.to_string()],
            )
        })
        .unwrap();
    let refresh = data
        .list_databases()
        .unwrap()
        .into_iter()
        .find(|db| db.id == database_id)
        .unwrap()
        .refresh;
    assert_eq!(refresh.state, "needs_attention");
    assert!(refresh
        .last_error_text
        .as_deref()
        .unwrap_or_default()
        .contains("Автоматические попытки остановлены после 8 неудач"));

    // failed: детерминированная ошибка без intent — B2 читает databases.
    storage
        .with_connection(|c| {
            c.execute("DELETE FROM v2_refresh_intents WHERE database_id=?1", [database_id.to_string()])?;
            c.execute(
                "UPDATE databases SET last_refresh_error_code='POLICY_INVALID',last_refresh_error_at=?2 WHERE id=?1",
                params![database_id.to_string(), Utc::now().to_rfc3339()],
            )
        })
        .unwrap();
    let refresh = data
        .list_databases()
        .unwrap()
        .into_iter()
        .find(|db| db.id == database_id)
        .unwrap()
        .refresh;
    assert_eq!(refresh.state, "failed");
    assert_eq!(refresh.last_error_code.as_deref(), Some("POLICY_INVALID"));
    assert!(refresh
        .last_error_text
        .as_deref()
        .unwrap_or_default()
        .contains("Действующая настройка содержит правила"));
}
//++agent TASK-225
