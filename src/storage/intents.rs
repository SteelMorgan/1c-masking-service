//++agent TASK-222 [05.10.2026]
//! Durable refresh intents и commit pull-generation для pull-модели.
//!
//! `v2_refresh_intents` переиспользуется как durable-очередь refresh
//! (имя таблицы оставлено для совместимости миграций). Phase всегда 'full' —
//! refresh всегда полный (metadata + dictionary). `cache_generations` —
//! журнал прогонов: успешный pull атомарно помечает прежнюю 'active'
//! generation 'failed', вставляет новую 'active' и поднимает
//! `databases.active_cache_version`.

use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::domain::RefreshIntent;

use super::SqliteStorage;

impl SqliteStorage {
    /// Читает строку `dictionary_configs` (mode/source_paths/filter_ast).
    pub(crate) fn dictionary_config_row(
        &self,
        database_id: Uuid,
    ) -> rusqlite::Result<Option<(String, String, Option<String>)>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT mode,source_paths_json,filter_ast_json FROM dictionary_configs WHERE database_id=?1",
                    [database_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
        })
    }

    /// Ожидающие intents в порядке постановки — очередь pull worker.
    /// §8.1: берутся только `state='pending'`, у которых наступил
    /// `next_attempt_at` (или повтора ещё не назначали); `needs_attention`
    /// не выбирается до явного сброса Admin-ом или рестарта сервиса.
    pub(crate) fn pending_refresh_intents(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<RefreshIntent>> {
        self.with_connection(|connection| {
            let now = Utc::now().to_rfc3339();
            let mut statement = connection.prepare(
                "SELECT database_id,reason,actor_id,created_at,attempts,state
                 FROM v2_refresh_intents
                 WHERE state='pending'
                   AND (next_attempt_at IS NULL OR next_attempt_at<=?2)
                 ORDER BY created_at LIMIT ?1",
            )?;
            let rows = statement.query_map(params![limit.clamp(1, 100) as i64, now], |row| {
                let actor_id: Option<String> = row.get(2)?;
                Ok(RefreshIntent {
                    database_id: parse_uuid(row.get::<_, String>(0)?)?,
                    reason: row.get(1)?,
                    actor_id: actor_id.and_then(|id| Uuid::parse_str(&id).ok()),
                    created_at: row.get(3)?,
                    attempts: row.get(4)?,
                    state: row.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    //++agent TASK-225 [26.09.2026] фаза-2 C
    /// Есть ли по базе ожидающий pull (`state='pending'` — intent в
    /// очереди или выполняется прямо сейчас: worker снимает его только
    /// при успехе). `needs_attention` сюда не входит — прогрев там
    /// остановлен до ручного refresh, и ответ агенту должен быть
    /// обычным SERVICE_NOT_READY, а не обещанием повтора.
    pub(crate) fn refresh_intent_pending(&self, database_id: Uuid) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM v2_refresh_intents
                 WHERE database_id=?1 AND state='pending')",
                [database_id.to_string()],
                |row| row.get::<_, i64>(0),
            )? != 0)
        })
    }
    //++agent TASK-225

    /// §8.1: фиксирует transient-неудачу серии — `attempts+1`,
    /// `first_failed_at` (если NULL), `last_error_*`, `next_attempt_at`
    /// (уже посчитанный caller'ом момент повтора). При достижении
    /// `max_attempts` intent переводится в `needs_attention`. Код и время
    /// зеркалируются в `databases` для поля `refresh` ответа B2.
    /// Возвращает (новое число попыток, перешёл ли в needs_attention).
    pub(crate) fn record_refresh_failure(
        &self,
        database_id: Uuid,
        code: &str,
        next_attempt_at: &str,
        max_attempts: u64,
    ) -> rusqlite::Result<(u64, bool)> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let now = Utc::now().to_rfc3339();
            let (attempts, needs_attention): (i64, bool) = transaction.query_row(
                "UPDATE v2_refresh_intents SET
                   attempts=attempts+1,
                   first_failed_at=COALESCE(first_failed_at,?2),
                   last_error_code=?3,
                   last_error_at=?2,
                   next_attempt_at=?4,
                   state=CASE WHEN attempts+1>=?5 THEN 'needs_attention' ELSE state END
                 WHERE database_id=?1
                 RETURNING attempts, state='needs_attention'",
                params![
                    database_id.to_string(),
                    now,
                    code,
                    next_attempt_at,
                    max_attempts.min(i64::MAX as u64) as i64
                ],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )?;
            transaction.execute(
                "UPDATE databases SET last_refresh_error_code=?2,last_refresh_error_at=?3,updated_at=?3 WHERE id=?1",
                params![database_id.to_string(), code, now],
            )?;
            transaction.commit()?;
            Ok((attempts.max(0) as u64, needs_attention))
        })
    }

    /// §8.1: детерминированная неудача pull — intent снимается (повтор
    /// бесполезен), код и время сохраняются в `databases`, чтобы B2
    /// отдавал `refresh.state="failed"` до следующего успешного pull.
    pub(crate) fn record_refresh_terminal_failure(
        &self,
        database_id: Uuid,
        code: &str,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "UPDATE databases SET last_refresh_error_code=?2,last_refresh_error_at=?3,updated_at=?3 WHERE id=?1",
                params![database_id.to_string(), code, now],
            )?;
            transaction.execute(
                "DELETE FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
            )?;
            transaction.commit()
        })
    }

    /// §8.1: успешный pull — фиксирует `last_refresh_ok_at` и снимает
    /// состояние `failed` (последняя детерминированная ошибка гасится).
    /// Вызывается в транзакции commit pull-generation: durable-фиксация
    /// успеха атомарна с самим commit.
    fn record_refresh_success_tx(
        transaction: &rusqlite::Transaction<'_>,
        database_id: Uuid,
        now: &str,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            "UPDATE databases SET last_refresh_ok_at=?2,last_refresh_error_code=NULL,last_refresh_error_at=NULL WHERE id=?1",
            params![database_id.to_string(), now],
        )?;
        Ok(())
    }

    /// §8.2: успех после серии неудач — одна строка аудита с числом
    /// попыток в `code` (в таблице нет details-колонки).
    pub(crate) fn audit_feed_pull_recovered(
        &self,
        database_id: Uuid,
        attempts: u64,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO audit_events(actor_kind,action,database_id,outcome,code,correlation_id,created_at)
                 VALUES ('service','feed.pull.recovered',?1,'success',?2,?3,?4)",
                params![
                    database_id.to_string(),
                    format!("attempts={attempts}"),
                    Uuid::new_v4().to_string(),
                    Utc::now().to_rfc3339()
                ],
            )?;
            Ok(())
        })
    }

    /// Условное удаление: intent удаляется только если его `created_at` —
    /// тот, что обрабатывал pull. Concurrent upsert (Admin-мутация во время
    /// pull) меняет created_at → delete промахивается → новая мутация
    /// получает свой refresh следующим тиком. Lock-free вместо удержания
    /// per-DB admission на всю сетевую работу pull.
    pub(crate) fn delete_refresh_intent_if_unchanged(
        &self,
        database_id: Uuid,
        created_at: &str,
    ) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute(
                "DELETE FROM v2_refresh_intents WHERE database_id=?1 AND created_at=?2",
                params![database_id.to_string(), created_at],
            )? == 1)
        })
    }

    /// Безусловное удаление intent — disable БД и детерминированные
    /// ошибки pull (конфигурация/форма страниц), при которых повтор
    /// бесполезен и fail-closed уже обеспечен.
    pub(crate) fn delete_refresh_intent(&self, database_id: Uuid) -> rusqlite::Result<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute(
                "DELETE FROM v2_refresh_intents WHERE database_id=?1",
                [database_id.to_string()],
            )? == 1)
        })
    }

    /// Startup rewarm: после restart RAM snapshots/manifests потеряны — для
    /// каждой enabled-базы создаётся intent 'full', если его ещё нет
    /// (существующий intent не перезаписывается — он уже отражает
    /// поставленную работу). Вызывается `MaskingService::new`.
    pub(crate) fn enqueue_startup_pull_intents(&self) -> rusqlite::Result<usize> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let inserted = transaction.execute(
                "INSERT INTO v2_refresh_intents(database_id,phase,reason,actor_id,created_at)
                 SELECT d.id,'full','startup_rewarm',NULL,?1
                 FROM databases d
                 WHERE d.mode='enabled'
                   AND NOT EXISTS(
                       SELECT 1 FROM v2_refresh_intents i WHERE i.database_id=d.id)",
                [Utc::now().to_rfc3339()],
            )?;
            //++agent TASK-225 [25.09.2026]
            // §8.1: рестар сервиса сбрасывает needs_attention — после
            // рестарта причина отказа могла уйти (менеджер доступен),
            // поэтому зависшие intents возвращаются в работу.
            transaction.execute(
                "UPDATE v2_refresh_intents SET state='pending',attempts=0,next_attempt_at=NULL WHERE state<>'pending'",
                [],
            )?;
            //++agent TASK-225
            transaction.commit()?;
            Ok(inserted)
        })
    }

    pub(crate) fn next_cache_version(&self, database_id: Uuid) -> rusqlite::Result<u64> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT COALESCE(active_cache_version,0)+1 FROM databases WHERE id=?1",
                    [database_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .map(|version| version.max(0) as u64)
        })
    }

    /// Атомарный commit успешного pull: старые 'active' generations →
    /// 'failed', новая строка 'active' с digest/счётчиками/selectors,
    /// `active_cache_version` поднимается до `version`. RAM-сторона
    /// (policy cache + manifest) обновляется caller'ом только после
    /// успешного commit — durable commit идёт первым.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_pull_generation(
        &self,
        database_id: Uuid,
        version: u64,
        digest: &str,
        metadata_count: usize,
        dictionary_count: usize,
        selectors_json: &str,
        //++agent TASK-225 [25.09.2026]
        // §5a.3: статистика источников последнего pull —
        // [{source_path,category,values,bytes}] для диагностики B2.
        source_stats_json: &str,
        //++agent TASK-225
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            let transaction = connection.transaction_with_behavior(
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "UPDATE cache_generations SET status='failed' WHERE database_id=?1 AND status='active'",
                [database_id.to_string()],
            )?;
            transaction.execute(
                "INSERT OR REPLACE INTO cache_generations(database_id,version,digest,status,metadata_count,dictionary_count,selectors_json,source_stats_json,created_at,activated_at)
                 VALUES (?1,?2,?3,'active',?4,?5,?6,?7,?8,?8)",
                params![
                    database_id.to_string(),
                    version.min(i64::MAX as u64) as i64,
                    digest,
                    metadata_count as i64,
                    dictionary_count as i64,
                    selectors_json,
                    source_stats_json,
                    now
                ],
            )?;
            transaction.execute(
                "UPDATE databases SET active_cache_version=?2,updated_at=?3 WHERE id=?1",
                params![database_id.to_string(), version.min(i64::MAX as u64) as i64, now],
            )?;
            //++agent TASK-225 [25.09.2026]
            // §8.1: успешный pull гасит состояние failed/retrying и
            // фиксирует last_refresh_ok_at атомарно с commit поколения.
            Self::record_refresh_success_tx(&transaction, database_id, &now)?;
            //++agent TASK-225
            transaction.commit()
        })
    }

    /// Audit неуспешного pull — аналог прежнего `feed.fail`: нейтральный
    /// code без бизнес-данных.
    pub(crate) fn audit_feed_pull_failed(
        &self,
        database_id: Uuid,
        code: &str,
    ) -> rusqlite::Result<()> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO audit_events(actor_kind,action,database_id,outcome,code,correlation_id,created_at)
                 VALUES ('service','feed.pull',?1,'failed',?2,?3,?4)",
                params![
                    database_id.to_string(),
                    code,
                    Uuid::new_v4().to_string(),
                    Utc::now().to_rfc3339()
                ],
            )?;
            Ok(())
        })
    }
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}
//++agent TASK-222
