//! Миграция 0018: chat_id уходит из схемы, вызывающий — только атрибут
//! аудита caller_label. Guard фаз — фактическая схема, а не номер версии.

use onec_masking_service::storage::SqliteStorage;
use rusqlite::Connection;
use uuid::Uuid;

fn columns(connection: &Connection, table: &str) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<String>>>()
        .unwrap()
}

fn count(connection: &Connection, sql: &str) -> i64 {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// База в состоянии «до 0018»: legacy DDL c chat_id и строки во всех
/// таблицах, которые миграция должна очистить.
fn legacy_database(path: &std::path::Path, database_id: Uuid) {
    let connection = Connection::open(path).unwrap();
    for file in [
        "0001_core.sql",
        "0002_terminal_history.sql",
        "0009_call_contexts.sql",
    ] {
        let sql = std::fs::read_to_string(format!("migrations/{file}")).unwrap();
        connection.execute_batch(&sql).unwrap();
    }
    connection
        .execute(
            "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
             VALUES (?1,?1,'enabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
            [database_id.to_string()],
        )
        .unwrap();
    let history_id = Uuid::new_v4().to_string();
    connection
        .execute(
            "INSERT INTO history(id,database_id,chat_id,call_id,tool_name,outcome,policy_version,
                                 mask_reasons_json,public_result_json,report_json,created_at,expires_at)
             VALUES (?1,?2,'legacy-chat',?3,'execute_query','tool_result',1,'[]','{}','{}',
                     '2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
            rusqlite::params![history_id, database_id.to_string(), Uuid::new_v4().to_string()],
        )
        .unwrap();
    connection
        .execute_batch(
            "CREATE TABLE v2_call_receipts (
                 call_id TEXT PRIMARY KEY, database_id TEXT NOT NULL, database_instance_id TEXT NOT NULL,
                 session_id TEXT NOT NULL, connection_generation TEXT NOT NULL, chat_id TEXT NOT NULL,
                 tool_name TEXT NOT NULL, correlation_id TEXT NOT NULL, service_epoch TEXT NOT NULL,
                 lease_id TEXT NOT NULL UNIQUE, policy_version INTEGER NOT NULL, policy_digest TEXT NOT NULL,
                 plan_digest TEXT NOT NULL, issued_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
                 state TEXT NOT NULL, terminal_code TEXT,
                 history_id TEXT REFERENCES history(id) ON DELETE SET NULL)",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO v2_call_receipts(call_id,database_id,database_instance_id,session_id,
                 connection_generation,chat_id,tool_name,correlation_id,service_epoch,lease_id,
                 policy_version,policy_digest,plan_digest,issued_at_ms,expires_at_ms,state,history_id)
             VALUES (?1,?2,'i','s','g','legacy-chat','execute_query','c','e',?3,1,'p','d',1,2,'completed',?4)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                database_id.to_string(),
                Uuid::new_v4().to_string(),
                history_id
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO call_contexts(call_id,database_id,chat_id,tool_name,created_at,expires_at)
             VALUES (?1,?2,'legacy-chat','execute_query','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
            rusqlite::params![Uuid::new_v4().to_string(), database_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO audit_events(actor_kind,action,database_id,chat_id,outcome,correlation_id,created_at)
             VALUES ('service','call.denied',?1,'legacy-chat','denied','c','2026-01-01T00:00:00Z')",
            [database_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO unscoped_terminal_events(id,call_id,correlation_id,tool_name,error_code,created_at,expires_at)
             VALUES (?1,?2,'c','execute_query','CHAT_IDENTITY_REQUIRED','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
            rusqlite::params![Uuid::new_v4().to_string(), Uuid::new_v4().to_string()],
        )
        .unwrap();
}

fn assert_migrated(connection: &Connection) {
    let receipts = columns(connection, "v2_call_receipts");
    assert!(!receipts.contains(&"chat_id".to_owned()), "{receipts:?}");
    for table in ["history", "call_contexts", "audit_events"] {
        let names = columns(connection, table);
        assert!(!names.contains(&"chat_id".to_owned()), "{table}: {names:?}");
        assert!(
            names.contains(&"caller_label".to_owned()),
            "{table}: {names:?}"
        );
    }
    assert_eq!(
        count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    assert_eq!(
        count(
            connection,
            "SELECT COUNT(*) FROM schema_migrations WHERE version=18"
        ),
        1
    );
}

#[test]
fn legacy_schema_is_migrated_and_chat_bound_records_are_cleared() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sqlite3");
    let database_id = Uuid::new_v4();
    legacy_database(&path, database_id);

    let storage = SqliteStorage::open(&path).unwrap();
    storage
        .with_connection(|connection| {
            assert_migrated(connection);
            for table in ["history", "call_contexts", "unscoped_terminal_events"] {
                assert_eq!(
                    count(connection, &format!("SELECT COUNT(*) FROM {table}")),
                    0,
                    "{table} must be cleared"
                );
            }
            // Аудит сохраняется, но прежний chat_id в метку не переносится.
            assert_eq!(count(connection, "SELECT COUNT(*) FROM audit_events"), 1);
            assert_eq!(
                count(
                    connection,
                    "SELECT COUNT(*) FROM audit_events WHERE caller_label IS NOT NULL"
                ),
                0
            );
            // Уникальность истории — (database_id, call_id) без разговора.
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='history'",
                [],
                |row| row.get(0),
            )?;
            assert!(sql.contains("UNIQUE (database_id, call_id)"), "{sql}");
            Ok(())
        })
        .unwrap();
}

#[test]
fn repeated_start_on_migrated_schema_is_a_no_op() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sqlite3");
    let database_id = Uuid::new_v4();
    {
        let storage = SqliteStorage::open(&path).unwrap();
        storage
            .with_connection(|connection| {
                assert_migrated(connection);
                connection.execute(
                    "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
                     VALUES (?1,?1,'enabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                    [database_id.to_string()],
                )?;
                connection.execute(
                    "INSERT INTO history(id,database_id,caller_label,call_id,tool_name,outcome,policy_version,
                         mask_reasons_json,public_result_json,report_json,created_at,expires_at)
                     VALUES (?1,?2,'client/1.0 #abcdef12',?3,'execute_query','tool_result',1,'[]','{}','{}',
                             '2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
                    rusqlite::params![
                        Uuid::new_v4().to_string(),
                        database_id.to_string(),
                        Uuid::new_v4().to_string()
                    ],
                )?;
                Ok(())
            })
            .unwrap();
    }
    let storage = SqliteStorage::open(&path).unwrap();
    storage
        .with_connection(|connection| {
            assert_migrated(connection);
            assert_eq!(count(connection, "SELECT COUNT(*) FROM history"), 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn partially_migrated_schema_is_completed_in_place() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sqlite3");
    let database_id = Uuid::new_v4();
    {
        let storage = SqliteStorage::open(&path).unwrap();
        storage
            .with_connection(|connection| {
                connection.execute(
                    "INSERT INTO databases(id,instance_id,mode,created_at,updated_at)
                     VALUES (?1,?1,'enabled','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                    [database_id.to_string()],
                )?;
                connection.execute(
                    "INSERT INTO history(id,database_id,caller_label,call_id,tool_name,outcome,policy_version,
                         mask_reasons_json,public_result_json,report_json,created_at,expires_at)
                     VALUES (?1,?2,NULL,?3,'execute_query','tool_result',1,'[]','{}','{}',
                             '2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
                    rusqlite::params![
                        Uuid::new_v4().to_string(),
                        database_id.to_string(),
                        Uuid::new_v4().to_string()
                    ],
                )?;
                // Остаток прерванной миграции: call_contexts и аудит
                // ещё в прежней форме, а version=18 уже записана.
                connection.execute_batch(
                    "DROP TABLE call_contexts;
                     CREATE TABLE call_contexts (
                         call_id TEXT PRIMARY KEY, database_id TEXT NOT NULL,
                         chat_id TEXT NOT NULL, tool_name TEXT NOT NULL, title TEXT,
                         created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         had_mask_tokens INTEGER NOT NULL DEFAULT 0);
                     ALTER TABLE audit_events RENAME COLUMN caller_label TO chat_id;",
                )?;
                Ok(())
            })
            .unwrap();
    }
    let storage = SqliteStorage::open(&path).unwrap();
    storage
        .with_connection(|connection| {
            assert_migrated(connection);
            // История уже в новой форме — её фаза не запускалась повторно.
            assert_eq!(count(connection, "SELECT COUNT(*) FROM history"), 1);
            Ok(())
        })
        .unwrap();
}
