mod common;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use onec_masking_service::{
    domain::{
        DatabaseMode, ErrorCode, FieldSources, FinalizeOutcome, FinalizeRequest, PolicyRule,
        PolicySnapshot, PreflightRequest, RuleAction, RuleSelector, SCHEMA_VERSION,
    },
    manager_client::ManagerClient,
    AppState, SqliteStorage,
};
use serde_json::{json, Value};
use uuid::Uuid;

use common::{
    dictionary_page, dictionary_value, empty_feed_responder, enqueue_refresh_intent, failed_page,
    force_intent_due, metadata_item, metadata_page, pending_intent_count, pull_empty_cache,
    FakeManager, DICTIONARY_TOOL, METADATA_TOOL,
};

fn request_ids() -> (Uuid, Uuid, Uuid) {
    (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
}

async fn configured_state(mode: DatabaseMode) -> (Arc<AppState>, Uuid) {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    assert!(storage.set_database_mode(database_id, mode).unwrap());
    if mode == DatabaseMode::Enabled {
        pull_empty_cache(&state, database_id).await;
    }
    (state, database_id)
}

#[test]
fn expired_history_is_never_loaded_for_idempotent_retry() {
    let storage = SqliteStorage::in_memory().unwrap();
    let database_id = Uuid::new_v4();
    let call_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .write_history(
            database_id,
            "chat-expired",
            call_id,
            "execute_query",
            "tool_result",
            &json!({"content":[{"type":"text","text":"masked-old-result"}],"is_error":false}),
            &json!({"version":1,"blocks":[]}),
            1,
            &[],
            86_400,
            None,
            Uuid::new_v4(),
            None,
        )
        .unwrap();
    storage
        .with_connection(|connection| {
            connection.execute(
                "UPDATE history SET expires_at='1970-01-01T00:00:00Z' WHERE call_id=?1",
                [call_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();

    assert!(storage
        .load_history(database_id, "chat-expired", call_id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn unknown_database_is_created_unconfigured_before_business_call() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let (database_id, call_id, correlation_id) = request_ids();
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query":"SELECT 1"}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ActionRequired);
    assert_eq!(
        storage
            .database_settings(database_id)
            .unwrap()
            .unwrap()
            .mode,
        DatabaseMode::Unconfigured
    );
    let retry = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query":"DIFFERENT RAW ARGUMENT MUST NOT BE STORED"}),
        })
        .await
        .unwrap_err();
    assert_eq!(retry.code, ErrorCode::ActionRequired);
    storage
        .with_connection(|connection| {
            let (history_count, audit_count, stored): (i64, i64, String) = connection.query_row(
                "SELECT COUNT(*),
                        (SELECT COUNT(*) FROM audit_events WHERE action='call.denied' AND correlation_id=?1),
                        public_result_json || report_json || mask_reasons_json
                 FROM history WHERE database_id=?2 AND chat_id='chat-a' AND call_id=?3",
                rusqlite::params![
                    correlation_id.to_string(),
                    database_id.to_string(),
                    call_id.to_string()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(history_count, 1);
            assert_eq!(audit_count, 1);
            assert!(stored.contains("ACTION_REQUIRED"));
            assert!(!stored.contains("DIFFERENT RAW ARGUMENT"));
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn finalize_masks_every_public_copy_and_never_persists_raw_values() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let (_, call_id, correlation_id) = request_ids();
    let raw_name = "Иванов Иван Иванович";
    let raw_secret = "super-private-password";
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                // Контракт Р2: непрозрачный бизнес-result; сырое значение
                // проверяется во всех копиях (data + произвольные поля).
                // Колонки data-строк должны быть объявлены в field_sources —
                // незадекларированная колонка закрывает выдачу (fail-closed).
                result: json!({
                    "success": true,
                    "data": [{"ФИО":raw_name,"api_key":raw_secret}],
                    "note": format!("Владелец: {raw_name}"),
                    "creds": {"password":raw_secret}
                }),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[
                    {"name":"ФИО","sources":["Справочник.People.FullName"]},
                    {"name":"api_key","sources":["Справочник.People.APIKey"]}
                ]}),
                lineage: vec![
                    json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                    json!({"column":"api_key","source_path":"Справочник.People.APIKey"}),
                ],
            },
        })
        .await
        .unwrap();
    let public = serde_json::to_string(&response.public_result).unwrap();
    assert!(!public.contains(raw_name));
    assert!(!public.contains(raw_secret));
    assert!(public.contains("[MASK:v1:FIO:"));
    assert!(public.contains("[SECRET_REMOVED]"));

    // Контракт Р2: секрет вырезается и внутри строки data (api_key —
    // объявленная колонка), и в произвольном объекте (password).
    let masked: Value = serde_json::from_str(
        response.public_result["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(masked["data"][0]["api_key"], "[SECRET_REMOVED]");
    assert_eq!(masked["creds"]["password"], "[SECRET_REMOVED]");
    assert!(masked["data"][0]["ФИО"]
        .as_str()
        .unwrap()
        .starts_with("[MASK:v1:FIO:"));

    state.storage.with_connection(|connection| {
        let (stored_public, report): (String, String) = connection.query_row(
            "SELECT public_result_json, report_json FROM history WHERE database_id=?1 AND call_id=?2",
            [database_id.to_string(), call_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(!stored_public.contains(raw_name));
        assert!(!stored_public.contains(raw_secret));
        assert!(!report.contains(raw_name));
        assert!(!report.contains(raw_secret));
        assert!(report.contains("\"kind\":\"table\""));
        Ok(())
    }).unwrap();
}

//++agent TASK-221 [23.09.2026 18:30:00]
#[tokio::test]
async fn canonical_api_key_alias_is_cut_from_every_copy_before_mapping() {
    for mode in [DatabaseMode::Enabled, DatabaseMode::Disabled] {
        let (state, database_id) = configured_state(mode).await;
        let alias = "биг_ПроверкаМаскировки";
        let raw = "synthetic-api-key-not-a-real-secret-221";
        let call_id = Uuid::new_v4();
        state
            .masking
            .set_policy_snapshot(
                database_id,
                PolicySnapshot {
                    rules: vec![PolicyRule {
                        selector: RuleSelector::Name,
                        pattern: alias.to_owned(),
                        action: RuleAction::Mask,
                        category: "TEST".to_owned(),
                        priority: 0,
                        rule_id: None,
                    }],
                    ..PolicySnapshot::default()
                },
            )
            .await;
        let response = state.masking.finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "synthetic-alias".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult { result: json!({
                "success": true,
                "data": [{alias: raw}],
                "note": format!("{{\"{alias}\":\"{raw}\"}}"),
                "copy": {alias: raw}
            })},
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":alias,"types":["Строка"],"sources":["Справочник.big_MarketAccounts.APIKey"]}]}),
                lineage: vec![json!({"column":alias,"source_path":"Справочник.big_MarketAccounts.APIKey","source_types":["Строка"],"secret_cut":false})],
            },
        }).await.unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        assert!(!public.contains("[MASK:v1:"));
        assert!(public.matches("[SECRET_REMOVED]").count() >= 3);
        state.storage.with_connection(|connection| {
            let (stored, mapping_batch): (String, Option<String>) = connection.query_row(
                "SELECT public_result_json || report_json || mask_reasons_json, mapping_batch_id FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert!(!stored.contains(raw));
            assert!(mapping_batch.is_none());
            Ok(())
        }).unwrap();
    }
}

#[tokio::test]
async fn query_rows_with_missing_or_degraded_lineage_fail_closed() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let alias = "НейтральноеПоле";
    let raw = "synthetic-api-key-not-a-real-secret-222";
    for field_sources in [
        FieldSources::default(),
        FieldSources {
            schema: json!({"columns":[{"name":alias,"sources":["Справочник.Test.APIKey"]}]}),
            lineage: vec![],
        },
        FieldSources {
            schema: json!({"columns":[{"name":alias,"sources":["Справочник.Test.APIKey"]}]}),
            lineage: vec![json!({"column":"ДругаяКолонка","source_path":"Справочник.Test.APIKey"})],
        },
    ] {
        let call_id = Uuid::new_v4();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "synthetic-degraded".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({
                        "success": true,
                        "data": [{alias: raw}],
                        "note": raw
                    }),
                },
                field_sources,
            })
            .await
            .unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(response.public_result["is_error"].as_bool().unwrap());
        assert!(!public.contains(raw));
        state.storage.with_connection(|connection| {
            let stored: String = connection.query_row(
                "SELECT public_result_json || report_json || mask_reasons_json FROM history WHERE call_id=?1",
                [call_id.to_string()], |row| row.get(0),
            )?;
            assert!(!stored.contains(raw));
            Ok(())
        }).unwrap();
    }
}

#[tokio::test]
async fn successful_query_requires_a_recognized_tabular_envelope() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let raw = "synthetic-unclassified-query-text-221";
    for result in [
        json!({"success":true,"message":raw}),
        json!({"success":true,"data":"not-an-array"}),
        json!({"message":raw}),
    ] {
        let call_id = Uuid::new_v4();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "query-envelope".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult { result },
                field_sources: FieldSources::default(),
            })
            .await
            .unwrap();
        assert_eq!(response.public_result["is_error"], true);
        assert!(!serde_json::to_string(&response).unwrap().contains(raw));
        state.storage.with_connection(|connection| {
            let stored: String = connection.query_row(
                "SELECT public_result_json || report_json || mask_reasons_json FROM history WHERE call_id=?1",
                [call_id.to_string()], |row| row.get(0),
            )?;
            assert!(!stored.contains(raw));
            assert!(stored.contains("service:query_lineage_incomplete"));
            Ok(())
        }).unwrap();
    }
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "query-envelope".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"data":[]}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    assert_eq!(response.public_result["is_error"], false);
}

#[tokio::test]
async fn password_mode_metadata_cuts_neutral_alias_even_without_secret_flag() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let alias = "НейтральноеПоле";
    let path = "Справочник.Test.OpaqueValue";
    let raw = "synthetic-password-mode-only-221";
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                metadata_sources: vec![onec_masking_service::domain::FeedMetadataItem {
                    source_path: path.to_owned(),
                    field_name: "OpaqueValue".to_owned(),
                    field_type: "Строка".to_owned(),
                    password_mode: true,
                }],
                ..PolicySnapshot::default()
            },
        )
        .await;
    let call_id = Uuid::new_v4();
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "synthetic-password-mode".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": true,
                    "data": [{alias: raw}],
                    "note": format!("value={raw}")
                }),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                lineage: vec![json!({"column":alias,"source_path":path,"secret_cut":false})],
            },
        })
        .await
        .unwrap();
    let public = serde_json::to_string(&response.public_result).unwrap();
    assert!(!public.contains(raw));
    assert!(public.matches("[SECRET_REMOVED]").count() >= 2);
    state.storage.with_connection(|connection| {
        let (stored, mapping_batch): (String, Option<String>) = connection.query_row(
            "SELECT public_result_json || report_json, mapping_batch_id FROM history WHERE call_id=?1",
            [call_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(!stored.contains(raw));
        assert!(mapping_batch.is_none());
        Ok(())
    }).unwrap();
}

#[tokio::test]
async fn secret_dictionary_and_regex_rules_cut_entire_value_without_mapping() {
    for (selector, pattern, dictionary) in [
        (
            RuleSelector::Dictionary,
            "CREDENTIAL".to_owned(),
            HashMap::from([(
                "synthetic-credential-221".to_owned(),
                "CREDENTIAL".to_owned(),
            )]),
        ),
        (
            RuleSelector::Regex,
            "synthetic-credential-221".to_owned(),
            HashMap::new(),
        ),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        state
            .masking
            .set_policy_snapshot(
                database_id,
                PolicySnapshot {
                    rules: vec![PolicyRule {
                        selector,
                        pattern,
                        action: RuleAction::Secret,
                        category: "CREDENTIAL".to_owned(),
                        priority: 1,
                        rule_id: None,
                    }],
                    dictionary,
                    ..PolicySnapshot::default()
                },
            )
            .await;
        let raw = "before synthetic-credential-221 after";
        let call_id = Uuid::new_v4();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "synthetic-secret-rule".to_owned(),
                tool_name: "find_references_to_object".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({
                        "success": true,
                        "note": raw,
                        "НейтральноеПоле": raw
                    }),
                },
                field_sources: FieldSources::default(),
            })
            .await
            .unwrap();
        // Контракт Р2: замаскированный бизнес-result живёт в content[0].text.
        let masked: Value = serde_json::from_str(
            response.public_result["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(masked["note"], "[SECRET_REMOVED]");
        assert_eq!(masked["НейтральноеПоле"], "[SECRET_REMOVED]");
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        assert!(!public.contains("before "));
        assert!(!public.contains(" after"));
        assert!(!public.contains("[MASK:v1:"));
        state.storage.with_connection(|connection| {
            let (stored, mapping_batch): (String, Option<String>) = connection.query_row(
                "SELECT public_result_json || report_json || mask_reasons_json, mapping_batch_id FROM history WHERE call_id=?1",
                [call_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert!(!stored.contains(raw));
            assert!(mapping_batch.is_none());
            Ok(())
        }).unwrap();
    }
}

#[tokio::test]
async fn canonical_fio_source_overrides_keep_rule_and_missing_lineage_fails_closed() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let alias = "НейтральноеПоле";
    let path = "Справочник.Клиенты.ФИО";
    let raw = "Тестов Т.Т.";
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                rules: vec![PolicyRule {
                    selector: RuleSelector::SourcePath,
                    pattern: path.to_owned(),
                    action: RuleAction::Keep,
                    category: "KEEP".to_owned(),
                    priority: 999,
                    rule_id: None,
                }],
                ..PolicySnapshot::default()
            },
        )
        .await;
    for (lineage, should_succeed) in [
        (vec![json!({"column":alias,"source_path":path})], true),
        (Vec::new(), false),
    ] {
        let call_id = Uuid::new_v4();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "synthetic-fio-source".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({
                        "success": true,
                        "data": [{alias: raw}],
                        "note": format!("value={raw}")
                    }),
                },
                field_sources: FieldSources {
                    schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                    lineage,
                },
            })
            .await
            .unwrap();
        assert_eq!(response.public_result["is_error"], !should_succeed);
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        if should_succeed {
            assert!(public.contains("[MASK:v1:FIO:"));
        }
        state
            .storage
            .with_connection(|connection| {
                let stored: String = connection.query_row(
                    "SELECT public_result_json || report_json FROM history WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| row.get(0),
                )?;
                assert!(!stored.contains(raw));
                Ok(())
            })
            .unwrap();
    }
}

//++agent TASK-221 2026-09-23
#[tokio::test]
async fn canonical_full_name_source_masks_initials_despite_neutral_alias_and_keep() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let alias = "НейтральноеПоле";
    let path = "Справочник.Клиенты.НаименованиеПолное";
    let raw = "Тестов Т.Т.";
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                rules: vec![PolicyRule {
                    selector: RuleSelector::SourcePath,
                    pattern: path.to_owned(),
                    action: RuleAction::Keep,
                    category: "KEEP".to_owned(),
                    priority: 999,
                    rule_id: None,
                }],
                ..PolicySnapshot::default()
            },
        )
        .await;
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "synthetic-full-name".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": true,
                    "data": [{alias: raw}],
                    "note": format!("value={raw}")
                }),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                lineage: vec![json!({"column":alias,"source_path":path})],
            },
        })
        .await
        .unwrap();
    let public = serde_json::to_string(&response.public_result).unwrap();
    assert!(!public.contains(raw));
    assert!(public.contains("[MASK:v1:FIO:"));
}

#[tokio::test]
async fn second_canonical_source_applies_stricter_mask_or_secret_rule() {
    for (action, expected) in [
        (RuleAction::Mask, "[MASK:v1:STRICT:"),
        (RuleAction::Secret, "[SECRET_REMOVED]"),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        let alias = "НейтральноеПоле";
        let public_source = "Справочник.Клиенты.ОбщееПоле";
        let strict_source = "Справочник.Клиенты.ВторойИсточник";
        let raw = "synthetic-multisource-221";
        state
            .masking
            .set_policy_snapshot(
                database_id,
                PolicySnapshot {
                    rules: vec![
                        PolicyRule {
                            selector: RuleSelector::SourcePath,
                            pattern: public_source.to_owned(),
                            action: RuleAction::Keep,
                            category: "KEEP".to_owned(),
                            priority: 999,
                            rule_id: None,
                        },
                        PolicyRule {
                            selector: RuleSelector::SourcePath,
                            pattern: strict_source.to_owned(),
                            action,
                            category: "STRICT".to_owned(),
                            priority: 0,
                            rule_id: None,
                        },
                    ],
                    ..PolicySnapshot::default()
                },
            )
            .await;
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "synthetic-multisource".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({
                        "success": true,
                        "data": [{alias: raw}],
                        "copy": [{alias: raw}]
                    }),
                },
                field_sources: FieldSources {
                    schema: json!({"columns":[{"name":alias,
                    "sources":[public_source,strict_source]}]}),
                    lineage: vec![
                        json!({"column":alias,"source_path":public_source}),
                        json!({"column":alias,"source_path":strict_source}),
                    ],
                },
            })
            .await
            .unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        assert!(public.contains(expected));
    }
}
//--agent TASK-221

#[tokio::test]
async fn schema_type_array_and_legacy_scalar_feed_type_policy() {
    for types in [json!(["Число", "Строка"]), json!("Строка")] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        state
            .masking
            .set_policy_snapshot(
                database_id,
                PolicySnapshot {
                    rules: vec![PolicyRule {
                        selector: RuleSelector::Type,
                        pattern: "Строка".to_owned(),
                        action: RuleAction::Mask,
                        category: "TYPE".to_owned(),
                        priority: 0,
                        rule_id: None,
                    }],
                    ..PolicySnapshot::default()
                },
            )
            .await;
        let raw = "synthetic-type-value-221";
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "synthetic-type-array".to_owned(),
                tool_name: "get_object_by_link".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({"success":true,"НейтральноеПоле":raw}),
                },
                field_sources: FieldSources {
                    schema: json!({"columns":[{"name":"НейтральноеПоле","types":types}]}),
                    lineage: vec![],
                },
            })
            .await
            .unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        assert!(public.contains("[MASK:v1:TYPE:"));
    }
}

//++agent TASK-222 [05.10.2026]
// Активная SECRET-политика — детерминированная ошибка конфигурации:
// pull не публикует ready-снапшот, intent снимается (повтор бесполезен).
#[tokio::test]
async fn active_secret_policy_cannot_publish_ready_pull() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    storage
        .install_policy(
            database_id,
            1,
            &[PolicyRule {
                selector: RuleSelector::Regex,
                pattern: "synthetic-pattern".to_owned(),
                action: RuleAction::Secret,
                category: "SECRET".to_owned(),
                priority: 1,
                rule_id: None,
            }],
        )
        .unwrap();

    let fake = FakeManager::spawn(empty_feed_responder);
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert!(!state.masking.database_ready(database_id).await);
    assert_eq!(pending_intent_count(&storage, database_id), 0);
    let failures: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE action='feed.pull' AND database_id=?1 AND code='POLICY_INVALID'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(failures, 1);
}
//++agent TASK-222

#[tokio::test]
async fn stricter_same_level_rule_wins_and_policy_evidence_is_persisted_without_raw_value() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                version: 7,
                rules: vec![
                    PolicyRule {
                        selector: RuleSelector::Name,
                        pattern: "customer".to_owned(),
                        action: RuleAction::Keep,
                        category: "CUSTOMER".to_owned(),
                        priority: 999,
                        rule_id: None,
                    },
                    PolicyRule {
                        selector: RuleSelector::Name,
                        pattern: "customer".to_owned(),
                        action: RuleAction::Mask,
                        category: "CUSTOMER".to_owned(),
                        priority: 0,
                        rule_id: None,
                    },
                    PolicyRule {
                        selector: RuleSelector::SourcePath,
                        pattern: "Catalog.People.FullName".to_owned(),
                        action: RuleAction::Secret,
                        category: "SECRET_PERSON".to_owned(),
                        priority: -100,
                        rule_id: None,
                    },
                    PolicyRule {
                        selector: RuleSelector::Dictionary,
                        pattern: "SECRET_PERSON".to_owned(),
                        action: RuleAction::Secret,
                        category: "SECRET_PERSON".to_owned(),
                        priority: -100,
                        rule_id: None,
                    },
                ],
                dictionary: HashMap::from([(
                    "Петров Петр Петрович".to_owned(),
                    "SECRET_PERSON".to_owned(),
                )]),
                ..PolicySnapshot::default()
            },
        )
        .await;
    let raw_customer = "Sensitive Customer";
    let raw_name = "Иванов Иван Иванович";
    let call_id = Uuid::new_v4();
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-policy".to_owned(),
            tool_name: "get_object_by_link".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": true,
                    "customer": raw_customer,
                    "ФИО": raw_name,
                    "note": "Петров Петр Петрович"
                }),
            },
            field_sources: FieldSources {
                schema: json!({}),
                lineage: vec![json!({"result_name":"ФИО","source_path":"Catalog.People.FullName"})],
            },
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&response.public_result).unwrap();
    assert!(!rendered.contains(raw_customer));
    assert!(rendered.contains("[MASK:v1:CUSTOMER:"));
    assert!(!rendered.contains(raw_name));
    assert!(!rendered.contains("Петров Петр Петрович"));
    assert!(rendered.contains("[SECRET_REMOVED]"));

    state
        .storage
        .with_connection(|connection| {
            let (version, reasons): (i64, String) = connection.query_row(
                "SELECT policy_version,mask_reasons_json FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(version, 7);
            assert!(reasons.contains("name:customer:mask"));
            assert!(reasons.contains("source_path:secret_person:secret"));
            assert!(reasons.contains("dictionary:SECRET_PERSON:secret"));
            assert!(!reasons.contains(raw_customer));
            assert!(!reasons.contains(raw_name));
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn transport_errors_are_sanitized_before_history_and_unknown_tools_fail_closed() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let raw_error = "upstream failed with Authorization: Bearer never-store-this";
    let call_id = Uuid::new_v4();
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-error".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::TransportError {
                error: json!({"message":raw_error}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(raw_error));
    state
        .storage
        .with_connection(|connection| {
            let stored: String = connection.query_row(
                "SELECT public_result_json || report_json FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get(0),
            )?;
            assert!(!stored.contains(raw_error));
            Ok(())
        })
        .unwrap();

    let pending_call_id = Uuid::new_v4();
    let pending_correlation_id = Uuid::new_v4();
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: 1,
            call_id: pending_call_id,
            correlation_id: pending_correlation_id,
            database_id,
            chat_id: "chat-error".to_owned(),
            tool_name: "future_unreviewed_tool".to_owned(),
            arguments: json!({}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ToolPendingReview);
    state
        .storage
        .with_connection(|connection| {
            let (history_count, audit_count, stored): (i64, i64, String) = connection.query_row(
                "SELECT COUNT(*),
                        (SELECT COUNT(*) FROM audit_events WHERE history_id=h.id AND action='call.denied'),
                        h.public_result_json || h.report_json
                 FROM history h WHERE h.call_id=?1",
                [pending_call_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!((history_count, audit_count), (1, 1));
            assert!(stored.contains("TOOL_PENDING_REVIEW"));
            assert!(!stored.contains(raw_error));
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn oversized_or_malformed_completed_calls_store_idempotent_sanitized_history() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    for (result, forbidden, expected_reason) in [
        (
            json!({"success":true,"rows":vec!["oversized-raw"; 10_001]}),
            "oversized-raw",
            "service:result_limit_exceeded",
        ),
        (
            json!({"success":true,"nested":{"html":"<script>raw-secret()</script>"}}),
            "raw-secret",
            "service:result_invalid",
        ),
    ] {
        let call_id = Uuid::new_v4();
        let request = FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-bounds".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult { result },
            field_sources: FieldSources::default(),
        };
        let response = state.masking.finalize(request.clone()).await.unwrap();
        assert_eq!(response.public_result["is_error"], true);
        assert!(!serde_json::to_string(&response)
            .unwrap()
            .contains(forbidden));
        let retry = state.masking.finalize(request).await.unwrap();
        assert_eq!(retry, response);
        state
            .storage
            .with_connection(|connection| {
                let (count, outcome, stored, reasons): (i64, String, String, String) = connection
                    .query_row(
                    "SELECT COUNT(*),outcome,public_result_json || report_json,mask_reasons_json
                         FROM history WHERE database_id=?1 AND chat_id=?2 AND call_id=?3",
                    rusqlite::params![database_id.to_string(), "chat-bounds", call_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                assert_eq!(count, 1);
                assert_eq!(outcome, "sanitized_error");
                assert!(!stored.contains(forbidden));
                assert!(reasons.contains(expected_reason));
                Ok(())
            })
            .unwrap();
    }
}

#[tokio::test]
async fn disabled_public_projection_is_raw_but_history_is_always_masked() {
    let (state, database_id) = configured_state(DatabaseMode::Disabled).await;
    let (_, call_id, correlation_id) = request_ids();
    let raw_name = "Петров Петр Петрович";
    let raw_secret = "top-secret";
    let request = FinalizeRequest {
        schema_version: SCHEMA_VERSION,
        call_id,
        correlation_id,
        database_id,
        chat_id: "chat-a".to_owned(),
        tool_name: "get_metadata".to_owned(),
        outcome: FinalizeOutcome::ToolResult {
            result: json!({"success":true,"ФИО":raw_name,"access_token":raw_secret}),
        },
        field_sources: FieldSources::default(),
    };
    let first = state.masking.finalize(request.clone()).await.unwrap();
    let first_json = serde_json::to_string(&first.public_result).unwrap();
    assert!(first_json.contains(raw_name));
    assert!(!first_json.contains(raw_secret));
    assert!(first_json.contains("[SECRET_REMOVED]"));

    let retry = state.masking.finalize(request).await.unwrap();
    assert_eq!(retry, first);
    state
        .storage
        .with_connection(|connection| {
            let stored: String = connection.query_row(
                "SELECT public_result_json FROM history WHERE database_id=?1 AND call_id=?2",
                [database_id.to_string(), call_id.to_string()],
                |row| row.get(0),
            )?;
            assert!(!stored.contains(raw_name));
            assert!(!stored.contains(raw_secret));
            assert!(stored.contains("[MASK:v1:FIO:"));
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM history WHERE database_id=?1 AND call_id=?2",
                [database_id.to_string(), call_id.to_string()],
                |row| row.get(0),
            )?;
            assert_eq!(count, 1);
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn all_six_selected_tool_classes_create_automatic_masked_history() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let raw = "Смирнов Семен Семенович";
    for tool_name in [
        "execute_query",
        "find_references_to_object",
        "get_object_by_link",
        "get_metadata",
        "get_access_rights",
        "get_link_of_object",
    ] {
        let (result, field_sources) = if tool_name == "execute_query" {
            (
                json!({"success":true,"data":[{"ФИО":raw}]}),
                FieldSources {
                    schema: json!({"columns":[{"name":"ФИО","sources":["Справочник.People.FullName"]}]}),
                    lineage: vec![
                        json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                    ],
                },
            )
        } else {
            (json!({"success":true,"ФИО":raw}), FieldSources::default())
        };
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: 1,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-six".to_owned(),
                tool_name: tool_name.to_owned(),
                outcome: FinalizeOutcome::ToolResult { result },
                field_sources,
            })
            .await
            .unwrap();
        assert_eq!(response.public_result["is_error"], false);
    }
    state
        .storage
        .with_connection(|connection| {
            let (count, raw_count): (i64, i64) = connection.query_row(
                "SELECT COUNT(*),SUM(instr(public_result_json,?1)>0 OR instr(report_json,?1)>0)
                 FROM history WHERE database_id=?2 AND chat_id='chat-six'",
                rusqlite::params![raw, database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(count, 6);
            assert_eq!(raw_count, 0);
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn mask_tokens_resolve_only_inside_exact_database_and_chat_scope() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let (_, call_id, correlation_id) = request_ids();
    let raw_name = "Сидоров Сидор Сидорович";
    let finalized = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "get_object_by_link".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"ФИО":raw_name}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let serialized = serde_json::to_string(&finalized.public_result).unwrap();
    let start = serialized.find("[MASK:v1:FIO:").unwrap();
    let end = serialized[start..].find(']').unwrap() + start + 1;
    let token = &serialized[start..end];

    let allowed = state
        .masking
        .preflight(PreflightRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query":format!("WHERE name = '{token}'")}),
        })
        .await
        .unwrap();
    assert!(allowed.arguments["query"]
        .as_str()
        .unwrap()
        .contains(raw_name));

    let denied_call_id = Uuid::new_v4();
    let denied = state
        .masking
        .preflight(PreflightRequest {
            schema_version: 1,
            call_id: denied_call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-b".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query":token}),
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::MaskTokenInvalid);
    state
        .storage
        .with_connection(|connection| {
            let (history_count, audit_count, stored): (i64, i64, String) = connection.query_row(
                "SELECT COUNT(*),
                        (SELECT COUNT(*) FROM audit_events WHERE history_id=h.id AND code='MASK_TOKEN_INVALID'),
                        h.public_result_json || h.report_json
                 FROM history h WHERE h.call_id=?1",
                [denied_call_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!((history_count, audit_count), (1, 1));
            assert!(stored.contains("MASK_TOKEN_INVALID"));
            assert!(!stored.contains(raw_name));
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn reveal_uses_history_batch_and_exact_database_chat_scope() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let call_id = Uuid::new_v4();
    let raw_name = "Орлов Олег Олегович";
    state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-reveal".to_owned(),
            tool_name: "get_object_by_link".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success":true,"ФИО":raw_name,"password":"never-reveal"
                }),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let history_id = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT id FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| {
                    let value: String = row.get(0)?;
                    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )
        })
        .unwrap();
    let revealed = state
        .masking
        .reveal_history(history_id, database_id, "chat-reveal")
        .await
        .unwrap();
    let rendered = serde_json::to_string(&revealed).unwrap();
    assert!(rendered.contains(raw_name));
    assert!(!rendered.contains("never-reveal"));
    assert!(rendered.contains("[SECRET_REMOVED]"));
    let foreign = state
        .masking
        .reveal_history(history_id, database_id, "other-chat")
        .await
        .unwrap_err();
    assert_eq!(foreign.code, ErrorCode::HistoryUnavailable);
    let restarted = AppState::new(state.storage.clone(), "https://masking.test");
    let unavailable = restarted
        .masking
        .reveal_history(history_id, database_id, "chat-reveal")
        .await
        .unwrap_err();
    //++agent TASK-224 [08.10.2026] итерация 4: рестарт очищает историю
    // целиком (RAM mapping потерян — раскрывать уже нечего), поэтому
    // reveal сообщает об отсутствии записи, а не о недоступности маппинга.
    assert_eq!(unavailable.code, ErrorCode::HistoryUnavailable);
    //--agent TASK-224
}

#[tokio::test]
async fn dictionary_and_regex_detectors_apply_to_free_text() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                version: 2,
                rules: vec![onec_masking_service::domain::PolicyRule {
                    selector: onec_masking_service::domain::RuleSelector::Regex,
                    pattern: r"\b\d{10}\b".to_owned(),
                    action: onec_masking_service::domain::RuleAction::Mask,
                    category: "INN".to_owned(),
                    priority: 10,
                    rule_id: None,
                }],
                dictionary: HashMap::from([("ООО Ромашка".to_owned(), "ORG".to_owned())]),
                dictionary_sources: HashMap::new(),
                //++agent TASK-225 [26.09.2026]
                // §5a: индекс словаря опционален — тестовый снимок идёт
                // fallback-путём прямого перебора.
                //++agent TASK-225
                dictionary_index: None,
                metadata_sources: Vec::new(),
                ready: true,
                policy_id: None,
                dictionary_fingerprint: 0,
            },
        )
        .await;
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"note":"ООО Ромашка, ИНН 7707083893"}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let text = serde_json::to_string(&response.public_result).unwrap();
    assert!(!text.contains("ООО Ромашка"));
    assert!(!text.contains("7707083893"));
    assert!(text.contains("[MASK:v1:ORG:"));
    assert!(text.contains("[MASK:v1:INN:"));
}

#[test]
fn dictionary_filter_ast_matches_manager_identifier_and_node_bounds() {
    let storage = SqliteStorage::in_memory().unwrap();
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();

    let valid = json!({
        "source_path":"Справочник.Контрагенты.Наименование",
        "category":"FIO",
        "filter_ast":{"op":"eq","field":"ПометкаУдаления_2","value":false}
    });
    storage
        .set_dictionary_config(database_id, "part", &[valid])
        .unwrap();

    for invalid_field in ["Account.Name", "2Наименование", "Name-Value"] {
        let selector = json!({
            "source_path":"Справочник.Контрагенты.Наименование",
            "category":"FIO",
            "filter_ast":{"op":"eq","field":invalid_field,"value":false}
        });
        assert!(storage
            .set_dictionary_config(database_id, "part", &[selector])
            .is_err());
    }

    let leaf = json!({"op":"eq","field":"Наименование","value":true});
    let branch = json!({"op":"and","args":vec![leaf; 32]});
    let too_many_nodes = json!({"op":"and","args":vec![branch; 32]});
    let selector = json!({
        "source_path":"Справочник.Контрагенты.Наименование",
        "category":"FIO",
        "filter_ast":too_many_nodes
    });
    assert!(storage
        .set_dictionary_config(database_id, "part", &[selector])
        .is_err());
}

//++agent TASK-222 [05.10.2026]
// Pull-модель: снапшот публикуется атомарно после полного прогона, а
// неуспешный pull (страничный отказ) оставляет прежний ready-снапшот и
// durable intent для повтора.
#[tokio::test]
async fn pull_publishes_snapshot_atomically_and_failed_pull_keeps_previous() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .set_dictionary_config(
            database_id,
            "part",
            &[
                json!({"source_path":"Catalog.Organizations.Description","category":"ORG",
                     "filter_ast":{"op":"eq","field":"DeletionMark","value":false}}),
            ],
        )
        .unwrap();

    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Organizations.Description",
                "Description",
                "String",
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(
            vec![dictionary_value(
                "Catalog.Organizations.Description",
                "ORG",
                "ООО Вектор",
            )],
            None,
            true,
        )),
    });
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );

    // Селектор, ушедший в manager, несёт filter_ast из durable-конфигурации.
    let dictionary_calls = fake.calls_for(DICTIONARY_TOOL);
    assert_eq!(dictionary_calls.len(), 1);
    assert_eq!(
        dictionary_calls[0]["selector"],
        json!({"source_path":"Catalog.Organizations.Description","category":"ORG",
               "filter_ast":{"op":"eq","field":"DeletionMark","value":false},"page_size":1000})
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 0);

    let history_count: i64 = state
        .storage
        .with_connection(|connection| {
            connection.query_row("SELECT COUNT(*) FROM history", [], |row| row.get(0))
        })
        .unwrap();
    assert_eq!(history_count, 0);

    let result = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-feed".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"note":"Контрагент ООО Вектор"}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&result.public_result).unwrap();
    assert!(!rendered.contains("ООО Вектор"));
    assert!(rendered.contains("[MASK:v1:ORG:"));

    // Страничный отказ — transient: intent остаётся на retry, активная
    // генерация и RAM-снапшот не тронуты.
    let failing = FakeManager::spawn(|_, _| Ok(failed_page("FEED_UNAVAILABLE")));
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&failing.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert!(state.masking.database_ready(database_id).await);
    assert_eq!(pending_intent_count(&state.storage, database_id), 1);
    let active_version: i64 = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT active_cache_version FROM databases WHERE id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(active_version, 2);
    let after_failed_refresh = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-feed".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"note":"ООО Вектор / ООО Новый"}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&after_failed_refresh.public_result).unwrap();
    assert!(!rendered.contains("ООО Вектор"));
    assert!(rendered.contains("ООО Новый"));

    // Restart: RAM-снапшот потерян, durable intent уже стоит (его не
    // перезаписывает startup-rewarm), pull поднимает готовность снова.
    // Transient-неудача выше отложила intent (§8.1 backoff) — делаем его
    // наступившим, чтобы тик поднял его сразу.
    let restarted = AppState::new(state.storage.clone(), "https://masking.test");
    assert!(!restarted.masking.database_ready(database_id).await);
    assert_eq!(pending_intent_count(&state.storage, database_id), 1);
    force_intent_due(&state.storage, database_id);
    let recovered = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Organizations.Description",
                "Description",
                "String",
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(
            vec![dictionary_value(
                "Catalog.Organizations.Description",
                "ORG",
                "ООО Вектор",
            )],
            None,
            true,
        )),
    });
    assert_eq!(
        restarted
            .masking
            .refresh_due_intents(&recovered.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(restarted.masking.database_ready(database_id).await);
}

#[tokio::test]
async fn pull_follows_opaque_cursor_until_final_chunk() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .set_dictionary_config(
            database_id,
            "part",
            &[json!({"source_path":"Catalog.Organizations.Description","category":"ORG","filter_ast":null})],
        )
        .unwrap();
    let fake = FakeManager::spawn(|name, arguments| {
        let cursor = arguments["cursor"].as_str();
        match (name, cursor) {
            (METADATA_TOOL, None) => Ok(metadata_page(
                vec![metadata_item(
                    "Catalog.Organizations.Description",
                    "Description",
                    "String",
                    false,
                )],
                Some("m-page-2"),
                false,
            )),
            (METADATA_TOOL, Some("m-page-2")) => Ok(metadata_page(
                vec![metadata_item(
                    "Catalog.Organizations.Code",
                    "Code",
                    "Number",
                    false,
                )],
                None,
                true,
            )),
            (DICTIONARY_TOOL, None) => Ok(dictionary_page(
                vec![dictionary_value(
                    "Catalog.Organizations.Description",
                    "ORG",
                    "ООО Первый",
                )],
                Some("d-page-2"),
                false,
            )),
            (DICTIONARY_TOOL, Some("d-page-2")) => Ok(dictionary_page(
                vec![dictionary_value(
                    "Catalog.Organizations.Description",
                    "ORG",
                    "ООО Второй",
                )],
                None,
                true,
            )),
            _ => Ok(dictionary_page(Vec::new(), None, true)),
        }
    });
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(state.masking.database_ready(database_id).await);

    // Курсор opaque: сервис возвращает его в manager дословно, до
    // final_chunk; значения обеих страниц собраны в один снапшот.
    let metadata_calls = fake.calls_for(METADATA_TOOL);
    assert_eq!(metadata_calls.len(), 2);
    assert!(metadata_calls[0]["cursor"].is_null());
    assert_eq!(metadata_calls[1]["cursor"], "m-page-2");
    let dictionary_calls = fake.calls_for(DICTIONARY_TOOL);
    assert_eq!(dictionary_calls.len(), 2);
    assert_eq!(dictionary_calls[1]["cursor"], "d-page-2");

    let result = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: 1,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-pages".to_owned(),
            tool_name: "find_references_to_object".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success":true,"note":"ООО Первый и ООО Второй"}),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&result.public_result).unwrap();
    assert!(!rendered.contains("ООО Первый"));
    assert!(!rendered.contains("ООО Второй"));
    assert_eq!(rendered.matches("[MASK:v1:ORG:").count(), 2);
}

#[tokio::test]
async fn unavailable_manager_and_call_rejection_keep_durable_intent() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;

    // Несуществующий сокет — transport failure.
    let dead = ManagerClient::new(PathBuf::from("/nonexistent/manager.sock"), None);
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state.masking.refresh_due_intents(&dead, 10).await.unwrap(),
        0
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 1);
    assert!(state.masking.database_ready(database_id).await);

    // Отказ уровня /internal/v1/tools/call (success:false в конверте).
    // Новая очередь = новая серия (§8.2: аудируется первая неудача серии):
    // enqueue сбрасывает attempts и делает intent наступившим, иначе
    // transient-backoff отложил бы повтор.
    enqueue_refresh_intent(&state.storage, database_id);
    let rejecting = FakeManager::spawn(|_, _| Err("INTERNAL_TOOL_FORBIDDEN".to_owned()));
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&rejecting.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 1);
    let (unavailable, rejected): (i64, i64) = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT SUM(code='MANAGER_UNAVAILABLE'), SUM(code='INTERNAL_TOOL_FAILED')
                 FROM audit_events WHERE action='feed.pull' AND database_id=?1",
                [database_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!((unavailable, rejected), (1, 1));

    // Битая форма страницы — детерминированная ошибка: intent снимается.
    enqueue_refresh_intent(&state.storage, database_id);
    let malformed = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(json!({
            "success": true,
            "metadata": [],
            "dictionary_values": [],
            "next_cursor": "still-more",
            "final_chunk": true,
            "manifest_digest": "d"
        })),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&malformed.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 0);
}

// Р1 решение (а): producer manifest_digest необязателен и ни на что не
// влияет — страницы без digest и с произвольными разными digest собираются
// в один прогон, журнальный digest сервис считает сам.
#[tokio::test]
async fn producer_manifest_digest_is_optional_and_never_verified() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let fake = FakeManager::spawn(|name, arguments| {
        let cursor = arguments["cursor"].as_str();
        match (name, cursor) {
            (METADATA_TOOL, None) => Ok(json!({
                "success": true,
                "metadata": [metadata_item("Catalog.A.F","F","String",false)],
                "dictionary_values": [],
                "next_cursor": "page-2",
                "final_chunk": false
            })),
            (METADATA_TOOL, Some("page-2")) => Ok(json!({
                "success": true,
                "metadata": [metadata_item("Catalog.B.F","F","String",false)],
                "dictionary_values": [],
                "next_cursor": null,
                "final_chunk": true,
                "manifest_digest": "unrelated-producer-digest"
            })),
            _ => Ok(dictionary_page(Vec::new(), None, true)),
        }
    });
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 0);
    assert!(state.masking.database_ready(database_id).await);
}

#[tokio::test]
async fn dictionary_value_from_unrequested_source_is_rejected() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .set_dictionary_config(
            database_id,
            "part",
            &[json!({"source_path":"Catalog.Organizations.Description","category":"ORG","filter_ast":null})],
        )
        .unwrap();
    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Organizations.Description",
                "Description",
                "String",
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(
            vec![dictionary_value(
                "Catalog.Organizations.Other",
                "ORG",
                "ООО Чужой",
            )],
            None,
            true,
        )),
    });
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 0);
}

#[tokio::test]
async fn secret_source_can_never_arrive_via_dictionary_pull() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .set_dictionary_config(
            database_id,
            "part",
            &[json!({"source_path":"Catalog.Keys.ApiKey","category":"ORG","filter_ast":null})],
        )
        .unwrap();
    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Keys.ApiKey",
                "ApiKey",
                "String",
                true,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(
            vec![dictionary_value(
                "Catalog.Keys.ApiKey",
                "ORG",
                "synthetic-api-key",
            )],
            None,
            true,
        )),
    });
    enqueue_refresh_intent(&state.storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert_eq!(pending_intent_count(&state.storage, database_id), 0);
    let forbidden: i64 = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='feed.pull'
                 AND database_id=?1 AND code='FEED_SECRET_SOURCE_FORBIDDEN'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(forbidden, 1);
}

#[tokio::test]
async fn durable_intents_drain_per_database_and_isolate_failures() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let mut ready_databases = Vec::new();
    for _ in 0..2 {
        let database_id = Uuid::new_v4();
        storage.ensure_database(database_id).unwrap();
        storage
            .set_database_mode(database_id, DatabaseMode::Enabled)
            .unwrap();
        enqueue_refresh_intent(&storage, database_id);
        ready_databases.push(database_id);
    }
    let broken = Uuid::new_v4();
    storage.ensure_database(broken).unwrap();
    storage
        .set_database_mode(broken, DatabaseMode::Enabled)
        .unwrap();
    storage
        .install_policy(
            broken,
            1,
            &[PolicyRule {
                selector: RuleSelector::Regex,
                pattern: "x".to_owned(),
                action: RuleAction::Secret,
                category: "SECRET".to_owned(),
                priority: 0,
                rule_id: None,
            }],
        )
        .unwrap();
    enqueue_refresh_intent(&storage, broken);

    let fake = FakeManager::spawn(empty_feed_responder);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        2
    );
    for database_id in ready_databases {
        assert!(state.masking.database_ready(database_id).await);
        assert_eq!(pending_intent_count(&storage, database_id), 0);
    }
    assert!(!state.masking.database_ready(broken).await);
    assert_eq!(pending_intent_count(&storage, broken), 0);
}

#[tokio::test]
async fn startup_rewires_enabled_databases_with_durable_intent() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    // AppState::new → MaskingService::new ставит 'full' intent для
    // каждой enabled-базы (RAM-снапшоты restart не переживают).
    let state = AppState::new(storage.clone(), "https://masking.test");
    assert_eq!(pending_intent_count(&storage, database_id), 1);
    assert!(!state.masking.database_ready(database_id).await);
}

#[tokio::test]
async fn pull_accepts_large_composite_type_and_rejects_oversized_field_type() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");

    let component =
        "Строка(100), СправочникСсылка.Номенклатура, СправочникСсылка.ХарактеристикиНоменклатуры";
    let mut composite_type = std::iter::repeat_n(component, 104)
        .collect::<Vec<_>>()
        .join(", ");
    composite_type.push_str(&"X".repeat(17_242 - composite_type.len()));
    assert_eq!(composite_type.len(), 17_242);
    let accepted_db = Uuid::new_v4();
    storage.ensure_database(accepted_db).unwrap();
    storage
        .set_database_mode(accepted_db, DatabaseMode::Enabled)
        .unwrap();
    let accepted_type = composite_type.clone();
    let fake_ok = FakeManager::spawn(move |name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Products.CompositeAttribute",
                "CompositeAttribute",
                &accepted_type,
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    enqueue_refresh_intent(&storage, accepted_db);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake_ok.client(), 10)
            .await
            .unwrap(),
        1
    );
    assert!(state.masking.database_ready(accepted_db).await);

    let oversized_type = "T".repeat(1024 * 1024 + 1);
    let rejected_db = Uuid::new_v4();
    storage.ensure_database(rejected_db).unwrap();
    storage
        .set_database_mode(rejected_db, DatabaseMode::Enabled)
        .unwrap();
    let fake_big = FakeManager::spawn(move |name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![metadata_item(
                "Catalog.Products.OversizedAttribute",
                "OversizedAttribute",
                &oversized_type,
                false,
            )],
            None,
            true,
        )),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    enqueue_refresh_intent(&storage, rejected_db);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake_big.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert!(!state.masking.database_ready(rejected_db).await);
    assert_eq!(pending_intent_count(&storage, rejected_db), 0);
}

#[tokio::test]
async fn all_dictionary_mode_expands_only_safe_catalog_string_fields() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    storage
        .install_policy(
            database_id,
            1,
            &[
                source_mask_rule("Catalog.Organizations.Description"),
                source_mask_rule("Catalog.Keys.ApiKey"),
            ],
        )
        .unwrap();
    storage
        .set_dictionary_config(
            database_id,
            "all",
            &[json!({"source_path":"*","category":"ORG","filter_ast":null})],
        )
        .unwrap();

    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![
                metadata_item(
                    "Catalog.Organizations.Description",
                    "Description",
                    "String",
                    false,
                ),
                metadata_item("Catalog.Users.Password", "Password", "String", true),
                metadata_item("Catalog.Keys.ApiKey", "ApiKey", "String", false),
                metadata_item("Catalog.Organizations.Code", "Code", "Number", false),
                metadata_item("Document.Sales.Comment", "Comment", "String", false),
            ],
            None,
            true,
        )),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    let calls = fake.calls_for(DICTIONARY_TOOL);
    let paths: Vec<&str> = calls
        .iter()
        .filter_map(|arguments| arguments["selector"]["source_path"].as_str())
        .collect();
    // Password/secret-поля, нестроковые типы и не-Catalog классы не
    // expand-ятся даже при явном Mask-allowlist.
    assert_eq!(paths, ["Catalog.Organizations.Description"]);
    assert!(calls
        .iter()
        .all(|arguments| arguments["selector"]["category"] == "ORG"));
}

#[tokio::test]
async fn all_dictionary_mode_fails_when_explicit_allowlist_exceeds_hard_cap() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    let rules: Vec<_> = (0..101)
        .map(|index| source_mask_rule(&format!("Catalog.Items.Field{index}")))
        .collect();
    storage.install_policy(database_id, 1, &rules).unwrap();
    storage
        .set_dictionary_config(
            database_id,
            "all",
            &[json!({"source_path":"*","category":"ORG","filter_ast":null})],
        )
        .unwrap();

    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            (0..101)
                .map(|index| {
                    metadata_item(
                        &format!("Catalog.Items.Field{index}"),
                        &format!("Field{index}"),
                        "String",
                        false,
                    )
                })
                .collect(),
            None,
            true,
        )),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        0
    );
    assert!(!state.masking.database_ready(database_id).await);
    assert_eq!(pending_intent_count(&storage, database_id), 0);
    let exceeded: i64 = storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='feed.pull'
                 AND database_id=?1 AND code='FEED_LIMIT_EXCEEDED'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(exceeded, 1);
}

//++agent TASK-221 [24.09.2026 10:05:00]
/// MUST-16 All live дефект (DEV 09:38Z): trusted manifest от BSL
/// `ПолноеИмя()` отдаёт `Справочник.*` source_path — All-expansion обязана
/// принимать русский класс справочника наравне с `Catalog.*`; прочие
/// классы и secret-поля исключаются, даже если allowlist их содержит.
#[tokio::test]
async fn all_dictionary_mode_expands_ru_catalog_prefix() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    storage
        .install_policy(
            database_id,
            1,
            &[
                source_mask_rule("Справочник.Клиенты.НаименованиеПолное"),
                source_mask_rule("Catalog.Organizations.Description"),
                source_mask_rule("Документ.Продажи.Комментарий"),
                source_mask_rule("Справочник.Клиенты.СекретныйКлюч"),
            ],
        )
        .unwrap();
    storage
        .set_dictionary_config(
            database_id,
            "all",
            &[json!({"source_path":"*","category":"ORG","filter_ast":null})],
        )
        .unwrap();

    let fake = FakeManager::spawn(|name, _| match name {
        METADATA_TOOL => Ok(metadata_page(
            vec![
                metadata_item(
                    "Справочник.Клиенты.НаименованиеПолное",
                    "НаименованиеПолное",
                    "Строка",
                    false,
                ),
                metadata_item(
                    "Catalog.Organizations.Description",
                    "Description",
                    "String",
                    false,
                ),
                metadata_item(
                    "Документ.Продажи.Комментарий",
                    "Комментарий",
                    "Строка",
                    false,
                ),
                metadata_item(
                    "Справочник.Клиенты.СекретныйКлюч",
                    "СекретныйКлюч",
                    "Строка",
                    false,
                ),
            ],
            None,
            true,
        )),
        _ => Ok(dictionary_page(Vec::new(), None, true)),
    });
    enqueue_refresh_intent(&storage, database_id);
    assert_eq!(
        state
            .masking
            .refresh_due_intents(&fake.client(), 10)
            .await
            .unwrap(),
        1
    );
    let calls = fake.calls_for(DICTIONARY_TOOL);
    let paths: Vec<&str> = calls
        .iter()
        .filter_map(|arguments| arguments["selector"]["source_path"].as_str())
        .collect();
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&"Справочник.Клиенты.НаименованиеПолное"));
    assert!(paths.contains(&"Catalog.Organizations.Description"));
}
//++agent TASK-221
//++agent TASK-222

fn source_mask_rule(source_path: &str) -> onec_masking_service::domain::PolicyRule {
    onec_masking_service::domain::PolicyRule {
        selector: onec_masking_service::domain::RuleSelector::SourcePath,
        pattern: source_path.to_owned(),
        action: onec_masking_service::domain::RuleAction::Mask,
        category: "DATA".to_owned(),
        priority: 0,
        rule_id: None,
    }
}

//++agent TASK-224 [08.10.2026] итерация 4
// Отчёт истории: порядок колонок — порядок запроса (field_sources.schema),
// колонки с маскированными значениями помечаются masked, нескалярные ячейки
// приводятся к читаемому скаляру, title — текст запроса из контекста,
// записанного preflight-фазой.
#[tokio::test]
async fn finalize_report_preserves_query_column_order_marks_masked_and_scalars() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let (_, call_id, correlation_id) = request_ids();
    let query = "SELECT Контрагент, Дата, Ссылка FROM Документ.Продажи";
    state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-report".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query": query}),
        })
        .await
        .unwrap();
    state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-report".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": true,
                    "data": [{
                        "Дата": "2026-10-08",
                        "Контрагент": "Иванов Иван Иванович",
                        "Ссылка": {"Представление": "Продажа 0001"}
                    }]
                }),
            },
            field_sources: FieldSources {
                // Порядок колонок специально не совпадает с алфавитным —
                // он восстанавливается только из schema.columns.
                schema: json!({"columns":[
                    {"name":"Контрагент","sources":["Справочник.People.FullName"]},
                    {"name":"Дата","sources":["Справочник.Test.Name"]},
                    {"name":"Ссылка","sources":["Справочник.Test.Name"]}
                ]}),
                lineage: vec![
                    json!({"column":"Контрагент","source_path":"Справочник.People.FullName"}),
                    json!({"column":"Дата","source_path":"Справочник.Test.Name"}),
                    json!({"column":"Ссылка","source_path":"Справочник.Test.Name"}),
                ],
            },
        })
        .await
        .unwrap();

    let report: Value = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT report_json FROM history WHERE call_id=?1",
                [call_id.to_string()],
                |row| row.get::<_, String>(0),
            )
        })
        .map(|text| serde_json::from_str(&text).unwrap())
        .unwrap();

    assert_eq!(report["title"], query);
    let table = &report["blocks"][0];
    assert_eq!(table["kind"], "table");
    let columns = table["columns"].as_array().unwrap();
    let ids: Vec<&str> = columns
        .iter()
        .map(|column| column["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["Контрагент", "Дата", "Ссылка"]);
    let masked: Vec<bool> = columns
        .iter()
        .map(|column| column["masked"].as_bool().unwrap())
        .collect();
    assert_eq!(masked, [true, false, false]);
    let row = table["rows"][0].as_array().unwrap();
    assert!(row
        .iter()
        .all(|cell| cell.is_null() || cell.is_boolean() || cell.is_number() || cell.is_string()));
    assert!(row[0].as_str().unwrap().starts_with("[MASK:v1:FIO:"));
    assert_eq!(row[2], "Продажа 0001");
}

// Запись истории и контекст вызова живут не дольше min(history_ttl,
// mapping_ttl): без RAM mapping раскрытие невозможно, хранить дольше
// бессмысленно и опасно.
#[tokio::test]
async fn history_and_call_context_live_no_longer_than_the_shorter_ttl() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .with_connection(|connection| {
            connection.execute(
                "UPDATE databases SET mapping_ttl_seconds=300, history_ttl_seconds=7200 WHERE id=?1",
                [database_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
    let (_, call_id, correlation_id) = request_ids();
    state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-ttl".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query": "SELECT 1"}),
        })
        .await
        .unwrap();
    state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-ttl".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success": true, "data": [{"Дата": "2026-10-08"}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[
                    {"name":"Дата","sources":["Справочник.Test.Name"]}
                ]}),
                lineage: vec![json!({"column":"Дата","source_path":"Справочник.Test.Name"})],
            },
        })
        .await
        .unwrap();

    state
        .storage
        .with_connection(|connection| {
            let lifetime = |sql: &str| {
                connection
                    .query_row(sql, [call_id.to_string()], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map(|(created, expires)| {
                        let created = chrono::DateTime::parse_from_rfc3339(&created).unwrap();
                        let expires = chrono::DateTime::parse_from_rfc3339(&expires).unwrap();
                        (expires - created).num_seconds()
                    })
            };
            let history_ttl =
                lifetime("SELECT created_at, expires_at FROM history WHERE call_id=?1")?;
            let context_ttl =
                lifetime("SELECT created_at, expires_at FROM call_contexts WHERE call_id=?1")?;
            assert_eq!(history_ttl, 300);
            assert_eq!(context_ttl, 300);
            Ok(())
        })
        .unwrap();
}

// Рестарт сервиса = потеря RAM mapping → вся накопленная история и контексты
// вызовов нераскрываемы и удаляются при старте (fail-closed по хранению).
#[test]
fn service_start_purges_history_and_call_contexts() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .write_history(
            database_id,
            "chat-purge",
            Uuid::new_v4(),
            "execute_query",
            "tool_result",
            &json!({"content":[{"type":"text","text":"masked"}],"is_error":false}),
            &json!({"version":1,"blocks":[]}),
            1,
            &[],
            86_400,
            None,
            Uuid::new_v4(),
            None,
        )
        .unwrap();
    storage
        .write_call_context(
            Uuid::new_v4(),
            database_id,
            "chat-purge",
            "execute_query",
            Some("SELECT 1"),
            86_400,
        )
        .unwrap();
    let _state = AppState::new(storage.clone(), "https://masking.test");
    let (history_count, context_count): (i64, i64) = storage
        .with_connection(|connection| {
            let history_count =
                connection.query_row("SELECT COUNT(*) FROM history", [], |row| row.get(0))?;
            let context_count =
                connection.query_row("SELECT COUNT(*) FROM call_contexts", [], |row| row.get(0))?;
            Ok((history_count, context_count))
        })
        .unwrap();
    assert_eq!((history_count, context_count), (0, 0));
}

//++agent TASK-224 [25.09.2026] ревью R1
// Заголовок отчёта — durable-форма: ни в call_contexts.title, ни в
// history.report_json не остаётся сырых секретов из arguments — ни
// значений секретных ключей, ни литералов, вписанных в текст запроса.
#[tokio::test]
async fn call_title_never_persists_raw_secrets_from_arguments() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let finalize = |call_id: Uuid, correlation_id: Uuid| FinalizeRequest {
        schema_version: SCHEMA_VERSION,
        call_id,
        correlation_id,
        database_id,
        chat_id: "chat-secret".to_owned(),
        tool_name: "execute_query".to_owned(),
        outcome: FinalizeOutcome::ToolResult {
            result: json!({"success": true, "data": [{"Дата": "2026-10-08"}]}),
        },
        field_sources: FieldSources {
            schema: json!({"columns":[{"name":"Дата","sources":["Справочник.Test.Name"]}]}),
            lineage: vec![json!({"column":"Дата","source_path":"Справочник.Test.Name"})],
        },
    };
    let preflight = |call_id: Uuid, correlation_id: Uuid, arguments: Value| PreflightRequest {
        schema_version: SCHEMA_VERSION,
        call_id,
        correlation_id,
        database_id,
        chat_id: "chat-secret".to_owned(),
        tool_name: "execute_query".to_owned(),
        arguments,
    };
    let durable_parts = |call_id: Uuid| {
        state
            .storage
            .with_connection(|connection| {
                let title: Option<String> = connection.query_row(
                    "SELECT title FROM call_contexts WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| row.get(0),
                )?;
                let report: String = connection.query_row(
                    "SELECT report_json FROM history WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok((title, report))
            })
            .unwrap()
    };

    // Секретные литералы внутри свободного текста query — вырезаются
    // присвоениями (`Пароль = "…"`, `api_key = '…'`).
    let (_, call_id, correlation_id) = request_ids();
    state
        .masking
        .preflight(preflight(
            call_id,
            correlation_id,
            json!({"query": "ВЫБРАТЬ * ГДЕ Пароль = \"s3cr3t-lit-1\" И api_key = 'sk-live-777'"}),
        ))
        .await
        .unwrap();
    state
        .masking
        .finalize(finalize(call_id, correlation_id))
        .await
        .unwrap();
    let (title, report) = durable_parts(call_id);
    let durable = format!("{}\n{}", title.unwrap_or_default(), report);
    assert!(durable.contains("[SECRET_REMOVED]"), "{durable}");
    for secret in ["s3cr3t-lit-1", "sk-live-777"] {
        assert!(!durable.contains(secret), "leaked {secret}: {durable}");
    }

    // Без `query` заголовок — JSON аргументов: значения секретных ключей
    // заменяются на [SECRET_REMOVED], нейтральные поля сохраняются.
    let (_, call_id, correlation_id) = request_ids();
    state
        .masking
        .preflight(preflight(
            call_id,
            correlation_id,
            json!({"password":"raw-pass-9","api_key":"sk-key-2","note":"проверка связи"}),
        ))
        .await
        .unwrap();
    state
        .masking
        .finalize(finalize(call_id, correlation_id))
        .await
        .unwrap();
    let (title, report) = durable_parts(call_id);
    let durable = format!("{}\n{}", title.unwrap_or_default(), report);
    assert!(durable.contains("проверка связи"), "{durable}");
    assert!(durable.contains("[SECRET_REMOVED]"), "{durable}");
    for secret in ["raw-pass-9", "sk-key-2"] {
        assert!(!durable.contains(secret), "leaked {secret}: {durable}");
    }

    // Fail-closed: аргументы глубже предела зачистки → заголовок не
    // сохраняется вовсе (отчёт показывает имя инструмента).
    let (_, call_id, correlation_id) = request_ids();
    let mut deep = json!("leaf");
    for _ in 0..100 {
        deep = json!({"x": deep});
    }
    let _ = state
        .masking
        .preflight(preflight(call_id, correlation_id, deep))
        .await;
    let (title, report) = durable_parts(call_id);
    assert!(title.is_none());
    let report: Value = serde_json::from_str(&report).unwrap();
    assert!(report["title"].is_null());
}
//--agent TASK-224
//--agent TASK-224

//++agent TASK-225 [25.09.2026]
// Фаза «все вызовы через маскировщик»: неизвестный инструмент отклоняется
// как deny-pending-review и авто-регистрируется в очереди классификации
// (спека §7); mask-токены в аргументах раскрываются только для data-mask
// при Enabled.

/// Снимок строки tool_classifications:
/// (class, auto_added, denied_count, first_seen_at, last_denied_at).
type ClassificationRow = (String, i64, i64, Option<String>, Option<String>);

/// Классификация инструмента прямым чтением строки tool_classifications.
fn classification_row(
    storage: &SqliteStorage,
    database_id: Uuid,
    tool_name: &str,
) -> Option<ClassificationRow> {
    use rusqlite::OptionalExtension;
    storage
        .with_connection(|connection| {
            connection
                .query_row(
                    "SELECT class,auto_added,denied_count,first_seen_at,last_denied_at
                     FROM tool_classifications WHERE database_id=?1 AND tool_name=?2",
                    rusqlite::params![database_id.to_string(), tool_name],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
        })
        .unwrap()
}

fn audit_code_count(storage: &SqliteStorage, code: &str) -> i64 {
    storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT COUNT(*) FROM audit_events WHERE action='call.denied' AND code=?1",
                [code],
                |row| row.get(0),
            )
        })
        .unwrap()
}

#[tokio::test]
async fn unknown_tool_is_denied_auto_registered_and_counted() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let storage = &state.storage;

    // Первый вызов неизвестного инструмента — отказ до 1С + авто-строка.
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "totally_unknown_tool".to_owned(),
            arguments: json!({"a": 1}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ToolPendingReview);
    let (class, auto_added, denied_count, first_seen_at, last_denied_at) =
        classification_row(storage, database_id, "totally_unknown_tool").unwrap();
    assert_eq!(class, "deny-pending-review");
    assert_eq!(auto_added, 1);
    assert_eq!(denied_count, 1);
    let first_seen = first_seen_at.expect("first_seen_at set on insert");
    assert!(last_denied_at.is_some());

    // Повторный вызов (другой call_id) — счётчик растёт, first_seen_at
    // неизменен. Идемпотентный ретрай той же пары (call_id, correlation_id)
    // не считается дважды.
    let retry_call = Uuid::new_v4();
    let retry_correlation = Uuid::new_v4();
    for (call_id, correlation_id) in [
        (Uuid::new_v4(), Uuid::new_v4()),
        (retry_call, retry_correlation),
        (retry_call, retry_correlation),
    ] {
        let error = state
            .masking
            .preflight(PreflightRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id,
                database_id,
                chat_id: "chat-a".to_owned(),
                tool_name: "totally_unknown_tool".to_owned(),
                arguments: json!({"a": 2}),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ToolPendingReview);
    }
    let (_, _, denied_count, first_seen_at, _) =
        classification_row(storage, database_id, "totally_unknown_tool").unwrap();
    assert_eq!(denied_count, 3);
    assert_eq!(first_seen_at.as_deref(), Some(first_seen.as_str()));

    // Решение администратора: auto_added=0, счётчик отказов сохраняется.
    storage
        .set_tool_classification(
            database_id,
            "totally_unknown_tool",
            onec_masking_service::domain::ToolClass::MetadataBypass,
            "admin-1",
        )
        .unwrap();
    let (class, auto_added, denied_count, _, _) =
        classification_row(storage, database_id, "totally_unknown_tool").unwrap();
    assert_eq!(class, "metadata-bypass");
    assert_eq!(auto_added, 0);
    assert_eq!(denied_count, 3);

    // Классифицированный инструмент пропускается preflight.
    let allowed = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "totally_unknown_tool".to_owned(),
            arguments: json!({"a": 3}),
        })
        .await
        .unwrap();
    assert_eq!(allowed.decision, "allow");
}

#[tokio::test]
async fn invalid_tool_name_is_denied_audited_and_not_registered() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let storage = &state.storage;
    let before = audit_code_count(storage, "TOOL_NAME_INVALID");

    // Имя вне авто-алфавита спеки §7 (пробелы/кириллица): отказ остаётся
    // TOOL_PENDING_REVIEW, строка в справочник не пишется — только audit.
    for tool_name in ["bad tool!", "кириллица_имя"] {
        let error = state
            .masking
            .preflight(PreflightRequest {
                schema_version: SCHEMA_VERSION,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-a".to_owned(),
                tool_name: tool_name.to_owned(),
                arguments: json!({}),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ToolPendingReview);
        assert!(classification_row(storage, database_id, tool_name).is_none());
    }
    assert_eq!(audit_code_count(storage, "TOOL_NAME_INVALID"), before + 2);
}

#[tokio::test]
async fn auto_registration_limit_denies_without_new_row() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let storage = &state.storage;
    // Лимит спеки §7: 500 авто-строк на базу — досеваем прямо в SQLite.
    storage
        .with_connection(|connection| {
            for index in 0..500 {
                connection.execute(
                    "INSERT INTO tool_classifications(database_id,tool_name,class,reviewer,updated_at,auto_added,first_seen_at,denied_count,last_denied_at)
                     VALUES (?1,?2,'deny-pending-review',NULL,'2026-09-25T00:00:00Z',1,'2026-09-25T00:00:00Z',1,'2026-09-25T00:00:00Z')",
                    rusqlite::params![database_id.to_string(), format!("auto_tool_{index}")],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let before = audit_code_count(storage, "TOOL_AUTOADD_LIMIT");

    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "over_limit_tool".to_owned(),
            arguments: json!({}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ToolPendingReview);
    assert!(classification_row(storage, database_id, "over_limit_tool").is_none());
    assert_eq!(audit_code_count(storage, "TOOL_AUTOADD_LIMIT"), before + 1);
}

#[tokio::test]
async fn unconfigured_database_denies_before_auto_registration() {
    // Спека §7: для только созданной (unconfigured) базы отказ —
    // ACTION_REQUIRED, авто-регистрация инструментов не выполняется.
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "brand_new_tool".to_owned(),
            arguments: json!({}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ActionRequired);
    assert!(classification_row(&storage, database_id, "brand_new_tool").is_none());
}

#[tokio::test]
async fn mask_tokens_resolve_only_for_data_mask_in_enabled_mode() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let raw = "Скрытова Анна Петровна";

    // Минтим токен: finalize data-mask результата создаёт маппинг для
    // chat-a; токен извлекаем из публичной (замаскированной) выдачи.
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success": true, "data": [{"ФИО": raw}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":"ФИО","sources":["Справочник.People.FullName"]}]}),
                lineage: vec![
                    json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                ],
            },
        })
        .await
        .unwrap();
    let masked: Value = serde_json::from_str(
        response.public_result["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let token = masked["data"][0]["ФИО"].as_str().unwrap().to_owned();
    assert!(token.starts_with("[MASK:v1:FIO:"));

    // data-mask + Enabled: валидный токен раскрывается в аргументах.
    let allowed = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"link": token}),
        })
        .await
        .unwrap();
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.arguments["link"], json!(raw));

    // Токен чужого чата — отказ, подстановки нет.
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-b".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"link": token}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MaskTokenInvalid);

    // metadata-bypass: само наличие токена — отказ до ухода в 1С
    // (get_metadata — metadata-bypass по встроенной классификации).
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "get_metadata".to_owned(),
            arguments: json!({"link": token}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MaskTokenInvalid);

    // data-mask вне Enabled (режим Disabled) — токены не раскрываются.
    assert!(storage_flip_to_disabled(&state.storage, database_id));
    let error = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"link": token}),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MaskTokenInvalid);
}

fn storage_flip_to_disabled(storage: &SqliteStorage, database_id: Uuid) -> bool {
    storage
        .set_database_mode(database_id, DatabaseMode::Disabled)
        .unwrap()
}

//++agent TASK-225 [26.09.2026] ревью-2 N-1
// Эксплойт из ревью: `ВЫБРАТЬ "[MASK:…]" КАК` — токен раскрывается на
// preflight, эхо разбора содержит исходное значение. По решению §12
// вызов с расшифрованными токенами не получает свободный текст ошибки:
// только код и позиция — ни в public_result, ни в durable-истории.
#[tokio::test]
async fn parse_error_after_token_resolution_exposes_only_code_and_position() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let raw = "Скрытова Анна Петровна";

    // Минтим токен через finalize data-mask результата.
    let minted = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success": true, "data": [{"ФИО": raw}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":"ФИО","sources":["Справочник.People.FullName"]}]}),
                lineage: vec![
                    json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                ],
            },
        })
        .await
        .unwrap();
    let masked: Value =
        serde_json::from_str(minted.public_result["content"][0]["text"].as_str().unwrap()).unwrap();
    let token = masked["data"][0]["ФИО"].as_str().unwrap().to_owned();

    // Эксплойт: токен внутри текста запроса + намеренная синтаксическая
    // ошибка — preflight подставляет исходное значение в запрос.
    let call_id = Uuid::new_v4();
    let preflight = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query": format!("ВЫБРАТЬ \"{token}\" КАК")}),
        })
        .await
        .unwrap();
    assert_eq!(preflight.decision, "allow");
    assert_eq!(
        preflight.arguments["query"],
        json!(format!("ВЫБРАТЬ \"{raw}\" КАК"))
    );

    // Граница отвечает QUERY_PARSE_ERROR с эхом запроса — уже с
    // исходным значением внутри текста.
    let echo = format!("{{(1, 15)}}: Ожидается имя\nВЫБРАТЬ \"{raw}\" КАК");
    let finalized = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": false,
                    "error": "QUERY_PARSE_ERROR",
                    "message": echo,
                    "position": "(1, 15)",
                }),
            },
            field_sources: FieldSources {
                schema: json!({}),
                lineage: vec![],
            },
        })
        .await
        .unwrap();

    let public = serde_json::to_string(&finalized.public_result).unwrap();
    assert!(
        !public.contains(raw),
        "исходное значение утекло через QUERY_PARSE_ERROR: {public}"
    );
    assert!(
        !public.contains("message"),
        "message должен быть снят: {public}"
    );
    assert!(public.contains("QUERY_PARSE_ERROR"), "{public}");
    assert!(public.contains("(1, 15)"), "позиция остаётся: {public}");

    // Durable-история хранит тот же зачищенный результат.
    let stored = state
        .storage
        .load_history(database_id, "chat-a", call_id)
        .unwrap()
        .expect("запись истории должна существовать");
    let stored_text = serde_json::to_string(&stored.public_result).unwrap();
    assert!(
        !stored_text.contains(raw),
        "история содержит сырое значение: {stored_text}"
    );
    assert!(!stored_text.contains("message"), "{stored_text}");
}

// Регрессия: вызов без токенов текст ошибки разбора сохраняет —
// зачистка включается только флагом расшифрованных токенов.
#[tokio::test]
async fn parse_error_without_tokens_keeps_message() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let call_id = Uuid::new_v4();
    let preflight = state
        .masking
        .preflight(PreflightRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            arguments: json!({"query": "ВЫБРАТЬ 1 КАК В"}),
        })
        .await
        .unwrap();
    assert_eq!(preflight.decision, "allow");

    let finalized = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": false,
                    "error": "QUERY_PARSE_ERROR",
                    "message": "{(1, 15)}: Ожидается имя\nВЫБРАТЬ 1 КАК <<?>>В",
                    "position": "(1, 15)",
                }),
            },
            field_sources: FieldSources {
                schema: json!({}),
                lineage: vec![],
            },
        })
        .await
        .unwrap();
    let public = serde_json::to_string(&finalized.public_result).unwrap();
    assert!(public.contains("QUERY_PARSE_ERROR"), "{public}");
    assert!(
        public.contains("Ожидается имя"),
        "текст разбора без токенов доходит: {public}"
    );
}

// Решение оркестратора по N-1: finalize без записи контекста вызова —
// неизвестно, резолвились ли токены (строка могла быть вытерта
// рестартом между preflight и finalize) ⇒ fail-closed: свободный текст
// ошибки разбора снимается, код и позиция остаются.
#[tokio::test]
async fn parse_error_without_context_strips_text() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let call_id = Uuid::new_v4();

    let finalized = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-noctx".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "success": false,
                    "error": "QUERY_PARSE_ERROR",
                    "message": "{(1, 15)}: Ожидается имя\nВЫБРАТЬ 1 КАК <<?>>В",
                    "position": "(1, 15)",
                }),
            },
            field_sources: FieldSources {
                schema: json!({}),
                lineage: vec![],
            },
        })
        .await
        .unwrap();

    let public = serde_json::to_string(&finalized.public_result).unwrap();
    assert!(public.contains("QUERY_PARSE_ERROR"), "{public}");
    assert!(public.contains("(1, 15)"), "позиция остаётся: {public}");
    assert!(
        !public.contains("Ожидается имя"),
        "без контекста текст не отдаём: {public}"
    );

    let stored = state
        .storage
        .load_history(database_id, "chat-noctx", call_id)
        .unwrap()
        .expect("запись истории должна существовать");
    let stored_text = serde_json::to_string(&stored.public_result).unwrap();
    assert!(stored_text.contains("QUERY_PARSE_ERROR"), "{stored_text}");
    assert!(
        !stored_text.contains("Ожидается имя"),
        "в истории текст тоже зачищен: {stored_text}"
    );
}
//++agent TASK-225

#[tokio::test]
async fn opaque_tool_result_is_finalized_and_is_error_preserved() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;

    // metadata-bypass инструмент с непрозрачным результатом (весь
    // ToolCallResult как JSON, field_sources пустые) — проходит
    // финализацию, публичная форма оборачивается сервисом.
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "get_metadata".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "content": [{"type": "text", "text": "metadata answer"}],
                    "is_error": true
                }),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    assert_eq!(response.public_result["is_error"], json!(true));
    let text = response.public_result["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("metadata answer"), "{text}");

    // Opaque execute_query без field_sources: lineage обязателен —
    // отказ в безопасную форму, а не проход сырых данных.
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({
                    "content": [{"type": "text", "text": "raw query rows"}]
                }),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    assert_eq!(response.public_result["is_error"], json!(true));
    let text = response.public_result["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(!text.contains("raw query rows"), "{text}");
}

#[tokio::test]
async fn terminal_event_accepts_manager_valid_tool_names() {
    // Outbox менеджера ретраит строго с головы: terminal-ивент с именем,
    // допустимым на стороне менеджера (непустое, ≤128 байт), обязан быть
    // принят сервисом — иначе очередь встаёт навсегда. Кириллица и ':'
    // допустимы для terminal-записи (но не для авто-регистрации, см. §7).
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    for tool_name in ["биг_ПолучитьДанные", "ns:tool_name", "tool-with-dash"] {
        let response = state
            .masking
            .record_terminal_event(onec_masking_service::domain::TerminalEventRequest {
                schema_version: SCHEMA_VERSION,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                tool_name: tool_name.to_owned(),
                error_code: "TOOL_PENDING_REVIEW".to_owned(),
                scope: onec_masking_service::domain::TerminalScope {
                    kind: onec_masking_service::domain::TerminalScopeKind::Verified,
                    database_id: Some(database_id),
                    chat_id: Some("chat-a".to_owned()),
                },
            })
            .unwrap();
        assert_eq!(response.status, "recorded");
    }
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
// Безисточниковые колонки от границы (контракт ДопускиКолонок):
// schema.columns[i].sourceless ∈ {count,literal,parameter,value,
// composite} при пустом sources допускает колонку; значения во всех
// строках обязаны быть JSON-примитивами, для count — только числа.
// `unverified` и неизвестные виды — отказ.

#[tokio::test]
async fn sourceless_columns_with_primitive_values_pass_lineage_check() {
    for (kind, value) in [
        ("count", json!(5)),
        ("count", json!(0)),
        ("literal", json!("строка-литерал")),
        ("parameter", json!(true)),
        ("value", json!(null)),
        ("composite", json!(12.5)),
        // Непустое ЗНАЧЕНИЕ(...)/композит с ссылкой: граница сериализует
        // ссылку плоским объектом _objectRef — форма допускается, поля
        // дальше маскируются движком.
        (
            "value",
            json!({"_objectRef": true, "УникальныйИдентификатор":
                   "00000000-0000-0000-0000-000000000000",
                   "ТипОбъекта": "ПеречислениеСсылка.big_OKX_OrderSides",
                   "Представление": "buy"}),
        ),
        (
            "composite",
            json!({"_objectRef": true, "УникальныйИдентификатор":
                   "00000000-0000-0000-0000-000000000000",
                   "ТипОбъекта": "СправочникСсылка.big_MarketAccounts",
                   "Представление": "demo"}),
        ),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-sourceless".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({"success": true, "data": [{"Кол": value}]}),
                },
                field_sources: FieldSources {
                    schema: json!({"columns":[{"name":"Кол","sources":[],"sourceless":kind}]}),
                    lineage: vec![],
                },
            })
            .await
            .unwrap();
        assert_eq!(
            response.public_result["is_error"],
            json!(false),
            "kind={kind}"
        );
        let text = response.public_result["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("\"Кол\""), "kind={kind}: {text}");
    }
}

#[tokio::test]
async fn sourceless_columns_fail_closed_on_violations() {
    let raw = "sensitive-sourceless-marker-value";
    for (column, value, lineage, note) in [
        // count допускает только числа: строка и null — отказ.
        (
            json!({"name":"Кол","sources":[],"sourceless":"count"}),
            json!("не-число"),
            vec![],
            "count with string",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"count"}),
            json!(null),
            vec![],
            "count with null",
        ),
        // Примитивность формы: объект/массив в ячейке — отказ.
        (
            json!({"name":"Кол","sources":[],"sourceless":"literal"}),
            json!({"x":1}),
            vec![],
            "literal with object value",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"parameter"}),
            json!([1, 2]),
            vec![],
            "parameter with array value",
        ),
        // Неизвестный вид sourceless, отсутствие sourceless, маркеры
        // unverified (строгий режим — следующий шаг), противоречивое
        // evidence (sourceless при непустых sources) — отказ.
        (
            json!({"name":"Кол","sources":[],"sourceless":"smth_else"}),
            json!("ok"),
            vec![],
            "unknown sourceless kind",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"unverified"}),
            json!("ok"),
            vec![],
            "unverified as kind",
        ),
        (
            json!({"name":"Кол","sources":[]}),
            json!("ok"),
            vec![],
            "empty sources without sourceless",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"literal","unverified":true}),
            json!("ok"),
            vec![],
            "unverified marker on column",
        ),
        (
            json!({"name":"Кол","sources":["Справочник.Test.APIKey"],"sourceless":"literal"}),
            json!("ok"),
            vec![],
            "sourceless with non-empty sources",
        ),
        // Объект в ячейке допустим только в форме _objectRef и только для
        // value/composite: чужой объект, неплоская вложенность и ref-форма
        // в literal/parameter/count — отказ.
        (
            json!({"name":"Кол","sources":[],"sourceless":"value"}),
            json!({"not_ref": "x"}),
            vec![],
            "value with non-ref object",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"value"}),
            json!({"_objectRef": true, "Представление": {"nested": 1}}),
            vec![],
            "value ref with nested object field",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"literal"}),
            json!({"_objectRef": true, "Представление": "buy"}),
            vec![],
            "literal with ref-shaped object",
        ),
        (
            json!({"name":"Кол","sources":[],"sourceless":"count"}),
            json!({"_objectRef": true}),
            vec![],
            "count with ref-shaped object",
        ),
        // Поддельное lineage для безисточниковой колонки и lineage-элемент
        // с маркером unverified — отказ.
        (
            json!({"name":"Кол","sources":[],"sourceless":"literal"}),
            json!("ok"),
            vec![json!({"column":"Кол","source_path":"Справочник.Test.APIKey"})],
            "lineage for sourceless column",
        ),
        (
            json!({"name":"Кол","sources":["Справочник.Test.APIKey"]}),
            json!("ok"),
            vec![json!({"column":"Кол","source_path":"Справочник.Test.APIKey","unverified":true})],
            "unverified marker in lineage",
        ),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        let call_id = Uuid::new_v4();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-sourceless".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({"success": true, "data": [{"Кол": value}], "note": raw}),
                },
                field_sources: FieldSources {
                    schema: json!({"columns":[column]}),
                    lineage,
                },
            })
            .await
            .unwrap();
        assert_eq!(response.public_result["is_error"], json!(true), "{note}");
        assert!(
            !serde_json::to_string(&response.public_result)
                .unwrap()
                .contains(raw),
            "{note}"
        );
        state
            .storage
            .with_connection(|connection| {
                let stored: String = connection.query_row(
                    "SELECT public_result_json || report_json || mask_reasons_json FROM history WHERE call_id=?1",
                    [call_id.to_string()],
                    |row| row.get(0),
                )?;
                assert!(!stored.contains(raw), "{note}");
                assert!(stored.contains("service:query_lineage_incomplete"), "{note}");
                Ok(())
            })
            .unwrap();
    }
}

#[tokio::test]
async fn sourceless_column_values_are_masked_like_regular_columns() {
    // Словарь/правила применяются к безисточниковым колонкам так же, как
    // к колонкам с источником (спека: «маскирование — как у прочих»).
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                rules: vec![PolicyRule {
                    selector: RuleSelector::Name,
                    pattern: "СекретныйЛитерал".to_owned(),
                    action: RuleAction::Mask,
                    category: "TEST".to_owned(),
                    priority: 0,
                    rule_id: None,
                }],
                ..PolicySnapshot::default()
            },
        )
        .await;
    let raw = "sensitive-literal-under-rule";
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            database_id,
            chat_id: "chat-sourceless".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success": true, "data": [{"СекретныйЛитерал": raw}]}),
            },
            field_sources: FieldSources {
                schema: json!({"columns":[{"name":"СекретныйЛитерал","sources":[],"sourceless":"literal"}]}),
                lineage: vec![],
            },
        })
        .await
        .unwrap();
    assert_eq!(response.public_result["is_error"], json!(false));
    let public = serde_json::to_string(&response.public_result).unwrap();
    assert!(!public.contains(raw));
    assert!(public.contains("[MASK:v1:TEST:"));
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
// Двойная сериализация: бизнес-result metadata-bypass инструмента —
// JSON-строка (BSL возвращает сериализованный JSON). В text должна
// уйти сама строка, а не экранированный литерал `"{\"valid\":...}"`.
#[tokio::test]
async fn string_business_result_goes_to_text_verbatim() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let storage = state.storage.clone();
    storage
        .set_tool_classification(
            database_id,
            "validate_query",
            onec_masking_service::domain::ToolClass::MetadataBypass,
            "admin-test",
        )
        .unwrap();
    let (_, call_id, correlation_id) = request_ids();
    let business = "{\n\"valid\": true,\n\"message\": \"ok\"\n}";
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "validate_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!(business),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    let text = response.public_result["content"][0]["text"]
        .as_str()
        .unwrap();
    assert_eq!(text, business);
    // text — валидный JSON сам по себе (парсится как объект, не строка).
    assert!(serde_json::from_str::<Value>(text).unwrap().is_object());
}

// Opaque-результат без конверта границы — уже ToolCallResult; повторная
// обёртка вложила бы весь объект в text. Возвращается как есть.
#[tokio::test]
async fn opaque_tool_call_result_passes_through_without_rewrap() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .set_tool_classification(
            database_id,
            "infobase_info",
            onec_masking_service::domain::ToolClass::MetadataBypass,
            "admin-test",
        )
        .unwrap();
    let (_, call_id, correlation_id) = request_ids();
    let opaque = json!({
        "content": [{"type": "text", "text": "{\"platform\":\"8.3.27\"}"}],
        "isError": false
    });
    let response = state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-a".to_owned(),
            tool_name: "infobase_info".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: opaque.clone(),
            },
            field_sources: FieldSources::default(),
        })
        .await
        .unwrap();
    assert_eq!(response.public_result, opaque);
}
//++agent TASK-225

//++agent TASK-225 [25.09.2026]
// Строгий режим lineage (databases.strict_mode, default ON): колонка с
// `unverified:true` + `output_types` не отклоняется, а каждое значение
// уходит одним типизированным токеном — строки, числа, булево, null и
// контейнеры. Неизвестные поля evidence и противоречия — отказ.
#[test]
fn strict_mode_defaults_to_on_for_new_databases() {
    let storage = SqliteStorage::in_memory().unwrap();
    let (settings, created) = storage.ensure_database(Uuid::new_v4()).unwrap();
    assert!(created);
    assert!(settings.strict_mode);
}

async fn finalize_unverified(
    state: &AppState,
    database_id: Uuid,
    columns: Value,
    rows: Value,
    lineage: Vec<Value>,
) -> Value {
    let (call_id, correlation_id, _) = request_ids();
    state
        .masking
        .finalize(FinalizeRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            correlation_id,
            database_id,
            chat_id: "chat-strict".to_owned(),
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult {
                result: json!({"success": true, "data": rows}),
            },
            field_sources: FieldSources {
                schema: json!({"columns": columns}),
                lineage,
            },
        })
        .await
        .unwrap()
        .public_result
}

#[tokio::test]
async fn strict_mode_masks_unverified_values_of_any_json_type() {
    for (value, category) in [
        (json!("СыраяПодстрока"), "UNVERIFIED_STRING"),
        (json!(42.5), "UNVERIFIED_NUMBER"),
        (json!(true), "UNVERIFIED_BOOL"),
        (json!(null), "UNVERIFIED_NULL"),
        (json!({"_objectRef": true, "id": "x"}), "UNVERIFIED_OBJECT"),
        (json!([1, 2]), "UNVERIFIED_ARRAY"),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        let public = finalize_unverified(
            &state,
            database_id,
            json!([{"name":"Выражение","sources":[],"unverified":true,"output_types":["Строка"]}]),
            json!([{"Выражение": value}]),
            vec![],
        )
        .await;
        assert_eq!(public["is_error"], json!(false), "{category}");
        let text = public["content"][0]["text"].as_str().unwrap();
        let inner: Value = serde_json::from_str(text).unwrap();
        let cell = &inner["data"][0]["Выражение"];
        assert!(
            cell.as_str()
                .is_some_and(|token| token.starts_with(&format!("[MASK:v1:{category}:"))),
            "{category}: {text}"
        );
    }
}

#[tokio::test]
async fn strict_mode_off_keeps_unverified_refusal() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    state
        .storage
        .with_connection(|connection| {
            connection.execute(
                "UPDATE databases SET strict_mode=0 WHERE id=?1",
                [database_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
    let public = finalize_unverified(
        &state,
        database_id,
        json!([{"name":"Выражение","sources":[],"unverified":true,"output_types":["Строка"]}]),
        json!([{"Выражение": "скрыто"}]),
        vec![],
    )
    .await;
    assert_eq!(public["is_error"], json!(true));
    assert!(!serde_json::to_string(&public).unwrap().contains("скрыто"));
}

#[tokio::test]
async fn strict_mode_rejects_malformed_unverified_evidence() {
    for (column, lineage, note) in [
        // Нет output_types на unverified-колонке — отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":true}),
            vec![],
            "unverified without output_types",
        ),
        // output_types не массив строк — отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":true,"output_types":"Строка"}),
            vec![],
            "output_types not an array",
        ),
        // unverified ≠ true — отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":"yes","output_types":[]}),
            vec![],
            "unverified not boolean true",
        ),
        (
            json!({"name":"Кол","sources":[],"unverified":false,"output_types":[]}),
            vec![],
            "unverified false marker",
        ),
        // unverified + sourceless — противоречие, отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":true,"output_types":[],"sourceless":"literal"}),
            vec![],
            "unverified with sourceless",
        ),
        // Неизвестный ключ колонки — отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":true,"output_types":[],"surprise":1}),
            vec![],
            "unknown column key",
        ),
        // sources не массив — отказ.
        (
            json!({"name":"Кол","unverified":true,"output_types":[]}),
            vec![],
            "unverified without sources array",
        ),
        // Маркер на lineage-элементе — отказ.
        (
            json!({"name":"Кол","sources":["Справочник.Test.Поле"],"unverified":true,"output_types":[]}),
            vec![json!({"column":"Кол","source_path":"Справочник.Test.Поле","unverified":true})],
            "unverified on lineage item",
        ),
        // Неизвестный ключ lineage-элемента — отказ.
        (
            json!({"name":"Кол","sources":[],"unverified":true,"output_types":[]}),
            vec![json!({"column":"Кол","source_path":"Справочник.Test.Поле","extra":"x"})],
            "unknown lineage key",
        ),
    ] {
        let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
        let public = finalize_unverified(
            &state,
            database_id,
            json!([column]),
            json!([{"Кол": "значение"}]),
            lineage,
        )
        .await;
        assert_eq!(public["is_error"], json!(true), "{note}");
    }
}

#[tokio::test]
async fn strict_mode_unverified_column_with_unresolvable_sources_is_masked() {
    // Кейс границы: sources непусты, но путь не разрешается — колонка
    // помечается unverified, lineage-элемент по тому же пути допустим,
    // значение маскируется целиком.
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let public = finalize_unverified(
        &state,
        database_id,
        json!([{"name":"Выражение","sources":["Справочник.Несуществующий.Путь"],"unverified":true,"output_types":["Строка","Число"]}]),
        json!([{"Выражение": "сырое"}]),
        vec![json!({"column":"Выражение","source_path":"Справочник.Несуществующий.Путь","source_types":[],"secret_cut":false})],
    )
    .await;
    assert_eq!(public["is_error"], json!(false));
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(serialized.contains("[MASK:v1:UNVERIFIED_STRING:"));
    assert!(!serialized.contains("сырое"));
}

#[tokio::test]
async fn strict_mode_keeps_verified_and_secret_columns_unchanged() {
    // output_types на обычных колонках не ломает проверенный путь;
    // секрет по-прежнему режется до маскирования.
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let public = finalize_unverified(
        &state,
        database_id,
        json!([
            {"name":"Секрет","sources":["Справочник.Test.APIKey"],"output_types":["Строка"]},
            {"name":"Выражение","sources":[],"unverified":true,"output_types":["Строка"]},
            {"name":"К","sources":[],"sourceless":"count","output_types":["Число"]}
        ]),
        json!([{"Секрет": "тайное-значение", "Выражение": "подстрока", "К": 27}]),
        vec![json!({"column":"Секрет","source_path":"Справочник.Test.APIKey","source_types":["Строка"],"secret_cut":true})],
    )
    .await;
    assert_eq!(public["is_error"], json!(false));
    let text = public["content"][0]["text"].as_str().unwrap();
    let inner: Value = serde_json::from_str(text).unwrap();
    let row = &inner["data"][0];
    assert_eq!(row["Секрет"], json!("[SECRET_REMOVED]"), "{text}");
    assert!(
        row["Выражение"]
            .as_str()
            .is_some_and(|token| token.starts_with("[MASK:v1:UNVERIFIED_STRING:")),
        "{text}"
    );
    // КОЛИЧЕСТВО(*) без маркера остаётся числом без маскирования.
    assert_eq!(row["К"], json!(27), "{text}");
}
//++agent TASK-225
//++agent TASK-225 [26.09.2026]
// Контракт границы: ошибка разбора запроса доходит до агента с платформенным
// текстом (эхо его запроса); код QUERY_PARSE_ERROR и message проходят
// через маскировку как обычные строки — словарное значение в тексте режется.
#[tokio::test]
async fn query_parse_error_envelope_survives_masking_with_text() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let dict_word = "секретная-строка-225";
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                dictionary: HashMap::from([(dict_word.to_owned(), "TEST".to_owned())]),
                ready: true,
                ..PolicySnapshot::default()
            },
        )
        .await;
    let parse_text = "{(1,10)}: Ожидается имя <<?>>В";
    for (message, survives) in [
        (json!(parse_text), true),
        (json!(format!("Ошибка у значения {dict_word}")), false),
    ] {
        let call_id = Uuid::new_v4();
        // Решение оркестратора по N-1: текст доходит только когда
        // контекст вызова есть и флаг токенов=0 — реальный путь,
        // preflight перед finalize пишет контекст (флаг не ставится:
        // в аргументах токенов нет). Без записи контекста — fail-closed,
        // текст снимается (см. parse_error_without_context_strips_text).
        state
            .masking
            .preflight(PreflightRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-parse".to_owned(),
                tool_name: "execute_query".to_owned(),
                arguments: json!({"query": "ВЫБРАТЬ 1"}),
            })
            .await
            .unwrap();
        let response = state
            .masking
            .finalize(FinalizeRequest {
                schema_version: SCHEMA_VERSION,
                call_id,
                correlation_id: Uuid::new_v4(),
                database_id,
                chat_id: "chat-parse".to_owned(),
                tool_name: "execute_query".to_owned(),
                outcome: FinalizeOutcome::ToolResult {
                    result: json!({
                        "success": false,
                        "error": "QUERY_PARSE_ERROR",
                        "message": message,
                    }),
                },
                field_sources: FieldSources::default(),
            })
            .await
            .unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(public.contains("QUERY_PARSE_ERROR"), "{public}");
        if survives {
            assert!(public.contains("Ожидается имя"), "{public}");
        }
        assert!(!public.contains(dict_word), "{public}");
    }
    let stored: String = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT group_concat(public_result_json, ';') FROM history
                 WHERE database_id=?1 AND chat_id='chat-parse'",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(stored.contains("QUERY_PARSE_ERROR"));
    assert!(!stored.contains(dict_word));
}
//++agent TASK-225
