use std::{collections::HashMap, sync::Arc};

use onec_masking_service::{
    domain::{
        DatabaseMode, ErrorCode, FinalizeOutcome, FinalizeRequest, MaskingEvidence, PolicyRule,
        PolicySnapshot, PreflightRequest, RuleAction, RuleSelector, SCHEMA_VERSION,
    },
    AppState, SqliteStorage,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

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
        activate_empty_test_cache(&state, database_id).await;
    }
    (state, database_id)
}

async fn activate_empty_test_cache(state: &AppState, database_id: Uuid) {
    let job_id = state.storage.enqueue_feed_job(database_id, 1).unwrap();
    let job = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.job_id == job_id)
        .unwrap();
    let payload = onec_masking_service::domain::FeedPayload {
        selection_id: None,
        page_index: 0,
        metadata: Vec::new(),
        dictionary_values: Vec::new(),
        final_chunk: true,
    };
    let digest = digest_payload(&serde_json::to_value(&payload).unwrap());
    state
        .masking
        .upload_feed_chunk(
            job.job_id,
            0,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: SCHEMA_VERSION,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&digest),
                payload,
            },
        )
        .unwrap();
    let aggregate: [u8; 32] = Sha256::digest(digest).into();
    state
        .masking
        .activate_feed(
            job.job_id,
            onec_masking_service::domain::FeedActivateRequest {
                schema_version: SCHEMA_VERSION,
                correlation_id: Uuid::new_v4(),
                expected_chunks: 1,
                expected_metadata_count: 0,
                expected_dictionary_count: 0,
                aggregate_digest: hex(&aggregate),
            },
        )
        .await
        .unwrap();
    state
        .storage
        .with_connection(|connection| {
            connection.execute(
                "DELETE FROM feed_jobs WHERE id=?1",
                [job.job_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn feed_activation_rejects_stale_state_without_replacing_active_generation() {
    let storage = SqliteStorage::in_memory().unwrap();
    let database_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();

    let first_job_id = storage.enqueue_feed_job(database_id, 1).unwrap();
    let first_job = storage
        .pending_feed_jobs(10)
        .unwrap()
        .into_iter()
        .find(|job| job.job_id == first_job_id)
        .unwrap();
    assert!(storage.mark_feed_receiving(first_job_id).unwrap());
    storage
        .activate_feed_job(&first_job, "digest-v1", 3, 2)
        .unwrap();

    let stale_job_id = storage.enqueue_feed_job(database_id, 2).unwrap();
    let stale_job = storage
        .pending_feed_jobs(10)
        .unwrap()
        .into_iter()
        .find(|job| job.job_id == stale_job_id)
        .unwrap();
    assert!(storage.mark_feed_receiving(stale_job_id).unwrap());
    assert!(storage
        .fail_feed_job(stale_job_id, "CANCELLED", Uuid::new_v4())
        .unwrap());

    assert!(storage
        .activate_feed_job(&stale_job, "must-not-publish", 100, 100)
        .is_err());
    storage
        .with_connection(|connection| {
            let (active_version, stale_generations, stale_state): (i64, i64, String) = connection
                .query_row(
                "SELECT d.active_cache_version,
                            (SELECT COUNT(*) FROM cache_generations
                             WHERE database_id=d.id AND version=2),
                            (SELECT state FROM feed_jobs WHERE id=?2)
                     FROM databases d WHERE d.id=?1",
                rusqlite::params![database_id.to_string(), stale_job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(active_version, 1);
            assert_eq!(stale_generations, 0);
            assert_eq!(stale_state, "failed");
            let first_status: String = connection.query_row(
                "SELECT status FROM cache_generations WHERE database_id=?1 AND version=1",
                [database_id.to_string()],
                |row| row.get(0),
            )?;
            assert_eq!(first_status, "active");
            Ok(())
        })
        .unwrap();
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
                result: json!({
                    "content": [
                        {"type":"text", "text":format!("Владелец: {raw_name}")},
                        {"type":"json", "json":{"ФИО":raw_name,"password":raw_secret}}
                    ],
                    "structured_content":{"rows":[{"ФИО":raw_name,"api_key":raw_secret}]},
                    "is_error":false
                }),
            },
            evidence: MaskingEvidence {
                schema: json!({"columns":[
                    {"name":"ФИО","sources":["Справочник.People.FullName"]},
                    {"name":"api_key","sources":["Справочник.People.APIKey"]}
                ]}),
                lineage: vec![
                    json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                    json!({"column":"api_key","source_path":"Справочник.People.APIKey"}),
                ],
                ..MaskingEvidence::default()
            },
        })
        .await
        .unwrap();
    let public = serde_json::to_string(&response.public_result).unwrap();
    assert!(!public.contains(raw_name));
    assert!(!public.contains(raw_secret));
    assert!(public.contains("[MASK:v1:FIO:"));
    assert!(public.contains("[SECRET_REMOVED]"));

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
                "content":[
                    {"type":"text","text":format!("{{\"{alias}\":\"{raw}\"}}")},
                    {"type":"json","json":{"data":[{alias:raw}]}}
                ],
                "structured_content":{"success":true,"data":[{alias:raw}]},
                "is_error":false
            })},
            evidence: MaskingEvidence {
                schema: json!({"columns":[{"name":alias,"types":["Строка"],"sources":["Справочник.big_MarketAccounts.APIKey"]}]}),
                lineage: vec![json!({"column":alias,"source_path":"Справочник.big_MarketAccounts.APIKey","source_types":["Строка"],"secret_cut":false})],
                degraded_reasons: Vec::new(),
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
    for evidence in [
        MaskingEvidence::default(),
        MaskingEvidence {
            schema: json!({"columns":[{"name":alias,"sources":["Справочник.Test.APIKey"]}]}),
            lineage: vec![],
            degraded_reasons: vec!["lineage_incomplete".to_owned()],
        },
        MaskingEvidence {
            schema: json!({"columns":[{"name":alias,"sources":["Справочник.Test.APIKey"]}]}),
            lineage: vec![json!({"column":"ДругаяКолонка","source_path":"Справочник.Test.APIKey"})],
            degraded_reasons: vec![],
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
                        "content":[{"type":"text","text":raw}],
                        "structured_content":{"data":[{alias:raw}]},
                        "is_error":false
                    }),
                },
                evidence,
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
        json!({"content":[{"type":"text","text":raw}],"is_error":false}),
        json!({"content":[{"type":"json","json":{"message":raw}}],"is_error":false}),
        json!({"content":[{"type":"text","text":raw}],"structured_content":{"success":true},"is_error":false}),
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
                evidence: MaskingEvidence::default(),
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
                result: json!({
                    "content":[{"type":"text","text":"0 rows"}],
                    "structured_content":{"success":true,"data":[]},
                    "is_error":false
                }),
            },
            evidence: MaskingEvidence::default(),
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
                    "content":[{"type":"text","text":format!("value={raw}")}],
                    "structured_content":{"data":[{alias:raw}]},
                    "is_error":false
                }),
            },
            evidence: MaskingEvidence {
                schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                lineage: vec![json!({"column":alias,"source_path":path,"secret_cut":false})],
                ..MaskingEvidence::default()
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
                        "content":[{"type":"text","text":raw},
                            {"type":"json","json":{"НейтральноеПоле":raw}}],
                        "is_error":false
                    }),
                },
                evidence: MaskingEvidence::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            response.public_result["content"][0]["text"],
            "[SECRET_REMOVED]"
        );
        assert_eq!(
            response.public_result["content"][1]["json"]["НейтральноеПоле"],
            "[SECRET_REMOVED]"
        );
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
                        "content":[{"type":"json","json":{"data":[{alias:raw}]}},
                            {"type":"text","text":format!("value={raw}")}],
                        "structured_content":{"success":true,"data":[{alias:raw}]},
                        "is_error":false
                    }),
                },
                evidence: MaskingEvidence {
                    schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                    lineage,
                    ..MaskingEvidence::default()
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
                    "content":[{"type":"json","json":{"data":[{alias:raw}]}},
                        {"type":"text","text":format!("value={raw}")}],
                    "structured_content":{"success":true,"data":[{alias:raw}]},
                    "is_error":false
                }),
            },
            evidence: MaskingEvidence {
                schema: json!({"columns":[{"name":alias,"sources":[path]}]}),
                lineage: vec![json!({"column":alias,"source_path":path})],
                ..MaskingEvidence::default()
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
                        },
                        PolicyRule {
                            selector: RuleSelector::SourcePath,
                            pattern: strict_source.to_owned(),
                            action,
                            category: "STRICT".to_owned(),
                            priority: 0,
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
                        "content":[{"type":"json","json":{"data":[{alias:raw}]}}],
                        "structured_content":{"success":true,"data":[{alias:raw}]},
                        "is_error":false
                    }),
                },
                evidence: MaskingEvidence {
                    schema: json!({"columns":[{"name":alias,
                    "sources":[public_source,strict_source]}]}),
                    lineage: vec![
                        json!({"column":alias,"source_path":public_source}),
                        json!({"column":alias,"source_path":strict_source}),
                    ],
                    ..MaskingEvidence::default()
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
                    result: json!({
                        "content":[{"type":"json","json":{"НейтральноеПоле":raw}}],
                        "is_error":false
                    }),
                },
                evidence: MaskingEvidence {
                    schema: json!({"columns":[{"name":"НейтральноеПоле","types":types}]}),
                    ..MaskingEvidence::default()
                },
            })
            .await
            .unwrap();
        let public = serde_json::to_string(&response.public_result).unwrap();
        assert!(!public.contains(raw));
        assert!(public.contains("[MASK:v1:TYPE:"));
    }
}

#[tokio::test]
async fn legacy_active_secret_policy_cannot_publish_ready_feed() {
    let storage = Arc::new(SqliteStorage::in_memory().unwrap());
    let state = AppState::new(storage.clone(), "https://masking.test");
    let database_id = Uuid::new_v4();
    let policy_id = Uuid::new_v4();
    storage.ensure_database(database_id).unwrap();
    storage
        .set_database_mode(database_id, DatabaseMode::Enabled)
        .unwrap();
    storage.with_connection(|connection| {
        let now = chrono::Utc::now().to_rfc3339();
        connection.execute(
            "INSERT INTO policies(id,database_id,version,status,created_at) VALUES (?1,?2,1,'active',?3)",
            rusqlite::params![policy_id.to_string(), database_id.to_string(), now],
        )?;
        connection.execute(
            "INSERT INTO policy_rules(id,policy_id,selector_kind,selector_value,action,category,priority,enabled,created_at) VALUES (?1,?2,'regex','synthetic-pattern','secret','SECRET',1,1,?3)",
            rusqlite::params![Uuid::new_v4().to_string(), policy_id.to_string(), now],
        )?;
        connection.execute(
            "UPDATE databases SET active_policy_id=?1 WHERE id=?2",
            rusqlite::params![policy_id.to_string(), database_id.to_string()],
        )?;
        Ok(())
    }).unwrap();
    let job_id = storage.enqueue_feed_job(database_id, 1).unwrap();
    let job = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.job_id == job_id)
        .unwrap();
    let payload = onec_masking_service::domain::FeedPayload {
        selection_id: None,
        page_index: 0,
        metadata: Vec::new(),
        dictionary_values: Vec::new(),
        final_chunk: true,
    };
    let digest = digest_payload(&serde_json::to_value(&payload).unwrap());
    state
        .masking
        .upload_feed_chunk(
            job.job_id,
            0,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: SCHEMA_VERSION,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&digest),
                payload,
            },
        )
        .unwrap();
    let aggregate: [u8; 32] = Sha256::digest(digest).into();
    let error = state
        .masking
        .activate_feed(
            job.job_id,
            onec_masking_service::domain::FeedActivateRequest {
                schema_version: SCHEMA_VERSION,
                correlation_id: Uuid::new_v4(),
                expected_chunks: 1,
                expected_metadata_count: 0,
                expected_dictionary_count: 0,
                aggregate_digest: hex(&aggregate),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyInvalid);
    assert!(!state.masking.database_ready(database_id).await);
}
//++agent TASK-221

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
                    },
                    PolicyRule {
                        selector: RuleSelector::Name,
                        pattern: "customer".to_owned(),
                        action: RuleAction::Mask,
                        category: "CUSTOMER".to_owned(),
                        priority: 0,
                    },
                    PolicyRule {
                        selector: RuleSelector::SourcePath,
                        pattern: "Catalog.People.FullName".to_owned(),
                        action: RuleAction::Secret,
                        category: "SECRET_PERSON".to_owned(),
                        priority: -100,
                    },
                    PolicyRule {
                        selector: RuleSelector::Dictionary,
                        pattern: "SECRET_PERSON".to_owned(),
                        action: RuleAction::Secret,
                        category: "SECRET_PERSON".to_owned(),
                        priority: -100,
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
                result: json!({"content":[
                    {"type":"json","json":{"customer":raw_customer,"ФИО":raw_name}},
                    {"type":"text","text":"Петров Петр Петрович"}
                ],"is_error":false}),
            },
            evidence: MaskingEvidence {
                lineage: vec![json!({"result_name":"ФИО","source_path":"Catalog.People.FullName"})],
                ..MaskingEvidence::default()
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
            evidence: MaskingEvidence::default(),
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
            json!({"content":[{"type":"json","json":{"rows":vec!["oversized-raw"; 10_001]}}],"is_error":false}),
            "oversized-raw",
            "service:result_limit_exceeded",
        ),
        (
            json!({"content":[{"type":"json","json":{"nested":{"html":"<script>raw-secret()</script>"}}}],"is_error":false}),
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
            tool_name: "execute_query".to_owned(),
            outcome: FinalizeOutcome::ToolResult { result },
            evidence: MaskingEvidence::default(),
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
            result: json!({
                "content":[{"type":"json","json":{"ФИО":raw_name,"access_token":raw_secret}}],
                "is_error":false
            }),
        },
        evidence: MaskingEvidence::default(),
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
        let (result, evidence) = if tool_name == "execute_query" {
            (
                json!({"content":[{"type":"json","json":{"data":[{"ФИО":raw}]}}],
                    "structured_content":{"success":true,"data":[{"ФИО":raw}]},"is_error":false}),
                MaskingEvidence {
                    schema: json!({"columns":[{"name":"ФИО","sources":["Справочник.People.FullName"]}]}),
                    lineage: vec![
                        json!({"column":"ФИО","source_path":"Справочник.People.FullName"}),
                    ],
                    ..MaskingEvidence::default()
                },
            )
        } else {
            (
                json!({"content":[{"type":"json","json":{"ФИО":raw}}],"is_error":false}),
                MaskingEvidence::default(),
            )
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
                evidence,
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
    let finalized = state.masking.finalize(FinalizeRequest {
        schema_version: 1,
        call_id,
        correlation_id,
        database_id,
        chat_id: "chat-a".to_owned(),
        tool_name: "get_object_by_link".to_owned(),
        outcome: FinalizeOutcome::ToolResult {
            result: json!({"content":[{"type":"json","json":{"ФИО":raw_name}}],"is_error":false}),
        },
        evidence: MaskingEvidence::default(),
    }).await.unwrap();
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
    state.masking.finalize(FinalizeRequest {
        schema_version: 1, call_id, correlation_id: Uuid::new_v4(), database_id,
        chat_id: "chat-reveal".to_owned(), tool_name: "get_object_by_link".to_owned(),
        outcome: FinalizeOutcome::ToolResult { result: json!({
            "content":[{"type":"json","json":{"ФИО":raw_name,"password":"never-reveal"}}],"is_error":false
        })}, evidence: MaskingEvidence::default(),
    }).await.unwrap();
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
    assert_eq!(unavailable.code, ErrorCode::MappingUnavailable);
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
                }],
                dictionary: HashMap::from([("ООО Ромашка".to_owned(), "ORG".to_owned())]),
                metadata_sources: Vec::new(),
                ready: true,
            },
        )
        .await;
    let response = state.masking.finalize(FinalizeRequest {
        schema_version: 1,
        call_id: Uuid::new_v4(),
        correlation_id: Uuid::new_v4(),
        database_id,
        chat_id: "chat-a".to_owned(),
        tool_name: "find_references_to_object".to_owned(),
        outcome: FinalizeOutcome::ToolResult {
            result: json!({"content":[{"type":"text","text":"ООО Ромашка, ИНН 7707083893"}],"is_error":false}),
        },
        evidence: MaskingEvidence::default(),
    }).await.unwrap();
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

#[tokio::test]
async fn feed_is_staged_in_ram_and_activated_atomically() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let job_id = Uuid::new_v4();
    state.storage.with_connection(|connection| {
        let now = chrono::Utc::now().to_rfc3339();
        connection.execute(
            "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at)
             VALUES (?1,?2,'part',?3,NULL,?4)",
            rusqlite::params![Uuid::new_v4().to_string(), database_id.to_string(),
                r#"[{"source_path":"Catalog.Organizations.Description","category":"ORG","filter_ast":{"op":"eq","field":"DeletionMark","value":false}}]"#, now],
        )?;
        connection.execute(
            "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at)
             VALUES (?1,?2,2,'pending',?3,?3)",
            rusqlite::params![job_id.to_string(), database_id.to_string(), now],
        )?;
        Ok(())
    }).unwrap();
    let job = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap()
        .remove(0);
    let selection_id = Uuid::parse_str(
        job.dictionary_selectors[0]["selection_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        job.dictionary_selectors[0]["filter_ast"],
        json!({"op":"eq","field":"DeletionMark","value":false})
    );
    let payload = onec_masking_service::domain::FeedPayload {
        selection_id: Some(selection_id),
        page_index: 0,
        metadata: vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Catalog.Organizations.Description".to_owned(),
            field_name: "Description".to_owned(),
            field_type: "String".to_owned(),
            password_mode: false,
        }],
        dictionary_values: vec![onec_masking_service::domain::FeedDictionaryValue {
            source_path: "Catalog.Organizations.Description".to_owned(),
            category: "ORG".to_owned(),
            value: "ООО Вектор".to_owned(),
        }],
        final_chunk: true,
    };
    let digest = digest_payload(&serde_json::to_value(&payload).unwrap());
    state
        .masking
        .upload_feed_chunk(
            job_id,
            0,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&digest),
                payload,
            },
        )
        .unwrap();
    let aggregate: [u8; 32] = Sha256::digest(digest).into();
    state
        .masking
        .activate_feed(
            job_id,
            onec_masking_service::domain::FeedActivateRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                expected_chunks: 1,
                expected_metadata_count: 1,
                expected_dictionary_count: 1,
                aggregate_digest: hex(&aggregate),
            },
        )
        .await
        .unwrap();
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
                result: json!({
                    "content":[{"type":"text","text":"Контрагент ООО Вектор"}],"is_error":false
                }),
            },
            evidence: MaskingEvidence::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&result.public_result).unwrap();
    assert!(!rendered.contains("ООО Вектор"));
    assert!(rendered.contains("[MASK:v1:ORG:"));

    let failed_job_id = Uuid::new_v4();
    state
        .storage
        .with_connection(|connection| {
            let now = chrono::Utc::now().to_rfc3339();
            connection.execute(
                "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at)
                 VALUES (?1,?2,3,'pending',?3,?3)",
                rusqlite::params![failed_job_id.to_string(), database_id.to_string(), now],
            )?;
            Ok(())
        })
        .unwrap();
    let failed_job = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.job_id == failed_job_id)
        .unwrap();
    let failed_selection_id = Uuid::parse_str(
        failed_job.dictionary_selectors[0]["selection_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let failed_payload = onec_masking_service::domain::FeedPayload {
        selection_id: Some(failed_selection_id),
        page_index: 0,
        metadata: vec![],
        dictionary_values: vec![onec_masking_service::domain::FeedDictionaryValue {
            source_path: "Catalog.Organizations.Description".to_owned(),
            category: "ORG".to_owned(),
            value: "ООО Новый".to_owned(),
        }],
        final_chunk: true,
    };
    let failed_digest = digest_payload(&serde_json::to_value(&failed_payload).unwrap());
    state
        .masking
        .upload_feed_chunk(
            failed_job_id,
            0,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&failed_digest),
                payload: failed_payload,
            },
        )
        .unwrap();
    let failed = state
        .masking
        .activate_feed(
            failed_job_id,
            onec_masking_service::domain::FeedActivateRequest {
                schema_version: 1,
                correlation_id: Uuid::new_v4(),
                expected_chunks: 1,
                expected_metadata_count: 0,
                expected_dictionary_count: 1,
                aggregate_digest: "invalid".to_owned(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(failed.code, ErrorCode::PolicyInvalid);
    assert!(state.masking.database_ready(database_id).await);
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
                result: json!({"content":[{"type":"text","text":"ООО Вектор / ООО Новый"}],"is_error":false}),
            },
            evidence: MaskingEvidence::default(),
        })
        .await
        .unwrap();
    let rendered = serde_json::to_string(&after_failed_refresh.public_result).unwrap();
    assert!(!rendered.contains("ООО Вектор"));
    assert!(rendered.contains("ООО Новый"));

    let restarted = AppState::new(state.storage.clone(), "https://masking.test");
    assert!(!restarted.masking.database_ready(database_id).await);
    let refresh = restarted
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap();
    assert!(refresh
        .iter()
        .any(|job| job.database_id == database_id && job.target_version == 3));
}

#[tokio::test]
async fn metadata_feed_accepts_large_composite_type_and_rejects_payload_over_chunk_limit() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let job_id = state.storage.enqueue_feed_job(database_id, 2).unwrap();
    state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap();

    let component =
        "Строка(100), СправочникСсылка.Номенклатура, СправочникСсылка.ХарактеристикиНоменклатуры";
    let mut composite_type = std::iter::repeat_n(component, 104)
        .collect::<Vec<_>>()
        .join(", ");
    composite_type.push_str(&"X".repeat(17_242 - composite_type.len()));
    assert_eq!(composite_type.len(), 17_242);
    let accepted = onec_masking_service::domain::FeedPayload {
        selection_id: None,
        page_index: 0,
        metadata: vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Catalog.Products.CompositeAttribute".to_owned(),
            field_name: "CompositeAttribute".to_owned(),
            field_type: composite_type.clone(),
            password_mode: false,
        }],
        dictionary_values: Vec::new(),
        final_chunk: false,
    };
    let accepted_digest = digest_payload(&serde_json::to_value(&accepted).unwrap());
    assert_eq!(
        state
            .masking
            .upload_feed_chunk(
                job_id,
                0,
                onec_masking_service::domain::FeedChunkRequest {
                    schema_version: SCHEMA_VERSION,
                    correlation_id: Uuid::new_v4(),
                    chunk_digest: hex(&accepted_digest),
                    payload: accepted,
                },
            )
            .unwrap(),
        0
    );

    let oversized_type = "T".repeat(1024 * 1024);
    let rejected = onec_masking_service::domain::FeedPayload {
        selection_id: None,
        page_index: 1,
        metadata: vec![onec_masking_service::domain::FeedMetadataItem {
            source_path: "Catalog.Products.OversizedAttribute".to_owned(),
            field_name: "OversizedAttribute".to_owned(),
            field_type: oversized_type,
            password_mode: false,
        }],
        dictionary_values: Vec::new(),
        final_chunk: true,
    };
    let rejected_digest = digest_payload(&serde_json::to_value(&rejected).unwrap());
    let error = state
        .masking
        .upload_feed_chunk(
            job_id,
            1,
            onec_masking_service::domain::FeedChunkRequest {
                schema_version: SCHEMA_VERSION,
                correlation_id: Uuid::new_v4(),
                chunk_digest: hex(&rejected_digest),
                payload: rejected,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResultLimitExceeded);
}

#[tokio::test]
async fn all_dictionary_mode_expands_only_safe_catalog_string_fields() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    let job_id = insert_all_feed_job(&state, database_id);
    let cold_jobs = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap();
    let cold_job = cold_jobs.iter().find(|job| job.job_id == job_id).unwrap();
    assert!(cold_job.dictionary_selectors.is_empty());

    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                rules: vec![
                    source_mask_rule("Catalog.Organizations.Description"),
                    source_mask_rule("Catalog.Keys.ApiKey"),
                ],
                metadata_sources: vec![
                    feed_metadata(
                        "Catalog.Organizations.Description",
                        "Description",
                        "String",
                        false,
                    ),
                    feed_metadata("Catalog.Users.Password", "Password", "String", true),
                    feed_metadata("Catalog.Keys.ApiKey", "ApiKey", "String", false),
                    feed_metadata("Catalog.Organizations.Code", "Code", "Number", false),
                    feed_metadata("Document.Sales.Comment", "Comment", "String", false),
                ],
                ..PolicySnapshot::default()
            },
        )
        .await;
    let jobs = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap();
    let job = jobs.iter().find(|job| job.job_id == job_id).unwrap();
    assert_eq!(job.dictionary_selectors.len(), 1);
    let selector = &job.dictionary_selectors[0];
    assert_eq!(selector["source_path"], "Catalog.Organizations.Description");
    assert_eq!(selector["category"], "ORG");
    assert_ne!(selector["source_path"], "*");
}

#[tokio::test]
async fn all_dictionary_mode_fails_when_explicit_allowlist_exceeds_hard_cap() {
    let (state, database_id) = configured_state(DatabaseMode::Enabled).await;
    insert_all_feed_job(&state, database_id);
    let metadata_sources: Vec<_> = (0..101)
        .map(|index| {
            feed_metadata(
                &format!("Catalog.Items.Field{index}"),
                &format!("Field{index}"),
                "String",
                false,
            )
        })
        .collect();
    let rules = metadata_sources
        .iter()
        .map(|item| source_mask_rule(&item.source_path))
        .collect();
    state
        .masking
        .set_policy_snapshot(
            database_id,
            PolicySnapshot {
                rules,
                metadata_sources,
                ..PolicySnapshot::default()
            },
        )
        .await;
    let error = state
        .masking
        .pending_feed_jobs(10, Uuid::new_v4())
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResultLimitExceeded);
    let state_value: String = state
        .storage
        .with_connection(|connection| {
            connection.query_row(
                "SELECT state FROM feed_jobs WHERE database_id=?1",
                [database_id.to_string()],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(state_value, "failed");
}

fn insert_all_feed_job(state: &Arc<AppState>, database_id: Uuid) -> Uuid {
    let job_id = Uuid::new_v4();
    state.storage.with_connection(|connection| {
        let now = chrono::Utc::now().to_rfc3339();
        connection.execute(
            "INSERT INTO dictionary_configs(id,database_id,mode,source_paths_json,filter_ast_json,updated_at)
             VALUES (?1,?2,'all',?3,NULL,?4)",
            rusqlite::params![Uuid::new_v4().to_string(), database_id.to_string(),
                r#"[{"source_path":"*","category":"ORG","filter_ast":null}]"#, now],
        )?;
        connection.execute(
            "INSERT INTO feed_jobs(id,database_id,target_version,state,created_at,updated_at)
             VALUES (?1,?2,2,'pending',?3,?3)",
            rusqlite::params![job_id.to_string(), database_id.to_string(), now],
        )?;
        Ok(())
    }).unwrap();
    job_id
}

fn feed_metadata(
    source_path: &str,
    field_name: &str,
    field_type: &str,
    password_mode: bool,
) -> onec_masking_service::domain::FeedMetadataItem {
    onec_masking_service::domain::FeedMetadataItem {
        source_path: source_path.to_owned(),
        field_name: field_name.to_owned(),
        field_type: field_type.to_owned(),
        password_mode,
    }
}

fn source_mask_rule(source_path: &str) -> onec_masking_service::domain::PolicyRule {
    onec_masking_service::domain::PolicyRule {
        selector: onec_masking_service::domain::RuleSelector::SourcePath,
        pattern: source_path.to_owned(),
        action: onec_masking_service::domain::RuleAction::Mask,
        category: "DATA".to_owned(),
        priority: 0,
    }
}

fn digest_payload(value: &serde_json::Value) -> [u8; 32] {
    fn sort(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(object) => {
                let sorted: std::collections::BTreeMap<_, _> = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect();
                serde_json::to_value(sorted).unwrap()
            }
            serde_json::Value::Array(array) => {
                serde_json::Value::Array(array.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    Sha256::digest(serde_json::to_vec(&sort(value)).unwrap()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
