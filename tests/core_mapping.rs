use onec_masking_service::domain::{MappingLimits, MappingStore};
use uuid::Uuid;

#[test]
fn mapping_has_absolute_ttl_and_does_not_cross_scope() {
    let database_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut candidates = Vec::new();
    let token = store
        .plan_token(
            &mut candidates,
            database_id,
            "chat-a",
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            0,
        )
        .unwrap();
    store.publish(candidates).unwrap();
    assert_eq!(store.resolve(database_id, "chat-a", &token), None);
    assert_eq!(store.resolve(database_id, "chat-b", &token), None);
}

#[test]
fn same_value_reuses_token_only_within_namespace() {
    let database_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut first = Vec::new();
    let token = store
        .plan_token(
            &mut first,
            database_id,
            "chat-a",
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    store.publish(first).unwrap();
    let mut second = Vec::new();
    let reused = store
        .plan_token(
            &mut second,
            database_id,
            "chat-a",
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    let foreign = store
        .plan_token(
            &mut second,
            database_id,
            "chat-b",
            "FIO",
            "Иванов Иван",
            Uuid::new_v4(),
            3600,
        )
        .unwrap();
    assert_eq!(reused, token);
    assert_ne!(foreign, token);
}

//++agent TASK-225 [27.09.2026 00:00:00] W: защита в глубину — записи,
// сохранённые до фикса слоя-1, хранят оригинал с вложенным токеном;
// reveal разворачивает токены рекурсивно в пределах своей партии.
#[test]
fn resolve_for_batch_expands_nested_tokens_recursively() {
    let database_id = Uuid::new_v4();
    let batch_id = Uuid::new_v4();
    let mut store = MappingStore::new(MappingLimits::default());
    let mut first = Vec::new();
    let fio_token = store
        .plan_token(
            &mut first,
            database_id,
            "chat-a",
            "FIO",
            "Иванов Иван Иванович",
            batch_id,
            3600,
        )
        .unwrap();
    store.publish(first).unwrap();
    // «Наследие»: ACCOUNT-запись хранит промежуточную форму с FIO-токеном.
    let mut second = Vec::new();
    let account_token = store
        .plan_token(
            &mut second,
            database_id,
            "chat-a",
            "ACCOUNT",
            &format!("{fio_token} / DEMOSPOT1"),
            batch_id,
            3600,
        )
        .unwrap();
    store.publish(second).unwrap();

    let engine = onec_masking_service::domain::MaskEngine::default();
    let resolved = engine
        .resolve_tokens_for_batch(
            &serde_json::json!({"Наименование": account_token}),
            database_id,
            "chat-a",
            batch_id,
            &mut store,
        )
        .unwrap();
    let rendered = serde_json::to_string(&resolved).unwrap();
    assert!(
        rendered.contains("Иванов Иван Иванович / DEMOSPOT1"),
        "{rendered}"
    );
    assert!(!rendered.contains("[MASK:"), "{rendered}");
}
//++agent TASK-225
