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
