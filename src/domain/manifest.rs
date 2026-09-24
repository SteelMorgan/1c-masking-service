//++agent TASK-222 [05.10.2026]
//! In-memory манифест metadata, полученный pull-моделью через manager.
//!
//! Перенесён из `feed_v2` без lease-зависимостей: RAM-store, содержимое
//! manifest переживает только process lifetime — restart требует refetch
//! через тот же trusted feed, durable id не доказывает наличие или полноту
//! RAM manifest.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::models::FeedMetadataItem;

/// `digest` — service-local integrity (Rust sha256 над serde bytes), а
/// `declared_digest` — опциональный producer evidence (`manifest_digest`
/// страниц): BSL его не отдаёт (решение Р1(а)), межстраничной сверки нет;
/// как Rust-recomputed proof не трактуется никогда.
pub(crate) struct MetadataManifestEntry {
    pub generation: Uuid,
    #[allow(dead_code)] // содержимое manifest — trusted state для All-expansion/diagnostics
    pub items: Vec<FeedMetadataItem>,
    #[allow(dead_code)] // читается Admin status/digest-proof
    pub digest: String,
    #[allow(dead_code)] // читается Admin status/audit trail
    pub declared_digest: String,
    pub bytes: usize,
    #[allow(dead_code)] // читается Admin status/diagnostics
    pub completed_at: DateTime<Utc>,
}

// Transport bound совпадает с producer-стороной BSL (100_000 items /
// 8 МиБ): RAM-store bound выше не поднимаем.
pub(crate) const MAX_MANIFEST_ITEMS: usize = 100_000;
pub(crate) const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestError {
    LimitExceeded,
    InvalidContext,
}

#[derive(Default)]
pub(crate) struct MetadataManifestStore {
    entries: HashMap<Uuid, MetadataManifestEntry>,
    bytes: usize,
}

impl MetadataManifestStore {
    #[allow(dead_code)] // потребитель — Admin status/diagnostics
    pub fn get(&self, database_id: Uuid) -> Option<&MetadataManifestEntry> {
        self.entries.get(&database_id)
    }

    pub fn generation(&self, database_id: Uuid) -> Option<Uuid> {
        self.entries.get(&database_id).map(|entry| entry.generation)
    }

    /// Latest-per-DB supersede: новая generation заменяет предыдущий manifest.
    /// Fail-closed bounds без silent eviction — per-entry и aggregate лимиты.
    /// `declared_digest` — опциональный producer digest из metadata страниц
    /// (BSL не отдаёт; пустая строка — отсутствие evidence), как
    /// Rust-recomputed proof не трактуется.
    /// Вызывается только после успешного durable commit pull-generation —
    /// rollback-пути нет: при неуспешном pull manifest вообще не трогается.
    pub fn insert(
        &mut self,
        database_id: Uuid,
        generation: Uuid,
        items: Vec<FeedMetadataItem>,
        declared_digest: String,
    ) -> Result<Option<MetadataManifestEntry>, ManifestError> {
        if generation.is_nil() || items.is_empty() || items.len() > MAX_MANIFEST_ITEMS {
            return Err(ManifestError::LimitExceeded);
        }
        let serialized = serde_json::to_vec(&items).map_err(|_| ManifestError::InvalidContext)?;
        let replaced = self
            .entries
            .get(&database_id)
            .map_or(0, |entry| entry.bytes);
        if serialized.len() > MAX_MANIFEST_BYTES
            || self.bytes - replaced + serialized.len() > MAX_MANIFEST_BYTES
        {
            return Err(ManifestError::LimitExceeded);
        }
        let entry = MetadataManifestEntry {
            generation,
            digest: digest(&serialized),
            declared_digest,
            bytes: serialized.len(),
            items,
            completed_at: Utc::now(),
        };
        self.bytes = self.bytes - replaced + entry.bytes;
        Ok(self.entries.insert(database_id, entry))
    }

    /// Purge-примитив для cleanup tick / supersede вне insert: вызывающий
    /// решает, какие БД сохранить; bytes aggregate корректируется сам.
    pub fn retain(&mut self, mut keep: impl FnMut(Uuid, &MetadataManifestEntry) -> bool) {
        let mut removed = 0usize;
        self.entries.retain(|database_id, entry| {
            let keep_entry = keep(*database_id, entry);
            if !keep_entry {
                removed += entry.bytes;
            }
            keep_entry
        });
        self.bytes -= removed;
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
//++agent TASK-222
