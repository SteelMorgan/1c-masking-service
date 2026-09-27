use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::ProcessingError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct MappingLimits {
    pub service_entries: usize,
    pub database_entries: usize,
    pub chat_entries: usize,
    pub candidates_per_call: usize,
}

impl Default for MappingLimits {
    fn default() -> Self {
        Self {
            service_entries: 100_000,
            database_entries: 20_000,
            chat_entries: 10_000,
            candidates_per_call: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MappingCandidate {
    pub token: String,
    pub original: String,
    pub database_id: Uuid,
    pub chat_id: String,
    pub category: String,
    pub batch_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    reverse_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct MappingEntry {
    original: String,
    database_id: Uuid,
    chat_id: String,
    category: String,
    batch_ids: HashSet<Uuid>,
    created_at: DateTime<Utc>,
    last_read_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    reverse_key: [u8; 32],
}

pub struct MappingStore {
    by_token: HashMap<String, MappingEntry>,
    by_reverse: HashMap<[u8; 32], String>,
    hmac_key: [u8; 32],
    limits: MappingLimits,
}

impl MappingStore {
    pub fn new(limits: MappingLimits) -> Self {
        let mut hmac_key = [0_u8; 32];
        OsRng.fill_bytes(&mut hmac_key);
        Self {
            by_token: HashMap::new(),
            by_reverse: HashMap::new(),
            hmac_key,
            limits,
        }
    }

    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_token(
        &self,
        candidates: &mut Vec<MappingCandidate>,
        database_id: Uuid,
        chat_id: &str,
        category: &str,
        original: &str,
        batch_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<String, ProcessingError> {
        let reverse_key = self.reverse_key(database_id, chat_id, category, original);
        if let Some(existing) = candidates
            .iter()
            .find(|entry| entry.reverse_key == reverse_key)
        {
            return Ok(existing.token.clone());
        }
        if let Some(token) = self.by_reverse.get(&reverse_key) {
            if self
                .by_token
                .get(token)
                .is_some_and(|entry| entry.expires_at > Utc::now())
            {
                let entry = self
                    .by_token
                    .get(token)
                    .expect("reverse index points to entry");
                candidates.push(MappingCandidate {
                    token: token.clone(),
                    original: original.to_owned(),
                    database_id,
                    chat_id: chat_id.to_owned(),
                    category: category.to_owned(),
                    batch_id,
                    created_at: entry.created_at,
                    expires_at: entry.expires_at,
                    reverse_key,
                });
                return Ok(token.clone());
            }
        }
        if candidates.len() >= self.limits.candidates_per_call {
            return Err(ProcessingError);
        }
        let mut random = [0_u8; 24];
        OsRng.fill_bytes(&mut random);
        let category = sanitize_category(category);
        let token = format!("[MASK:v1:{category}:{}]", URL_SAFE_NO_PAD.encode(random));
        let created_at = Utc::now();
        candidates.push(MappingCandidate {
            token: token.clone(),
            original: original.to_owned(),
            database_id,
            chat_id: chat_id.to_owned(),
            category,
            batch_id,
            created_at,
            expires_at: created_at + Duration::seconds(ttl_seconds.min(i64::MAX as u64) as i64),
            reverse_key,
        });
        Ok(token)
    }

    pub fn publish(&mut self, candidates: Vec<MappingCandidate>) -> Result<(), ProcessingError> {
        self.cleanup(2_000);
        self.can_publish(&candidates)?;
        for candidate in candidates {
            if let Some(token) = self.by_reverse.get(&candidate.reverse_key) {
                if let Some(entry) = self.by_token.get_mut(token) {
                    entry.batch_ids.insert(candidate.batch_id);
                }
                continue;
            }
            self.by_reverse
                .insert(candidate.reverse_key, candidate.token.clone());
            self.by_token.insert(
                candidate.token,
                MappingEntry {
                    original: candidate.original,
                    database_id: candidate.database_id,
                    chat_id: candidate.chat_id,
                    category: candidate.category,
                    batch_ids: HashSet::from([candidate.batch_id]),
                    created_at: candidate.created_at,
                    last_read_at: None,
                    expires_at: candidate.expires_at,
                    reverse_key: candidate.reverse_key,
                },
            );
        }
        Ok(())
    }

    pub fn can_publish(&self, candidates: &[MappingCandidate]) -> Result<(), ProcessingError> {
        let new_count = candidates
            .iter()
            .filter(|candidate| !self.by_reverse.contains_key(&candidate.reverse_key))
            .count();
        if self.by_token.len().saturating_add(new_count) > self.limits.service_entries {
            return Err(ProcessingError);
        }
        let mut additions_by_database: HashMap<Uuid, usize> = HashMap::new();
        let mut additions_by_chat: HashMap<(Uuid, &str), usize> = HashMap::new();
        for candidate in candidates
            .iter()
            .filter(|item| !self.by_reverse.contains_key(&item.reverse_key))
        {
            *additions_by_database
                .entry(candidate.database_id)
                .or_default() += 1;
            *additions_by_chat
                .entry((candidate.database_id, candidate.chat_id.as_str()))
                .or_default() += 1;
        }
        for (database_id, additions) in additions_by_database {
            let current = self
                .by_token
                .values()
                .filter(|entry| entry.database_id == database_id)
                .count();
            if current.saturating_add(additions) > self.limits.database_entries {
                return Err(ProcessingError);
            }
        }
        for ((database_id, chat_id), additions) in additions_by_chat {
            let current = self
                .by_token
                .values()
                .filter(|entry| entry.database_id == database_id && entry.chat_id == chat_id)
                .count();
            if current.saturating_add(additions) > self.limits.chat_entries {
                return Err(ProcessingError);
            }
        }
        Ok(())
    }

    pub fn resolve(&mut self, database_id: Uuid, chat_id: &str, token: &str) -> Option<String> {
        let now = Utc::now();
        let entry = self.by_token.get_mut(token)?;
        if !token.starts_with(&format!("[MASK:v1:{}:", entry.category)) {
            return None;
        }
        let same_database = bool::from(entry.database_id.as_bytes().ct_eq(database_id.as_bytes()));
        let same_chat = bool::from(entry.chat_id.as_bytes().ct_eq(chat_id.as_bytes()));
        if !same_database || !same_chat || entry.expires_at <= now {
            return None;
        }
        entry.last_read_at = Some(now);
        Some(entry.original.clone())
    }

    pub fn resolve_for_batch(
        &mut self,
        database_id: Uuid,
        chat_id: &str,
        batch_id: Uuid,
        token: &str,
    ) -> Option<String> {
        let now = Utc::now();
        let entry = self.by_token.get_mut(token)?;
        if !token.starts_with(&format!("[MASK:v1:{}:", entry.category)) {
            return None;
        }
        let same_database = bool::from(entry.database_id.as_bytes().ct_eq(database_id.as_bytes()));
        let same_chat = bool::from(entry.chat_id.as_bytes().ct_eq(chat_id.as_bytes()));
        if !same_database
            || !same_chat
            || !entry.batch_ids.contains(&batch_id)
            || entry.expires_at <= now
        {
            return None;
        }
        entry.last_read_at = Some(now);
        Some(entry.original.clone())
    }

    //++agent TASK-225 [27.09.2026 00:00:00] T: удаление базы из реестра —
    // её токены без записи мертвы и неразрешимы, висячими не держим.
    pub fn purge_database(&mut self, database_id: Uuid) {
        self.by_token
            .retain(|_, entry| entry.database_id != database_id);
        self.by_reverse
            .retain(|_, token| self.by_token.contains_key(token));
    }
    //++agent TASK-225

    pub fn cleanup(&mut self, limit: usize) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .by_token
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .take(limit)
            .map(|(token, _)| token.clone())
            .collect();
        for token in &expired {
            if let Some(entry) = self.by_token.remove(token) {
                self.by_reverse.remove(&entry.reverse_key);
            }
        }
        expired.len()
    }

    fn reverse_key(
        &self,
        database_id: Uuid,
        chat_id: &str,
        category: &str,
        original: &str,
    ) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts a 32 byte key");
        mac.update(database_id.as_bytes());
        mac.update(&[0]);
        mac.update(chat_id.as_bytes());
        mac.update(&[0]);
        mac.update(category.as_bytes());
        mac.update(&[0]);
        mac.update(original.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

fn sanitize_category(category: &str) -> String {
    let cleaned: String = category
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .flat_map(char::to_uppercase)
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "DATA".to_owned()
    } else {
        cleaned
    }
}
