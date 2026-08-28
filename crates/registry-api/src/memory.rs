//! An in-memory [`Store`], used by the test suite and by local development.
//!
//! It enforces the same conditional-write contract as the real backend, so a
//! concurrency bug in the handlers fails here rather than in production.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use registry_core::Status;

use crate::store::{AgentRecord, Commit, Page, Store, StoreError, StoreResult, VersionRecord};

#[derive(Default)]
struct Inner {
    agents: BTreeMap<String, AgentRecord>,
    versions: BTreeMap<String, Vec<VersionRecord>>,
    cards: BTreeMap<(String, String), Vec<u8>>,
    keys: BTreeMap<String, Vec<serde_json::Value>>,
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn get_agent(&self, agent_id: &str) -> StoreResult<Option<AgentRecord>> {
        Ok(self.inner.lock().unwrap().agents.get(agent_id).cloned())
    }

    async fn commit(&self, commit: &Commit) -> StoreResult<AgentRecord> {
        let mut inner = self.inner.lock().unwrap();
        let existing = inner.agents.get(&commit.agent_id);
        match (existing, commit.expected_seq) {
            (None, None) => {}
            (Some(a), Some(expected)) if a.seq == expected && a.status == Status::Active => {}
            _ => return Err(StoreError::Conflict),
        }

        let created_at = existing
            .map(|a| a.created_at.clone())
            .unwrap_or_else(|| commit.created_at.clone());

        let record = AgentRecord {
            agent_id: commit.agent_id.clone(),
            status: Status::Active,
            seq: commit.seq,
            card_digest: commit.card_digest.clone(),
            card_version: commit.card_version.clone(),
            authorized_kids: commit.authorized_kids.clone(),
            created_at,
            updated_at: commit.created_at.clone(),
        };

        // Card bytes go in first and are never rewritten: they are addressed by
        // their own digest, so a repeated write is the same object.
        inner.cards.insert(
            (commit.agent_id.clone(), commit.card_digest.clone()),
            commit.card_bytes.clone(),
        );
        inner
            .versions
            .entry(commit.agent_id.clone())
            .or_default()
            .push(VersionRecord {
                seq: commit.seq,
                card_digest: commit.card_digest.clone(),
                card_version: commit.card_version.clone(),
                signing_kids: commit.authorized_kids.clone(),
                created_at: commit.created_at.clone(),
            });
        inner
            .keys
            .insert(commit.agent_id.clone(), commit.keys.clone());
        inner.agents.insert(commit.agent_id.clone(), record.clone());
        Ok(record)
    }

    async fn withdraw(
        &self,
        agent_id: &str,
        expected_seq: u64,
        at: &str,
    ) -> StoreResult<AgentRecord> {
        let mut inner = self.inner.lock().unwrap();
        let Some(record) = inner.agents.get_mut(agent_id) else {
            return Err(StoreError::Conflict);
        };
        if record.seq != expected_seq || record.status != Status::Active {
            return Err(StoreError::Conflict);
        }
        record.status = Status::Withdrawn;
        record.updated_at = at.to_string();
        Ok(record.clone())
    }

    async fn get_card_bytes(&self, agent_id: &str, digest: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .cards
            .get(&(agent_id.to_string(), digest.to_string()))
            .cloned())
    }

    async fn get_keys(&self, agent_id: &str) -> StoreResult<Option<Vec<serde_json::Value>>> {
        Ok(self.inner.lock().unwrap().keys.get(agent_id).cloned())
    }

    async fn list_versions(
        &self,
        agent_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<VersionRecord>> {
        let inner = self.inner.lock().unwrap();
        let mut versions = inner.versions.get(agent_id).cloned().unwrap_or_default();
        versions.sort_by_key(|v| std::cmp::Reverse(v.seq));

        let start = match cursor {
            None => 0,
            Some(raw) => {
                let seq: u64 = raw.parse().map_err(|_| StoreError::BadCursor)?;
                // A cursor the backend does not recognise is a bad cursor, not
                // page one. Restarting silently is how a client paginating over
                // a register that is being written to loops forever.
                versions
                    .iter()
                    .position(|v| v.seq == seq)
                    .map(|i| i + 1)
                    .ok_or(StoreError::BadCursor)?
            }
        };
        let items: Vec<VersionRecord> = versions.iter().skip(start).take(limit).cloned().collect();
        // A cursor whenever the page filled, not only when more is known to
        // remain. That is what the deployed backend does — DynamoDB returns a
        // `LastEvaluatedKey` whenever the limit was reached, including on the
        // last item — and two backends behind one contract must not differ in a
        // way that only the untested one exhibits. §7.4 says how a client ends
        // a listing: on an empty page, not on a missing cursor.
        let next_cursor = (items.len() == limit)
            .then(|| items.last().map(|v| v.seq.to_string()))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    async fn find_version(
        &self,
        agent_id: &str,
        digest: &str,
    ) -> StoreResult<Option<VersionRecord>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .versions
            .get(agent_id)
            .and_then(|v| v.iter().find(|v| v.card_digest == digest))
            .cloned())
    }

    async fn list_agents(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<AgentRecord>> {
        let inner = self.inner.lock().unwrap();
        let mut all: Vec<AgentRecord> = inner.agents.values().cloned().collect();
        // Newest-updated first, with the identifier breaking ties so that the
        // order is total and a cursor cannot skip or repeat an entry.
        //
        // The tie-break descends, because the deployed backend sorts the
        // composite `{updatedAt}#{agentId}` in reverse and there is no way for
        // it to descend on one half and ascend on the other. §7.4 does not pin
        // the tie-break, but the two backends behind one contract must not
        // differ — and this is the store every HTTP test runs against, so a
        // disagreement here means the ordering that ships is the one nothing
        // exercises.
        all.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| b.agent_id.cmp(&a.agent_id))
        });
        let start = match cursor {
            None => 0,
            Some(c) => all
                .iter()
                .position(|a| a.agent_id == c)
                .map(|i| i + 1)
                .ok_or(StoreError::BadCursor)?,
        };
        let items: Vec<AgentRecord> = all.iter().skip(start).take(limit).cloned().collect();
        // Same rule as the version listing above, for the same reason.
        let next_cursor = (items.len() == limit)
            .then(|| items.last().map(|a| a.agent_id.clone()))
            .flatten();
        Ok(Page { items, next_cursor })
    }
}
