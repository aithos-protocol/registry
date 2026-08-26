//! The storage contract.
//!
//! Two properties drive this interface. First, card bytes are immutable and
//! addressed by digest, so they are written once and never rewritten — a
//! `Store` is closer to a content-addressed blob store than to a database.
//! Second, the authorization decision in [`registry_core`] is made against a
//! snapshot of the agent's state, so committing it must be conditional on that
//! snapshot still being current. Without that condition, two concurrent writes
//! could both pass authorization and one would silently overwrite the other.

use std::collections::BTreeSet;

use async_trait::async_trait;
use thiserror::Error;

use registry_core::Status;

#[derive(Debug, Error)]
pub enum StoreError {
    /// The conditional write failed: the agent changed under us. The caller
    /// re-reads and re-evaluates, or reports a conflict.
    #[error("the agent was modified concurrently")]
    Conflict,
    /// A pagination cursor that this backend cannot use. Cursors come from
    /// clients, so a bad one is a client error — mapping it to a 500 would let
    /// anyone fill the error budget with forged input.
    #[error("the pagination cursor is not valid")]
    BadCursor,
    #[error("storage backend failure: {0}")]
    Backend(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The current state of an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub agent_id: String,
    pub status: Status,
    pub seq: u64,
    pub card_digest: String,
    pub card_version: String,
    pub authorized_kids: BTreeSet<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One immutable published version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRecord {
    pub seq: u64,
    pub card_digest: String,
    pub card_version: String,
    pub signing_kids: BTreeSet<String>,
    pub created_at: String,
}

/// Everything one accepted write commits, in a single unit.
#[derive(Debug, Clone)]
pub struct Commit {
    pub agent_id: String,
    /// The state the authorization decision was made against. `None` means the
    /// agent must not exist yet.
    pub expected_seq: Option<u64>,
    pub seq: u64,
    pub card_digest: String,
    pub card_version: String,
    /// Exact canonical bytes, stored verbatim and never re-serialized.
    pub card_bytes: Vec<u8>,
    /// The public JWKs now authorized, in submission order.
    pub keys: Vec<serde_json::Value>,
    pub authorized_kids: BTreeSet<String>,
    pub created_at: String,
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[async_trait]
pub trait Store: Send + Sync + 'static {
    async fn get_agent(&self, agent_id: &str) -> StoreResult<Option<AgentRecord>>;

    /// Commit an accepted write.
    ///
    /// Must fail with [`StoreError::Conflict`] unless the agent's current
    /// sequence still equals `commit.expected_seq`. This is the only place
    /// where concurrency is decided.
    async fn commit(&self, commit: &Commit) -> StoreResult<AgentRecord>;

    /// Mark an agent withdrawn, conditional on `expected_seq`.
    async fn withdraw(
        &self,
        agent_id: &str,
        expected_seq: u64,
        at: &str,
    ) -> StoreResult<AgentRecord>;

    /// Card bytes for one version, by digest.
    async fn get_card_bytes(&self, agent_id: &str, digest: &str) -> StoreResult<Option<Vec<u8>>>;

    /// The currently authorized public JWKs.
    async fn get_keys(&self, agent_id: &str) -> StoreResult<Option<Vec<serde_json::Value>>>;

    /// One page of an agent's version history, newest first.
    ///
    /// Paginated because a publisher may legitimately create thousands of
    /// versions, and a single unpaginated query would silently return only the
    /// first page worth of them.
    async fn list_versions(
        &self,
        agent_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<VersionRecord>>;

    /// The version an agent published under this digest, if any.
    ///
    /// Card objects are written before the transaction that commits them, so a
    /// failed commit leaves one behind. Serving bytes without checking this
    /// would mean answering for something the registry never published.
    async fn find_version(
        &self,
        agent_id: &str,
        digest: &str,
    ) -> StoreResult<Option<VersionRecord>>;

    async fn list_agents(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<AgentRecord>>;
}
