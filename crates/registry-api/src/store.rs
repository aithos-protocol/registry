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
    /// The timestamp of *this* write.
    pub created_at: String,
    /// The entry's original `createdAt`, when it already exists.
    ///
    /// A store that replaces the whole item on update — DynamoDB's `Put` does —
    /// has no other way to keep it, and an entry that reports its last update
    /// as its creation time has quietly lost the fact it was meant to record.
    pub existing_created_at: Option<String>,
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// One currently observed domain (`DOMAIN-CERTIFICATION.md` §4.2, §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    /// A-label, lowercase — stored exactly as certified.
    pub domain: String,
    /// First observation of the current continuous run.
    pub certified_at: String,
    /// Most recent successful observation.
    pub last_checked_at: String,
    /// Failed revalidation passes since the last success. At three the domain
    /// leaves `observed` (§7); any success resets it to zero.
    pub consecutive_failures: u8,
}

/// An agent's certification state (`DOMAIN-CERTIFICATION.md` §4).
///
/// `requested` is what a key signed, verbatim; `observed` is what the registry
/// can currently see, and is the only half ever published. They are stored
/// together and updated by two different writers — certification replaces the
/// whole state, revalidation touches `observed` alone — which is why the two
/// write methods below carry different conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificationState {
    /// The set from the last accepted certification. Sorted ascending, which
    /// is also the signed order (§5.2).
    pub requested: BTreeSet<String>,
    /// The subset currently observed in DNS, with its §4.2 timestamps.
    pub observed: Vec<DomainRecord>,
    /// The `issuedAt` of the last accepted certification, in the registry's
    /// canonical fixed-width millisecond form — see [`Store::put_certification`]
    /// for why the width is load-bearing. `None` when nothing was ever
    /// certified.
    pub issued_at: Option<String>,
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

    /// The agent's certification state; the empty state when none is stored.
    async fn get_certification(&self, agent_id: &str) -> StoreResult<CertificationState>;

    /// Commit an accepted certification — the whole state at once.
    ///
    /// `state.issued_at` MUST be `Some`, in the canonical fixed-width
    /// millisecond RFC 3339 form the handlers produce, and the commit MUST
    /// fail with [`StoreError::Conflict`] unless the stored `issued_at` is
    /// absent or **byte-wise smaller**. Byte order is the one comparison a
    /// conditional write can make remotely, so the contract makes byte order
    /// and instant order the same thing by fixing the width — the same move
    /// the listing index makes with its timestamps. The condition is on
    /// `issued_at` and never on `seq`: certifying and publishing are two
    /// writers that must not contend for one conditional write
    /// (`DOMAIN-CERTIFICATION.md` §4.3, and the overwrite trap the separate
    /// item exists to avoid).
    async fn put_certification(
        &self,
        agent_id: &str,
        state: &CertificationState,
    ) -> StoreResult<()>;

    /// Replace `observed` alone, leaving `requested` untouched — the
    /// revalidation pass's write (§7).
    ///
    /// Conditional on the stored `issued_at` still being `expected_issued_at`:
    /// a certification that lands between the pass's read and its write
    /// replaces the whole state, and observations computed against the old
    /// `requested` must then die with it rather than overwrite the new one.
    /// [`StoreError::Conflict`] means exactly that, and the pass simply moves
    /// on — the next one reads fresh state.
    async fn put_observations(
        &self,
        agent_id: &str,
        expected_issued_at: &str,
        observed: &[DomainRecord],
    ) -> StoreResult<()>;
}
