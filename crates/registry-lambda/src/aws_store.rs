//! A [`Store`] over DynamoDB and S3.
//!
//! The split follows the shape of the data. Card bytes are immutable and named
//! by their own digest, so they live in S3 as plain objects. Agent state is
//! mutable and its every transition is conditional, so it lives in DynamoDB,
//! where a conditional write expresses that condition directly.

use std::collections::BTreeSet;

use async_trait::async_trait;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::{AttributeValue as Av, Put, TransactWriteItem};
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use registry_api::store::{
    AgentRecord, CertificationState, Commit, DomainRecord, Page, Store, StoreError, StoreResult,
    VersionRecord,
};
use registry_core::Status;
use serde_json::json;

use crate::item::{self, Item};
use crate::keys;
use crate::reconciler::{CommittedState, SweepState};

pub struct AwsStore {
    ddb: aws_sdk_dynamodb::Client,
    s3: aws_sdk_s3::Client,
    table: String,
    bucket: String,
}

impl AwsStore {
    pub fn new(
        ddb: aws_sdk_dynamodb::Client,
        s3: aws_sdk_s3::Client,
        table: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        Self {
            ddb,
            s3,
            table: table.into(),
            bucket: bucket.into(),
        }
    }

    async fn get_agent_item(&self, agent_id: &str) -> StoreResult<Option<Item>> {
        let out = self
            .ddb
            .get_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::CURRENT_SK.into()))
            // The write path reads state and then commits conditionally on it,
            // so an eventually consistent read here would only widen the window
            // the condition already closes — but it would also make a fresh
            // publication invisible to its own follow-up request.
            .consistent_read(true)
            .send()
            .await
            .map_err(backend)?;
        Ok(out.item)
    }

    async fn put_object(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
        cache_control: &str,
    ) -> StoreResult<()> {
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type(content_type)
            .cache_control(cache_control)
            .send()
            .await
            .map_err(backend)?;
        Ok(())
    }
}

#[async_trait]
impl Store for AwsStore {
    async fn get_agent(&self, agent_id: &str) -> StoreResult<Option<AgentRecord>> {
        match self.get_agent_item(agent_id).await? {
            None => Ok(None),
            Some(item) => Ok(Some(item::agent_record(&item).map_err(backend)?)),
        }
    }

    async fn commit(&self, commit: &Commit) -> StoreResult<AgentRecord> {
        // The card object goes in first. It is addressed by its own digest, so
        // writing it twice is writing the same object, and if the transaction
        // below fails it is left orphaned — harmless, and unreachable, since a
        // historical read requires the version record too.
        //
        // The current-version pointers are not written here. They are owned by
        // the stream reconciler, which sees an agent's transitions in commit
        // order; writing them from two places would reintroduce exactly the
        // reordering this split exists to prevent.
        self.put_object(
            &keys::card_object_key(&commit.agent_id, &commit.card_digest),
            commit.card_bytes.clone(),
            "application/a2a+json",
            "public, max-age=31536000, immutable",
        )
        .await?;

        // `Put` inside a transaction replaces the whole item, so whatever
        // `createdAt` goes in here is what the entry will have from now on.
        // `commit.created_at` is *this* write's timestamp — correct for a
        // creation and wrong for every update, which is how an entry's real
        // creation time was being overwritten each time it was republished.
        // The caller already read the current record to authorize this write,
        // and passes its `createdAt` back for exactly this reason.
        let created_at = commit
            .existing_created_at
            .clone()
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
        let version = VersionRecord {
            seq: commit.seq,
            card_digest: commit.card_digest.clone(),
            card_version: commit.card_version.clone(),
            signing_kids: commit.authorized_kids.clone(),
            created_at: commit.created_at.clone(),
        };

        let keys_json = serde_json::to_string(&commit.keys).map_err(backend)?;
        let mut agent_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item::agent_item(&record, &keys_json)));

        agent_put = match commit.expected_seq {
            // Creation: the identifier must be unclaimed.
            None => agent_put.condition_expression("attribute_not_exists(pk)"),
            // Update: the state the authorization decision was made against
            // must still be the current one.
            Some(expected) => agent_put
                .condition_expression("#seq = :expected AND #status = :active")
                .expression_attribute_names("#seq", "seq")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":expected", Av::N(expected.to_string()))
                .expression_attribute_values(":active", Av::S("ACTIVE".into())),
        };

        let version_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item::version_item(&commit.agent_id, &version)))
            .condition_expression("attribute_not_exists(sk)");

        // Written in the same transaction as the version itself, so the index
        // can never disagree with what it indexes.
        let digest_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item::digest_item(&commit.agent_id, &version)));

        self.ddb
            .transact_write_items()
            // Without this, a transaction whose response was lost is retried by
            // the SDK, the retry trips `attribute_not_exists(sk)` on the version
            // item, and a write that in fact succeeded is reported as a 409 —
            // exactly the case §6.1 says must not be answered with a conflict.
            // The token is derived from what the write *is*, so a genuine retry
            // of the same write reuses it and a different write cannot.
            .client_request_token(request_token(commit))
            .transact_items(
                TransactWriteItem::builder()
                    .put(agent_put.build().map_err(backend)?)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(version_put.build().map_err(backend)?)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(digest_put.build().map_err(backend)?)
                    .build(),
            )
            .send()
            .await
            .map_err(transaction_error)?;

        Ok(record)
    }

    async fn withdraw(
        &self,
        agent_id: &str,
        expected_seq: u64,
        at: &str,
    ) -> StoreResult<AgentRecord> {
        let out = self
            .ddb
            .update_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::CURRENT_SK.into()))
            .update_expression("SET #status = :withdrawn, updatedAt = :at, gsi1sk = :gsi1sk")
            .condition_expression("#seq = :expected AND #status = :active")
            .expression_attribute_names("#seq", "seq")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":withdrawn", Av::S("WITHDRAWN".into()))
            .expression_attribute_values(":active", Av::S("ACTIVE".into()))
            .expression_attribute_values(":expected", Av::N(expected_seq.to_string()))
            .expression_attribute_values(":at", Av::S(at.to_string()))
            .expression_attribute_values(":gsi1sk", Av::S(keys::list_sk(at, agent_id)))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await
            .map_err(conditional_error)?;

        let item = out
            .attributes
            .ok_or_else(|| StoreError::Backend("update returned no attributes".into()))?;

        // The pointers are not removed here either. The status change above
        // reaches the reconciler through the stream, and it purges them by the
        // same path a publication takes.

        item::agent_record(&item).map_err(backend)
    }

    async fn get_card_bytes(&self, agent_id: &str, digest: &str) -> StoreResult<Option<Vec<u8>>> {
        let key = keys::card_object_key(agent_id, digest);
        match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(out) => {
                let data = out.body.collect().await.map_err(backend)?;
                Ok(Some(data.into_bytes().to_vec()))
            }
            Err(e) if s3_missing(&e) => Ok(None),
            Err(e) => Err(backend(e)),
        }
    }

    async fn get_keys(&self, agent_id: &str) -> StoreResult<Option<Vec<serde_json::Value>>> {
        match self.get_agent_item(agent_id).await? {
            None => Ok(None),
            Some(item) => Ok(Some(item::agent_keys(&item).map_err(backend)?)),
        }
    }

    async fn list_versions(
        &self,
        agent_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<VersionRecord>> {
        let mut query = self
            .ddb
            .query()
            .table_name(&self.table)
            .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
            .expression_attribute_values(":pk", Av::S(keys::agent_pk(agent_id)))
            .expression_attribute_values(":prefix", Av::S("VERSION#".into()))
            .scan_index_forward(false)
            .limit(limit as i32);

        if let Some(cursor) = cursor {
            let seq: u64 = cursor.parse().map_err(|_| StoreError::BadCursor)?;
            let sk = keys::version_sk(seq);
            // A cursor naming a version that does not exist is not one this
            // registry issued. DynamoDB accepts any key inside the partition as
            // a starting point, so without this a forged number silently
            // returned a page from an arbitrary position — and `CURSOR_INVALID`
            // was unreachable here while the in-memory store raised it for the
            // same input. Two backends behind one contract have to agree.
            let exists = self
                .ddb
                .get_item()
                .table_name(&self.table)
                .key("pk", Av::S(keys::agent_pk(agent_id)))
                .key("sk", Av::S(sk.clone()))
                .projection_expression("sk")
                // Consistent, like every other read that decides something.
                // Without it a cursor the registry issued for a version
                // committed moments earlier can come back `CURSOR_INVALID` —
                // the store reporting a client error for input it produced
                // itself.
                .consistent_read(true)
                .send()
                .await
                .map_err(backend)?
                .item
                .is_some();
            if !exists {
                return Err(StoreError::BadCursor);
            }

            query = query.set_exclusive_start_key(Some(Item::from([
                ("pk".to_string(), Av::S(keys::agent_pk(agent_id))),
                ("sk".to_string(), Av::S(sk)),
            ])));
        }

        let out = query.send().await.map_err(backend)?;
        let items: Vec<VersionRecord> = out
            .items
            .unwrap_or_default()
            .iter()
            .map(|i| item::version_record(i).map_err(backend))
            .collect::<StoreResult<_>>()?;

        // The cursor is the sequence itself: an agent's versions are keyed by
        // it, so nothing else is needed to resume, and a forged one cannot
        // address anything outside this agent's partition.
        let next_cursor = out
            .last_evaluated_key
            .as_ref()
            .and_then(|_| items.last().map(|v| v.seq.to_string()));
        Ok(Page { items, next_cursor })
    }

    async fn find_version(
        &self,
        agent_id: &str,
        digest: &str,
    ) -> StoreResult<Option<VersionRecord>> {
        let out = self
            .ddb
            .get_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::digest_sk(digest)))
            // Consistent, like the record read. `get_version_card` gates the
            // bytes on this item, so an eventually-consistent read meant a
            // `GET .../versions/{digest}/agent-card.json` immediately after the
            // `201` that created it could answer 404 — for a version the same
            // response had just named. The path is cached `immutable` at the
            // edge, so a client that hit that 404 would keep it.
            .consistent_read(true)
            .send()
            .await
            .map_err(backend)?;

        out.item
            .map(|i| item::version_record(&i).map_err(backend))
            .transpose()
    }

    async fn list_agents(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<Page<AgentRecord>> {
        let mut query = self
            .ddb
            .query()
            .table_name(&self.table)
            .index_name("gsi1")
            .key_condition_expression("gsi1pk = :pk")
            .expression_attribute_values(":pk", Av::S(keys::LIST_PK.into()))
            .scan_index_forward(false)
            .limit(limit as i32);

        if let Some(cursor) = cursor {
            query = query.set_exclusive_start_key(Some(decode_cursor(cursor)?));
        }

        let out = query.send().await.map_err(backend)?;
        let items: Vec<AgentRecord> = out
            .items
            .unwrap_or_default()
            .iter()
            .map(|i| item::agent_record(i).map_err(backend))
            .collect::<StoreResult<_>>()?;

        let next_cursor = out.last_evaluated_key.as_ref().map(encode_cursor);
        Ok(Page { items, next_cursor })
    }

    async fn get_certification(&self, agent_id: &str) -> StoreResult<CertificationState> {
        let out = self
            .ddb
            .get_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::CERT_SK.into()))
            // Consistent, like every read the write path decides on: the
            // replay comparison of §5.3(4) is made against this.
            .consistent_read(true)
            .send()
            .await
            .map_err(backend)?;
        match out.item {
            None => Ok(CertificationState::default()),
            Some(item) => item::certification_state(&item).map_err(backend),
        }
    }

    async fn put_certification(
        &self,
        agent_id: &str,
        state: &CertificationState,
    ) -> StoreResult<()> {
        let issued_at = state
            .issued_at
            .as_deref()
            .ok_or_else(|| StoreError::Backend("a certification carries an issuedAt".into()))?;

        // `UpdateItem` creates the item when it is absent, and the condition
        // is the store contract's: absent, or byte-wise older than this
        // certification. Byte order is instant order because the handlers
        // write the fixed-width canonical form — the same bargain the listing
        // index strikes. The condition never mentions `seq`: publishing owns
        // the `CURRENT` item, certification owns this one, and the two must
        // never contend for a conditional write.
        self.ddb
            .update_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::CERT_SK.into()))
            .update_expression(
                "SET requestedDomains = :r, observed = :o, certificationIssuedAt = :t",
            )
            .condition_expression(
                "attribute_not_exists(certificationIssuedAt) OR certificationIssuedAt < :t",
            )
            .expression_attribute_values(":r", Av::S(item::requested_json(&state.requested)))
            .expression_attribute_values(":o", Av::S(item::observed_json(&state.observed)))
            .expression_attribute_values(":t", Av::S(issued_at.to_string()))
            .send()
            .await
            .map_err(conditional_error)?;
        Ok(())
    }

    async fn put_observations(
        &self,
        agent_id: &str,
        expected_issued_at: &str,
        observed: &[DomainRecord],
    ) -> StoreResult<()> {
        // Conditional on the certification being the one the revalidation
        // pass read: a fresh certification replaces the whole state, and
        // observations computed against the old `requested` must die with it
        // rather than overwrite the new one. `attribute_exists` is implied by
        // the equality — an absent item fails the condition too.
        self.ddb
            .update_item()
            .table_name(&self.table)
            .key("pk", Av::S(keys::agent_pk(agent_id)))
            .key("sk", Av::S(keys::CERT_SK.into()))
            .update_expression("SET observed = :o")
            .condition_expression("certificationIssuedAt = :expected")
            .expression_attribute_values(":o", Av::S(item::observed_json(observed)))
            .expression_attribute_values(":expected", Av::S(expected_issued_at.to_string()))
            .send()
            .await
            .map_err(conditional_error)?;
        Ok(())
    }
}

impl AwsStore {
    /// Every agent's identifier, for the reconciliation sweep.
    ///
    /// Identifiers only. The state each one is in is read separately, and
    /// consistently, at the moment it is acted on — a listing is an
    /// eventually-consistent index read that can be minutes stale by the time
    /// the far end of it comes up, and acting on stale state would let the
    /// sweep rewrite a pointer the stream had already moved forward.
    ///
    /// Deliberately not part of the `Store` trait: nothing on the request path
    /// may enumerate the whole register, and a method that exists only here is
    /// a method a handler cannot reach by accident.
    pub async fn sweep_agent_ids(&self) -> StoreResult<Vec<String>> {
        let mut ids = Vec::new();
        let mut start: Option<Item> = None;

        loop {
            let mut query = self
                .ddb
                .query()
                .table_name(&self.table)
                .index_name("gsi1")
                .key_condition_expression("gsi1pk = :pk")
                .expression_attribute_values(":pk", Av::S(keys::LIST_PK.into()))
                .projection_expression("agentId")
                // Newest first. The agents most likely to have drifted are the
                // ones that changed most recently — a dropped stream record is
                // a record about a recent change — and they are also the ones a
                // sweep that runs out of time would otherwise reach last.
                .scan_index_forward(false)
                .limit(500);
            if let Some(key) = start {
                query = query.set_exclusive_start_key(Some(key));
            }

            let out = query.send().await.map_err(backend)?;
            for raw in out.items.unwrap_or_default() {
                // Dropping an unreadable row silently would let the sweep cover
                // nothing and report convergence: `agents = 0, "read path
                // matches the register"`, with `sweeper-errors` seeing no fault,
                // `sweeper-stopped` seeing an invocation and `sweep-repairs`
                // seeing the healthy value. This is the one component whose job
                // is to notice silence; its own silence must not look like
                // success.
                let id = raw
                    .get("agentId")
                    .and_then(|v| v.as_s().ok())
                    .ok_or_else(|| {
                        StoreError::Backend(
                            "a row in the listing index has no readable agentId".to_string(),
                        )
                    })?;
                ids.push(id.clone());
            }

            match out.last_evaluated_key {
                Some(key) => start = Some(key),
                None => break,
            }
        }
        Ok(ids)
    }
}

impl CommittedState for AwsStore {
    async fn state_of(&self, agent_id: &str) -> Result<SweepState, String> {
        let raw = self
            .get_agent_item(agent_id)
            .await
            .map_err(|e| format!("reading the record for {agent_id}: {e}"))?
            .ok_or_else(|| {
                // Agent items are never deleted, so an identifier that was
                // listed and is now absent means something outside this system
                // touched the table. Failing is right: repairing the read path
                // from a record that does not exist is guesswork.
                format!("agent {agent_id} was listed but has no record")
            })?;

        let record = item::agent_record(&raw).map_err(|e| e.to_string())?;
        match record.status {
            Status::Withdrawn => Ok(SweepState::Withdrawn),
            Status::Active => {
                // The stored key set is what the reconciler publishes. If it
                // cannot be read, the pointer must not be rewritten from a
                // guess — the same rule the stream path applies.
                let raw_keys = raw
                    .get("keys")
                    .and_then(|v| v.as_s().ok())
                    .ok_or_else(|| format!("agent {agent_id} has no readable key set"))?;
                let keys: serde_json::Value =
                    serde_json::from_str(raw_keys).map_err(|e| e.to_string())?;
                Ok(SweepState::Active {
                    seq: record.seq,
                    card_digest: record.card_digest,
                    keys,
                })
            }
        }
    }
}

/// A DynamoDB idempotency token for one commit.
///
/// At most 36 characters, identical across retries of the same request and
/// different for any other. Derived from everything that varies between two
/// commits, `createdAt` included: DynamoDB refuses a token replayed with
/// different parameters, and the timestamp is one of the item's attributes. An
/// SDK-level retry resends identical bytes, so it reuses both — which is the
/// case this exists for. Without it, a transaction whose response was lost is
/// retried, the retry trips `attribute_not_exists(sk)` on the version item, and
/// a write that in fact succeeded is reported as a 409 — exactly the case §6.1
/// says must not be answered with a conflict.
fn request_token(commit: &Commit) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in [
        commit.agent_id.as_bytes(),
        &commit.seq.to_be_bytes(),
        commit.card_digest.as_bytes(),
        commit.created_at.as_bytes(),
    ] {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    // 32 hex characters, inside DynamoDB's 36-character ceiling.
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

// --- cursors -------------------------------------------------------------

/// Cursors are opaque to clients and carry only the four key attributes of the
/// index, so they can never be used to read something the query would not.
fn encode_cursor(key: &Item) -> String {
    let map: serde_json::Map<String, serde_json::Value> = key
        .iter()
        .filter_map(|(k, v)| v.as_s().ok().map(|s| (k.clone(), json!(s))))
        .collect();
    base64url(serde_json::Value::Object(map).to_string().as_bytes())
}

fn decode_cursor(cursor: &str) -> StoreResult<Item> {
    let raw = base64url_decode(cursor).ok_or(StoreError::BadCursor)?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| StoreError::BadCursor)?;
    let obj = value.as_object().ok_or(StoreError::BadCursor)?;
    let allowed: BTreeSet<&str> = ["pk", "sk", "gsi1pk", "gsi1sk"].into_iter().collect();
    let key: Item = obj
        .iter()
        .filter(|(k, _)| allowed.contains(k.as_str()))
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), Av::S(s.to_string()))))
        .collect();
    // A cursor missing a key attribute would reach DynamoDB and come back as a
    // validation error, which this code would then report as a server fault.
    if key.len() != allowed.len() {
        return Err(StoreError::BadCursor);
    }
    // Present is not the same as plausible. `gsi1pk` is a constant for this
    // index, so a cursor naming anything else is one DynamoDB will reject —
    // and a rejection surfacing as a 500 lets anyone fill the error budget with
    // forged input, which is the one thing `BadCursor` exists to prevent.
    if key
        .get("gsi1pk")
        .and_then(|v| v.as_s().ok())
        .map(String::as_str)
        != Some(crate::keys::LIST_PK)
    {
        return Err(StoreError::BadCursor);
    }
    Ok(key)
}

fn base64url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s).ok()
}

// --- error mapping -------------------------------------------------------

fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// A failed condition on a single-item write means the state moved under us
/// between the authorization decision and the commit.
fn conditional_error(e: SdkError<UpdateItemError>) -> StoreError {
    let err = e.into_service_error();
    if err.is_conditional_check_failed_exception() {
        StoreError::Conflict
    } else {
        StoreError::Backend(err.to_string())
    }
}

/// A cancelled transaction means the same thing, but DynamoDB reports the
/// reason per item rather than as the error type — so this has to look inside
/// rather than match on the exception alone. A transaction can also be
/// cancelled for capacity or conflict reasons that are worth retrying, and
/// those must not be reported as an authorization conflict.
fn transaction_error(e: SdkError<TransactWriteItemsError>) -> StoreError {
    let err = e.into_service_error();
    if let TransactWriteItemsError::TransactionCanceledException(cancelled) = &err
        && cancelled
            .cancellation_reasons()
            .iter()
            .any(|reason| reason.code() == Some("ConditionalCheckFailed"))
    {
        return StoreError::Conflict;
    }
    StoreError::Backend(err.to_string())
}

fn s3_missing(e: &SdkError<GetObjectError>) -> bool {
    matches!(e, SdkError::ServiceError(inner) if inner.err().is_no_such_key())
}
