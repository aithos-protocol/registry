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
    AgentRecord, Commit, Page, Store, StoreError, StoreResult, VersionRecord,
};
use registry_core::Status;
use serde_json::json;

use crate::item::{self, Item};
use crate::keys;

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

    /// Refresh the objects CloudFront serves on the public read path.
    ///
    /// These are a cache, not the source of truth: the API answers from
    /// DynamoDB and the immutable version objects regardless. A failure here
    /// therefore leaves CloudFront serving the previous version until the next
    /// publication, which is why it is logged loudly rather than swallowed.
    async fn refresh_current_pointers(&self, commit: &Commit) {
        // Two publications close together can have their pointer writes
        // reordered, leaving the edge serving the older card until someone
        // publishes again — which may never happen. Re-reading the committed
        // sequence first does not close that window, but it narrows it to the
        // gap between this check and the write below. Closing it properly
        // means reconciling from the table itself, outside the request path.
        match self.get_agent(&commit.agent_id).await {
            Ok(Some(current)) if current.seq > commit.seq => {
                tracing::info!(
                    agent_id = %commit.agent_id,
                    superseded = commit.seq,
                    current = current.seq,
                    "skipping a pointer refresh that a later publication already overtook"
                );
                return;
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(
                %error,
                agent_id = %commit.agent_id,
                "could not confirm the committed sequence before refreshing pointers"
            ),
        }

        let jwks = json!({ "keys": commit.keys }).to_string();
        let attempts = [
            (
                keys::current_card_key(&commit.agent_id),
                commit.card_bytes.clone(),
                "application/a2a+json",
            ),
            (
                keys::current_jwks_key(&commit.agent_id),
                jwks.into_bytes(),
                "application/jwk-set+json",
            ),
        ];
        for (key, body, content_type) in attempts {
            if let Err(error) = self
                .put_object(&key, body, content_type, "public, max-age=60")
                .await
            {
                tracing::error!(
                    %key,
                    %error,
                    agent_id = %commit.agent_id,
                    seq = commit.seq,
                    "the current-version pointer was not refreshed; CloudFront will serve the \
                     previous version until the next publication"
                );
            }
        }
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
        // below fails it is left orphaned and harmless. The reverse order would
        // let a committed version point at bytes that were never stored.
        self.put_object(
            &keys::card_object_key(&commit.agent_id, &commit.card_digest),
            commit.card_bytes.clone(),
            "application/a2a+json",
            "public, max-age=31536000, immutable",
        )
        .await?;

        let record = AgentRecord {
            agent_id: commit.agent_id.clone(),
            status: Status::Active,
            seq: commit.seq,
            card_digest: commit.card_digest.clone(),
            card_version: commit.card_version.clone(),
            authorized_kids: commit.authorized_kids.clone(),
            created_at: commit.created_at.clone(),
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

        self.refresh_current_pointers(commit).await;

        // `createdAt` is only correct here for a creation; re-read so that an
        // update reports the original creation time rather than this write's.
        match self.get_agent(&commit.agent_id).await? {
            Some(stored) => Ok(stored),
            None => Ok(record),
        }
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

        // The status change alone would leave the entry published. The public
        // read path is served from the object store, which the API never sees,
        // and withdrawal is terminal — so no later publication would ever
        // overwrite these pointers. Without this, the one purpose of
        // withdrawal is defeated on the path that carries the traffic.
        //
        // Only the pointers go. The immutable objects under `versions/` are
        // the record of what was published and are never touched; the IAM
        // policy enforces that boundary rather than leaving it to this code.
        //
        // No cache invalidation is issued: the pointers carry a 60 second TTL,
        // which already bounds how long a withdrawn card can still be served,
        // and buying a few seconds is not worth another permission.
        for key in [
            keys::current_card_key(agent_id),
            keys::current_jwks_key(agent_id),
        ] {
            self.s3
                .delete_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
                .map_err(|error| {
                    StoreError::Backend(format!("withdrawn but {key} still published: {error}"))
                })?;
        }

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
            query = query.set_exclusive_start_key(Some(Item::from([
                ("pk".to_string(), Av::S(keys::agent_pk(agent_id))),
                ("sk".to_string(), Av::S(keys::version_sk(seq))),
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
