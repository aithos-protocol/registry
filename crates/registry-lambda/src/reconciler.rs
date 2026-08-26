//! Reconciles the public read-path pointers from the table itself.
//!
//! The pointers under `v1/agents/…` are what the edge serves. Writing them from
//! the request path, right after the commit, has a flaw that no amount of care
//! inside that path can fix: two publications close together can have their
//! pointer writes reordered, leaving the edge on the older card until someone
//! publishes again — which may never happen.
//!
//! A DynamoDB stream orders records **per partition key**, and every item
//! belonging to one agent shares one. So consuming the stream gives the
//! pointers a single writer that sees an agent's transitions in the order they
//! were committed. The request path no longer touches them at all: one writer
//! with guaranteed order beats two racing ones, and the cost is the fraction of
//! a second the stream takes to arrive — invisible next to the pointers' own
//! sixty-second cache lifetime.
//!
//! Being driven by the committed state rather than by the request also means a
//! withdrawal purges the pointers through exactly the same path as a
//! publication, instead of needing its own.

use aws_sdk_s3::primitives::ByteStream;
use serde_json::{Value, json};

use crate::keys;

pub struct Reconciler {
    s3: aws_sdk_s3::Client,
    bucket: String,
}

/// What one stream record asks for.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Publish the card at this digest, with these keys.
    Publish {
        agent_id: String,
        card_digest: String,
        keys: Value,
    },
    /// Remove the pointers: the entry is withdrawn.
    Withdraw { agent_id: String },
    /// Not about an agent's current state.
    Ignore,
}

impl Reconciler {
    pub fn new(s3: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            s3,
            bucket: bucket.into(),
        }
    }

    /// Handle one stream event.
    ///
    /// Errors propagate so that Lambda retries the batch: pointers that are
    /// silently left stale are the failure this whole component exists to
    /// prevent, so failing loudly is the point.
    pub async fn handle(&self, event: &Value) -> Result<usize, String> {
        let records = event
            .get("Records")
            .and_then(Value::as_array)
            .ok_or_else(|| "the stream event carries no Records array".to_string())?;

        let mut applied = 0;
        for record in records {
            match action_for(record) {
                Action::Ignore => {}
                Action::Publish {
                    agent_id,
                    card_digest,
                    keys,
                } => {
                    self.publish(&agent_id, &card_digest, &keys).await?;
                    applied += 1;
                }
                Action::Withdraw { agent_id } => {
                    self.withdraw(&agent_id).await?;
                    applied += 1;
                }
            }
        }
        Ok(applied)
    }

    async fn publish(&self, agent_id: &str, digest: &str, keys: &Value) -> Result<(), String> {
        // The card is copied from its immutable object rather than carried in
        // the stream record: the record holds the digest, and the bytes it
        // names are already stored under it. Copying server-side keeps the
        // bytes exact — they are never re-serialized on the way through.
        let source = format!(
            "{}/{}",
            self.bucket,
            keys::card_object_key(agent_id, digest)
        );
        self.s3
            .copy_object()
            .bucket(&self.bucket)
            .key(keys::current_card_key(agent_id))
            .copy_source(&source)
            .content_type("application/a2a+json")
            .cache_control("public, max-age=60")
            .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
            .send()
            .await
            .map_err(|e| format!("copying {source} to the current-card pointer: {e}"))?;

        let jwks = json!({ "keys": keys }).to_string();
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(keys::current_jwks_key(agent_id))
            .body(ByteStream::from(jwks.into_bytes()))
            .content_type("application/jwk-set+json")
            .cache_control("public, max-age=60")
            .send()
            .await
            .map_err(|e| format!("writing the jwks pointer for {agent_id}: {e}"))?;

        Ok(())
    }

    async fn withdraw(&self, agent_id: &str) -> Result<(), String> {
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
                .map_err(|e| format!("removing {key}: {e}"))?;
        }
        Ok(())
    }
}

/// Decide what one stream record asks for.
///
/// Pure, so the whole decision is testable without AWS — which matters, since
/// this runs where nobody is watching.
fn action_for(record: &Value) -> Action {
    let image = &record["dynamodb"]["NewImage"];

    // Only the current-state item drives the pointers. Version and digest
    // items are immutable history and say nothing about what is current.
    if record["dynamodb"]["Keys"]["sk"]["S"].as_str() != Some(keys::CURRENT_SK) {
        return Action::Ignore;
    }

    let Some(agent_id) = image["agentId"]["S"].as_str() else {
        // A REMOVE event has no new image. Agent items are never deleted, so
        // reaching here means something outside this system touched the table.
        return Action::Ignore;
    };

    if image["status"]["S"].as_str() == Some("WITHDRAWN") {
        return Action::Withdraw {
            agent_id: agent_id.to_string(),
        };
    }

    let Some(card_digest) = image["cardDigest"]["S"].as_str() else {
        return Action::Ignore;
    };
    let keys = image["keys"]["S"]
        .as_str()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or_else(|| json!([]));

    Action::Publish {
        agent_id: agent_id.to_string(),
        card_digest: card_digest.to_string(),
        keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sk: &str, image: Value) -> Value {
        json!({ "dynamodb": { "Keys": { "sk": { "S": sk } }, "NewImage": image } })
    }

    #[test]
    fn an_active_agent_publishes_its_card_and_keys() {
        let action = action_for(&record(
            "CURRENT",
            json!({
                "agentId": { "S": "abc" },
                "status": { "S": "ACTIVE" },
                "cardDigest": { "S": "sha256:dead" },
                "keys": { "S": "[{\"kty\":\"EC\"}]" },
            }),
        ));
        assert_eq!(
            action,
            Action::Publish {
                agent_id: "abc".into(),
                card_digest: "sha256:dead".into(),
                keys: json!([{ "kty": "EC" }]),
            }
        );
    }

    #[test]
    fn a_withdrawn_agent_removes_its_pointers() {
        let action = action_for(&record(
            "CURRENT",
            json!({
                "agentId": { "S": "abc" },
                "status": { "S": "WITHDRAWN" },
                "cardDigest": { "S": "sha256:dead" },
            }),
        ));
        assert_eq!(
            action,
            Action::Withdraw {
                agent_id: "abc".into()
            }
        );
    }

    /// Version and digest items are immutable history. Letting them drive the
    /// pointers would republish an old card every time one was written.
    #[test]
    fn history_items_are_ignored() {
        for sk in ["VERSION#00000000000000000001", "DIGEST#dead"] {
            let action = action_for(&record(sk, json!({ "agentId": { "S": "abc" } })));
            assert_eq!(action, Action::Ignore, "sort key {sk}");
        }
    }

    #[test]
    fn a_record_with_no_new_image_is_ignored() {
        let event = json!({ "dynamodb": { "Keys": { "sk": { "S": "CURRENT" } } } });
        assert_eq!(action_for(&event), Action::Ignore);
    }
}
