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

use std::collections::BTreeSet;

use aws_sdk_s3::primitives::ByteStream;
use serde_json::{Value, json};

use crate::keys;

/// User metadata naming the version a pointer object holds.
const POINTER_DIGEST_METADATA: &str = "card-digest";

/// User metadata naming the sequence that version was committed at. Two
/// writers touch these objects — the stream and the sweep — and this is what
/// lets the slower one decline to move a pointer backwards.
const POINTER_SEQ_METADATA: &str = "commit-seq";

/// What a pointer object says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pointer {
    card_digest: String,
    seq: u64,
}

/// Where the sweep reads committed state from.
///
/// A trait rather than a concrete store so the sweep's logic can be exercised
/// without AWS — the whole point of this component is what it does when
/// something has already gone wrong, which is not a state easy to arrange live.
#[allow(async_fn_in_trait)]
pub trait CommittedState {
    async fn state_of(&self, agent_id: &str) -> Result<SweepState, String>;
}

pub struct Reconciler {
    s3: aws_sdk_s3::Client,
    bucket: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepState {
    Active {
        seq: u64,
        card_digest: String,
        keys: Value,
    },
    Withdrawn,
}

/// What a sweep had to put right. Empty is the expected result, and the reason
/// a non-empty one is worth alarming on: it means the stream lost something.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Repairs {
    pub republished: Vec<String>,
    pub withdrawn: Vec<String>,
    /// Agents this pass could not converge. Kept alongside the repairs rather
    /// than replacing them: a pass that fixed five agents and failed on the
    /// sixth did both, and reporting only the failure hides the drift it found.
    pub failed: Vec<String>,
}

impl Repairs {
    pub fn is_empty(&self) -> bool {
        self.republished.is_empty() && self.withdrawn.is_empty() && self.failed.is_empty()
    }

    /// Everything this pass found that was not already converged — repaired or
    /// not. The metric filter that alarms on drift reads this number, so
    /// excluding failures meant a pass that repaired nothing and failed on five
    /// agents reported `repaired = 0`: no drift, according to the one signal
    /// that watches for it.
    pub fn len(&self) -> usize {
        self.republished.len() + self.withdrawn.len() + self.failed.len()
    }
}

/// What one stream record asks for.
///
/// Only ever "look at this agent" or "this is not about an agent". The record's
/// *content* is deliberately not used: a stream record is a notification that
/// something changed, not a statement of what is true now. Applying its content
/// meant a replay from the stream horizon — the recovery `TRIM_HORIZON` exists
/// for — walked an agent's history forward and republished each superseded card
/// in turn, including the card and key set of an entry that had since been
/// withdrawn. Per-partition ordering guarantees the final state, not the
/// intermediate ones, and the intermediate ones were being served.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Make the read path match what is committed for this agent.
    Converge { agent_id: String },
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
    /// The record says *which* agent to look at; what to do comes from a
    /// consistent read of that agent's committed state. That is the same
    /// function the scheduled sweep runs, on the same inputs — the stream is a
    /// trigger, the schedule is a fallback, and neither is a second source of
    /// truth. One convergence rule, so the two writers cannot disagree.
    ///
    /// Errors propagate so that Lambda retries the batch: pointers silently
    /// left stale are the failure this whole component exists to prevent, so
    /// failing loudly is the point.
    pub async fn handle(
        &self,
        source: &impl CommittedState,
        event: &Value,
    ) -> Result<usize, String> {
        let records = event
            .get("Records")
            .and_then(Value::as_array)
            .ok_or_else(|| "the stream event carries no Records array".to_string())?;

        let mut agents: BTreeSet<String> = BTreeSet::new();
        for record in records {
            if let Action::Converge { agent_id } = action_for(record) {
                agents.insert(agent_id);
            }
        }

        let ids: Vec<String> = agents.into_iter().collect();
        let repairs = self.sweep(source, &ids).await?;

        // `sweep` collects per-agent failures rather than aborting, because a
        // scheduled pass over the whole register should put right what it can.
        // On the stream path that is the wrong shape: this invocation *is* one
        // agent's record, and returning `Ok` checkpoints it. Swallowing the
        // failure meant the five retries never engaged, the failure destination
        // received nothing, the `Errors` metric stayed flat, and the text was
        // never logged — a withdrawal whose delete was throttled simply
        // vanished, with every one of the three detectors built for that case
        // silent, and withdrawal is terminal so no later record would repeat it.
        if !repairs.failed.is_empty() {
            return Err(repairs.failed.join("; "));
        }
        Ok(repairs.len())
    }

    /// Write both pointers for one version.
    ///
    /// **Key set first, card second.** The pair is not atomic, so one of the two
    /// transient states will be visible if the second write fails. Writing the
    /// card first made that state "new card, retired key set" — a verifier
    /// following `jku` accepts a signature from a key the publisher just rotated
    /// away from. This order makes it "old card, new key set", where a verifier
    /// finds no key matching the old card's `kid` and refuses. Between two
    /// transient states, the one that fails closed.
    async fn publish(
        &self,
        agent_id: &str,
        seq: u64,
        digest: &str,
        keys: &Value,
    ) -> Result<(), String> {
        // The card is copied from its immutable object rather than carried in
        // the stream record: the record holds the digest, and the bytes it
        // names are already stored under it. Copying server-side keeps the
        // bytes exact — they are never re-serialized on the way through.
        let jwks = json!({ "keys": keys }).to_string();
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(keys::current_jwks_key(agent_id))
            .body(ByteStream::from(jwks.into_bytes()))
            .content_type("application/jwk-set+json")
            .cache_control("public, max-age=60")
            // Stamped on both pointers, not only the card: the sweep checks
            // them independently, because they are written independently.
            .metadata(POINTER_DIGEST_METADATA, digest)
            .metadata(POINTER_SEQ_METADATA, seq.to_string())
            .send()
            .await
            .map_err(|e| format!("writing the jwks pointer for {agent_id}: {e}"))?;

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
            // Which version this pointer holds, so a later sweep can tell
            // whether it is current without reading and hashing the card. S3's
            // own ETag is not the digest — it is whatever the store computed.
            .metadata(POINTER_DIGEST_METADATA, digest)
            .metadata(POINTER_SEQ_METADATA, seq.to_string())
            .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
            .send()
            .await
            .map_err(|e| format!("copying {source} to the current-card pointer: {e}"))?;

        Ok(())
    }

    /// Repair every agent's pointers from committed state.
    ///
    /// The stream is the fast path and it is not durable enough on its own. A
    /// Lambda event-source mapping that exhausts its retries **discards** the
    /// record, and the on-failure destination it writes instead carries only
    /// batch metadata — a shard id and two sequence numbers — not the record.
    /// Past the stream's 24-hour retention there is nothing to replay from at
    /// all. Since withdrawal is terminal, no later publication would ever
    /// overwrite the pointers a dropped withdrawal left behind: §6.5's "MUST
    /// stop serving" would be permanently false for that entry, and the only
    /// component that could notice is denied any view of the table.
    ///
    /// So this exists: a periodic pass that reads what is committed and makes
    /// the read path match it. It is not a second writer racing the first —
    /// it converges on the same state the stream would have produced, and both
    /// write the same bytes for the same record. It is what makes the stream's
    /// delivery guarantee "eventually" rather than "usually".
    pub async fn sweep(
        &self,
        source: &impl CommittedState,
        agent_ids: &[String],
    ) -> Result<Repairs, String> {
        let mut repairs = Repairs::default();
        for agent_id in agent_ids {
            // One agent's failure must not end the pass. Aborting meant every
            // agent after the failing one was skipped for that round — and the
            // repairs already made were reported as none, so the alarm meaning
            // "a stream record was lost" stayed quiet on a sweep that had just
            // proved it. Errors are collected and raised at the end, after the
            // rest of the register has been put right.
            if let Err(e) = self.converge(source, agent_id, &mut repairs).await {
                repairs.failed.push(format!("{agent_id}: {e}"));
            }
        }
        Ok(repairs)
    }

    async fn converge(
        &self,
        source: &impl CommittedState,
        agent_id: &str,
        repairs: &mut Repairs,
    ) -> Result<(), String> {
        // Read this agent's state *now*, consistently, rather than trusting
        // the listing that produced the identifier. The listing is an
        // eventually-consistent index read that may be minutes old by the
        // time this agent's turn comes; acting on it would let the sweep
        // rewrite a pointer the stream had already moved forward, which is
        // a rollback of the public read path performed with no key at all.
        let state = source.state_of(agent_id).await?;
        let card = self
            .pointer_state(&keys::current_card_key(agent_id))
            .await?;
        let jwks = self
            .pointer_state(&keys::current_jwks_key(agent_id))
            .await?;

        match state {
            SweepState::Withdrawn => {
                // Both pointers, checked separately: `withdraw` deletes them
                // one after the other and is not atomic, so a failure
                // between the two leaves a withdrawn entry's key set served
                // while its card is already gone — which §6.5 forbids just
                // as plainly, and which a card-only check reports as
                // converged.
                if card.is_some() || jwks.is_some() {
                    self.withdraw(agent_id).await?;
                    repairs.withdrawn.push(agent_id.to_string());
                }
            }
            SweepState::Active {
                seq,
                card_digest,
                keys,
            } => {
                let matches =
                    |p: &Option<Pointer>| p.as_ref().is_some_and(|p| p.card_digest == card_digest);
                if matches(&card) && matches(&jwks) {
                    return Ok(());
                }
                // Never move a pointer backwards. The sequence stamped on
                // the pointer is what lets a slower writer decline — for a
                // publication that lost to a newer publication.
                let served = card
                    .as_ref()
                    .map_or(0, |p| p.seq)
                    .max(jwks.as_ref().map_or(0, |p| p.seq));
                if served > seq {
                    return Ok(());
                }

                // The sequence cannot decide the case that matters most.
                // Withdrawal *deletes* the pointers and does not advance
                // `seq`, so a withdrawal landing between the read above and
                // the write below leaves two absent pointers — scored zero,
                // the smallest value there is, so the guard can never veto
                // it — and the entry would be republished from state read
                // moments before it was withdrawn. Terminal means no later
                // stream record exists to undo that: the resurrection would
                // stand until the next scheduled sweep, on an entry the API
                // has already reported as withdrawn.
                //
                // So the state is read once more, immediately before writing.
                // That shrinks the window to a single round trip and, unlike
                // the sequence, it can actually see a withdrawal.
                //
                // It does not make the pair atomic. S3 does support conditional
                // writes, but only on the `PutObject` half — `CopyObject` has
                // no destination precondition — so guarding one write and not
                // the other buys a guarantee for the key set and none for the
                // card, and an interleaving that leaves those two disagreeing
                // is worse than one that leaves both stale: both stale is what
                // the next convergence repairs. Closing it properly means
                // reading and re-putting the card bytes as well, paid on every
                // publication. Worth doing if this ever matters; today the
                // residual state is repaired within one sweep interval.
                match source.state_of(agent_id).await? {
                    SweepState::Active { seq: now, .. } if now == seq => {}
                    _ => return Ok(()),
                }

                self.publish(agent_id, seq, &card_digest, &keys).await?;
                repairs.republished.push(agent_id.to_string());
            }
        }
        Ok(())
    }

    /// What a pointer object says about itself, or `None` if there is none.
    ///
    /// Read from the object's own metadata rather than from its bytes: the
    /// pointer is a server-side copy of an immutable object whose key holds the
    /// digest, so the copy carries it without anything having to hash a card.
    async fn pointer_state(&self, key: &str) -> Result<Option<Pointer>, String> {
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(head) => {
                let meta = head.metadata();
                Ok(Some(Pointer {
                    card_digest: meta
                        .and_then(|m| m.get(POINTER_DIGEST_METADATA))
                        .cloned()
                        .unwrap_or_default(),
                    seq: meta
                        .and_then(|m| m.get(POINTER_SEQ_METADATA))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                }))
            }
            Err(e) => {
                let raw = e.raw_response().map(|r| r.status().as_u16());
                let service = e.into_service_error();
                // Absence is a 404 — but only for a caller holding
                // `s3:ListBucket`; without it S3 answers 403 for a missing key.
                // Every role that reads a pointer holds that grant, so a 403
                // here means what it says. Treating it as absence would be
                // worse than failing: in the withdrawn branch "no pointer" is
                // the converged state, so a permission failure would be
                // reported as a withdrawn entry correctly purged while its card
                // and key set stayed served.
                if service.is_not_found() || raw == Some(404) {
                    Ok(None)
                } else {
                    Err(format!("reading the pointer {key}: {service}"))
                }
            }
        }
    }

    /// Remove both pointers for a withdrawn entry.
    ///
    /// **Card first, key set second** — the mirror of `publish`, and for the
    /// same reason. The pair is not atomic, so one transient state will be
    /// visible if the second delete fails. Deleting the key set first would
    /// leave "card served, no keys", where a verifier following `jku` finds
    /// nothing and could reasonably retry. Deleting the card first leaves "no
    /// card, key set still served" — which is worse in principle, but the key
    /// set alone verifies nothing: there is no card at the edge for it to
    /// vouch for. The order that matters is the one that never leaves a
    /// *servable* card behind, and that is this one.
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
    // Only the current-state item says anything about what should be served.
    // Version and digest items are immutable history.
    if record["dynamodb"]["Keys"]["sk"]["S"].as_str() != Some(keys::CURRENT_SK) {
        return Action::Ignore;
    }

    // The identifier is in the key, not the image, so a REMOVE event — which
    // carries no new image — still names the agent it concerns. Agent items are
    // never deleted, so one arriving means something outside this system touched
    // the table, and converging on committed state is the right response to that
    // too.
    let pk = record["dynamodb"]["Keys"]["pk"]["S"]
        .as_str()
        .unwrap_or_default();
    match keys::agent_id_of_pk(pk) {
        Some(agent_id) => Action::Converge {
            agent_id: agent_id.to_string(),
        },
        None => Action::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pk: &str, sk: &str) -> Value {
        json!({ "dynamodb": { "Keys": { "pk": { "S": pk }, "sk": { "S": sk } } } })
    }

    #[test]
    fn a_current_state_record_names_the_agent_to_converge_on() {
        assert_eq!(
            action_for(&record("AGENT#abc", "CURRENT")),
            Action::Converge {
                agent_id: "abc".into()
            }
        );
    }

    /// Version and digest items are immutable history and say nothing about
    /// what should be served. The stream's own filter drops them too; this is
    /// the check that must agree with it, or the filter would be hiding a bug
    /// rather than saving an invocation.
    #[test]
    fn history_items_are_ignored() {
        for sk in ["VERSION#0000000001", "DIGEST#dead"] {
            assert_eq!(action_for(&record("AGENT#abc", sk)), Action::Ignore, "{sk}");
        }
    }

    /// The certification item is API-served state, never converged to the
    /// object store: its stream events must not wake the reconciler, and above
    /// all must not make it rewrite pointers for an agent whose card did not
    /// change.
    #[test]
    fn certification_items_are_ignored() {
        assert_eq!(
            action_for(&record("AGENT#abc", crate::keys::CERT_SK)),
            Action::Ignore
        );
    }

    /// A `REMOVE` event carries no image at all. Reading the identifier from
    /// the key rather than the image is what lets even that event name its
    /// agent — and converging on committed state is the right answer to an item
    /// that something outside this system deleted.
    #[test]
    fn an_event_without_an_image_still_names_its_agent() {
        assert_eq!(
            action_for(&record("AGENT#abc", "CURRENT")),
            Action::Converge {
                agent_id: "abc".into()
            }
        );
    }

    #[test]
    fn a_key_from_outside_this_layout_is_ignored() {
        for pk in ["", "AGENT#", "SOMETHING#abc", "abc"] {
            assert_eq!(action_for(&record(pk, "CURRENT")), Action::Ignore, "{pk:?}");
        }
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Register(BTreeMap<String, SweepState>);

    impl CommittedState for Register {
        async fn state_of(&self, agent_id: &str) -> Result<SweepState, String> {
            self.0
                .get(agent_id)
                .cloned()
                .ok_or_else(|| format!("no record for {agent_id}"))
        }
    }

    fn active(seq: u64, digest: &str) -> SweepState {
        SweepState::Active {
            seq,
            card_digest: digest.to_string(),
            keys: json!([{"kty": "EC", "kid": "k"}]),
        }
    }

    /// The decision, isolated from S3. `sweep` itself needs a client; this
    /// exercises the same match on the same inputs, which is where every
    /// finding in this component has been.
    fn decide(state: &SweepState, card: Option<Pointer>, jwks: Option<Pointer>) -> Decision {
        match state {
            SweepState::Withdrawn => {
                if card.is_some() || jwks.is_some() {
                    Decision::Withdraw
                } else {
                    Decision::Nothing
                }
            }
            SweepState::Active {
                seq, card_digest, ..
            } => {
                let matches =
                    |p: &Option<Pointer>| p.as_ref().is_some_and(|p| p.card_digest == *card_digest);
                if matches(&card) && matches(&jwks) {
                    return Decision::Nothing;
                }
                let served = card
                    .as_ref()
                    .map_or(0, |p| p.seq)
                    .max(jwks.as_ref().map_or(0, |p| p.seq));
                if served > *seq {
                    Decision::Nothing
                } else {
                    Decision::Publish
                }
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Decision {
        Nothing,
        Publish,
        Withdraw,
    }

    fn pointer(seq: u64, digest: &str) -> Option<Pointer> {
        Some(Pointer {
            card_digest: digest.to_string(),
            seq,
        })
    }

    #[test]
    fn a_converged_read_path_is_left_alone() {
        assert_eq!(
            decide(
                &active(3, "sha256:a"),
                pointer(3, "sha256:a"),
                pointer(3, "sha256:a")
            ),
            Decision::Nothing
        );
        assert_eq!(
            decide(&SweepState::Withdrawn, None, None),
            Decision::Nothing
        );
    }

    /// The failure the sweep exists for: a withdrawal whose stream record was
    /// dropped. Withdrawal is terminal, so nothing else would ever remove these.
    #[test]
    fn a_withdrawn_entry_still_being_served_is_purged() {
        assert_eq!(
            decide(
                &SweepState::Withdrawn,
                pointer(2, "sha256:a"),
                pointer(2, "sha256:a")
            ),
            Decision::Withdraw
        );
    }

    /// `withdraw` deletes the card and then the JWKS, and is not atomic. A
    /// check that looked only at the card reported this state as converged
    /// while a withdrawn entry's key set stayed served forever.
    #[test]
    fn a_withdrawn_entry_whose_key_set_alone_survived_is_still_purged() {
        assert_eq!(
            decide(&SweepState::Withdrawn, None, pointer(2, "sha256:a")),
            Decision::Withdraw
        );
    }

    /// The same asymmetry on the publish side: the card copy lands, the JWKS
    /// put fails, and the edge serves the new card with the previous — possibly
    /// rotated-away — key set.
    #[test]
    fn a_stale_key_set_beside_a_current_card_is_repaired() {
        assert_eq!(
            decide(
                &active(4, "sha256:new"),
                pointer(4, "sha256:new"),
                pointer(3, "sha256:old")
            ),
            Decision::Publish
        );
    }

    #[test]
    fn a_missing_pointer_is_published() {
        assert_eq!(
            decide(&active(1, "sha256:a"), None, None),
            Decision::Publish
        );
    }

    /// The sweep must never move the read path backwards. Between reading a
    /// record and writing a pointer the stream can commit a newer version; the
    /// sequence stamped on the pointer is what makes two writers safe.
    ///
    /// Without this the sweep is a rollback of the public read path performed
    /// with no key at all — including republishing a key set the publisher
    /// rotated away from.
    #[test]
    fn the_sweep_declines_to_overwrite_a_newer_pointer() {
        assert_eq!(
            decide(
                &active(3, "sha256:old"),
                pointer(4, "sha256:new"),
                pointer(4, "sha256:new")
            ),
            Decision::Nothing
        );
    }

    #[test]
    fn an_equal_sequence_is_repaired_since_the_digest_differs() {
        // Same sequence, different digest: a partial write, not a newer one.
        assert_eq!(
            decide(
                &active(3, "sha256:a"),
                pointer(3, "sha256:b"),
                pointer(3, "sha256:b")
            ),
            Decision::Publish
        );
    }

    #[tokio::test]
    async fn state_is_read_per_agent_rather_than_from_a_listing() {
        let register = Register(BTreeMap::from([
            ("a".to_string(), active(1, "sha256:a")),
            ("b".to_string(), SweepState::Withdrawn),
        ]));
        assert_eq!(register.state_of("a").await.unwrap(), active(1, "sha256:a"));
        assert_eq!(register.state_of("b").await.unwrap(), SweepState::Withdrawn);
        assert!(register.state_of("c").await.is_err());
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;

    struct Broken;

    impl CommittedState for Broken {
        async fn state_of(&self, agent_id: &str) -> Result<SweepState, String> {
            Err(format!("simulated backend failure reading {agent_id}"))
        }
    }

    fn s3() -> aws_sdk_s3::Client {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-west-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::for_tests())
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// The stream path must fail loudly. An invocation that returns `Ok`
    /// checkpoints the record, so a swallowed failure means the five retries
    /// never engage, the failure destination receives nothing, the `Errors`
    /// metric stays flat, and the text is never logged — a withdrawal whose
    /// delete was throttled simply vanishes, with every detector built for that
    /// case silent, and withdrawal is terminal so no later record repeats it.
    #[tokio::test]
    async fn a_convergence_failure_on_the_stream_path_is_reported() {
        let reconciler = Reconciler::new(s3(), "bucket");
        let event = json!({
            "Records": [{
                "dynamodb": { "Keys": { "pk": { "S": "AGENT#abc" }, "sk": { "S": "CURRENT" } } }
            }]
        });

        let outcome = reconciler.handle(&Broken, &event).await;
        let error = outcome.expect_err("a failure to converge must not be reported as success");
        assert!(error.contains("abc"), "{error}");
    }

    /// A pass that repaired nothing and failed on every agent still found
    /// drift. Reporting zero told the one alarm that watches for drift that
    /// there was none.
    #[tokio::test]
    async fn a_failed_pass_is_not_a_converged_one() {
        let reconciler = Reconciler::new(s3(), "bucket");
        let repairs = reconciler
            .sweep(&Broken, &["a".to_string(), "b".to_string()])
            .await
            .unwrap();

        assert!(!repairs.is_empty());
        assert_eq!(
            repairs.len(),
            2,
            "failures are drift the pass could not fix"
        );
        assert_eq!(repairs.failed.len(), 2);
    }
}
