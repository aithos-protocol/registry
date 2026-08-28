//! Write authorization: who may create, update or withdraw an entry
//! (`SPEC.md` §6).
//!
//! The whole rule set is: every signature must verify, at least one must come
//! from a key that was already authorized, and the card's own `version` must
//! move strictly forward. Rotation falls out of that for free, because the new
//! authorized set is simply the set of keys that signed the new version.

use std::collections::{BTreeMap, BTreeSet};

use a2a_card::CanonicalCard;
use a2a_card::canonical::{b64url, canonicalize};
use semver::Version;
use serde_json::Value;

use crate::error::{Code, RegistryError, Result};
use crate::jwk::Jwk;
use crate::jws;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Withdrawn,
}

/// What the registry already holds for an agent.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub agent_id: String,
    pub status: Status,
    pub card_digest: String,
    pub card_version: Version,
    pub authorized_kids: BTreeSet<String>,
}

/// What an accepted write does to the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Created,
    Updated,
    /// The submitted bytes are the ones already published. Nothing to commit.
    ///
    /// This is what a client retrying after a network timeout sends, and that
    /// happens routinely: the write may well have succeeded and only the
    /// response was lost. Answering it with a conflict would report failure
    /// for an operation that worked.
    ///
    /// The test is on the digest, not on the content: only byte-identical
    /// resubmission qualifies. With the three accepted algorithms — all
    /// deterministic — re-signing unchanged content reproduces the same
    /// document and lands here too, while a client using a randomised ECDSA
    /// implementation would produce a new document needing a new version.
    Unchanged,
}

/// A detached JWS whose payload is transmitted alongside it.
///
/// Used for the two operations whose meaning is not carried by the card: the
/// publication proof (§6.2) and the withdrawal (§6.5).
#[derive(Debug, Clone)]
pub struct DetachedJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// A write that passed every rule. Nothing here has touched storage yet.
#[derive(Debug, Clone)]
pub struct AcceptedWrite {
    pub agent_id: String,
    pub card_digest: String,
    pub card_version: Version,
    /// The keys that signed this version; this becomes the new authorized set.
    pub authorized_kids: BTreeSet<String>,
    /// Those same keys as the registry will publish them, rebuilt from verified
    /// material. Returned here rather than left to the caller so that what gets
    /// stored cannot differ from what was checked.
    pub keys: Vec<serde_json::Value>,
    pub outcome: Outcome,
}

impl AcceptedWrite {
    pub fn is_creation(&self) -> bool {
        self.outcome == Outcome::Created
    }
}

/// The action string a publication proof must carry.
pub const PUBLISH_ACTION: &str = "publish";

/// The most keys — and so the most proofs — one write may carry. Mirrors the
/// API's own limit; duplicated here so the rules hold without a caller applying
/// them first.
pub const MAX_KEYS: usize = 8;

/// Evaluate a `PUT /v1/agents/{agent_id}`.
///
/// # Why the card's own signatures are not enough
///
/// An A2A card signature (§8.4) covers the card minus its `signatures` member,
/// and nothing else. It names no registry and no identifier — deliberately, so
/// that one signed card is portable. That portability is a problem for an
/// operation that *claims* something: a card signed by a publisher and served
/// on their own website carries every signature this registry would check, so
/// anyone who can read it could submit it here under the signer's thumbprint.
/// They could register an entry the key holder never asked for; and, by
/// dropping the co-signature of a backup key before submitting, they could
/// choose the entry's authorized key set and leave the real publisher with a
/// version conflict and one key fewer than they registered.
///
/// So a write carries a second, separate signature — a *publication proof* —
/// over a payload that names this registry, this identifier and this exact
/// card. It is the same construction the withdrawal already used, for the same
/// reason: an operation is authorized by a signature over the operation, not by
/// a signature over a document that happens to accompany it.
pub fn evaluate_write(
    agent_id: &str,
    card: &CanonicalCard,
    submitted_keys: &[Value],
    proofs: &[DetachedJws],
    registry_origin: &str,
    current: Option<&AgentState>,
) -> Result<AcceptedWrite> {
    if let Some(state) = current
        && state.status == Status::Withdrawn
    {
        return Err(RegistryError::new(
            Code::Withdrawn,
            "this agent was withdrawn by its key holder; the identifier is not reusable",
        ));
    }

    let keys = index_keys(submitted_keys)?;
    let signing_kids = verify_card_signatures(card, &keys)?;

    // A key nobody signed with would silently widen the authorized set.
    for kid in keys.keys() {
        if !signing_kids.contains(kid) {
            return Err(RegistryError::new(
                Code::UnusedKey,
                format!("submitted key {kid:?} is referenced by no signature"),
            ));
        }
    }

    let card_version = parse_card_version(card)?;

    // Checked after the card's own signatures, so a caller who holds no key
    // learns nothing from the ordering, and before the version rule, so a
    // stranger cannot probe the current version by submitting cards.
    //
    // One proof per key entering the authorized set. A single proof from the
    // genesis key is not enough: the authorized set is the set of *card*
    // signers, and a card signature covers the card minus `signatures[]`, which
    // is public the moment the card is published. Anyone could therefore append
    // their own signature to someone else's published card and open an entry in
    // their own name whose authorized set — and whose served JWKS — names a key
    // holder who never asked for it. Requiring every key in the set to have
    // signed a proof for *this* registry, *this* identifier and *this* card is
    // what makes the published set mean what §7.2 says it means.
    let proof_kids = verify_publication_proofs(agent_id, card, proofs, registry_origin, &keys)?;
    if proof_kids != signing_kids {
        let missing: Vec<&String> = signing_kids.difference(&proof_kids).collect();
        return Err(RegistryError::new(
            Code::UnprovenKey,
            format!(
                "key(s) {missing:?} signed the card but no publication proof; every key that \
                 enters the authorized set must ask for this publication itself"
            ),
        ));
    }

    let outcome = match current {
        None => {
            // §6.2(4): the identifier must be the thumbprint of a key that
            // actually signed this first version.
            if !signing_kids.contains(agent_id) {
                return Err(RegistryError::new(
                    Code::AgentIdMismatch,
                    format!(
                        "agentId {agent_id:?} is not the thumbprint of any signing key; \
                         a new entry is named by its genesis key"
                    ),
                ));
            }
            // The genesis key names the entry, so the genesis key is the one
            // that must ask for it to exist. Any other signer would let a
            // co-signature on someone else's card open an entry in their name.
            if !proof_kids.contains(agent_id) {
                return Err(RegistryError::new(
                    Code::NotAuthorizedKey,
                    format!(
                        "no publication proof is signed by the genesis key {agent_id:?}; \
                         a new entry must be requested by the key that names it"
                    ),
                ));
            }
            Outcome::Created
        }
        Some(state) => {
            // §6.3(2): the lineage rule. One key from the previous set is
            // enough, which is what makes rotation and backup keys work.
            if signing_kids.is_disjoint(&state.authorized_kids) {
                return Err(RegistryError::new(
                    Code::NotAuthorizedKey,
                    "no signature comes from a currently authorized key",
                ));
            }
            // Redundant while the proof set and the signing set are required
            // to be equal, and kept for that reason rather than in spite of it:
            // if that equality is ever relaxed, this is the rule that must
            // still hold, and a rule expressed only as a consequence of another
            // one disappears the moment the other changes.
            if proof_kids.is_disjoint(&state.authorized_kids) {
                return Err(RegistryError::new(
                    Code::NotAuthorizedKey,
                    "no publication proof comes from a currently authorized key",
                ));
            }
            // An identical resubmission changes nothing, so it succeeds
            // rather than conflicting. Checked after the lineage rule above,
            // so an unauthorized caller learns nothing from it.
            if card.digest == state.card_digest {
                return Ok(AcceptedWrite {
                    agent_id: agent_id.to_string(),
                    card_digest: state.card_digest.clone(),
                    card_version: state.card_version.clone(),
                    authorized_kids: state.authorized_kids.clone(),
                    keys: public_keys(&keys),
                    outcome: Outcome::Unchanged,
                });
            }

            // §6.4: without a monotonic element, anyone who has merely seen an
            // older card could re-submit it to roll the entry back; every past
            // version stays validly signed forever.
            if precedence(&card_version) <= precedence(&state.card_version) {
                return Err(RegistryError::new(
                    Code::VersionNotIncreasing,
                    format!(
                        "card version {card_version} does not exceed the current {}",
                        state.card_version
                    ),
                ));
            }
            Outcome::Updated
        }
    };

    Ok(AcceptedWrite {
        agent_id: agent_id.to_string(),
        card_digest: card.digest.clone(),
        card_version,
        authorized_kids: signing_kids,
        keys: public_keys(&keys),
        outcome,
    })
}

/// Verify every signature on the card and return the set of signing `kid`s.
fn verify_card_signatures(
    card: &CanonicalCard,
    keys: &BTreeMap<String, Jwk>,
) -> Result<BTreeSet<String>> {
    let signatures = card
        .value
        .get("signatures")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            RegistryError::new(Code::SignatureInvalid, "the card carries no signature")
        })?;

    let payload = card
        .signing_payload()
        .map_err(|e| RegistryError::new(Code::CardInvalid, e.to_string()))?;

    let mut signing_kids = BTreeSet::new();
    for (i, sig) in signatures.iter().enumerate() {
        let at = |detail: String| {
            RegistryError::new(Code::SignatureInvalid, format!("/signatures/{i}: {detail}"))
        };

        let protected_b64 = sig
            .get("protected")
            .and_then(Value::as_str)
            .ok_or_else(|| at("`protected` is absent or not a string".into()))?;
        let signature_b64 = sig
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| at("`signature` is absent or not a string".into()))?;

        let header = jws::parse_protected(protected_b64).map_err(|e| RegistryError {
            code: e.code,
            detail: format!("/signatures/{i}: {}", e.detail),
        })?;

        let key = keys.get(&header.kid).ok_or_else(|| {
            RegistryError::new(
                Code::KidNotThumbprint,
                format!(
                    "/signatures/{i}: no submitted key has thumbprint {:?}",
                    header.kid
                ),
            )
        })?;

        jws::verify_detached(&header, protected_b64, signature_b64, &payload, key).map_err(
            |e| RegistryError {
                code: e.code,
                detail: format!("/signatures/{i}: {}", e.detail),
            },
        )?;

        if !signing_kids.insert(header.kid.clone()) {
            return Err(at(format!("key {:?} signs this card twice", header.kid)));
        }
    }
    Ok(signing_kids)
}

/// The verified keys in thumbprint order, in the form the registry publishes.
fn public_keys(keys: &BTreeMap<String, Jwk>) -> Vec<Value> {
    keys.values().map(Jwk::to_public).collect()
}

fn index_keys(submitted: &[Value]) -> Result<BTreeMap<String, Jwk>> {
    let mut keys = BTreeMap::new();
    for value in submitted {
        let jwk = Jwk::parse(value)?;
        if keys
            .insert(jwk.thumbprint().to_string(), jwk.clone())
            .is_some()
        {
            return Err(RegistryError::new(
                Code::DuplicateKey,
                format!("key {:?} was submitted twice", jwk.thumbprint()),
            ));
        }
    }
    if keys.is_empty() {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            "no key was submitted",
        ));
    }
    Ok(keys)
}

/// The version stripped to what SemVer 2.0.0 §10 calls precedence.
///
/// `semver::Version`'s own ordering includes build metadata — it has to, to stay
/// consistent with `Eq` — but SemVer says build metadata is ignored when
/// determining precedence, and `SPEC.md` §6.4 pins SemVer's ordering. Without
/// this, `1.0.0+b` counted as an update over `1.0.0`: a different card at the
/// same version, which is exactly what the monotonic rule exists to refuse.
pub fn precedence(v: &Version) -> Version {
    Version {
        build: semver::BuildMetadata::EMPTY,
        ..v.clone()
    }
}

fn parse_card_version(card: &CanonicalCard) -> Result<Version> {
    let raw = card
        .card_version()
        .ok_or_else(|| RegistryError::new(Code::CardInvalid, "the card has no `version` member"))?;
    // A version that cannot be parsed is a defect in the card, not a failure to
    // exceed something: on a creation there is nothing to exceed.
    Version::parse(raw).map_err(|e| {
        RegistryError::new(
            Code::CardInvalid,
            format!("card version {raw:?} is not Semantic Versioning 2.0.0: {e}"),
        )
    })
}

/// Verify every publication proof and return the set of `kid`s that signed one.
fn verify_publication_proofs(
    agent_id: &str,
    card: &CanonicalCard,
    proofs: &[DetachedJws],
    registry_origin: &str,
    keys: &BTreeMap<String, Jwk>,
) -> Result<BTreeSet<String>> {
    if proofs.is_empty() {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            "the write carries no publication proof",
        ));
    }
    if proofs.len() > MAX_KEYS {
        return Err(RegistryError::new(
            Code::TooManyKeys,
            format!("{} publication proofs; at most {MAX_KEYS}", proofs.len()),
        ));
    }

    let mut kids = BTreeSet::new();
    for (i, proof) in proofs.iter().enumerate() {
        let kid = verify_publication_proof(agent_id, card, proof, registry_origin, keys).map_err(
            |e| RegistryError {
                code: e.code,
                detail: format!("/proofs/{i}: {}", e.detail),
            },
        )?;
        if !kids.insert(kid.clone()) {
            return Err(RegistryError::new(
                Code::DuplicateKey,
                format!("/proofs/{i}: key {kid:?} proves this publication twice"),
            ));
        }
    }
    Ok(kids)
}

/// Verify one publication proof and return the `kid` that signed it.
///
/// The payload is checked to be *exactly* the object the spec names — no extra
/// members — so that a signature can never cover more than the registry read.
fn verify_publication_proof(
    agent_id: &str,
    card: &CanonicalCard,
    proof: &DetachedJws,
    registry_origin: &str,
    keys: &BTreeMap<String, Jwk>,
) -> Result<String> {
    let (payload, value) = decode_bound_payload(&proof.payload)?;

    expect_exactly(
        &value,
        &[
            "action",
            "agentId",
            "cardDigest",
            "registryOrigin",
            "issuedAt",
        ],
    )?;
    expect(&value, "action", PUBLISH_ACTION)?;
    expect(&value, "agentId", agent_id)?;
    expect(&value, "cardDigest", &card.digest)?;
    expect(&value, "registryOrigin", registry_origin)?;
    expect_timestamp(&value, "issuedAt")?;

    let header = jws::parse_protected(&proof.protected)?;
    let key = keys.get(&header.kid).ok_or_else(|| {
        RegistryError::new(
            Code::KidNotThumbprint,
            format!(
                "the publication proof is signed by {:?}, which is not among the submitted keys",
                header.kid
            ),
        )
    })?;
    jws::verify_detached(&header, &proof.protected, &proof.signature, &payload, key)?;
    Ok(header.kid)
}

/// Decode a transmitted JWS payload and check it is the canonical encoding of
/// what it decodes to.
///
/// Without the re-encoding check a signature could cover bytes that differ from
/// the object the registry reads — the same member, spelled two ways.
fn decode_bound_payload(payload_b64: &str) -> Result<(Vec<u8>, Value)> {
    let payload = a2a_card::canonical::b64url_decode(payload_b64).map_err(|_| {
        RegistryError::new(Code::SignatureInvalid, "payload is not unpadded base64url")
    })?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| RegistryError::new(Code::SignatureInvalid, "payload is not valid UTF-8"))?;
    let value = a2a_card::strict::parse(text)
        .map_err(|e| RegistryError::new(Code::SignatureInvalid, format!("payload: {e}")))?;

    let recomputed = canonicalize(&value)
        .map_err(|e| RegistryError::new(Code::SignatureInvalid, e.to_string()))?;
    if b64url(&recomputed) != payload_b64 {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            "payload is not the canonical encoding of the object it decodes to",
        ));
    }
    Ok((payload, value))
}

// --- withdrawal (§6.5) ---------------------------------------------------

/// The action string a withdrawal payload must carry.
pub const WITHDRAW_ACTION: &str = "withdraw";

/// Verify a `DELETE /v1/agents/{agent_id}` request.
///
/// The payload binds the current card digest, so an old withdrawal cannot be
/// replayed against a later version of the entry.
pub fn evaluate_withdrawal(
    state: &AgentState,
    registry_origin: &str,
    protected_b64: &str,
    payload_b64: &str,
    signature_b64: &str,
    submitted_keys: &[Value],
) -> Result<String> {
    if state.status == Status::Withdrawn {
        return Err(RegistryError::new(Code::Withdrawn, "already withdrawn"));
    }

    // §6.5: `payload` must equal BASE64URL(UTF8(JCS(object))) verbatim, so a
    // signature cannot cover bytes that differ from what the registry reads.
    let (payload, value) = decode_bound_payload(payload_b64)?;

    expect_exactly(
        &value,
        &[
            "action",
            "agentId",
            "cardDigest",
            "registryOrigin",
            "issuedAt",
        ],
    )?;
    expect(&value, "action", WITHDRAW_ACTION)?;
    expect(&value, "agentId", &state.agent_id)?;
    expect(&value, "cardDigest", &state.card_digest)?;
    expect(&value, "registryOrigin", registry_origin)?;
    expect_timestamp(&value, "issuedAt")?;

    let keys = index_keys(submitted_keys)?;
    let header = jws::parse_protected(protected_b64)?;
    // §5.6 without exception: a submitted key that signs nothing has no
    // business being here. The write path applies this and the withdrawal path
    // did not, so a `DELETE` could carry eight keys of which seven were parsed
    // — RSA moduli included — and then ignored. A rule enforced on one of its
    // two callers is a rule that reads as absolute and is not.
    for kid in keys.keys() {
        if kid != &header.kid {
            return Err(RegistryError::new(
                Code::UnusedKey,
                format!("submitted key {kid:?} did not sign this withdrawal"),
            ));
        }
    }
    if !state.authorized_kids.contains(&header.kid) {
        return Err(RegistryError::new(
            Code::NotAuthorizedKey,
            format!(
                "key {:?} is not currently authorized for this agent",
                header.kid
            ),
        ));
    }
    let key = keys.get(&header.kid).ok_or_else(|| {
        RegistryError::new(
            Code::KidNotThumbprint,
            format!("no submitted key has thumbprint {:?}", header.kid),
        )
    })?;
    jws::verify_detached(&header, protected_b64, signature_b64, &payload, key)?;

    Ok(header.kid)
}

/// Require the payload to hold exactly these members and no others.
///
/// §6.2 and §6.5 both say the payload "is exactly" the object they describe.
/// Accepting extras would let a signature cover meaning the registry never
/// read, which is the shape of every "the server ignored a field" bug that
/// later turns out to matter.
fn expect_exactly(value: &Value, members: &[&str]) -> Result<()> {
    let obj = value.as_object().ok_or_else(|| {
        RegistryError::new(Code::SignatureInvalid, "payload is not a JSON object")
    })?;
    for key in obj.keys() {
        if !members.contains(&key.as_str()) {
            return Err(RegistryError::new(
                Code::SignatureInvalid,
                format!("payload member {key:?} is not part of this payload"),
            ));
        }
    }
    Ok(())
}

/// Require an RFC 3339 UTC timestamp.
///
/// The registry does not reject a stale one: these payloads are bound to a card
/// digest and to an entry whose version only moves forward, so replaying an old
/// one accomplishes nothing that the digest binding does not already refuse.
/// The shape is still checked, because a member nobody parses is a member that
/// silently means nothing.
fn expect_timestamp(value: &Value, member: &str) -> Result<()> {
    let raw = value.get(member).and_then(Value::as_str).ok_or_else(|| {
        RegistryError::new(
            Code::SignatureInvalid,
            format!("payload member {member:?} is absent or not a string"),
        )
    })?;
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).map_err(
        |_| {
            RegistryError::new(
                Code::SignatureInvalid,
                format!("payload member {member:?} is {raw:?}, which is not an RFC 3339 timestamp"),
            )
        },
    )?;
    Ok(())
}

fn expect(value: &Value, member: &str, want: &str) -> Result<()> {
    match value.get(member).and_then(Value::as_str) {
        Some(got) if got == want => Ok(()),
        Some(got) => Err(RegistryError::new(
            Code::SignatureInvalid,
            format!("payload member {member:?} is {got:?}; {want:?} expected"),
        )),
        None => Err(RegistryError::new(
            Code::SignatureInvalid,
            format!("payload member {member:?} is absent or not a string"),
        )),
    }
}
