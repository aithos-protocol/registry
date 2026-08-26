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

/// A write that passed every rule. Nothing here has touched storage yet.
#[derive(Debug, Clone)]
pub struct AcceptedWrite {
    pub agent_id: String,
    pub card_digest: String,
    pub card_version: Version,
    /// The keys that signed this version; this becomes the new authorized set.
    pub authorized_kids: BTreeSet<String>,
    pub outcome: Outcome,
}

impl AcceptedWrite {
    pub fn is_creation(&self) -> bool {
        self.outcome == Outcome::Created
    }
}

/// Evaluate a `PUT /v1/agents/{agent_id}`.
pub fn evaluate_write(
    agent_id: &str,
    card: &CanonicalCard,
    submitted_keys: &[Value],
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
            // An identical resubmission changes nothing, so it succeeds
            // rather than conflicting. Checked after the lineage rule above,
            // so an unauthorized caller learns nothing from it.
            if card.digest == state.card_digest {
                return Ok(AcceptedWrite {
                    agent_id: agent_id.to_string(),
                    card_digest: state.card_digest.clone(),
                    card_version: state.card_version.clone(),
                    authorized_kids: state.authorized_kids.clone(),
                    outcome: Outcome::Unchanged,
                });
            }

            // §6.4: without a monotonic element, anyone who has merely seen an
            // older card could re-submit it to roll the entry back; every past
            // version stays validly signed forever.
            if card_version <= state.card_version {
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

fn index_keys(submitted: &[Value]) -> Result<BTreeMap<String, Jwk>> {
    let mut keys = BTreeMap::new();
    for value in submitted {
        let jwk = Jwk::parse(value)?;
        if keys
            .insert(jwk.thumbprint().to_string(), jwk.clone())
            .is_some()
        {
            return Err(RegistryError::new(
                Code::UnusedKey,
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

fn parse_card_version(card: &CanonicalCard) -> Result<Version> {
    let raw = card
        .card_version()
        .ok_or_else(|| RegistryError::new(Code::CardInvalid, "the card has no `version` member"))?;
    Version::parse(raw).map_err(|e| {
        RegistryError::new(
            Code::VersionNotIncreasing,
            format!("card version {raw:?} is not Semantic Versioning 2.0.0: {e}"),
        )
    })
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

    let payload = a2a_card::canonical::b64url_decode(payload_b64).map_err(|_| {
        RegistryError::new(Code::SignatureInvalid, "payload is not unpadded base64url")
    })?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| RegistryError::new(Code::SignatureInvalid, "payload is not valid UTF-8"))?;
    let value = a2a_card::strict::parse(text)
        .map_err(|e| RegistryError::new(Code::SignatureInvalid, format!("payload: {e}")))?;

    // §6.5: `payload` must equal BASE64URL(UTF8(JCS(object))) verbatim, so a
    // signature cannot cover bytes that differ from what the registry reads.
    let recomputed = canonicalize(&value)
        .map_err(|e| RegistryError::new(Code::SignatureInvalid, e.to_string()))?;
    if b64url(&recomputed) != payload_b64 {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            "payload is not the canonical encoding of the object it decodes to",
        ));
    }

    expect(&value, "action", WITHDRAW_ACTION)?;
    expect(&value, "agentId", &state.agent_id)?;
    expect(&value, "cardDigest", &state.card_digest)?;
    expect(&value, "registryOrigin", registry_origin)?;
    if !value.get("issuedAt").is_some_and(Value::is_string) {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            "payload has no `issuedAt` string",
        ));
    }

    let keys = index_keys(submitted_keys)?;
    let header = jws::parse_protected(protected_b64)?;
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
