//! Certification authorization: whether a signed `certify-domains` operation
//! is one this registry may act on (`DOMAIN-CERTIFICATION.md` §5).
//!
//! This is the withdrawal's construction (`SPEC.md` §6.5) applied to a
//! different payload: same envelope, same protected header rules, same
//! canonical-payload binding. What it deliberately does **not** carry is a
//! `cardDigest` — a certification is a statement about domains, not about a
//! card, and it survives publication of a new version.
//!
//! Resolution is not here. This crate decides what the signature authorizes;
//! whether the zones actually carry the records is the caller's question, and
//! it is asked *after* this one so that no DNS work is ever spent on a request
//! nobody signed.

use serde_json::Value;

use crate::domain::{Domain, MAX_DOMAINS};
use crate::error::{Code, RegistryError, Result};
use crate::jws;
use crate::write::{
    AgentState, Status, decode_bound_payload, expect, expect_exactly, expect_timestamp, index_keys,
};

/// The action string a certification payload must carry.
pub const CERTIFY_ACTION: &str = "certify-domains";

/// A certification that passed every rule. Nothing has been resolved or
/// stored yet.
#[derive(Debug, Clone)]
pub struct Certification {
    /// The authorized key that signed the operation.
    pub kid: String,
    /// The requested set, in the signed (ascending) order, each element
    /// already validated under §5.4.
    pub domains: Vec<Domain>,
    /// The payload's `issuedAt`, verbatim.
    pub issued_at: String,
}

/// Evaluate a `PUT /v1/agents/{agent_id}/domains`.
///
/// `last_issued_at` is the stored `certificationIssuedAt`, if any. The order
/// of checks follows §5.3, and the same two rules of thumb as the write path:
/// nothing about stored state (here, the replay comparison) is revealed before
/// a signature by a currently authorized key has verified, and nothing
/// expensive happens for a payload that is not even well formed.
pub fn evaluate_certification(
    state: &AgentState,
    registry_origin: &str,
    last_issued_at: Option<&str>,
    protected_b64: &str,
    payload_b64: &str,
    signature_b64: &str,
    submitted_keys: &[Value],
) -> Result<Certification> {
    // §5.7: a withdrawn agent certifies nothing, and the identifier is dead.
    if state.status == Status::Withdrawn {
        return Err(RegistryError::new(
            Code::Withdrawn,
            "this agent was withdrawn by its key holder; it certifies nothing",
        ));
    }

    // §5.2: `payload` must equal BASE64URL(UTF8(JCS(object))) verbatim, so a
    // signature cannot cover bytes that differ from what the registry reads.
    let (payload, value) = decode_bound_payload(payload_b64)?;

    expect_exactly(
        &value,
        &["action", "agentId", "domains", "issuedAt", "registryOrigin"],
    )?;
    expect(&value, "action", CERTIFY_ACTION)?;
    expect(&value, "agentId", &state.agent_id)?;
    expect(&value, "registryOrigin", registry_origin)?;
    expect_timestamp(&value, "issuedAt")?;
    let issued_at = value["issuedAt"]
        .as_str()
        .expect("expect_timestamp admitted a string")
        .to_string();

    let domains = parse_domains(&value)?;

    // The withdrawal's key rules, verbatim (§5.3(2–3)): every submitted key
    // must be the one that signed, the signing kid must be currently
    // authorized, and the signature must verify against the submitted key.
    let keys = index_keys(submitted_keys)?;
    let header = jws::parse_protected(protected_b64)?;
    for kid in keys.keys() {
        if kid != &header.kid {
            return Err(RegistryError::new(
                Code::UnusedKey,
                format!("submitted key {kid:?} did not sign this certification"),
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

    // §5.3(4): the replay defence. Every accepted payload stays validly signed
    // forever and the set replaces rather than accumulates, so without this,
    // anyone who observed an earlier certification could resubmit it and
    // silently restore a domain the publisher had removed. Compared as
    // instants, never as strings: RFC 3339 spells one instant several ways.
    if let Some(last) = last_issued_at {
        let last_instant = parse_instant(last).ok_or_else(|| {
            // The stored value was validated when it was stored, so this is a
            // damaged register, not a client error. Refusing closed beats
            // comparing against nothing: a corrupt stored timestamp must not
            // quietly reopen the replay window.
            RegistryError::new(
                Code::CertificationNotIncreasing,
                format!(
                    "the stored issuedAt {last:?} is not readable as RFC 3339; refusing to \
                     compare against it — this entry's certification state needs repair"
                ),
            )
        })?;
        let new_instant = parse_instant(&issued_at).expect("expect_timestamp admitted this value");
        if new_instant <= last_instant {
            return Err(RegistryError::new(
                Code::CertificationNotIncreasing,
                format!(
                    "issuedAt {issued_at:?} does not exceed the stored {last:?}; a rollback \
                     needs a fresh signature, not an old one"
                ),
            ));
        }
    }

    Ok(Certification {
        kid: header.kid,
        domains,
        issued_at,
    })
}

/// Extract and validate `domains` (§5.2, §5.4).
fn parse_domains(value: &Value) -> Result<Vec<Domain>> {
    let raw = value
        .get("domains")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RegistryError::new(
                Code::SignatureInvalid,
                "payload member \"domains\" is absent or not an array",
            )
        })?;

    let mut items: Vec<&str> = Vec::with_capacity(raw.len());
    for (i, element) in raw.iter().enumerate() {
        let s = element.as_str().ok_or_else(|| {
            RegistryError::new(
                Code::SignatureInvalid,
                format!("domains[{i}] is not a string"),
            )
        })?;
        items.push(s);
    }

    if items.len() > MAX_DOMAINS {
        return Err(RegistryError::new(
            Code::TooManyDomains,
            format!("{} domains; at most {MAX_DOMAINS}", items.len()),
        ));
    }

    // §5.2: strictly ascending in code-point order, which also refuses
    // duplicates. JCS orders object members but not array elements, so this is
    // the registry's own rule, checked explicitly — it makes the payload a
    // deterministic function of the set, and `["a","b"]` versus `["b","a"]`
    // stops being a question.
    for pair in items.windows(2) {
        if pair[0] >= pair[1] {
            return Err(RegistryError::new(
                Code::DomainsNotCanonical,
                format!(
                    "domains[] is not strictly ascending in code-point order at {:?} then {:?}",
                    pair[0], pair[1]
                ),
            ));
        }
    }

    items
        .iter()
        .map(|s| {
            Domain::parse(s).map_err(|e| RegistryError {
                code: e.code,
                detail: format!("domains[]: {}", e.detail),
            })
        })
        .collect()
}

fn parse_instant(raw: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()
}
