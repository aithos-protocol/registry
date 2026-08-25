//! Strict A2A Agent Card handling: the deterministic core of the registry.
//!
//! Everything in this crate is pure. It performs no I/O, holds no key material
//! and has no opinion about storage or transport, so it can be compiled to
//! WebAssembly and run in the browser that authors and signs a card, byte for
//! byte identically to the server that verifies it.
//!
//! The pipeline is:
//!
//! 1. [`strict::parse`] — reject JSON that would not survive canonicalization
//!    unchanged (duplicate members, integers outside the I-JSON domain).
//! 2. [`presence::validate_card`] — check the pinned A2A schema and the
//!    field-presence rules of A2A §8.4.1.
//! 3. [`canonical`] — RFC 8785 bytes, digests, and the detached JWS signing
//!    payload.

pub mod canonical;
pub mod error;
pub mod presence;
pub mod schema;
pub mod strict;

pub use error::{CardError, Code, Issue};

use serde_json::Value;

/// A card that has passed every check of §5.1 to §5.3.
#[derive(Debug, Clone)]
pub struct CanonicalCard {
    /// The parsed card.
    pub value: Value,
    /// Exact RFC 8785 bytes. This is what the registry stores and serves
    /// verbatim; it is never re-serialized on read.
    pub bytes: Vec<u8>,
    /// `sha256:<hex>` of [`Self::bytes`].
    pub digest: String,
}

impl CanonicalCard {
    /// The bytes a signature is computed over (card without `signatures`).
    pub fn signing_payload(&self) -> Result<Vec<u8>, CardError> {
        canonical::signing_payload(&self.value)
    }

    /// The card's own `version` member, which the registry orders on.
    pub fn card_version(&self) -> Option<&str> {
        self.value.get("version")?.as_str()
    }
}

/// Parse, validate and canonicalize an Agent Card in one step.
pub fn parse_card(input: &str) -> Result<CanonicalCard, CardError> {
    let value = strict::parse(input)?;
    finish(value)
}

/// Same as [`parse_card`] for a card that has already been parsed strictly,
/// for example when it arrived nested inside a request envelope.
pub fn validate_value(value: Value) -> Result<CanonicalCard, CardError> {
    finish(value)
}

fn finish(value: Value) -> Result<CanonicalCard, CardError> {
    let issues = presence::validate_card(&value);
    if !issues.is_empty() {
        return Err(CardError::Invalid { issues });
    }
    let bytes = canonical::canonicalize(&value)?;
    let digest = canonical::digest(&bytes);
    Ok(CanonicalCard {
        value,
        bytes,
        digest,
    })
}
