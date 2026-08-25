//! RFC 8785 canonicalization, digests and the JWS signing payload,
//! per `SPEC.md` §5.3 and §5.4.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::CardError;

/// The top-level member excluded from the signing payload (A2A §8.4.1 rule 3).
pub const SIGNATURES_MEMBER: &str = "signatures";

/// Serialize a value to its RFC 8785 canonical UTF-8 bytes.
pub fn canonicalize(v: &Value) -> Result<Vec<u8>, CardError> {
    serde_jcs::to_vec(v).map_err(|e| CardError::Canonicalization(e.to_string()))
}

/// `sha256:<lowercase hex>` over the given bytes.
pub fn digest(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The bytes a card signature is computed over: the card with its top-level
/// `signatures` member removed, canonicalized.
///
/// Because JCS is deterministic and independent per member, removing one
/// top-level member from a canonical object and re-canonicalizing yields
/// exactly the canonical form of the remainder. There is no ambiguity here.
pub fn signing_payload(card: &Value) -> Result<Vec<u8>, CardError> {
    let mut stripped = card.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove(SIGNATURES_MEMBER);
    }
    canonicalize(&stripped)
}

/// The JWS signing input of RFC 7515 §5.1, for a detached payload:
/// `ASCII(protected || "." || BASE64URL(payload))`.
pub fn signing_input(protected_b64: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected_b64.len() + 1 + payload.len() * 4 / 3 + 4);
    out.extend_from_slice(protected_b64.as_bytes());
    out.push(b'.');
    out.extend_from_slice(Base64UrlUnpadded::encode_string(payload).as_bytes());
    out
}

/// Unpadded base64url, the only base64 variant this protocol uses.
pub fn b64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decode unpadded base64url.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, CardError> {
    Base64UrlUnpadded::decode_vec(s)
        .map_err(|e| CardError::Canonicalization(format!("invalid base64url: {e}")))
}
