//! Detached JWS verification for Agent Card signatures (`SPEC.md` §5.5).
//!
//! A2A card signatures carry only `protected` and `signature`: the payload is
//! the card itself, minus its `signatures` member, canonicalized. This module
//! parses the protected header under a strict profile and verifies the
//! signature over the reconstructed signing input.

use a2a_card::canonical::{b64url_decode, signing_input};
use serde_json::Value;

use crate::error::{Code, RegistryError, Result};
use crate::jwk::{Alg, Jwk, KeyKindRef};

/// The only members a protected header may carry.
const ALLOWED_HEADER_MEMBERS: &[&str] = &["alg", "typ", "kid", "jku"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub alg: Alg,
    pub kid: String,
    pub jku: Option<String>,
}

/// Parse the base64url-encoded protected header of one signature.
pub fn parse_protected(protected_b64: &str) -> Result<ProtectedHeader> {
    let raw = b64url_decode(protected_b64).map_err(|_| {
        RegistryError::new(
            Code::SignatureInvalid,
            "protected header is not unpadded base64url",
        )
    })?;
    let text = std::str::from_utf8(&raw).map_err(|_| {
        RegistryError::new(
            Code::SignatureInvalid,
            "protected header is not valid UTF-8",
        )
    })?;
    // Strict parsing here too: a duplicate `alg` member decided by parser
    // order is exactly the kind of ambiguity this profile refuses.
    let value = a2a_card::strict::parse(text).map_err(|e| {
        RegistryError::new(Code::SignatureInvalid, format!("protected header: {e}"))
    })?;
    let obj = value.as_object().ok_or_else(|| {
        RegistryError::new(
            Code::SignatureInvalid,
            "protected header is not a JSON object",
        )
    })?;

    for key in obj.keys() {
        if !ALLOWED_HEADER_MEMBERS.contains(&key.as_str()) {
            // `crit` and `b64` are refused by this same rule. Naming them
            // keeps the error actionable, since they are the two that carry
            // security meaning.
            let detail = match key.as_str() {
                "crit" => "protected header carries `crit`, which this profile does not accept",
                "b64" => {
                    "protected header carries `b64`; only the default base64url payload encoding is accepted"
                }
                _ => "protected header carries a member outside {alg, typ, kid, jku}",
            };
            return Err(RegistryError::new(
                Code::SignatureInvalid,
                format!("{detail} ({key:?})"),
            ));
        }
    }

    let typ = obj.get("typ").and_then(Value::as_str).ok_or_else(|| {
        RegistryError::new(Code::SignatureInvalid, "protected header has no `typ`")
    })?;
    if typ != "JOSE" {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            format!("`typ` is {typ:?}; A2A §8.4.2 asks for \"JOSE\""),
        ));
    }

    let alg_str = obj.get("alg").and_then(Value::as_str).ok_or_else(|| {
        RegistryError::new(Code::SignatureInvalid, "protected header has no `alg`")
    })?;
    let alg = Alg::parse(alg_str)?;

    let kid = obj
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| RegistryError::new(Code::SignatureInvalid, "protected header has no `kid`"))?
        .to_string();

    let jku = match obj.get("jku") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                RegistryError::new(Code::SignatureInvalid, "`jku` is not a string")
            })?;
            // `@` was rejected anywhere in the string, which also refuses a
            // legitimate path or query; and a bare `starts_with` accepted
            // `https:///path`, whose authority is empty, along with control
            // characters and whitespace. Both halves are checked against the
            // authority component instead.
            // RFC 3986 §3.1 makes the scheme case-insensitive, so `HTTPS://`
            // is the same URL. Refusing it rejected a valid card for a reason
            // that is not a rule.
            let lowered = s.to_ascii_lowercase();
            let Some(rest) = lowered.strip_prefix("https://") else {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` must be an absolute HTTPS URL",
                ));
            };
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if authority.is_empty() {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` names no host",
                ));
            }
            if authority.contains('@') {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` carries userinfo, which would name a host other than it appears to",
                ));
            }
            if s.contains('#') {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` carries a fragment, which is never sent to a server",
                ));
            }
            if s.chars().any(|c| c.is_control() || c == ' ') {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` contains whitespace or a control character",
                ));
            }
            Some(s.to_string())
        }
    };

    Ok(ProtectedHeader { alg, kid, jku })
}

/// Verify one detached signature over `payload`.
///
/// The order matters: the algorithm allowlist is applied while parsing the
/// header, the key/algorithm binding before any key is loaded, and the
/// thumbprint check before any signature work. Nothing expensive or
/// attacker-steered happens until the key is known to be the right one.
pub fn verify_detached(
    header: &ProtectedHeader,
    protected_b64: &str,
    signature_b64: &str,
    payload: &[u8],
    key: &Jwk,
) -> Result<()> {
    if key.thumbprint() != header.kid {
        return Err(RegistryError::new(
            Code::KidNotThumbprint,
            format!(
                "`kid` {:?} is not the RFC 7638 thumbprint of the supplied key ({:?})",
                header.kid,
                key.thumbprint()
            ),
        ));
    }
    if !key.accepts(header.alg) {
        return Err(RegistryError::new(
            Code::AlgNotAllowed,
            format!("key type does not match algorithm {}", header.alg.as_str()),
        ));
    }

    let sig = b64url_decode(signature_b64).map_err(|_| {
        RegistryError::new(
            Code::SignatureInvalid,
            "signature is not unpadded base64url",
        )
    })?;
    let input = signing_input(protected_b64, payload);

    let ok = match (key.key_ref(), header.alg) {
        (KeyKindRef::P256 { x, y }, Alg::Es256) => verify_es256(x, y, &sig, &input)?,
        (KeyKindRef::Ed25519 { x }, Alg::EdDsa) => verify_ed25519(x, &sig, &input)?,
        (KeyKindRef::Rsa { n, e }, Alg::Rs256) => verify_rs256(n, e, &sig, &input)?,
        _ => false,
    };

    if ok {
        Ok(())
    } else {
        Err(RegistryError::new(
            Code::SignatureInvalid,
            "signature does not verify",
        ))
    }
}

fn verify_es256(x: &[u8], y: &[u8], sig: &[u8], input: &[u8]) -> Result<bool> {
    use p256::EncodedPoint;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    // RFC 7518 §3.4: the JOSE form is the fixed-width R || S concatenation,
    // never the DER encoding that most command-line tools emit.
    if sig.len() != 64 {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            format!(
                "ES256 signature is {} bytes; the JOSE R||S form is 64",
                sig.len()
            ),
        ));
    }
    let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let Ok(vk) = VerifyingKey::from_encoded_point(&point) else {
        return Err(RegistryError::new(
            Code::KeyInvalid,
            "EC point is not on the P-256 curve",
        ));
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return Ok(false);
    };
    // ECDSA admits two valid signatures per message, `(r, s)` and `(r, n-s)`,
    // so one signed card has more than one valid byte encoding. Both halves are
    // accepted here deliberately. RFC 7518 does not require the low form and
    // roughly half of ECDSA implementations emit the high one, so refusing it
    // would reject correctly signed A2A cards from other tooling — a real
    // interoperability cost. What it would buy is nothing this registry needs:
    // a card in either form is still addressed by its own digest, still cannot
    // be published without a publication proof, and still cannot displace the
    // current version without moving `version` forward. The only visible effect
    // is that a client which re-signs rather than resends gets a new digest and
    // so a version conflict instead of the no-op of §6.1 — which §6.1 already
    // says, and which resending the published bytes avoids.
    Ok(vk.verify(input, &signature).is_ok())
}

/// Verify an Ed25519 signature under RFC 8032's **strict** rules.
///
/// `Verifier::verify` uses the permissive, cofactorless equation and checks
/// nothing about the public key's order. Under it the identity point is a valid
/// key for which the all-but-one-byte-zero signature verifies over *every*
/// message — so a fixed, publicly derivable `agentId` would be writable by
/// anyone, with no key material at all. `verify_strict` rejects small-order and
/// non-canonical points on both `A` and `R`, which is the property this registry
/// actually depends on: that a signature names exactly one key holder.
fn verify_ed25519(x: &[u8], sig: &[u8], input: &[u8]) -> Result<bool> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if sig.len() != 64 {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            format!("EdDSA signature is {} bytes; 64 expected", sig.len()),
        ));
    }
    let bytes: [u8; 32] = x.try_into().expect("validated to 32 bytes at parse time");
    let Ok(vk) = VerifyingKey::from_bytes(&bytes) else {
        return Err(RegistryError::new(
            Code::KeyInvalid,
            "not a valid Ed25519 public key",
        ));
    };
    // A key of small order can never sign anything meaningful, so refusing it
    // at the key rather than at the signature keeps the reason legible: the
    // problem is the key that was submitted, not the bytes that accompanied it.
    if vk.is_weak() {
        return Err(RegistryError::new(
            Code::AlgNotAllowed,
            "Ed25519 public key is of small order and cannot identify a signer",
        ));
    }
    let signature = Signature::from_slice(sig)
        .map_err(|_| RegistryError::new(Code::SignatureInvalid, "malformed Ed25519 signature"))?;
    Ok(vk.verify_strict(input, &signature).is_ok())
}

fn verify_rs256(n: &[u8], e: &[u8], sig: &[u8], input: &[u8]) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{BigUint, RsaPublicKey};
    use sha2::Sha256;

    let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)) else {
        return Err(RegistryError::new(
            Code::KeyInvalid,
            "not a valid RSA public key",
        ));
    };
    let vk = VerifyingKey::<Sha256>::new(key);
    let Ok(signature) = Signature::try_from(sig) else {
        return Ok(false);
    };
    Ok(vk.verify(input, &signature).is_ok())
}
