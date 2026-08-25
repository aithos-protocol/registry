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
            if !s.starts_with("https://") || s.contains('#') || s.contains('@') {
                return Err(RegistryError::new(
                    Code::SignatureInvalid,
                    "`jku` must be an absolute HTTPS URL with no userinfo and no fragment",
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
            Code::CardInvalid,
            "EC point is not on the P-256 curve",
        ));
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return Ok(false);
    };
    Ok(vk.verify(input, &signature).is_ok())
}

fn verify_ed25519(x: &[u8], sig: &[u8], input: &[u8]) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if sig.len() != 64 {
        return Err(RegistryError::new(
            Code::SignatureInvalid,
            format!("EdDSA signature is {} bytes; 64 expected", sig.len()),
        ));
    }
    let bytes: [u8; 32] = x.try_into().expect("validated to 32 bytes at parse time");
    let Ok(vk) = VerifyingKey::from_bytes(&bytes) else {
        return Err(RegistryError::new(
            Code::CardInvalid,
            "not a valid Ed25519 public key",
        ));
    };
    let signature = Signature::from_slice(sig)
        .map_err(|_| RegistryError::new(Code::SignatureInvalid, "malformed Ed25519 signature"))?;
    Ok(vk.verify(input, &signature).is_ok())
}

fn verify_rs256(n: &[u8], e: &[u8], sig: &[u8], input: &[u8]) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{BigUint, RsaPublicKey};
    use sha2::Sha256;

    let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)) else {
        return Err(RegistryError::new(
            Code::CardInvalid,
            "not a valid RSA public key",
        ));
    };
    let vk = VerifyingKey::<Sha256>::new(key);
    let Ok(signature) = Signature::try_from(sig) else {
        return Ok(false);
    };
    Ok(vk.verify(input, &signature).is_ok())
}
