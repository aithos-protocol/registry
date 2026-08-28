//! Public JWKs, RFC 7638 thumbprints and the key/algorithm binding.
//!
//! `SPEC.md` §3.2 makes the thumbprint the keystone of the whole design: a
//! signature's `kid` must equal the RFC 7638 thumbprint of the key that
//! verifies it. Since `kid` sits inside the signed protected header and the
//! thumbprint is a digest of the key material, a submitted public key cannot
//! be swapped for another. That is what lets the registry accept key material
//! in a plain request body without a second signed object wrapping it.

use a2a_card::canonical::{b64url, b64url_decode, canonicalize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Code, RegistryError, Result};

/// JOSE algorithms this registry accepts (`SPEC.md` §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    EdDsa,
    Rs256,
}

impl Alg {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "ES256" => Ok(Alg::Es256),
            "EdDSA" => Ok(Alg::EdDsa),
            "RS256" => Ok(Alg::Rs256),
            // `none` lands here, as does every algorithm-confusion attempt.
            other => Err(RegistryError::new(
                Code::AlgNotAllowed,
                format!("algorithm {other:?} is outside the allowlist ES256, EdDSA, RS256"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Es256 => "ES256",
            Alg::EdDsa => "EdDSA",
            Alg::Rs256 => "RS256",
        }
    }
}

/// The smallest RSA modulus accepted, in bits (`SPEC.md` §5.5).
pub const MIN_RSA_BITS: usize = 2048;

/// The largest RSA modulus this registry will accept.
///
/// The `rsa` crate refuses to construct a key above 4096 bits, so this is not a
/// policy choice so much as making an existing limit legible: without it the
/// refusal arrived at verification time, blaming the key's validity rather than
/// its size, after an identifier had already been derived from it — and told to
/// people.
pub const MAX_RSA_BITS: usize = 4096;

/// JWK members that carry private or symmetric key material. A publisher who
/// pastes the wrong file must be refused, not published.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A validated public JWK, kept alongside its original JSON so the JWKS
/// endpoint can serve exactly what was submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    value: Value,
    kind: KeyKind,
    thumbprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyKind {
    P256 { x: Vec<u8>, y: Vec<u8> },
    Ed25519 { x: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl Jwk {
    /// Parse and validate a JWK, rejecting private material and unsupported
    /// key types.
    pub fn parse(value: &Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| RegistryError::new(Code::KeyInvalid, "a JWK must be a JSON object"))?;

        for member in PRIVATE_MEMBERS {
            if obj.contains_key(*member) {
                return Err(RegistryError::new(
                    Code::PrivateKeySubmitted,
                    format!("JWK member {member:?} carries private or symmetric key material"),
                ));
            }
        }

        let kty = member_str(obj, "kty")?;
        let kind = match kty {
            "EC" => {
                let crv = member_str(obj, "crv")?;
                if crv != "P-256" {
                    return Err(RegistryError::new(
                        Code::AlgNotAllowed,
                        format!("EC curve {crv:?} is not supported; only P-256 is"),
                    ));
                }
                let x = fixed(member_str(obj, "x")?, 32, "x")?;
                let y = fixed(member_str(obj, "y")?, 32, "y")?;
                KeyKind::P256 { x, y }
            }
            "OKP" => {
                let crv = member_str(obj, "crv")?;
                if crv != "Ed25519" {
                    return Err(RegistryError::new(
                        Code::AlgNotAllowed,
                        format!("OKP curve {crv:?} is not supported; only Ed25519 is"),
                    ));
                }
                let x = fixed(member_str(obj, "x")?, 32, "x")?;
                KeyKind::Ed25519 { x }
            }
            "RSA" => {
                let n = decode(member_str(obj, "n")?, "n")?;
                let e = decode(member_str(obj, "e")?, "e")?;
                // RFC 7518 §6.3.1.1 requires the minimal big-endian octet
                // sequence: no leading zero byte. Accepting padding would let
                // one key present many encodings — many thumbprints, so many
                // `agentId`s for one holder — and would let a modulus be padded
                // up to whatever apparent size clears the floor below. Measuring
                // the stripped value alone is not enough: the padded bytes would
                // still be what the registry stores and republishes, so a
                // consumer measuring the served JWKS would read the wrong size.
                // Empty is not merely too small: `n.len() * 8 - leading_zeros`
                // underflows on it, which panics under overflow checks and
                // wraps past the size floor without them. Key parsing happens
                // before any signature or authorization check, so an anonymous
                // caller reaches this line.
                if n.is_empty() || e.is_empty() {
                    return Err(RegistryError::new(
                        Code::KeyInvalid,
                        "RSA `n` and `e` must not be empty",
                    ));
                }
                if n.first() == Some(&0) {
                    return Err(RegistryError::new(
                        Code::KeyInvalid,
                        "RSA modulus `n` has a leading zero byte; RFC 7518 requires the minimal encoding",
                    ));
                }
                if e.first() == Some(&0) {
                    return Err(RegistryError::new(
                        Code::KeyInvalid,
                        "RSA exponent `e` has a leading zero byte; RFC 7518 requires the minimal encoding",
                    ));
                }
                let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
                if bits < MIN_RSA_BITS {
                    return Err(RegistryError::new(
                        Code::AlgNotAllowed,
                        format!("RSA modulus is {bits} bits; the minimum is {MIN_RSA_BITS}"),
                    ));
                }
                // The verifier refuses anything above this, so a key over it
                // parses, yields a thumbprint — and therefore an `agentId` a
                // publisher may already have derived and told people about —
                // and can then never sign anything. Refusing at parse means
                // the answer names the reason.
                if bits > MAX_RSA_BITS {
                    return Err(RegistryError::new(
                        Code::AlgNotAllowed,
                        format!("RSA modulus is {bits} bits; the maximum is {MAX_RSA_BITS}"),
                    ));
                }
                KeyKind::Rsa { n, e }
            }
            // `oct` is symmetric: its "public" key is the secret itself.
            other => {
                return Err(RegistryError::new(
                    Code::AlgNotAllowed,
                    format!("key type {other:?} is not supported"),
                ));
            }
        };

        let thumbprint = compute_thumbprint(&kind)?;
        Ok(Jwk {
            value: value.clone(),
            kind,
            thumbprint,
        })
    }

    /// The RFC 7638 thumbprint, unpadded base64url. This is the key's `kid`
    /// and, for a genesis key, the agent's identifier.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The submitted JSON, exactly as received.
    ///
    /// Only for diagnostics. Never publish this: see [`Self::to_public`].
    pub fn as_submitted(&self) -> &Value {
        &self.value
    }

    /// The key as this registry will publish it.
    ///
    /// Rebuilt from the verified key material rather than passed through, and
    /// carrying only members this code checked: the RFC 7638 required set, the
    /// `kid` computed from it, and `use`. A submitted JWK may carry anything —
    /// a `kid` naming a different key, an `alg` this registry does not accept —
    /// and republishing that would mean vouching for values nobody validated,
    /// in the one document consumers are meant to trust.
    ///
    /// `kid` is required by §7.2 and is what makes the `jku` story work: a
    /// generic RFC 7515 verifier selects the key whose `kid` matches the
    /// signature's, and finds nothing if the registry omits it. Adding it does
    /// not disturb the thumbprint, which is computed over the required members
    /// alone.
    pub fn to_public(&self) -> Value {
        let mut jwk = match &self.kind {
            KeyKind::P256 { x, y } => json!({
                "crv": "P-256", "kty": "EC", "x": b64url(x), "y": b64url(y),
            }),
            KeyKind::Ed25519 { x } => json!({
                "crv": "Ed25519", "kty": "OKP", "x": b64url(x),
            }),
            KeyKind::Rsa { n, e } => json!({
                "e": b64url(e), "kty": "RSA", "n": b64url(n),
            }),
        };
        jwk["kid"] = json!(self.thumbprint);
        jwk["use"] = json!("sig");
        jwk
    }

    /// Whether this key type can be used with the given algorithm. Checking
    /// this before verification is what closes algorithm confusion.
    pub fn accepts(&self, alg: Alg) -> bool {
        matches!(
            (&self.kind, alg),
            (KeyKind::P256 { .. }, Alg::Es256)
                | (KeyKind::Ed25519 { .. }, Alg::EdDsa)
                | (KeyKind::Rsa { .. }, Alg::Rs256)
        )
    }
}

/// Opaque handle used by the verifier module.
pub(crate) enum KeyKindRef<'a> {
    P256 { x: &'a [u8], y: &'a [u8] },
    Ed25519 { x: &'a [u8] },
    Rsa { n: &'a [u8], e: &'a [u8] },
}

impl Jwk {
    pub(crate) fn key_ref(&self) -> KeyKindRef<'_> {
        match &self.kind {
            KeyKind::P256 { x, y } => KeyKindRef::P256 { x, y },
            KeyKind::Ed25519 { x } => KeyKindRef::Ed25519 { x },
            KeyKind::Rsa { n, e } => KeyKindRef::Rsa { n, e },
        }
    }
}

/// RFC 7638 §3: hash the canonical JSON of exactly the required members.
fn compute_thumbprint(kind: &KeyKind) -> Result<String> {
    let required = match kind {
        KeyKind::P256 { x, y } => json!({
            "crv": "P-256",
            "kty": "EC",
            "x": b64url(x),
            "y": b64url(y),
        }),
        KeyKind::Ed25519 { x } => json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": b64url(x),
        }),
        KeyKind::Rsa { n, e } => json!({
            "e": b64url(e),
            "kty": "RSA",
            "n": b64url(n),
        }),
    };
    // RFC 7638 asks for members ordered lexicographically by code point with
    // no whitespace. For these ASCII names that is exactly what JCS produces,
    // so the canonicalizer is reused rather than duplicated.
    let bytes = canonicalize(&required)
        .map_err(|e| RegistryError::new(Code::CardInvalid, e.to_string()))?;
    Ok(b64url(&Sha256::digest(&bytes)))
}

fn member_str<'a>(obj: &'a serde_json::Map<String, Value>, name: &str) -> Result<&'a str> {
    obj.get(name).and_then(Value::as_str).ok_or_else(|| {
        RegistryError::new(
            Code::KeyInvalid,
            format!("JWK member {name:?} is absent or not a string"),
        )
    })
}

fn decode(s: &str, name: &str) -> Result<Vec<u8>> {
    b64url_decode(s).map_err(|_| {
        RegistryError::new(
            Code::KeyInvalid,
            format!("JWK member {name:?} is not unpadded base64url"),
        )
    })
}

fn fixed(s: &str, len: usize, name: &str) -> Result<Vec<u8>> {
    let v = decode(s, name)?;
    if v.len() != len {
        return Err(RegistryError::new(
            Code::KeyInvalid,
            format!("JWK member {name:?} is {} bytes; {len} expected", v.len()),
        ));
    }
    Ok(v)
}
