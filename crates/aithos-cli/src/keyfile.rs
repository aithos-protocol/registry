//! Key files on disk.
//!
//! The model is the one every developer already has in their fingers: a file
//! under `~/.config/aithos/keys`, mode `0600`, no daemon and no agent. What it
//! holds is a JWK, because that is exactly what the protocol speaks — the
//! public half of the file is literally what gets submitted to a registry.
//!
//! At rest it is a JWE in compact form, `PBES2-HS256+A128KW` with `A256GCM`.
//! Standard JOSE rather than a private format, so the file can be inspected,
//! and so the parameters that matter are named in the header where anyone can
//! read them back.

use std::fs;
use std::path::{Path, PathBuf};

use a2a_card::canonical::{b64url, b64url_decode, canonicalize};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_kw::KekAes128;
use rand_core::RngCore;
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// PBKDF2 iterations. OWASP's floor for PBKDF2-HMAC-SHA256 at the time of
/// writing; recorded in the file header so an old file stays readable when this
/// number rises.
const ITERATIONS: u32 = 600_000;

/// The most iterations this will perform on a file's say-so.
///
/// The header is only authenticated after the derivation runs — that is how
/// PBES2 works — so a file claiming four billion iterations would hang for
/// hours before anything could tell you it had been tampered with. Generous
/// against the current cost, and finite.
const MAX_ITERATIONS: u64 = 10_000_000;

const ALG: &str = "PBES2-HS256+A128KW";
const ENC: &str = "A256GCM";

/// Where keys live, honouring `AITHOS_HOME` for anyone who keeps their
/// identities somewhere deliberate — a removable volume, say.
pub fn home() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("AITHOS_HOME") {
        return Ok(PathBuf::from(explicit));
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map_err(|_| Error::msg("neither AITHOS_HOME nor HOME is set"))?;
    Ok(base.join("aithos"))
}

pub fn key_dir() -> Result<PathBuf> {
    Ok(home()?.join("keys"))
}

pub fn key_path(kid: &str) -> Result<PathBuf> {
    // A thumbprint is unpadded base64url, so it can contain `-` and `_` but
    // never a path separator. Refusing anything else keeps a crafted name from
    // reaching outside the key directory.
    if kid.is_empty()
        || !kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::msg(format!("{kid:?} is not a key identifier")));
    }
    Ok(key_dir()?.join(format!("{kid}.jwk")))
}

/// A signing key held in memory.
///
/// The secret lives only inside `SigningKey`, which zeroizes itself on drop.
/// An earlier version also kept it *persistently* as a string inside a JWK and
/// claimed to wipe that too — which it could not, since a `serde_json` string
/// offers no way to reach its buffer.
///
/// What that does **not** claim: loading an encrypted key file decodes it into
/// a `serde_json::Value` on the way here, so the private scalar exists briefly
/// in a `String` this code cannot zeroize, as do the plaintext buffer and the
/// derived key-encryption key. Honouring the promise across that boundary would
/// mean a hand-rolled JWK decoder over a byte buffer. The property that holds is
/// narrower and worth stating precisely: nothing that *outlives the load* holds
/// a copy of the secret except the type that wipes itself.
pub struct PrivateKey {
    signing: p256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Generate a fresh P-256 key.
    ///
    /// P-256 rather than Ed25519 because a card published here should be
    /// verifiable by a generic A2A client, and `ES256` is the algorithm the
    /// specification itself uses in its examples.
    pub fn generate() -> Self {
        Self {
            signing: p256::ecdsa::SigningKey::random(&mut rand_core::OsRng),
        }
    }

    fn from_jwk(jwk: &Value) -> Result<Self> {
        let d = jwk
            .get("d")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::msg("the key file holds no private component"))?;
        let mut bytes =
            b64url_decode(d).map_err(|_| Error::msg("the private component is malformed"))?;
        let signing = p256::ecdsa::SigningKey::from_slice(&bytes)
            .map_err(|_| Error::msg("the private component is not a P-256 scalar"))?;
        bytes.zeroize();
        Ok(Self { signing })
    }

    /// The public half: what a registry is given, and what the thumbprint is
    /// computed over.
    /// Only the members RFC 7638 hashes.
    ///
    /// Kept separate from [`Self::public_jwk`] because the thumbprint is
    /// computed from this, and a `public_jwk` that carried the thumbprint while
    /// the thumbprint was computed from `public_jwk` recurses forever.
    fn bare_jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(point.x().expect("an uncompressed point has x")),
            "y": b64url(point.y().expect("an uncompressed point has y")),
        })
    }

    pub fn public_jwk(&self) -> Value {
        let mut jwk = self.bare_jwk();
        // A JWKS entry without a `kid` cannot be selected by a generic RFC 7515
        // verifier following `jku`, which is the whole interoperability story.
        // A registry rebuilds what it publishes rather than trusting this, but
        // a key handed to anything else should still describe itself.
        if let Ok(kid) = self.kid() {
            jwk["kid"] = json!(kid);
            jwk["use"] = json!("sig");
        }
        jwk
    }

    /// The full JWK, built only when something is about to write it.
    fn private_jwk(&self) -> Value {
        let mut jwk = self.bare_jwk();
        jwk["d"] = json!(b64url(&self.signing.to_bytes()));
        jwk
    }

    pub fn kid(&self) -> Result<String> {
        Ok(registry_core::Jwk::parse(&self.bare_jwk())
            .map_err(|e| Error::msg(e.to_string()))?
            .thumbprint()
            .to_string())
    }

    pub fn sign(&self, input: &[u8]) -> String {
        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = self.signing.sign(input);
        b64url(&signature.to_bytes())
    }

    /// Write the key, encrypting it unless `passphrase` is `None`.
    pub fn save(&self, path: &Path, passphrase: Option<&str>) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            restrict(parent, 0o700)?;
        }
        let contents = match passphrase {
            Some(passphrase) => encrypt(&self.private_jwk(), passphrase)?,
            None => serde_json::to_string_pretty(&self.private_jwk())? + "\n",
        };

        // Created at 0600, not created and then chmodded. With `--no-passphrase`
        // the file is plaintext private key material, and the window between
        // `write` and `chmod` is a window in which it sits at whatever the
        // umask allows — usually world-readable. `create_new` also replaces the
        // `path.exists()` check it used to do: asking and then acting is a race,
        // where refusing to create an existing file is one operation.
        write_new(path, contents.as_bytes()).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Error::msg(format!(
                "{} already exists; a key file is never overwritten",
                path.display()
            )),
            _ => Error::msg(format!("{}: {e}", path.display())),
        })
    }

    /// Read a key, prompting for a passphrase only if the file is encrypted.
    pub fn load(path: &Path, passphrase: impl FnOnce() -> Result<String>) -> Result<Self> {
        let raw =
            fs::read_to_string(path).map_err(|e| Error::msg(format!("{}: {e}", path.display())))?;
        let raw = raw.trim();

        if raw.starts_with('{') {
            return Self::from_jwk(&serde_json::from_str(raw)?);
        }
        Self::from_jwk(&decrypt(raw, &passphrase()?)?)
    }

    /// Whether a key file is passphrase-protected, without reading the key.
    pub fn is_encrypted(path: &Path) -> Result<bool> {
        let raw = fs::read_to_string(path)?;
        Ok(!raw.trim_start().starts_with('{'))
    }
}

/// Create a file that must not already exist, readable only by its owner.
#[cfg(unix)]
fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    // Windows inherits the parent directory's ACL; there is no mode to set.
    Ok(())
}

// --- JWE ------------------------------------------------------------------

fn derive(passphrase: &str, salt_input: &[u8], iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), salt_input, iterations, &mut key);
    key
}

/// RFC 7518 §4.8.1.1: the PBKDF2 salt is the algorithm name, a zero byte, then
/// the `p2s` header value — so a password reused across algorithms never
/// derives the same key.
fn salt_input(p2s: &[u8]) -> Vec<u8> {
    let mut salt = ALG.as_bytes().to_vec();
    salt.push(0);
    salt.extend_from_slice(p2s);
    salt
}

fn encrypt(jwk: &Value, passphrase: &str) -> Result<String> {
    let mut p2s = [0u8; 16];
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut p2s);
    rand_core::OsRng.fill_bytes(&mut cek);
    rand_core::OsRng.fill_bytes(&mut iv);

    let header = json!({
        "alg": ALG,
        "enc": ENC,
        "p2s": b64url(&p2s),
        "p2c": ITERATIONS,
    });
    let protected = b64url(&canonicalize(&header).map_err(|e| Error::msg(e.to_string()))?);

    let kek = KekAes128::new(&derive(passphrase, &salt_input(&p2s), ITERATIONS).into());
    let mut wrapped = [0u8; 40];
    kek.wrap(&cek, &mut wrapped)
        .map_err(|e| Error::msg(format!("wrapping the content key: {e}")))?;

    let plaintext = serde_json::to_vec(jwk)?;
    let cipher = Aes256Gcm::new(&cek.into());
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &plaintext,
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| Error::msg("encrypting the key"))?;

    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    cek.zeroize();

    Ok(format!(
        "{protected}.{}.{}.{}.{}\n",
        b64url(&wrapped),
        b64url(&iv),
        b64url(ciphertext),
        b64url(tag)
    ))
}

fn decrypt(compact: &str, passphrase: &str) -> Result<Value> {
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 5 {
        return Err(Error::msg("the key file is neither a JWK nor a JWE"));
    }

    let header: Value = serde_json::from_slice(
        &b64url_decode(parts[0]).map_err(|_| Error::msg("malformed key file header"))?,
    )?;
    if header["alg"] != json!(ALG) || header["enc"] != json!(ENC) {
        return Err(Error::msg(format!(
            "the key file uses {} with {}, which this version does not read",
            header["alg"], header["enc"]
        )));
    }

    let p2s = b64url_decode(header["p2s"].as_str().unwrap_or_default())
        .map_err(|_| Error::msg("malformed salt"))?;
    let iterations = header["p2c"]
        .as_u64()
        .ok_or_else(|| Error::msg("malformed iteration count"))?;
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(Error::msg(format!(
            "the key file asks for {iterations} iterations; this refuses anything above \
             {MAX_ITERATIONS}, since the header cannot be authenticated until the derivation \
             has already run"
        )));
    }
    let iterations = iterations as u32;

    let decode = |part: &str| b64url_decode(part).map_err(|_| Error::msg("malformed key file"));
    let (wrapped, iv, ciphertext, tag) = (
        decode(parts[1])?,
        decode(parts[2])?,
        decode(parts[3])?,
        decode(parts[4])?,
    );

    let kek = KekAes128::new(&derive(passphrase, &salt_input(&p2s), iterations).into());
    let mut cek = [0u8; 32];
    kek.unwrap(&wrapped, &mut cek)
        .map_err(|_| Error::msg("wrong passphrase"))?;

    // `Nonce::from_slice` asserts on length rather than returning an error, so a
    // truncated `iv` — disk corruption, or anyone who can write but not read the
    // key file — panicked with a backtrace instead of reaching the "has been
    // altered" message three lines below. Every other segment's length is
    // checked by the primitive that consumes it; this one was not.
    if iv.len() != 12 {
        cek.zeroize();
        return Err(Error::msg("the key file has been altered"));
    }

    let mut sealed = ciphertext;
    sealed.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new(&cek.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &sealed,
                aad: parts[0].as_bytes(),
            },
        )
        .map_err(|_| Error::msg("the key file has been altered"))?;
    cek.zeroize();

    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_survives_a_round_trip_through_encryption() {
        let key = PrivateKey::generate();
        let sealed = encrypt(&key.private_jwk(), "correct horse").unwrap();
        assert_eq!(sealed.split('.').count(), 5, "JWE compact serialization");

        let recovered = decrypt(sealed.trim(), "correct horse").unwrap();
        assert_eq!(recovered["d"], key.private_jwk()["d"]);
    }

    #[test]
    fn a_wrong_passphrase_is_reported_as_such() {
        let sealed = encrypt(&PrivateKey::generate().private_jwk(), "right").unwrap();
        let err = decrypt(sealed.trim(), "wrong").unwrap_err().to_string();
        assert!(err.contains("passphrase"), "got {err:?}");
    }

    /// The protected header is the AEAD's additional data, so editing the
    /// iteration count to something cheap cannot go unnoticed.
    #[test]
    fn tampering_with_the_header_is_detected() {
        let sealed = encrypt(&PrivateKey::generate().private_jwk(), "pass").unwrap();
        let mut parts: Vec<String> = sealed.trim().split('.').map(str::to_owned).collect();
        let header = json!({"alg": ALG, "enc": ENC, "p2s": "AAAAAAAAAAAAAAAAAAAAAA", "p2c": 1});
        parts[0] = b64url(&canonicalize(&header).unwrap());
        assert!(decrypt(&parts.join("."), "pass").is_err());
    }

    #[test]
    fn the_public_half_carries_no_private_component() {
        let key = PrivateKey::generate();
        let public = key.public_jwk();
        assert!(public.get("d").is_none());
        assert_eq!(public["kty"], json!("EC"));
        // The thumbprint is computed over the public half alone.
        assert_eq!(key.kid().unwrap().len(), 43);
    }

    /// The thumbprint is computed from the bare members, and the published form
    /// carries it. Deriving one from the other in both directions recurses.
    #[test]
    fn the_published_form_carries_the_thumbprint_without_recursing() {
        let key = PrivateKey::generate();
        let public = key.public_jwk();
        assert_eq!(public["kid"], json!(key.kid().unwrap()));
        assert_eq!(public["use"], json!("sig"));
        assert!(public.get("d").is_none());
        // Parsing the published form back yields the same identity.
        assert_eq!(
            registry_core::Jwk::parse(&public).unwrap().thumbprint(),
            key.kid().unwrap()
        );
    }

    #[test]
    fn a_key_identifier_cannot_escape_the_key_directory() {
        for bad in ["../../etc/passwd", "a/b", "", "with space"] {
            assert!(key_path(bad).is_err(), "accepted {bad:?}");
        }
        assert!(key_path("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs").is_ok());
    }
}
