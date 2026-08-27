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
/// An earlier version also kept it as a string inside a JWK and claimed to wipe
/// that too — which it could not, since a `serde_json` string offers no way to
/// reach its buffer. Not making the copy is the only version of that promise
/// worth stating.
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
    pub fn public_jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(point.x().expect("an uncompressed point has x")),
            "y": b64url(point.y().expect("an uncompressed point has y")),
        })
    }

    /// The full JWK, built only when something is about to write it.
    fn private_jwk(&self) -> Value {
        let mut jwk = self.public_jwk();
        jwk["d"] = json!(b64url(&self.signing.to_bytes()));
        jwk
    }

    pub fn kid(&self) -> Result<String> {
        Ok(registry_core::Jwk::parse(&self.public_jwk())
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
        if path.exists() {
            return Err(Error::msg(format!(
                "{} already exists; a key file is never overwritten",
                path.display()
            )));
        }

        let contents = match passphrase {
            Some(passphrase) => encrypt(&self.private_jwk(), passphrase)?,
            None => serde_json::to_string_pretty(&self.private_jwk())? + "\n",
        };
        fs::write(path, contents)?;
        restrict(path, 0o600)
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
        .ok_or_else(|| Error::msg("malformed iteration count"))? as u32;

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

    #[test]
    fn a_key_identifier_cannot_escape_the_key_directory() {
        for bad in ["../../etc/passwd", "a/b", "", "with space"] {
            assert!(key_path(bad).is_err(), "accepted {bad:?}");
        }
        assert!(key_path("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs").is_ok());
    }
}
