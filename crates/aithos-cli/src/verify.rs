//! Independent verification of a signed A2A Agent Card.
//!
//! This is the command the rest of the tool exists to make possible. Publishing
//! is rare — a few people, a few times a year. Verifying is what every consumer
//! of an agent does, and until now doing it meant reimplementing RFC 8785
//! canonicalization, A2A's field-presence rules and detached JWS.
//!
//! It deliberately works on any signed A2A card, not only cards from one
//! registry. A verifier that only trusts its own issuer is not a verifier.
//!
//! What it reports is as important as what it checks. A signature establishes
//! that a key holder published a document — nothing about a domain, a company,
//! or whether the endpoints inside the card are theirs. Output that lets a
//! reader believe otherwise would be a phishing tool with a tick next to it.

use std::collections::BTreeMap;
use std::time::Duration;

use a2a_card::CanonicalCard;
use a2a_card::canonical::digest;
use serde_json::Value;

use crate::error::{Error, Result};

/// Where a verifying key came from. It changes what the result means, so it is
/// never left implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Supplied by the operator out of band. The strongest case: the key was
    /// not taken from the same place as the thing it checks.
    Trusted,
    /// Fetched from the `jku` inside the card's own signature.
    SelfDeclared,
}

pub struct SignatureResult {
    pub kid: String,
    pub alg: String,
    pub source: Option<KeySource>,
    pub outcome: std::result::Result<(), String>,
}

pub struct Report {
    pub card_digest: String,
    pub payload_digest: String,
    pub name: String,
    pub version: String,
    pub signatures: Vec<SignatureResult>,
}

impl Report {
    /// Whether at least one signature verified against an out-of-band key.
    pub fn verified_against_trusted_key(&self) -> bool {
        self.signatures
            .iter()
            .any(|s| s.outcome.is_ok() && s.source == Some(KeySource::Trusted))
    }

    pub fn any_verified(&self) -> bool {
        self.signatures.iter().any(|s| s.outcome.is_ok())
    }
}

/// Verify every signature on a card.
///
/// `trusted` holds keys the operator supplied. Anything else is fetched from
/// the card's own `jku`, which proves only internal consistency — the document
/// and the key it names come from the same place.
pub fn verify(card: &CanonicalCard, trusted: &BTreeMap<String, Value>) -> Result<Report> {
    // An anchor was supplied, so the question being asked is "was this signed by
    // a key I hold?" — and falling back to the card's own `jku` answers a
    // different question while looking like an answer to that one.
    let anchored = !trusted.is_empty();
    let payload = card.signing_payload()?;
    let signatures = card
        .value
        .get("signatures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut results = Vec::new();
    for entry in &signatures {
        let protected = entry
            .get("protected")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let header = match registry_core::jws::parse_protected(protected) {
            Ok(header) => header,
            Err(e) => {
                results.push(SignatureResult {
                    kid: "?".into(),
                    alg: "?".into(),
                    source: None,
                    outcome: Err(e.detail),
                });
                continue;
            }
        };

        let (jwk, source) = match trusted.get(&header.kid) {
            Some(jwk) => (Some(jwk.clone()), Some(KeySource::Trusted)),
            None if anchored => {
                results.push(SignatureResult {
                    kid: header.kid.clone(),
                    alg: header.alg.as_str().into(),
                    source: None,
                    outcome: Err(
                        "no key you supplied has this thumbprint; the card's own `jku` was \
                         not consulted, because a trusted key set was given"
                            .into(),
                    ),
                });
                continue;
            }
            None => match header.jku.as_deref() {
                Some(url) => match fetch_key(url, &header.kid) {
                    Ok(jwk) => (Some(jwk), Some(KeySource::SelfDeclared)),
                    Err(e) => {
                        results.push(SignatureResult {
                            kid: header.kid.clone(),
                            alg: header.alg.as_str().into(),
                            source: None,
                            outcome: Err(e.to_string()),
                        });
                        continue;
                    }
                },
                None => {
                    results.push(SignatureResult {
                        kid: header.kid.clone(),
                        alg: header.alg.as_str().into(),
                        source: None,
                        outcome: Err(
                            "no key available: the signature names no `jku` and none was supplied"
                                .into(),
                        ),
                    });
                    continue;
                }
            },
        };

        let outcome = (|| {
            let jwk = registry_core::Jwk::parse(jwk.as_ref().expect("set above"))
                .map_err(|e| e.detail)?;
            registry_core::jws::verify_detached(&header, protected, signature, &payload, &jwk)
                .map_err(|e| e.detail)
        })();

        results.push(SignatureResult {
            kid: header.kid,
            alg: header.alg.as_str().into(),
            source,
            outcome,
        });
    }

    Ok(Report {
        card_digest: card.digest.clone(),
        payload_digest: digest(&payload),
        name: card.value["name"]
            .as_str()
            .unwrap_or("(unnamed)")
            .to_string(),
        version: card.card_version().unwrap_or("?").to_string(),
        signatures: results,
    })
}

/// Fetch one key from a JWKS named by a card.
///
/// The URL comes from the document being checked, so it is bounded on every
/// axis this tool can bound it: HTTPS only, no redirects at all, a short timeout
/// and a body limited while it is read.
///
/// Not bounded: where the name resolves to. A hostile card can point this at a
/// private address and read a coarse signal from the failure text. That is
/// accepted rather than overlooked — this is a command an operator runs against
/// a card they chose to inspect, from their own machine, and an address
/// blocklist is a large and evadable surface for a request the operator could
/// have made themselves with `curl`. It would be a different judgement in a
/// server that fetched `jku` on someone else's behalf; this one does not.
fn fetch_key(url: &str, kid: &str) -> Result<Value> {
    if !url.starts_with("https://") {
        return Err(Error::msg(format!("`jku` {url} is not an HTTPS URL")));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        // A redirect would let a card send this fetch somewhere its own URL did
        // not name, which is the whole value of reading the URL.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(Error::msg(format!(
            "`jku` {url} answered {}",
            response.status()
        )));
    }

    // Bounded while reading, not after. A hostile card can name a URL that
    // streams without end, and buffering it in order to measure it is the
    // attack rather than the defence against it.
    const MAX: u64 = 256 * 1024;
    if response.content_length().is_some_and(|len| len > MAX) {
        return Err(Error::msg(format!(
            "`jku` {url} declares more than 256 KiB"
        )));
    }

    let mut buffer = Vec::new();
    std::io::copy(&mut std::io::Read::take(response, MAX + 1), &mut buffer)?;
    if buffer.len() as u64 > MAX {
        return Err(Error::msg(format!(
            "`jku` {url} returned more than 256 KiB"
        )));
    }
    let body = String::from_utf8(buffer)
        .map_err(|_| Error::msg(format!("`jku` {url} did not return text")))?;

    let jwks: Value = serde_json::from_str(&body)?;
    jwks["keys"]
        .as_array()
        .and_then(|keys| {
            keys.iter().find(|k| {
                registry_core::Jwk::parse(k).is_ok_and(|parsed| parsed.thumbprint() == kid)
            })
        })
        .cloned()
        .ok_or_else(|| Error::msg(format!("{url} holds no key with thumbprint {kid}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card;
    use crate::keyfile::PrivateKey;

    fn trusted(key: &PrivateKey) -> BTreeMap<String, Value> {
        BTreeMap::from([(key.kid().unwrap(), key.public_jwk())])
    }

    #[test]
    fn a_signature_verifies_against_a_key_supplied_out_of_band() {
        let key = PrivateKey::generate();
        let signed = card::sign(
            &card::scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();

        let report = verify(&signed, &trusted(&key)).unwrap();
        assert!(report.verified_against_trusted_key());
        assert_eq!(report.signatures[0].source, Some(KeySource::Trusted));
        assert_eq!(report.card_digest, signed.digest);
    }

    #[test]
    fn a_tampered_card_does_not_verify() {
        let key = PrivateKey::generate();
        let signed = card::sign(
            &card::scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();

        let mut tampered = signed.value.clone();
        tampered["name"] = serde_json::json!("Impostor");
        let tampered = a2a_card::validate_value(tampered).unwrap();

        let report = verify(&tampered, &trusted(&key)).unwrap();
        assert!(!report.any_verified());
    }

    /// Without a key and without a `jku` there is nothing to check against, and
    /// the report has to say so rather than fall through to "no failures".
    #[test]
    fn an_unresolvable_key_is_a_failure_not_a_silence() {
        let key = PrivateKey::generate();
        let signed = card::sign(
            &card::scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();

        let report = verify(&signed, &BTreeMap::new()).unwrap();
        assert!(!report.any_verified());
        assert!(
            report.signatures[0]
                .outcome
                .as_ref()
                .unwrap_err()
                .contains("no key available")
        );
    }

    /// `--jwks` asks "was this signed by a key I hold?". Answering it by
    /// fetching the key the card names answers a different question — and the
    /// old code did that silently, then exited zero, so a card signed by an
    /// attacker passed a check the operator had scoped to their own keys.
    #[test]
    fn an_anchor_is_not_a_hint_to_fall_back_from() {
        let attacker = PrivateKey::generate();
        let unrelated = PrivateKey::generate();
        let card = card::sign(
            &card::scaffold("A", "https://a.example/x").unwrap(),
            &[&attacker],
            Some("https://attacker.example/jwks.json"),
        )
        .unwrap();

        // The anchor holds a key that signed nothing here.
        let report = verify(&card, &trusted(&unrelated)).unwrap();
        assert!(!report.any_verified());
        assert!(!report.verified_against_trusted_key());
        assert!(
            report.signatures[0]
                .outcome
                .as_ref()
                .unwrap_err()
                .contains("not consulted"),
            "{:?}",
            report.signatures[0].outcome
        );
    }

    #[test]
    fn a_jku_that_is_not_https_is_refused_without_a_request() {
        let err = fetch_key("http://internal.example/jwks.json", "x").unwrap_err();
        assert!(err.to_string().contains("not an HTTPS URL"));
    }
}
