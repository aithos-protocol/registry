//! Building, signing and checking cards.

use a2a_card::CanonicalCard;
use a2a_card::canonical::{b64url, canonicalize, signing_input};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::keyfile::PrivateKey;

/// A minimal card that already satisfies the strict profile.
///
/// Built with the official A2A SDK's types and encoded by its proto3 JSON
/// layer, never written out as JSON by hand: `a2a_card_sdk::encode` adds only
/// the `REQUIRED` defaults A2A §8.4.1 asks for and refuses anything the
/// registry would refuse.
pub fn scaffold(name: &str, url: &str) -> Result<Value> {
    use a2a_card_sdk::{AgentCapabilities, AgentCard, AgentInterface, AgentSkill};
    let card = AgentCard {
        name: name.into(),
        description: "Describe what this agent does, in a sentence a person would recognise."
            .into(),
        version: "0.1.0".into(),
        supported_interfaces: vec![AgentInterface::new(
            url,
            a2a_card_sdk::TRANSPORT_PROTOCOL_HTTP_JSON,
        )],
        capabilities: AgentCapabilities::default(),
        default_input_modes: vec!["application/json".into()],
        default_output_modes: vec!["application/json".into()],
        skills: vec![AgentSkill {
            id: "example-skill".into(),
            name: "Example skill".into(),
            description: "Describe what this skill does.".into(),
            tags: vec!["example".into()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    };
    Ok(a2a_card_sdk::encode(&card)?.value)
}

/// Parse and validate a card file, keeping any signatures it already carries.
pub fn load(path: &std::path::Path) -> Result<CanonicalCard> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::msg(format!("{}: {e}", path.display())))?;
    Ok(a2a_card::parse_card(&text)?)
}

/// Sign a card with each key and return the assembled document.
///
/// Existing signatures are dropped rather than added to: they were made over a
/// different set of authorized keys, and carrying them forward would quietly
/// widen what the registry accepts.
pub fn sign(card: &Value, keys: &[&PrivateKey], jku: Option<&str>) -> Result<CanonicalCard> {
    let mut body = card.clone();
    body.as_object_mut()
        .ok_or_else(|| Error::msg("a card must be a JSON object"))?
        .remove("signatures");

    let payload = canonicalize(&body)?;
    let mut signatures = Vec::with_capacity(keys.len());
    for key in keys {
        let mut header = json!({ "alg": "ES256", "typ": "JOSE", "kid": key.kid()? });
        if let Some(jku) = jku {
            header["jku"] = json!(jku);
        }
        let protected = b64url(&canonicalize(&header)?);
        let signature = key.sign(&signing_input(&protected, &payload));
        signatures.push(json!({ "protected": protected, "signature": signature }));
    }

    body.as_object_mut()
        .expect("checked above")
        .insert("signatures".into(), Value::Array(signatures));
    Ok(a2a_card::validate_value(body)?)
}

/// Build the publication proof §6.2 requires alongside a card.
///
/// The card's own signatures say "this document was signed by these keys". They
/// do not say where the signer wants it published, or under which identifier —
/// a card is portable by design. The proof says exactly that, and only that.
pub fn publication_proof(
    key: &PrivateKey,
    registry: &str,
    agent_id: &str,
    card_digest: &str,
) -> Result<Value> {
    let payload = json!({
        "action": "publish",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": now_rfc3339(),
        "registryOrigin": registry,
    });
    let bytes = canonicalize(&payload)?;
    let header = json!({ "alg": "ES256", "typ": "JOSE", "kid": key.kid()? });
    let protected = b64url(&canonicalize(&header)?);
    Ok(json!({
        "protected": protected,
        "payload": b64url(&bytes),
        "signature": key.sign(&signing_input(&protected, &bytes)),
    }))
}

/// Build the withdrawal §6.5 requires.
///
/// The same construction as the publication proof, over a different action and
/// bound to the digest of the card being withdrawn — so a withdrawal captured
/// today cannot be replayed against a later version of the entry.
pub fn withdrawal(
    key: &PrivateKey,
    registry: &str,
    agent_id: &str,
    card_digest: &str,
) -> Result<Value> {
    let payload = json!({
        "action": "withdraw",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": now_rfc3339(),
        "registryOrigin": registry,
    });
    let bytes = canonicalize(&payload)?;
    let header = json!({ "alg": "ES256", "typ": "JOSE", "kid": key.kid()? });
    let protected = b64url(&canonicalize(&header)?);
    Ok(json!({
        "protected": protected,
        "payload": b64url(&bytes),
        "signature": key.sign(&signing_input(&protected, &bytes)),
    }))
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting of a valid instant cannot fail")
}

/// Which entry a card belongs to.
///
/// The identifier is the thumbprint of the entry's *genesis* key and never
/// changes, so it cannot be derived from whoever happens to be signing now —
/// doing that turns a rotation into the creation of a second, unrelated entry.
///
/// A card that has been published carries its own address: the `jku` inside its
/// signed header names the entry's key set. That is read back here, which means
/// rotating keys needs no bookkeeping on the side.
pub fn agent_of(card: &Value, registry: &str) -> Option<String> {
    let signatures = card.get("signatures")?.as_array()?;
    for entry in signatures {
        // Every step here skips to the next signature rather than giving up on
        // the card. A `?` anywhere in this loop means a card whose *first*
        // signature is unreadable loses its entry association entirely — and
        // `publish` then falls back to the signing key's own thumbprint,
        // quietly creating a second entry instead of updating the one this card
        // belongs to. That is the worst outcome available here, so nothing in
        // this loop may return early.
        let Some(protected) = entry.get("protected").and_then(Value::as_str) else {
            continue;
        };
        let Ok(header) = registry_core::jws::parse_protected(protected) else {
            continue;
        };
        let Some(jku) = header.jku else { continue };
        let prefix = format!("{registry}/v1/agents/");
        if let Some(rest) = jku.strip_prefix(&prefix)
            && let Some(id) = rest.strip_suffix("/jwks.json")
            && !id.is_empty()
            && !id.contains('/')
        {
            return Some(id.to_string());
        }
    }
    None
}

/// Raise a card's version.
///
/// The card goes through the A2A SDK model and back. `decode` guarantees the
/// round trip is exact, so a card the SDK cannot carry is refused with the
/// reason instead of being signed with a member silently lost.
pub fn bump(card: &mut Value, level: &str) -> Result<semver::Version> {
    let canonical = a2a_card::validate_value(card.clone())?;
    let mut sdk = a2a_card_sdk::decode(&canonical).map_err(|e| {
        Error::msg(format!(
            "{e}\n\nSet the version in the card yourself and publish without --bump."
        ))
    })?;
    let raw = sdk.version.clone();
    let mut v: semver::Version = raw.parse().map_err(|_| {
        Error::msg(format!(
            "the card's version is {raw:?}, which is not Semantic Versioning. \
             A registry orders publications by it, so it has to be comparable."
        ))
    })?;

    match level {
        "major" => {
            v.major += 1;
            v.minor = 0;
            v.patch = 0;
        }
        "minor" => {
            v.minor += 1;
            v.patch = 0;
        }
        "patch" => v.patch += 1,
        other => {
            return Err(Error::msg(format!(
                "{other:?} is not major, minor or patch"
            )));
        }
    }
    v.pre = semver::Prerelease::EMPTY;
    v.build = semver::BuildMetadata::EMPTY;

    sdk.version = v.to_string();
    *card = a2a_card_sdk::encode(&sdk)?.value;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scaffold_passes_the_strict_profile() {
        let card = scaffold("Example Agent", "https://agent.example/a2a").unwrap();
        a2a_card::validate_value(card).expect("a scaffolded card must be publishable as is");
    }

    /// The CLI and the registry must agree exactly, so this drives the real
    /// admission rules rather than asserting on the shape of what was produced.
    #[test]
    fn signing_produces_a_write_the_registry_would_accept() {
        const REGISTRY: &str = "https://registry.example";
        let key = PrivateKey::generate();
        let agent_id = key.kid().unwrap();
        let card = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();
        let proof = publication_proof(&key, REGISTRY, &agent_id, &card.digest).unwrap();

        registry_core::evaluate_write(
            &agent_id,
            &card,
            &[key.public_jwk()],
            &[jws_of(&proof)],
            REGISTRY,
            None,
        )
        .expect("the signed card and its proof must satisfy the write rules");
    }

    /// A proof minted for one registry must not open an entry at another. This
    /// is the property that stops a card published anywhere from being replayed
    /// into this registry by whoever can read it.
    #[test]
    fn a_proof_does_not_travel_between_registries() {
        let key = PrivateKey::generate();
        let agent_id = key.kid().unwrap();
        let card = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();
        let proof =
            publication_proof(&key, "https://elsewhere.example", &agent_id, &card.digest).unwrap();

        let err = registry_core::evaluate_write(
            &agent_id,
            &card,
            &[key.public_jwk()],
            &[jws_of(&proof)],
            "https://registry.example",
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, registry_core::Code::SignatureInvalid);
        assert!(err.detail.contains("registryOrigin"), "{}", err.detail);
    }

    fn jws_of(proof: &Value) -> registry_core::DetachedJws {
        let field = |n: &str| proof[n].as_str().unwrap().to_string();
        registry_core::DetachedJws {
            protected: field("protected"),
            payload: field("payload"),
            signature: field("signature"),
        }
    }

    /// Signatures made over a different authorized set must not travel with an
    /// edited card: doing so would quietly widen what the registry accepts.
    #[test]
    fn re_signing_replaces_rather_than_appends() {
        let first = PrivateKey::generate();
        let second = PrivateKey::generate();
        let once = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&first],
            None,
        )
        .unwrap();
        let twice = sign(&once.value, &[&second], None).unwrap();

        let signatures = twice.value["signatures"].as_array().unwrap();
        assert_eq!(signatures.len(), 1);
    }

    /// Rotation must not create a second entry: the identifier belongs to the
    /// entry, not to whoever signs a given version.
    #[test]
    fn a_published_card_remembers_which_entry_it_belongs_to() {
        let genesis = PrivateKey::generate();
        let successor = PrivateKey::generate();
        let registry = "https://registry.example";
        let jku = format!("{registry}/v1/agents/{}/jwks.json", genesis.kid().unwrap());

        let published = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&genesis],
            Some(&jku),
        )
        .unwrap();
        assert_eq!(
            agent_of(&published.value, registry),
            Some(genesis.kid().unwrap())
        );

        // Re-signed by the successor alone, it still names the same entry.
        let rotated = sign(&published.value, &[&successor], Some(&jku)).unwrap();
        assert_eq!(
            agent_of(&rotated.value, registry),
            Some(genesis.kid().unwrap())
        );
        assert_ne!(
            agent_of(&rotated.value, registry),
            Some(successor.kid().unwrap())
        );
    }

    #[test]
    fn an_unpublished_card_belongs_to_no_entry_yet() {
        let key = PrivateKey::generate();
        let card = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            None,
        )
        .unwrap();
        assert_eq!(agent_of(&card.value, "https://registry.example"), None);
    }

    /// A `jku` pointing somewhere else says nothing about this registry.
    #[test]
    fn a_foreign_jku_is_not_read_as_an_entry_here() {
        let key = PrivateKey::generate();
        let jku = format!(
            "https://elsewhere.example/v1/agents/{}/jwks.json",
            key.kid().unwrap()
        );
        let card = sign(
            &scaffold("A", "https://a.example/x").unwrap(),
            &[&key],
            Some(&jku),
        )
        .unwrap();
        assert_eq!(agent_of(&card.value, "https://registry.example"), None);
    }

    #[test]
    fn bumping_moves_one_component_and_clears_the_rest() {
        let mut card = scaffold("A", "https://a.example/x").unwrap();
        card["version"] = json!("1.4.7");
        assert_eq!(bump(&mut card, "patch").unwrap().to_string(), "1.4.8");
        assert_eq!(bump(&mut card, "minor").unwrap().to_string(), "1.5.0");
        assert_eq!(bump(&mut card, "major").unwrap().to_string(), "2.0.0");
    }

    #[test]
    fn a_non_semver_version_is_explained_not_just_refused() {
        let mut card = scaffold("A", "https://a.example/x").unwrap();
        card["version"] = json!("v1");
        let err = bump(&mut card, "patch").unwrap_err().to_string();
        assert!(err.contains("orders publications"), "got {err:?}");
    }
}
