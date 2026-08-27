//! Building, signing and checking cards.

use a2a_card::CanonicalCard;
use a2a_card::canonical::{b64url, canonicalize, signing_input};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::keyfile::PrivateKey;

/// A minimal card that already satisfies the strict profile.
///
/// Scaffolding one matters more than it looks: A2A requires protobuf field
/// presence to be applied before signing, so a card assembled by hand from the
/// specification's field list is very likely to be rejected for a reason that
/// reads like pedantry until it is explained.
pub fn scaffold(name: &str, url: &str) -> Value {
    json!({
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "description": "Describe what this agent does, in a sentence a person would recognise.",
        "name": name,
        "skills": [{
            "description": "Describe what this skill does.",
            "id": "example-skill",
            "name": "Example skill",
            "tags": ["example"],
        }],
        "supportedInterfaces": [{
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
            "url": url,
        }],
        "version": "0.1.0",
    })
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
        let protected = entry.get("protected")?.as_str()?;
        let Ok(header) = registry_core::jws::parse_protected(protected) else {
            continue;
        };
        let jku = header.jku?;
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
pub fn bump(card: &mut Value, level: &str) -> Result<semver::Version> {
    let raw = card
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg("the card has no `version`"))?;
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

    card["version"] = json!(v.to_string());
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scaffold_passes_the_strict_profile() {
        let card = scaffold("Example Agent", "https://agent.example/a2a");
        a2a_card::validate_value(card).expect("a scaffolded card must be publishable as is");
    }

    #[test]
    fn signing_produces_a_card_the_registry_would_accept() {
        let key = PrivateKey::generate();
        let card = sign(&scaffold("A", "https://a.example/x"), &[&key], None).unwrap();

        let state = None;
        registry_core::evaluate_write(&key.kid().unwrap(), &card, &[key.public_jwk()], state)
            .expect("the signed card must satisfy the write rules");
    }

    /// Signatures made over a different authorized set must not travel with an
    /// edited card: doing so would quietly widen what the registry accepts.
    #[test]
    fn re_signing_replaces_rather_than_appends() {
        let first = PrivateKey::generate();
        let second = PrivateKey::generate();
        let once = sign(&scaffold("A", "https://a.example/x"), &[&first], None).unwrap();
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
            &scaffold("A", "https://a.example/x"),
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
        let card = sign(&scaffold("A", "https://a.example/x"), &[&key], None).unwrap();
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
        let card = sign(&scaffold("A", "https://a.example/x"), &[&key], Some(&jku)).unwrap();
        assert_eq!(agent_of(&card.value, "https://registry.example"), None);
    }

    #[test]
    fn bumping_moves_one_component_and_clears_the_rest() {
        let mut card = json!({ "version": "1.4.7" });
        assert_eq!(bump(&mut card, "patch").unwrap().to_string(), "1.4.8");
        assert_eq!(bump(&mut card, "minor").unwrap().to_string(), "1.5.0");
        assert_eq!(bump(&mut card, "major").unwrap().to_string(), "2.0.0");
    }

    #[test]
    fn a_non_semver_version_is_explained_not_just_refused() {
        let mut card = json!({ "version": "v1" });
        let err = bump(&mut card, "patch").unwrap_err().to_string();
        assert!(err.contains("orders publications"), "got {err:?}");
    }
}
