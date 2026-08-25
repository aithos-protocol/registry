//! Write authorization: creation, rotation, replay and withdrawal.

mod common;

use std::collections::BTreeSet;

use common::{Signer, card_body, sign_card, sign_card_with, sign_payload};
use registry_core::{AgentState, Code, Status, evaluate_withdrawal, evaluate_write};
use semver::Version;
use serde_json::{Value, json};

const ORIGIN: &str = "https://registry.aithos.be";

fn state(id: &str, version: &str, digest: &str, kids: &[String]) -> AgentState {
    AgentState {
        agent_id: id.to_string(),
        status: Status::Active,
        card_digest: digest.to_string(),
        card_version: Version::parse(version).unwrap(),
        authorized_kids: kids.iter().cloned().collect(),
    }
}

fn kids(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// --- creation ------------------------------------------------------------

#[test]
fn creation_names_the_entry_after_its_genesis_key() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);

    let accepted = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap();
    assert!(accepted.is_creation);
    assert_eq!(accepted.agent_id, k.kid());
    assert_eq!(accepted.authorized_kids, kids(&[&k.kid()]));
    assert_eq!(accepted.card_digest, card.digest);
}

#[test]
fn creation_under_someone_elses_identifier_is_refused() {
    let mine = Signer::p256();
    let theirs = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&mine]);

    let err = evaluate_write(&theirs.kid(), &card, &[mine.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::AgentIdMismatch);
}

#[test]
fn an_ed25519_key_works_the_same_way() {
    let k = Signer::ed25519();
    let card = sign_card(card_body("1.0.0"), &[&k]);
    evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap();
}

// --- update and the lineage rule ----------------------------------------

#[test]
fn update_signed_by_the_authorized_key_is_accepted() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.1.0"), &[&k]);
    let current = state(&k.kid(), "1.0.0", "sha256:old", &[k.kid()]);

    let accepted = evaluate_write(&k.kid(), &card, &[k.jwk()], Some(&current)).unwrap();
    assert!(!accepted.is_creation);
    assert_eq!(accepted.card_version, Version::parse("1.1.0").unwrap());
}

#[test]
fn update_signed_only_by_a_stranger_is_refused() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let card = sign_card(card_body("1.1.0"), &[&stranger]);
    let current = state(&owner.kid(), "1.0.0", "sha256:old", &[owner.kid()]);

    let err = evaluate_write(&owner.kid(), &card, &[stranger.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

/// Adding a backup key: sign one version with both, and the authorized set
/// widens. This is the whole of §3.4, with no extra mechanism.
#[test]
fn co_signing_adds_a_backup_key() {
    let a = Signer::p256();
    let b = Signer::ed25519();
    let card = sign_card(card_body("1.1.0"), &[&a, &b]);
    let current = state(&a.kid(), "1.0.0", "sha256:old", &[a.kid()]);

    let accepted = evaluate_write(&a.kid(), &card, &[a.jwk(), b.jwk()], Some(&current)).unwrap();
    assert_eq!(accepted.authorized_kids, kids(&[&a.kid(), &b.kid()]));
}

/// Rotating away from a key: sign with the survivor only, and the old key
/// drops out of the set. The identifier does not move; it names the genesis.
#[test]
fn rotation_drops_the_retired_key_but_keeps_the_identifier() {
    let a = Signer::p256();
    let b = Signer::p256();
    let card = sign_card(card_body("2.0.0"), &[&b]);
    let current = state(&a.kid(), "1.1.0", "sha256:old", &[a.kid(), b.kid()]);

    let accepted = evaluate_write(&a.kid(), &card, &[b.jwk()], Some(&current)).unwrap();
    assert_eq!(accepted.agent_id, a.kid());
    assert_eq!(accepted.authorized_kids, kids(&[&b.kid()]));

    // The retired key can no longer act on its own.
    let retired = sign_card(card_body("3.0.0"), &[&a]);
    let after = state(&a.kid(), "2.0.0", "sha256:new", &[b.kid()]);
    let err = evaluate_write(&a.kid(), &retired, &[a.jwk()], Some(&after)).unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

// --- §6.4 replay --------------------------------------------------------

/// Every published version stays validly signed forever, so an observer who
/// never held the key could otherwise re-submit an old card. The strictly
/// increasing version is what stops that.
#[test]
fn replaying_an_older_card_is_refused() {
    let k = Signer::p256();
    let old = sign_card(card_body("1.0.0"), &[&k]);
    let current = state(&k.kid(), "1.5.0", "sha256:current", &[k.kid()]);

    let err = evaluate_write(&k.kid(), &old, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

#[test]
fn resubmitting_the_same_version_is_refused() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.5.0"), &[&k]);
    let current = state(&k.kid(), "1.5.0", "sha256:current", &[k.kid()]);

    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

#[test]
fn a_non_semver_version_is_refused() {
    let k = Signer::p256();
    let card = sign_card(card_body("v1"), &[&k]);
    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

// --- signature integrity -------------------------------------------------

#[test]
fn tampering_with_the_card_breaks_the_signature() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);

    let mut tampered = card.value.clone();
    tampered
        .as_object_mut()
        .unwrap()
        .insert("name".into(), json!("Impostor Agent"));
    let tampered = a2a_card::validate_value(tampered).unwrap();

    let err = evaluate_write(&k.kid(), &tampered, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
}

#[test]
fn a_kid_that_is_not_the_thumbprint_is_refused() {
    let k = Signer::p256();
    let card = sign_card_with(
        card_body("1.0.0"),
        &[&k],
        |s, _| json!({"alg": s.alg(), "typ": "JOSE", "kid": "not-a-thumbprint"}),
    );
    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::KidNotThumbprint);
}

#[test]
fn alg_none_is_refused() {
    let k = Signer::p256();
    let card = sign_card_with(
        card_body("1.0.0"),
        &[&k],
        |_, kid| json!({"alg": "none", "typ": "JOSE", "kid": kid}),
    );
    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::AlgNotAllowed);
}

/// Claiming EdDSA over a P-256 key must fail on the binding, never reach the
/// verifier.
#[test]
fn algorithm_confusion_is_refused() {
    let k = Signer::p256();
    let card = sign_card_with(
        card_body("1.0.0"),
        &[&k],
        |_, kid| json!({"alg": "EdDSA", "typ": "JOSE", "kid": kid}),
    );
    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::AlgNotAllowed);
}

#[test]
fn crit_and_b64_headers_are_refused() {
    for extra in [
        json!({"crit": ["b64"]}),
        json!({"b64": false}),
        json!({"nonce": "x"}),
    ] {
        let k = Signer::p256();
        let card = sign_card_with(card_body("1.0.0"), &[&k], |s, kid| {
            let mut h = json!({"alg": s.alg(), "typ": "JOSE", "kid": kid});
            for (name, value) in extra.as_object().unwrap() {
                h.as_object_mut()
                    .unwrap()
                    .insert(name.clone(), value.clone());
            }
            h
        });
        let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
        assert_eq!(err.code, Code::SignatureInvalid, "header extra {extra}");
    }
}

#[test]
fn an_unused_submitted_key_is_refused() {
    let k = Signer::p256();
    let spare = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);

    let err = evaluate_write(&k.kid(), &card, &[k.jwk(), spare.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::UnusedKey);
}

#[test]
fn an_unsigned_card_is_refused() {
    let k = Signer::p256();
    let card = a2a_card::validate_value(card_body("1.0.0")).unwrap();
    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
}

// --- §6.5 withdrawal ----------------------------------------------------

fn withdrawal_payload(agent_id: &str, digest: &str) -> Value {
    json!({
        "action": "withdraw",
        "agentId": agent_id,
        "cardDigest": digest,
        "issuedAt": "2026-08-25T12:00:00.000Z",
        "registryOrigin": ORIGIN,
    })
}

#[test]
fn a_key_holder_can_withdraw_their_own_entry() {
    let k = Signer::p256();
    let current = state(&k.kid(), "1.0.0", "sha256:current", &[k.kid()]);
    let (p, pl, s) = sign_payload(&k, &withdrawal_payload(&k.kid(), "sha256:current"));

    let by = evaluate_withdrawal(&current, ORIGIN, &p, &pl, &s, &[k.jwk()]).unwrap();
    assert_eq!(by, k.kid());
}

/// The payload binds the current digest, so a withdrawal captured against an
/// older version cannot be replayed later.
#[test]
fn a_withdrawal_for_an_older_version_is_refused() {
    let k = Signer::p256();
    let current = state(&k.kid(), "2.0.0", "sha256:current", &[k.kid()]);
    let (p, pl, s) = sign_payload(&k, &withdrawal_payload(&k.kid(), "sha256:previous"));

    let err = evaluate_withdrawal(&current, ORIGIN, &p, &pl, &s, &[k.jwk()]).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("cardDigest"));
}

#[test]
fn a_withdrawal_aimed_at_another_registry_is_refused() {
    let k = Signer::p256();
    let current = state(&k.kid(), "1.0.0", "sha256:current", &[k.kid()]);
    let mut payload = withdrawal_payload(&k.kid(), "sha256:current");
    payload
        .as_object_mut()
        .unwrap()
        .insert("registryOrigin".into(), json!("https://evil.example"));
    let (p, pl, s) = sign_payload(&k, &payload);

    let err = evaluate_withdrawal(&current, ORIGIN, &p, &pl, &s, &[k.jwk()]).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
}

#[test]
fn a_stranger_cannot_withdraw_an_entry() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let current = state(&owner.kid(), "1.0.0", "sha256:current", &[owner.kid()]);
    let (p, pl, s) = sign_payload(
        &stranger,
        &withdrawal_payload(&owner.kid(), "sha256:current"),
    );

    let err = evaluate_withdrawal(&current, ORIGIN, &p, &pl, &s, &[stranger.jwk()]).unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

#[test]
fn a_withdrawn_entry_accepts_no_further_write() {
    let k = Signer::p256();
    let card = sign_card(card_body("2.0.0"), &[&k]);
    let mut current = state(&k.kid(), "1.0.0", "sha256:current", &[k.kid()]);
    current.status = Status::Withdrawn;

    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::Withdrawn);
}
