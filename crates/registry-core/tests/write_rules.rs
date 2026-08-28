//! Write authorization: creation, rotation, replay and withdrawal.

mod common;

use std::collections::BTreeSet;

use a2a_card::CanonicalCard;
use a2a_card::canonical::{b64url, canonicalize};
use common::{Signer, card_body, sign_card, sign_card_raw, sign_card_with, sign_payload};
use registry_core::{
    AcceptedWrite, AgentState, Code, DetachedJws, Outcome, Status, evaluate_withdrawal,
    evaluate_write,
};
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

/// Drive the admission rules with a publication proof (§6.2) signed by `prover`.
///
/// Every write carries one, and it is not what most of these tests are about,
/// so it is minted here rather than spelled out at each call site. `prover` is
/// named explicitly because *which* key signs it is load-bearing: the genesis
/// key on a creation, a currently authorized one on an update.
fn write_with(
    provers: &[&Signer],
    agent_id: &str,
    card: &CanonicalCard,
    keys: &[Value],
    current: Option<&AgentState>,
) -> registry_core::Result<AcceptedWrite> {
    let proofs: Vec<DetachedJws> = provers
        .iter()
        .map(|p| proof_by(p, agent_id, &card.digest))
        .collect();
    evaluate_write(agent_id, card, keys, &proofs, ORIGIN, current)
}

fn proof_by(prover: &Signer, agent_id: &str, card_digest: &str) -> DetachedJws {
    let payload = json!({
        "action": "publish",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": "2026-08-25T12:00:00Z",
        "registryOrigin": ORIGIN,
    });
    let (protected, payload, signature) = sign_payload(prover, &payload);
    DetachedJws {
        protected,
        payload,
        signature,
    }
}

// --- creation ------------------------------------------------------------

#[test]
fn creation_names_the_entry_after_its_genesis_key() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);

    let accepted = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap();
    assert!(accepted.is_creation());
    assert_eq!(accepted.agent_id, k.kid());
    assert_eq!(accepted.authorized_kids, kids(&[&k.kid()]));
    assert_eq!(accepted.card_digest, card.digest);
}

#[test]
fn creation_under_someone_elses_identifier_is_refused() {
    let mine = Signer::p256();
    let theirs = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&mine]);

    let err = write_with(&[&mine], &theirs.kid(), &card, &[mine.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::AgentIdMismatch);
}

#[test]
fn an_ed25519_key_works_the_same_way() {
    let k = Signer::ed25519();
    let card = sign_card(card_body("1.0.0"), &[&k]);
    write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap();
}

// --- update and the lineage rule ----------------------------------------

#[test]
fn update_signed_by_the_authorized_key_is_accepted() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.1.0"), &[&k]);
    let current = state(&k.kid(), "1.0.0", "sha256:old", &[k.kid()]);

    let accepted = write_with(&[&k], &k.kid(), &card, &[k.jwk()], Some(&current)).unwrap();
    assert!(!accepted.is_creation());
    assert_eq!(accepted.card_version, Version::parse("1.1.0").unwrap());
}

#[test]
fn update_signed_only_by_a_stranger_is_refused() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let card = sign_card(card_body("1.1.0"), &[&stranger]);
    let current = state(&owner.kid(), "1.0.0", "sha256:old", &[owner.kid()]);

    let err = write_with(
        &[&stranger],
        &owner.kid(),
        &card,
        &[stranger.jwk()],
        Some(&current),
    )
    .unwrap_err();
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

    let accepted = write_with(
        &[&a, &b],
        &a.kid(),
        &card,
        &[a.jwk(), b.jwk()],
        Some(&current),
    )
    .unwrap();
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

    let accepted = write_with(&[&b], &a.kid(), &card, &[b.jwk()], Some(&current)).unwrap();
    assert_eq!(accepted.agent_id, a.kid());
    assert_eq!(accepted.authorized_kids, kids(&[&b.kid()]));

    // The retired key can no longer act on its own.
    let retired = sign_card(card_body("3.0.0"), &[&a]);
    let after = state(&a.kid(), "2.0.0", "sha256:new", &[b.kid()]);
    let err = write_with(&[&a], &a.kid(), &retired, &[a.jwk()], Some(&after)).unwrap_err();
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

    let err = write_with(&[&k], &k.kid(), &old, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

/// A client that retries after a network timeout sends the same bytes again.
/// That happens routinely — the write may have succeeded and only the response
/// been lost — so it reports success rather than a conflict.
#[test]
fn resubmitting_identical_bytes_is_a_no_op() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.5.0"), &[&k]);
    let current = state(&k.kid(), "1.5.0", &card.digest, &[k.kid()]);

    let accepted = write_with(&[&k], &k.kid(), &card, &[k.jwk()], Some(&current)).unwrap();
    assert_eq!(accepted.outcome, Outcome::Unchanged);
    assert_eq!(accepted.card_digest, card.digest);
}

/// Signing twice reproduces the same document, so re-signing unchanged content
/// is indistinguishable from resubmitting it.
///
/// All three accepted algorithms are deterministic: ES256 through RFC 6979,
/// EdDSA by construction, RS256 through PKCS#1 v1.5. A client signing with a
/// randomised ECDSA implementation would produce a different document for the
/// same content, and would then need a new version like any other change —
/// which is why the rule is stated on the digest and not on the content.
#[test]
fn signing_the_same_content_twice_reproduces_the_same_document() {
    let k = Signer::p256();
    let first = sign_card(card_body("1.5.0"), &[&k]);
    let second = sign_card(card_body("1.5.0"), &[&k]);
    assert_eq!(first.digest, second.digest);
}

/// Different content at the same version is refused, whoever signed it. This
/// is the invariant the no-op case must not weaken.
#[test]
fn different_content_at_the_same_version_is_refused() {
    let k = Signer::p256();
    let published = sign_card(card_body("1.5.0"), &[&k]);
    let mut edited = card_body("1.5.0");
    edited["name"] = serde_json::json!("Renamed without bumping");
    let edited = sign_card(edited, &[&k]);
    assert_ne!(published.digest, edited.digest);

    let current = state(&k.kid(), "1.5.0", &published.digest, &[k.kid()]);
    let err = write_with(&[&k], &k.kid(), &edited, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

/// An unauthorized caller must not be able to probe whether its bytes match
/// the published ones: the lineage rule is checked first.
#[test]
fn an_identical_resubmission_from_a_stranger_is_still_refused() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let card = sign_card(card_body("1.5.0"), &[&stranger]);
    let current = state(&owner.kid(), "1.5.0", &card.digest, &[owner.kid()]);

    let err = write_with(
        &[&stranger],
        &owner.kid(),
        &card,
        &[stranger.jwk()],
        Some(&current),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

/// A version that is not semver at all is a malformed card, not a card whose
/// version failed to move. Reporting it as `VERSION_NOT_INCREASING` sent
/// publishers looking for a predecessor that does not exist.
#[test]
fn a_non_semver_version_is_refused_as_malformed() {
    let k = Signer::p256();
    let card = sign_card(card_body("v1"), &[&k]);
    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::CardInvalid);
    assert!(
        err.detail.contains("v1"),
        "detail should quote the version: {}",
        err.detail
    );
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

    let err = write_with(&[&k], &k.kid(), &tampered, &[k.jwk()], None).unwrap_err();
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
    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
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
    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
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
    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
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
        let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
        assert_eq!(err.code, Code::SignatureInvalid, "header extra {extra}");
    }
}

#[test]
fn an_unused_submitted_key_is_refused() {
    let k = Signer::p256();
    let spare = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);

    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk(), spare.jwk()], None).unwrap_err();
    assert_eq!(err.code, Code::UnusedKey);
}

#[test]
fn an_unsigned_card_is_refused() {
    let k = Signer::p256();
    let card = a2a_card::validate_value(card_body("1.0.0")).unwrap();
    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], None).unwrap_err();
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

    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::Withdrawn);
}

// --- round-2 audit regressions ------------------------------------------

/// The Ed25519 identity point is a valid encoding that decompresses, has small
/// order, and — under the permissive verification equation — accepts the
/// all-zero signature over *any* message. Its thumbprint is a constant, so if
/// the registry took it, one publicly derivable `agentId` would be writable by
/// anyone on earth with no key material at all.
#[test]
fn the_ed25519_identity_point_is_not_a_key() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(&identity),
    });
    let kid = registry_core::Jwk::parse(&jwk)
        .unwrap()
        .thumbprint()
        .to_string();

    // R = identity, S = 0 satisfies the cofactorless equation for any input.
    let mut signature = [0u8; 64];
    signature[0] = 1;
    let card = sign_card_raw(
        card_body("1.0.0"),
        &json!({"alg": "EdDSA", "typ": "JOSE", "kid": kid}),
        &b64url(&signature),
    );

    let proof = DetachedJws {
        protected: b64url(
            &canonicalize(&json!({"alg": "EdDSA", "typ": "JOSE", "kid": kid})).unwrap(),
        ),
        payload: b64url(
            &canonicalize(&json!({
                "action": "publish",
                "agentId": kid,
                "cardDigest": card.digest,
                "issuedAt": "2026-08-25T12:00:00Z",
                "registryOrigin": ORIGIN,
            }))
            .unwrap(),
        ),
        signature: b64url(&signature),
    };

    let err = evaluate_write(&kid, &card, &[jwk], &[proof], ORIGIN, None).unwrap_err();
    assert_eq!(err.code, Code::AlgNotAllowed, "{}", err.detail);
    assert!(err.detail.contains("small order"), "{}", err.detail);
}

/// An RSA modulus padded with leading zero bytes measures as long as its
/// encoding, not as large as the number. Without the minimal-encoding rule a
/// 512-bit key clears a 2048-bit floor, and the registry then republishes the
/// padded form, so a consumer measuring the served key reads the wrong size.
#[test]
fn a_zero_padded_rsa_modulus_is_refused() {
    // 2048 bits of 0xff, padded to 2056 by a leading zero byte.
    let mut n = vec![0u8];
    n.extend(std::iter::repeat_n(0xffu8, 256));
    let err = registry_core::Jwk::parse(&json!({
        "kty": "RSA",
        "n": b64url(&n),
        "e": b64url(&[1u8, 0, 1]),
    }))
    .unwrap_err();
    assert_eq!(err.code, Code::KeyInvalid, "{}", err.detail);
    assert!(err.detail.contains("leading zero"), "{}", err.detail);
}

/// §6.2: a card's own signatures say who signed the document, never who wants
/// it published here. Without the publication proof, anyone who can read a
/// published card can register it under the signer's identifier — and, by
/// dropping a co-signature first, choose the entry's authorized key set.
#[test]
fn a_card_alone_cannot_open_an_entry_for_its_signer() {
    let victim = Signer::p256();
    let attacker = Signer::p256();
    // The card as the victim published it somewhere else: signed by them, and
    // readable by anyone.
    let card = sign_card(card_body("1.0.0"), &[&victim]);

    // The attacker holds no key of the victim's, so the only proof they can
    // mint is one of their own.
    let proof = proof_by(&attacker, &victim.kid(), &card.digest);
    let err = evaluate_write(
        &victim.kid(),
        &card,
        &[victim.jwk()],
        std::slice::from_ref(&proof),
        ORIGIN,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, Code::KidNotThumbprint, "{}", err.detail);

    // Submitting their own key alongside does not help either: it signs
    // nothing, so the card would silently claim an authorized key it never had.
    let err = evaluate_write(
        &victim.kid(),
        &card,
        &[victim.jwk(), attacker.jwk()],
        &[proof],
        ORIGIN,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, Code::UnusedKey, "{}", err.detail);
}

/// A proof is bound to one registry, so a card and its proof cannot be lifted
/// from another registry and replayed here.
#[test]
fn a_proof_minted_for_another_registry_is_refused() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);
    let payload = json!({
        "action": "publish",
        "agentId": k.kid(),
        "cardDigest": card.digest,
        "issuedAt": "2026-08-25T12:00:00Z",
        "registryOrigin": "https://elsewhere.example",
    });
    let (protected, payload, signature) = sign_payload(&k, &payload);
    let proof = DetachedJws {
        protected,
        payload,
        signature,
    };

    let err = evaluate_write(&k.kid(), &card, &[k.jwk()], &[proof], ORIGIN, None).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("registryOrigin"), "{}", err.detail);
}

/// A proof for one card cannot be reused for another: it names the digest.
#[test]
fn a_proof_does_not_carry_over_to_a_different_card() {
    let k = Signer::p256();
    let first = sign_card(card_body("1.0.0"), &[&k]);
    let second = sign_card(card_body("2.0.0"), &[&k]);

    let proof = proof_by(&k, &k.kid(), &first.digest);
    let err = evaluate_write(&k.kid(), &second, &[k.jwk()], &[proof], ORIGIN, None).unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("cardDigest"), "{}", err.detail);
}

/// The authorized set is exactly the set of keys that asked for this
/// publication. A key that signed the card but produced no proof does not
/// enter it — and cannot be enrolled into it by whoever assembled the request.
#[test]
fn a_signing_key_without_a_proof_does_not_enter_the_authorized_set() {
    let owner = Signer::p256();
    let outsider = Signer::p256();
    let card = sign_card(card_body("1.1.0"), &[&owner, &outsider]);
    let current = state(&owner.kid(), "1.0.0", "sha256:old", &[owner.kid()]);

    let err = evaluate_write(
        &owner.kid(),
        &card,
        &[owner.jwk(), outsider.jwk()],
        &[proof_by(&owner, &owner.kid(), &card.digest)],
        ORIGIN,
        Some(&current),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::UnprovenKey, "{}", err.detail);
    assert!(err.detail.contains(&outsider.kid()), "{}", err.detail);

    // With the outsider's own proof it is a genuine co-signature, and accepted.
    let accepted = write_with(
        &[&owner, &outsider],
        &owner.kid(),
        &card,
        &[owner.jwk(), outsider.jwk()],
        Some(&current),
    )
    .expect("the owner may add a co-signer who agrees");
    assert_eq!(
        accepted.authorized_kids,
        kids(&[&owner.kid(), &outsider.kid()])
    );
}

/// The attack the proof exists to stop, in its subtler form: a card's signing
/// payload is public once published, so anyone can append their own signature
/// to someone else's card without invalidating the original. Without a proof
/// from every key, the attacker opens an entry *in their own name* whose
/// published key set names a key holder who never asked for it.
#[test]
fn a_scraped_card_cannot_enrol_its_signer_into_someone_elses_entry() {
    let victim = Signer::p256();
    let attacker = Signer::p256();

    // What the victim published, readable by anyone.
    let published = sign_card(card_body("1.0.0"), &[&victim]);

    // The attacker appends their own signature over the same payload. The
    // victim's signature still verifies — the payload did not change.
    let mut body = published.value.clone();
    let signatures = body["signatures"].as_array().unwrap().clone();
    let mut payload_only = body.clone();
    payload_only.as_object_mut().unwrap().remove("signatures");
    let (protected, _, signature) = {
        let bytes = canonicalize(&payload_only).unwrap();
        let h = json!({"alg": attacker.alg(), "typ": "JOSE", "kid": attacker.kid()});
        let protected = b64url(&canonicalize(&h).unwrap());
        let sig = attacker.sign_input(&a2a_card::canonical::signing_input(&protected, &bytes));
        (protected, (), b64url(&sig))
    };
    let mut both = signatures;
    both.push(json!({"protected": protected, "signature": signature}));
    body["signatures"] = Value::Array(both);
    let card = a2a_card::validate_value(body).unwrap();

    // The attacker names the entry after their own key, so the genesis rule is
    // satisfied, and proves the publication with the only key they hold.
    let err = evaluate_write(
        &attacker.kid(),
        &card,
        &[victim.jwk(), attacker.jwk()],
        &[proof_by(&attacker, &attacker.kid(), &card.digest)],
        ORIGIN,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, Code::UnprovenKey, "{}", err.detail);
    assert!(err.detail.contains(&victim.kid()), "{}", err.detail);
}

/// SemVer 2.0.0 §10: build metadata is ignored when determining precedence.
/// Counting it would let `1.0.0+b` replace `1.0.0` — different content at the
/// same version, which is exactly what the monotonic rule refuses.
#[test]
fn build_metadata_is_not_a_version_bump() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0+b"), &[&k]);
    let current = state(&k.kid(), "1.0.0", "sha256:old", &[k.kid()]);

    let err = write_with(&[&k], &k.kid(), &card, &[k.jwk()], Some(&current)).unwrap_err();
    assert_eq!(err.code, Code::VersionNotIncreasing);
}

/// §6.2 and §6.5 both say the payload *is* the object they describe. A member
/// the registry never reads is meaning a signature covers and nobody checks.
#[test]
fn a_proof_payload_may_not_carry_extra_members() {
    let k = Signer::p256();
    let card = sign_card(card_body("1.0.0"), &[&k]);
    let payload = json!({
        "action": "publish",
        "agentId": k.kid(),
        "cardDigest": card.digest,
        "issuedAt": "2026-08-25T12:00:00Z",
        "registryOrigin": ORIGIN,
        "note": "anything at all",
    });
    let (protected, payload, signature) = sign_payload(&k, &payload);
    let err = evaluate_write(
        &k.kid(),
        &card,
        &[k.jwk()],
        &[DetachedJws {
            protected,
            payload,
            signature,
        }],
        ORIGIN,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("note"), "{}", err.detail);
}
