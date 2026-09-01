//! Certification authorization: parsing, canonical payloads, replay, keys —
//! and the published vectors of `DOMAIN-CERTIFICATION.md` §12, which this
//! suite runs rather than mirrors, so what is published is what is tested.

mod common;

use std::collections::BTreeSet;

use a2a_card::canonical::{b64url, canonicalize};
use common::{Signer, sign_payload};
use registry_core::{
    AgentState, Code, Status, agent_id_in_record, evaluate_certification, rrset_names_agent,
};
use semver::Version;
use serde_json::{Value, json};

const ORIGIN: &str = "https://registry.aithos.world";

fn active(agent_id: &str, kids: &[String]) -> AgentState {
    AgentState {
        agent_id: agent_id.to_string(),
        status: Status::Active,
        card_digest: "sha256:current".to_string(),
        card_version: Version::parse("1.0.0").unwrap(),
        authorized_kids: kids.iter().cloned().collect(),
    }
}

fn payload(agent_id: &str, domains: &[&str], issued_at: &str) -> Value {
    json!({
        "action": "certify-domains",
        "agentId": agent_id,
        "domains": domains,
        "issuedAt": issued_at,
        "registryOrigin": ORIGIN,
    })
}

/// Sign `payload` with `signer` and evaluate it against `state`.
fn certify(
    state: &AgentState,
    last_issued_at: Option<&str>,
    signer: &Signer,
    payload: &Value,
) -> registry_core::Result<registry_core::Certification> {
    let (protected, payload_b64, signature) = sign_payload(signer, payload);
    evaluate_certification(
        state,
        ORIGIN,
        last_issued_at,
        &protected,
        &payload_b64,
        &signature,
        &[signer.jwk()],
    )
}

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/domain-certification")
}

fn vector(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// --- the published vectors (§12) -----------------------------------------

#[test]
fn record_parsing_vectors() {
    let v = vector("record-parsing.json");
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let record = case["record"].as_str().unwrap();

        // Where the record was transmitted as several character-strings, the
        // record data is their concatenation with no separator (§3.2).
        if let Some(strings) = case["characterStrings"].as_array() {
            let joined: String = strings
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect::<Vec<_>>()
                .concat();
            assert_eq!(joined, record, "{name}: concatenation");
        }

        let expected = case["agentIdInRecord"].as_str();
        assert_eq!(agent_id_in_record(record), expected, "{name}");
    }

    let sought = v["agentId"].as_str().unwrap();
    for case in v["rrsets"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let records: Vec<String> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            rrset_names_agent(&records, sought),
            case["matches"].as_bool().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn the_reference_payload_canonicalizes_to_the_published_bytes() {
    let v = vector("payload.json");
    let reference = &v["reference"];

    let bytes = canonicalize(&reference["payload"]).unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        reference["canonical"].as_str().unwrap(),
        "JCS canonicalization"
    );
    assert_eq!(
        b64url(&bytes),
        reference["payloadB64"].as_str().unwrap(),
        "the transmitted payload member"
    );
}

#[test]
fn refusal_vectors_are_refused_even_correctly_signed() {
    let v = vector("payload.json");
    for case in v["refusals"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let want = case["code"].as_str().unwrap();

        // Signed by a key that is genuinely authorized for the payload's
        // agent, so the refusal observed is the one the vector names and not a
        // signature or authorization failure standing in front of it.
        let k = Signer::p256();
        let mut p = case["payload"].clone();
        p["agentId"] = json!(k.kid());
        let state = active(&k.kid(), &[k.kid()]);

        let err = certify(&state, None, &k, &p).unwrap_err();
        assert_eq!(err.code.as_str(), want, "{name}: {}", err.detail);
    }
}

#[test]
fn replay_vectors_compare_instants_not_strings() {
    let v = vector("payload.json");
    let replay = &v["replay"];
    let stored = replay["storedIssuedAt"].as_str().unwrap();
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    for refused in replay["refused"].as_array().unwrap() {
        let issued_at = refused.as_str().unwrap();
        let err = certify(
            &state,
            Some(stored),
            &k,
            &payload(&k.kid(), &["acme.com"], issued_at),
        )
        .unwrap_err();
        assert_eq!(
            err.code.as_str(),
            replay["refusedCode"].as_str().unwrap(),
            "issuedAt {issued_at}: {}",
            err.detail
        );
    }

    let accepted = replay["accepted"].as_str().unwrap();
    certify(
        &state,
        Some(stored),
        &k,
        &payload(&k.kid(), &["acme.com"], accepted),
    )
    .unwrap_or_else(|e| panic!("issuedAt {accepted} must be accepted: {e}"));
}

#[test]
fn domain_vectors() {
    let v = vector("domains.json");
    for valid in v["valid"].as_array().unwrap() {
        let raw = valid.as_str().unwrap();
        registry_core::Domain::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
    }
    for case in v["invalid"].as_array().unwrap() {
        let raw = case["domain"].as_str().unwrap();
        let err = registry_core::Domain::parse(raw).unwrap_err();
        assert_eq!(
            err.code.as_str(),
            case["code"].as_str().unwrap(),
            "{raw}: {}",
            err.detail
        );
    }
}

// --- acceptance ----------------------------------------------------------

#[test]
fn a_certification_by_the_authorized_key_is_accepted() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    let accepted = certify(
        &state,
        None,
        &k,
        &payload(
            &k.kid(),
            &["acme.com", "acme.fr"],
            "2026-09-01T09:14:22.000Z",
        ),
    )
    .unwrap();

    assert_eq!(accepted.kid, k.kid());
    assert_eq!(accepted.issued_at, "2026-09-01T09:14:22.000Z");
    let domains: Vec<&str> = accepted.domains.iter().map(|d| d.as_str()).collect();
    assert_eq!(domains, ["acme.com", "acme.fr"], "in the signed order");
}

#[test]
fn an_ed25519_key_certifies_the_same_way() {
    let k = Signer::ed25519();
    let state = active(&k.kid(), &[k.kid()]);
    certify(
        &state,
        None,
        &k,
        &payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap();
}

#[test]
fn the_empty_set_is_accepted_and_removes_everything() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    let accepted = certify(
        &state,
        Some("2026-09-01T09:14:22.000Z"),
        &k,
        &payload(&k.kid(), &[], "2026-09-01T10:00:00.000Z"),
    )
    .unwrap();
    assert!(accepted.domains.is_empty());
}

#[test]
fn a_first_certification_has_nothing_to_exceed() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);
    // An old-looking issuedAt is fine when nothing is stored: the registry
    // compares only against its own stored value, never against its clock.
    certify(
        &state,
        None,
        &k,
        &payload(&k.kid(), &["acme.com"], "2020-01-01T00:00:00Z"),
    )
    .unwrap();
}

// --- refusals ------------------------------------------------------------

#[test]
fn a_withdrawn_agent_certifies_nothing() {
    let k = Signer::p256();
    let mut state = active(&k.kid(), &[k.kid()]);
    state.status = Status::Withdrawn;

    let err = certify(
        &state,
        None,
        &k,
        &payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::Withdrawn);
}

#[test]
fn a_stranger_cannot_certify_someone_elses_entry() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let state = active(&owner.kid(), &[owner.kid()]);

    let err = certify(
        &state,
        None,
        &stranger,
        &payload(&owner.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

/// Like §6.3: authorization is *here and now*. A key rotated out keeps its
/// history and loses its authority.
#[test]
fn a_rotated_out_key_no_longer_certifies() {
    let genesis = Signer::p256();
    let successor = Signer::p256();
    let state = active(&genesis.kid(), &[successor.kid()]);

    let err = certify(
        &state,
        None,
        &genesis,
        &payload(&genesis.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

#[test]
fn a_submitted_key_that_signed_nothing_is_refused() {
    let k = Signer::p256();
    let bystander = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    let p = payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z");
    let (protected, payload_b64, signature) = sign_payload(&k, &p);
    let err = evaluate_certification(
        &state,
        ORIGIN,
        None,
        &protected,
        &payload_b64,
        &signature,
        &[k.jwk(), bystander.jwk()],
    )
    .unwrap_err();
    assert_eq!(err.code, Code::UnusedKey);
}

#[test]
fn a_payload_for_another_agent_is_refused() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    let err = certify(
        &state,
        None,
        &k,
        &payload("SomeOtherAgent", &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("agentId"), "{}", err.detail);
}

/// The transmitted payload must be the canonical encoding of what it decodes
/// to — otherwise a signature covers bytes that differ from what the registry
/// reads.
#[test]
fn a_non_canonical_payload_encoding_is_refused() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);
    let p = payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z");
    let (protected, _, _) = sign_payload(&k, &p);

    // The same object, serialized with a space: same meaning, different bytes.
    let loose = serde_json::to_string_pretty(&p).unwrap();
    let loose_b64 = b64url(loose.as_bytes());
    let input = a2a_card::canonical::signing_input(&protected, loose.as_bytes());
    let signature = b64url(&k.sign_input(&input));

    let err = evaluate_certification(
        &state,
        ORIGIN,
        None,
        &protected,
        &loose_b64,
        &signature,
        &[k.jwk()],
    )
    .unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
    assert!(err.detail.contains("canonical"), "{}", err.detail);
}

#[test]
fn a_tampered_domain_list_does_not_verify() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);
    let signed = payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z");
    let (protected, _, signature) = sign_payload(&k, &signed);

    // Swap the payload for one naming a different domain, canonically encoded.
    let other = payload(&k.kid(), &["evil.example"], "2026-09-01T09:14:22.000Z");
    let other_b64 = b64url(&canonicalize(&other).unwrap());

    let err = evaluate_certification(
        &state,
        ORIGIN,
        None,
        &protected,
        &other_b64,
        &signature,
        &[k.jwk()],
    )
    .unwrap_err();
    assert_eq!(err.code, Code::SignatureInvalid);
}

/// A stranger probing with an old issuedAt must learn nothing about the stored
/// certification state: the key refusal comes first.
#[test]
fn replay_is_only_reported_to_a_key_holder() {
    let owner = Signer::p256();
    let stranger = Signer::p256();
    let state = active(&owner.kid(), &[owner.kid()]);

    let err = certify(
        &state,
        Some("2026-09-01T09:14:22.000Z"),
        &stranger,
        &payload(&owner.kid(), &["acme.com"], "2000-01-01T00:00:00Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::NotAuthorizedKey);
}

/// A corrupt stored timestamp refuses closed: it must not quietly reopen the
/// replay window by comparing against nothing.
#[test]
fn an_unreadable_stored_issued_at_refuses_rather_than_waves_through() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);

    let err = certify(
        &state,
        Some("not a timestamp"),
        &k,
        &payload(&k.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap_err();
    assert_eq!(err.code, Code::CertificationNotIncreasing);
    assert!(err.detail.contains("repair"), "{}", err.detail);
}

#[test]
fn domain_errors_name_their_codes_through_the_full_evaluation() {
    let k = Signer::p256();
    let state = active(&k.kid(), &[k.kid()]);
    for (domain, code) in [
        ("Acme.com", Code::DomainSyntaxInvalid),
        ("github.io", Code::DomainIsPublicSuffix),
    ] {
        let err = certify(
            &state,
            None,
            &k,
            &payload(&k.kid(), &[domain], "2026-09-01T09:14:22.000Z"),
        )
        .unwrap_err();
        assert_eq!(err.code, code, "{domain}");
    }
}

#[test]
fn the_authorized_set_not_the_signing_history_decides() {
    // A certification does not change the authorized set: only publications do
    // (§3.4 of SPEC.md). This pins that evaluate_certification returns the
    // signing kid and nothing about keys changes shape.
    let a = Signer::p256();
    let b = Signer::ed25519();
    let state = active(&a.kid(), &[a.kid(), b.kid()]);

    let accepted = certify(
        &state,
        None,
        &b,
        &payload(&a.kid(), &["acme.com"], "2026-09-01T09:14:22.000Z"),
    )
    .unwrap();
    assert_eq!(accepted.kid, b.kid(), "either authorized key may certify");
    assert_eq!(
        state.authorized_kids,
        [a.kid(), b.kid()].into_iter().collect::<BTreeSet<_>>()
    );
}
