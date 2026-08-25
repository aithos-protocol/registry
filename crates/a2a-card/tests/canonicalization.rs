//! Canonicalization conformance.
//!
//! Two independent sources of truth are used: the official RFC 8785 test
//! vectors, and the worked example of A2A §8.4.1.

use a2a_card::canonical::{canonicalize, digest, signing_payload};
use a2a_card::strict;

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

#[test]
fn rfc8785_official_vectors() {
    for name in [
        "arrays",
        "french",
        "structures",
        "unicode",
        "values",
        "weird",
    ] {
        let dir = vectors_dir().join("rfc8785");
        let input = std::fs::read_to_string(dir.join(format!("{name}.input.json"))).unwrap();
        let expected = std::fs::read_to_string(dir.join(format!("{name}.expected.json"))).unwrap();
        let expected = expected.trim_end_matches('\n');

        let v = serde_json::from_str::<serde_json::Value>(&input).unwrap();
        let got = String::from_utf8(canonicalize(&v).unwrap()).unwrap();
        assert_eq!(got, expected, "RFC 8785 vector {name}");
    }
}

/// The exact example from A2A §8.4.1, "Example of Default Value Removal".
///
/// The card fragment there is shown *after* the presence rules have been
/// applied by the publisher. Canonicalizing it must reproduce the specification's
/// byte string verbatim, including the nested member ordering.
#[test]
fn a2a_worked_example() {
    let after_presence = r#"{
        "name": "Example Agent",
        "description": "",
        "capabilities": { "streaming": false, "pushNotifications": false },
        "skills": []
    }"#;
    let expected = r#"{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}"#;

    let v = strict::parse(after_presence).unwrap();
    assert_eq!(
        String::from_utf8(canonicalize(&v).unwrap()).unwrap(),
        expected
    );
}

/// A second, independently written RFC 8785 implementation must agree with
/// ours on the real sample card. A canonicalization bug that both libraries
/// share would otherwise be invisible.
#[test]
fn differential_against_second_implementation() {
    let card = std::fs::read_to_string(vectors_dir().join("a2a-sample-agent-card.json")).unwrap();
    let v = strict::parse(&card).unwrap();

    let ours = String::from_utf8(canonicalize(&v).unwrap()).unwrap();
    let theirs = serde_json_canonicalizer::to_string(&v).unwrap();
    assert_eq!(ours, theirs);
}

#[test]
fn signing_payload_drops_only_signatures() {
    let card = std::fs::read_to_string(vectors_dir().join("a2a-sample-agent-card.json")).unwrap();
    let v = strict::parse(&card).unwrap();

    let payload = String::from_utf8(signing_payload(&v).unwrap()).unwrap();
    assert!(!payload.contains("\"signatures\""));

    // Removing a top-level member from a canonical object and re-canonicalizing
    // must equal the canonical form of the remainder: nothing else shifts.
    let mut stripped = v.clone();
    stripped.as_object_mut().unwrap().remove("signatures");
    assert_eq!(
        payload,
        String::from_utf8(canonicalize(&stripped).unwrap()).unwrap()
    );
}

#[test]
fn digest_is_prefixed_lowercase_hex() {
    let d = digest(b"");
    assert_eq!(
        d,
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
