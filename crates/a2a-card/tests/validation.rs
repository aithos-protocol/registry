//! Strict parsing (§5.1) and field-presence validation (§5.2).

use a2a_card::{Code, parse_card};

const MINIMAL: &str = r#"{
  "capabilities": {},
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["application/json"],
  "description": "A minimal but valid card.",
  "name": "Minimal Agent",
  "skills": [{"description": "Does one thing.", "id": "s1", "name": "Skill", "tags": ["demo"]}],
  "supportedInterfaces": [
    {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": "https://agent.example/a2a"}
  ],
  "version": "1.0.0"
}"#;

/// Patch the minimal card with one extra or replaced top-level member.
fn with(member: &str, json: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert(member.to_string(), serde_json::from_str(json).unwrap());
    v.to_string()
}

fn codes(input: &str) -> Vec<Code> {
    parse_card(input)
        .unwrap_err()
        .issues()
        .into_iter()
        .map(|i| i.code)
        .collect()
}

fn pointers(input: &str) -> Vec<String> {
    parse_card(input)
        .unwrap_err()
        .issues()
        .into_iter()
        .map(|i| i.pointer)
        .collect()
}

#[test]
fn minimal_card_is_accepted() {
    let card = parse_card(MINIMAL).unwrap();
    assert_eq!(card.card_version(), Some("1.0.0"));
    // Canonical bytes are sorted and whitespace-free.
    assert!(
        card.bytes
            .starts_with(br#"{"capabilities":{},"defaultInputModes""#)
    );
    assert!(card.digest.starts_with("sha256:"));
}

#[test]
fn a2a_sample_card_is_accepted() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/a2a-sample-agent-card.json");
    let input = std::fs::read_to_string(path).unwrap();
    parse_card(&input).expect("the specification's own sample card must validate");
}

// --- §5.1 strict parsing -------------------------------------------------

#[test]
fn duplicate_member_is_rejected() {
    // serde_json would silently keep the last one, changing the canonical bytes.
    let input = r#"{"name":"a","name":"b"}"#;
    assert_eq!(codes(input), vec![Code::JsonInvalid]);
    assert!(
        parse_card(input)
            .unwrap_err()
            .to_string()
            .contains("duplicate member")
    );
}

#[test]
fn integer_beyond_the_safe_range_is_rejected() {
    let input = with("capabilities", r#"{"streaming": 9007199254740993}"#);
    assert_eq!(codes(&input), vec![Code::JsonInvalid]);
}

/// `i64::MIN` is the value that makes at least one published JCS crate panic.
/// Rejecting it here means no canonicalizer ever sees it.
#[test]
fn i64_min_is_rejected_before_canonicalization() {
    let input = with("capabilities", r#"{"streaming": -9223372036854775808}"#);
    assert_eq!(codes(&input), vec![Code::JsonInvalid]);
}

#[test]
fn safe_range_boundary_is_accepted_by_the_parser() {
    // Rejected by the schema as a non-boolean, not by the number domain.
    let input = with("capabilities", r#"{"streaming": 9007199254740991}"#);
    assert_eq!(codes(&input), vec![Code::CardInvalid]);
}

#[test]
fn trailing_content_is_rejected() {
    assert_eq!(
        codes(&format!("{MINIMAL} trailing")),
        vec![Code::JsonInvalid]
    );
}

// --- §5.2 schema and presence -------------------------------------------

#[test]
fn unknown_member_is_rejected() {
    let input = with("unknownMember", r#""x""#);
    assert_eq!(codes(&input), vec![Code::CardInvalid]);
    assert_eq!(pointers(&input), vec!["/unknownMember"]);
}

#[test]
fn missing_required_member_is_reported_with_its_pointer() {
    let mut v: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
    v.as_object_mut().unwrap().remove("version");
    let input = v.to_string();
    assert_eq!(codes(&input), vec![Code::CardInvalid]);
    assert_eq!(pointers(&input), vec!["/version"]);
}

/// The case A2A §8.4.1 illustrates: an empty repeated field with implicit
/// presence must have been omitted before signing.
#[test]
fn empty_repeated_field_must_be_omitted() {
    let input = with("capabilities", r#"{"extensions": []}"#);
    assert_eq!(codes(&input), vec![Code::PresenceInvalid]);
    assert_eq!(pointers(&input), vec!["/capabilities/extensions"]);
}

#[test]
fn empty_string_with_implicit_presence_must_be_omitted() {
    let input = with(
        "supportedInterfaces",
        r#"[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"","url":"https://a.example/x"}]"#,
    );
    assert_eq!(codes(&input), vec![Code::PresenceInvalid]);
    assert_eq!(pointers(&input), vec!["/supportedInterfaces/0/tenant"]);
}

/// A field carrying the proto3 `optional` keyword may hold its default value.
#[test]
fn optional_field_may_carry_its_default() {
    let input = with(
        "capabilities",
        r#"{"streaming": false, "pushNotifications": false}"#,
    );
    parse_card(&input).unwrap();
}

/// A required member is present even when it equals the default.
#[test]
fn required_field_may_carry_its_default() {
    let input = with("description", r#""""#);
    parse_card(&input).unwrap();
}

/// Singular message fields track presence in proto3, so an empty object is a
/// legal explicitly-present value, not a default to be omitted.
#[test]
fn empty_message_field_is_legal() {
    let input = with(
        "signatures",
        r#"[{"protected":"eyJ9","signature":"AA","header":{}}]"#,
    );
    parse_card(&input).unwrap();
}

#[test]
fn oneof_with_two_members_is_rejected() {
    let input = with(
        "securitySchemes",
        r#"{"s":{"mtlsSecurityScheme":{"description":"d"},"openIdConnectSecurityScheme":{"openIdConnectUrl":"https://i.example/c"}}}"#,
    );
    assert_eq!(codes(&input), vec![Code::CardInvalid]);
    assert_eq!(pointers(&input), vec!["/securitySchemes/s"]);
}

#[test]
fn nested_required_members_are_checked() {
    let input = with("supportedInterfaces", r#"[{"url":"https://a.example/x"}]"#);
    assert_eq!(
        pointers(&input),
        vec![
            "/supportedInterfaces/0/protocolBinding",
            "/supportedInterfaces/0/protocolVersion"
        ]
    );
}

#[test]
fn every_issue_is_reported_not_just_the_first() {
    let mut v: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("version");
    o.remove("name");
    o.insert("bogus".into(), serde_json::Value::Null);
    assert_eq!(codes(&v.to_string()).len(), 3);
}
