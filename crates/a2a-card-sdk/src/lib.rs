//! Agent Cards authored with the official A2A Rust SDK.
//!
//! The SDK owns the *model*: [`AgentCard`] and everything under it are
//! re-exported from `a2a-lf`, and cards are built as typed values, never as
//! hand-written JSON. The SDK's generated proto3 JSON layer (`a2a-pb`) owns the
//! *encoding*. This crate adds only what the SDK does not do and A2A §8.4.1
//! requires before signing: restoring `REQUIRED` members the proto3 JSON
//! mapping omits at their default, then the strict gate of `a2a-card`.
//!
//! Both directions are checked, because neither SDK encoder is §8.4.1-exact on
//! its own (see `docs/tasks/author-cards-with-a2a-sdk.md`):
//!
//! - [`encode`] refuses to hand back anything `a2a-card` would refuse.
//! - [`decode`] refuses a card the SDK model cannot carry exactly: it re-encodes
//!   and compares bytes, so a field the SDK drops or rewrites is reported
//!   rather than silently lost from a card that is about to be signed.

pub use a2a::{
    AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentProvider, AgentSkill,
    SecurityRequirement, SecurityScheme, TRANSPORT_PROTOCOL_GRPC, TRANSPORT_PROTOCOL_HTTP_JSON,
    TRANSPORT_PROTOCOL_JSONRPC,
};
use a2a_card::CanonicalCard;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the A2A SDK could not encode the card: {0}")]
    Encode(String),
    #[error("the A2A SDK cannot read this card: {0}")]
    Unreadable(String),
    #[error(
        "the A2A SDK reads this card but cannot reproduce it exactly \
         (it would change the signed bytes); first difference near: {0}"
    )]
    NotRepresentable(String),
    #[error(transparent)]
    Card(#[from] a2a_card::CardError),
}

/// Encode an SDK card into its strict, signable form (without `signatures`).
pub fn encode(card: &AgentCard) -> Result<CanonicalCard, Error> {
    let mut unsigned = card.clone();
    unsigned.signatures = None;
    let mut value =
        a2a_pb::protojson_conv::to_value(&unsigned).map_err(|e| Error::Encode(e.to_string()))?;
    a2a_card::presence::complete_required(&mut value);
    Ok(a2a_card::validate_value(value)?)
}

/// Read a strictly valid card into the SDK model, guaranteeing that
/// [`encode`] gives back the same bytes (signatures aside).
pub fn decode(card: &CanonicalCard) -> Result<AgentCard, Error> {
    let mut body = card.value.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove(a2a_card::canonical::SIGNATURES_MEMBER);
    }
    let expected = a2a_card::canonical::canonicalize(&body)?;
    let sdk: AgentCard =
        serde_json::from_value(body).map_err(|e| Error::Unreadable(e.to_string()))?;
    let again = encode(&sdk)?;
    if again.bytes != expected {
        let at = expected
            .iter()
            .zip(&again.bytes)
            .position(|(a, b)| a != b)
            .unwrap_or(expected.len().min(again.bytes.len()));
        let from = at.saturating_sub(40);
        let near = String::from_utf8_lossy(&expected[from..(at + 40).min(expected.len())]);
        return Err(Error::NotRepresentable(near.into_owned()));
    }
    Ok(sdk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> AgentCard {
        AgentCard {
            name: "Example Agent".into(),
            description: String::new(),
            version: "0.1.0".into(),
            supported_interfaces: vec![AgentInterface::new(
                "https://agent.example/a2a",
                TRANSPORT_PROTOCOL_HTTP_JSON,
            )],
            capabilities: AgentCapabilities::default(),
            default_input_modes: vec!["application/json".into()],
            default_output_modes: vec!["application/json".into()],
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security_requirements: None,
            signatures: None,
        }
    }

    #[test]
    fn required_defaults_survive_encoding() {
        let c = encode(&minimal()).unwrap();
        assert_eq!(c.value["description"], "");
        assert_eq!(c.value["skills"], serde_json::json!([]));
    }

    #[test]
    fn security_requirements_use_the_proto_shape() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/a2a-sample-agent-card.json"
        ))
        .unwrap();
        let card = a2a_card::parse_card(&text).unwrap();
        let sdk = decode(&card).expect("the sample card round-trips through the SDK");
        let again = encode(&sdk).unwrap();
        assert_eq!(
            again.signing_payload().unwrap(),
            card.signing_payload().unwrap()
        );
    }

    #[test]
    fn a_card_the_sdk_cannot_carry_is_reported_not_rewritten() {
        let mut v = encode(&minimal()).unwrap().value;
        v["securitySchemes"] =
            serde_json::json!({"k": {"apiKeySecurityScheme": {"location": "header", "name": "X"}}});
        v["securityRequirements"] = serde_json::json!([{"schemes": {"k": {}}}]);
        let card = a2a_card::validate_value(v).unwrap();
        assert!(matches!(decode(&card), Err(Error::Unreadable(_))));
    }
}
