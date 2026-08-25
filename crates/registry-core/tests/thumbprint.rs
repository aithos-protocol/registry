//! RFC 7638 thumbprints.

use registry_core::Jwk;
use serde_json::json;

/// The worked example of RFC 7638 §3.1, whose thumbprint the RFC states.
#[test]
fn rfc7638_worked_example() {
    let jwk = json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29"
    });
    let parsed = Jwk::parse(&jwk).unwrap();
    assert_eq!(
        parsed.thumbprint(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

/// Members outside the RFC 7638 required set must not affect the thumbprint.
#[test]
fn thumbprint_ignores_optional_members() {
    let bare =
        json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    let decorated = json!({
        "kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "use":"sig","alg":"EdDSA","kid":"whatever","key_ops":["verify"]
    });
    assert_eq!(
        Jwk::parse(&bare).unwrap().thumbprint(),
        Jwk::parse(&decorated).unwrap().thumbprint()
    );
}

#[test]
fn private_material_is_refused() {
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut jwk =
            json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        jwk.as_object_mut()
            .unwrap()
            .insert(member.into(), json!("secret"));
        let err = Jwk::parse(&jwk).unwrap_err();
        assert_eq!(
            err.code,
            registry_core::Code::PrivateKeySubmitted,
            "member {member}"
        );
    }
}

#[test]
fn symmetric_keys_are_refused() {
    // An `oct` key's "public" half is the secret itself.
    let err = Jwk::parse(&json!({"kty":"oct","k":"c2VjcmV0"})).unwrap_err();
    assert_eq!(err.code, registry_core::Code::PrivateKeySubmitted);
}

#[test]
fn undersized_rsa_is_refused() {
    // A 512-bit modulus.
    let n = "w".repeat(86);
    let err = Jwk::parse(&json!({"kty":"RSA","n":n,"e":"AQAB"})).unwrap_err();
    assert_eq!(err.code, registry_core::Code::AlgNotAllowed);
    assert!(err.detail.contains("minimum is 2048"));
}

#[test]
fn unsupported_curves_are_refused() {
    let err = Jwk::parse(&json!({"kty":"EC","crv":"P-384","x":"AA","y":"AA"})).unwrap_err();
    assert_eq!(err.code, registry_core::Code::AlgNotAllowed);
}
