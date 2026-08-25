//! Test helpers: real keys, real signatures. Nothing here is mocked, because
//! the point of these tests is that the bytes line up.

use a2a_card::canonical::{b64url, canonicalize, signing_input};
use a2a_card::{CanonicalCard, validate_value};
use serde_json::{Value, json};

pub enum Signer {
    P256(p256::ecdsa::SigningKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl Signer {
    pub fn p256() -> Self {
        Signer::P256(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    pub fn ed25519() -> Self {
        use rand_core::RngCore as _;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        Signer::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub fn jwk(&self) -> Value {
        match self {
            Signer::P256(sk) => {
                let point = sk.verifying_key().to_encoded_point(false);
                json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64url(point.x().unwrap()),
                    "y": b64url(point.y().unwrap()),
                })
            }
            Signer::Ed25519(sk) => json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64url(sk.verifying_key().as_bytes()),
            }),
        }
    }

    pub fn alg(&self) -> &'static str {
        match self {
            Signer::P256(_) => "ES256",
            Signer::Ed25519(_) => "EdDSA",
        }
    }

    pub fn kid(&self) -> String {
        registry_core::Jwk::parse(&self.jwk())
            .unwrap()
            .thumbprint()
            .to_string()
    }

    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Signer::P256(sk) => {
                use p256::ecdsa::{Signature, signature::Signer as _};
                let sig: Signature = sk.sign(input);
                sig.to_bytes().to_vec()
            }
            Signer::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                sk.sign(input).to_bytes().to_vec()
            }
        }
    }
}

/// A well-formed card body, without its `signatures` member.
pub fn card_body(version: &str) -> Value {
    json!({
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "description": "A card used by the test suite.",
        "name": "Test Agent",
        "skills": [{"description": "Does one thing.", "id": "s1", "name": "Skill", "tags": ["demo"]}],
        "supportedInterfaces": [
            {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": "https://agent.example/a2a"}
        ],
        "version": version,
    })
}

/// Sign `body` with each signer and return the assembled, validated card.
pub fn sign_card(body: Value, signers: &[&Signer]) -> CanonicalCard {
    sign_card_with(
        body,
        signers,
        |s, kid| json!({"alg": s.alg(), "typ": "JOSE", "kid": kid}),
    )
}

/// Same, but the caller decides the protected header, so tests can build
/// deliberately malformed ones.
pub fn sign_card_with(
    body: Value,
    signers: &[&Signer],
    header: impl Fn(&Signer, &str) -> Value,
) -> CanonicalCard {
    let payload = canonicalize(&body).unwrap();
    let signatures: Vec<Value> = signers
        .iter()
        .map(|s| {
            let h = header(s, &s.kid());
            let protected = b64url(&canonicalize(&h).unwrap());
            let sig = s.sign(&signing_input(&protected, &payload));
            json!({"protected": protected, "signature": b64url(&sig)})
        })
        .collect();

    let mut card = body;
    card.as_object_mut()
        .unwrap()
        .insert("signatures".into(), Value::Array(signatures));
    validate_value(card).unwrap()
}

/// Sign an arbitrary object as an attached JWS, as withdrawal requests do.
pub fn sign_payload(signer: &Signer, payload: &Value) -> (String, String, String) {
    let bytes = canonicalize(payload).unwrap();
    let payload_b64 = b64url(&bytes);
    let h = json!({"alg": signer.alg(), "typ": "JOSE", "kid": signer.kid()});
    let protected = b64url(&canonicalize(&h).unwrap());
    let sig = signer.sign(&signing_input(&protected, &bytes));
    (protected, payload_b64, b64url(&sig))
}
