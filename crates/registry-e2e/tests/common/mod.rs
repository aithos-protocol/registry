//! Harness for tests that run against a real, deployed registry.
//!
//! These tests need no AWS credentials. Every endpoint they touch is public,
//! and each run generates its own keys, so anyone with network access to the
//! origin can run them.

use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};

/// The environment variable naming the registry under test.
pub const ORIGIN_VAR: &str = "REGISTRY_E2E_ORIGIN";

/// Resolve the origin, or explain what is missing.
///
/// These tests are `#[ignore]`d, so reaching this without the variable set
/// means someone asked for them explicitly and deserves a precise message.
pub fn origin() -> String {
    match std::env::var(ORIGIN_VAR) {
        Ok(value) if value.starts_with("https://") && !value.ends_with('/') => value,
        Ok(value) => {
            panic!("{ORIGIN_VAR} is {value:?}; it must be an https origin with no trailing slash")
        }
        Err(_) => panic!(
            "{ORIGIN_VAR} is not set. Run these against a deployed environment:\n\n    \
             REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
             cargo test -p registry-e2e -- --ignored --test-threads=1\n"
        ),
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("the HTTP client should build")
}

// --- keys and cards ------------------------------------------------------

pub struct Key(p256::ecdsa::SigningKey);

impl Key {
    pub fn new() -> Self {
        Key(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    /// The fixture key for domain certification, derived from a seed.
    ///
    /// The certification test needs an agent whose identifier a *stable* DNS
    /// record can name, and identifiers are key thumbprints — so the key has
    /// to be reproducible across runs. Deriving it from a secret seed keeps
    /// key files out of the loop: whoever holds the seed holds the fixture.
    pub fn from_seed(seed: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut material = Sha256::digest(seed.as_bytes());
        loop {
            if let Ok(key) = p256::ecdsa::SigningKey::from_bytes(&material) {
                return Key(key);
            }
            // Astronomically unlikely (the hash landed on 0 or above the
            // curve order); re-hash rather than fail a test over it.
            material = Sha256::digest(material);
        }
    }

    pub fn jwk(&self) -> Value {
        let point = self.0.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": Base64UrlUnpadded::encode_string(point.x().unwrap()),
            "y": Base64UrlUnpadded::encode_string(point.y().unwrap()),
        })
    }

    pub fn kid(&self) -> String {
        registry_core::Jwk::parse(&self.jwk())
            .unwrap()
            .thumbprint()
            .to_string()
    }

    fn sign(&self, input: &[u8]) -> String {
        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = self.0.sign(input);
        Base64UrlUnpadded::encode_string(&signature.to_bytes())
    }
}

/// A card body carrying a label, so an entry left in a shared environment is
/// obviously test data rather than something a person published.
pub fn card_body(version: &str, label: &str) -> Value {
    json!({
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "description": format!("Automated end-to-end test entry. {label}"),
        "name": "E2E Test Agent",
        "skills": [{
            "description": "Exists only so that this card is schema-valid.",
            "id": "noop",
            "name": "No operation",
            "tags": ["test"],
        }],
        "supportedInterfaces": [{
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
            "url": "https://example.invalid/a2a",
        }],
        "version": version,
    })
}

/// Sign a card body exactly as a browser client would, and return both the
/// assembled card and the canonical bytes the registry must store verbatim.
pub fn sign_card(body: Value, keys: &[&Key]) -> (Value, Vec<u8>) {
    let payload = a2a_card::canonical::canonicalize(&body).unwrap();
    let signatures: Vec<Value> = keys
        .iter()
        .map(|key| {
            let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
            let protected = Base64UrlUnpadded::encode_string(
                &a2a_card::canonical::canonicalize(&header).unwrap(),
            );
            let input = a2a_card::canonical::signing_input(&protected, &payload);
            json!({"protected": protected, "signature": key.sign(&input)})
        })
        .collect();

    let mut card = body;
    card.as_object_mut()
        .unwrap()
        .insert("signatures".into(), Value::Array(signatures));

    let canonical = a2a_card::validate_value(card.clone()).expect("the test card must be valid");
    (card, canonical.bytes)
}

/// Build the publication proof that §6.2 requires alongside a card.
pub fn proof(key: &Key, origin: &str, agent_id: &str, card_digest: &str) -> Value {
    let payload = json!({
        "action": "publish",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": "2026-08-25T12:00:00.000Z",
        "registryOrigin": origin,
    });
    let bytes = a2a_card::canonical::canonicalize(&payload).unwrap();
    let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
    let protected =
        Base64UrlUnpadded::encode_string(&a2a_card::canonical::canonicalize(&header).unwrap());
    json!({
        "protected": protected,
        "payload": Base64UrlUnpadded::encode_string(&bytes),
        "signature": key.sign(&a2a_card::canonical::signing_input(&protected, &bytes)),
    })
}

/// A write envelope whose proof is signed by the first key, for the entry that
/// key names. Rotation and takeover tests use [`write_body_for`] instead.
pub fn write_body(origin: &str, card: &Value, keys: &[&Key]) -> Value {
    write_body_for(origin, &keys[0].kid(), card, keys, keys[0])
}

pub fn write_body_for(
    origin: &str,
    agent_id: &str,
    card: &Value,
    keys: &[&Key],
    _signer: &Key,
) -> Value {
    // Some tests submit a card the registry must refuse. The card is checked
    // before the proof is, so a placeholder digest here never masks the reason
    // such a test is asserting on.
    let digest = a2a_card::validate_value(card.clone())
        .map(|c| c.digest)
        .unwrap_or_else(|_| "sha256:not-a-valid-card".to_string());
    json!({
        "agentCard": card,
        "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>(),
        "proofs": keys.iter().map(|k| proof(k, origin, agent_id, &digest)).collect::<Vec<_>>(),
    })
}

pub fn withdraw_body(key: &Key, origin: &str, agent_id: &str, card_digest: &str) -> Value {
    let payload = json!({
        "action": "withdraw",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": "2026-01-01T00:00:00.000Z",
        "registryOrigin": origin,
    });
    let bytes = a2a_card::canonical::canonicalize(&payload).unwrap();
    let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
    let protected =
        Base64UrlUnpadded::encode_string(&a2a_card::canonical::canonicalize(&header).unwrap());
    json!({
        "withdrawal": {
            "protected": protected,
            "payload": Base64UrlUnpadded::encode_string(&bytes),
            "signature": key.sign(&a2a_card::canonical::signing_input(&protected, &bytes)),
        },
        "keys": [key.jwk()],
    })
}

// --- requests ------------------------------------------------------------

pub struct Response {
    pub status: u16,
    pub bytes: Vec<u8>,
    pub content_type: String,
    /// Kept for diagnostics. Deliberately unused in assertions: on the static
    /// read path this is the object store's own validator, not the card digest.
    #[allow(dead_code)]
    pub etag: String,
}

impl Response {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }

    /// Assert the status, printing the body when it does not match: a bare
    /// "expected 200, got 422" from a live environment is not actionable.
    pub fn expect(&self, status: u16, what: &str) -> &Self {
        assert_eq!(
            self.status,
            status,
            "{what}: expected {status}, got {} with body {}",
            self.status,
            String::from_utf8_lossy(&self.bytes)
        );
        self
    }

    /// Assert the RFC 9457 problem code.
    pub fn expect_code(&self, code: &str) -> &Self {
        assert_eq!(
            self.json()["code"],
            json!(code),
            "expected problem code {code}, got body {}",
            String::from_utf8_lossy(&self.bytes)
        );
        self
    }
}

pub async fn put(client: &reqwest::Client, origin: &str, agent_id: &str, body: &Value) -> Response {
    send(
        client
            .put(format!("{origin}/v1/agents/{agent_id}"))
            .json(body),
    )
    .await
}

pub async fn delete(
    client: &reqwest::Client,
    origin: &str,
    agent_id: &str,
    body: &Value,
) -> Response {
    send(
        client
            .delete(format!("{origin}/v1/agents/{agent_id}"))
            .json(body),
    )
    .await
}

pub async fn get(client: &reqwest::Client, origin: &str, path: &str) -> Response {
    send(client.get(format!("{origin}{path}"))).await
}

fn header(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn send(request: reqwest::RequestBuilder) -> Response {
    try_send(request)
        .await
        .expect("the request should reach the registry")
}

/// The fallible form, for the polling helper: a distribution that is still
/// deploying can time out, and that is "not yet", not "broken".
async fn try_send(request: reqwest::RequestBuilder) -> Result<Response, reqwest::Error> {
    let response = request.send().await?;
    let status = response.status().as_u16();
    let content_type = header(&response, "content-type");
    let etag = header(&response, "etag");
    let bytes = response.bytes().await?.to_vec();
    Ok(Response {
        status,
        bytes,
        content_type,
        etag,
    })
}

/// Poll a public read path until it matches, or give up.
///
/// The static read path is served from S3 through CloudFront, so a freshly
/// published card is not visible at the edge instantly, and a 404 cached just
/// before publication has its own short lifetime. Converging within a bounded
/// time is the correct expectation; being immediate is not.
pub async fn get_until(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    accept: impl Fn(&Response) -> bool,
    what: &str,
) -> Response {
    const ATTEMPTS: u32 = 30;
    const EVERY: Duration = Duration::from_secs(3);

    let mut last: Option<Result<Response, String>> = None;
    for attempt in 1..=ATTEMPTS {
        match try_send(client.get(format!("{origin}{path}"))).await {
            Ok(response) if accept(&response) => {
                if attempt > 1 {
                    eprintln!("  {what}: converged after {attempt} attempts");
                }
                return response;
            }
            Ok(response) => last = Some(Ok(response)),
            Err(error) => last = Some(Err(error.to_string())),
        }
        tokio::time::sleep(EVERY).await;
    }

    let detail = match last.expect("at least one attempt was made") {
        Ok(response) => format!(
            "last status {} with body {}",
            response.status,
            String::from_utf8_lossy(&response.bytes)
        ),
        Err(error) => format!("last attempt failed to complete: {error}"),
    };
    panic!(
        "{what}: {path} did not converge within {}s; {detail}",
        ATTEMPTS * EVERY.as_secs() as u32
    );
}

// --- domain certification (DOMAIN-CERTIFICATION.md) -----------------------

/// The `certify-domains` envelope, signed by `key`, with a fresh `issuedAt`:
/// the registry requires each accepted certification to move strictly
/// forward, and the fixture entry lives across runs.
pub fn certify_body(key: &Key, origin: &str, agent_id: &str, domains: &[&str]) -> Value {
    let now = time_now_fixed_ms();
    let payload = json!({
        "action": "certify-domains",
        "agentId": agent_id,
        "domains": domains,
        "issuedAt": now,
        "registryOrigin": origin,
    });
    let bytes = a2a_card::canonical::canonicalize(&payload).unwrap();
    let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
    let protected =
        Base64UrlUnpadded::encode_string(&a2a_card::canonical::canonicalize(&header).unwrap());
    json!({
        "certification": {
            "protected": protected,
            "payload": Base64UrlUnpadded::encode_string(&bytes),
            "signature": key.sign(&a2a_card::canonical::signing_input(&protected, &bytes)),
        },
        "keys": [key.jwk()],
    })
}

/// Wall-clock UTC in the registry's own fixed-width millisecond form.
fn time_now_fixed_ms() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    )
}

pub async fn put_domains(
    client: &reqwest::Client,
    origin: &str,
    agent_id: &str,
    body: &Value,
) -> Response {
    send(
        client
            .put(format!("{origin}/v1/agents/{agent_id}/domains"))
            .json(body),
    )
    .await
}
