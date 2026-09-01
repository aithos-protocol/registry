//! HTTP test harness: a router over an in-memory store, and real signatures.
//!
//! Shared by several test binaries, each using its own subset — the
//! certification helpers mean nothing to the write-path suite — so
//! per-binary dead-code analysis is quieted here rather than answered.
#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use registry_api::{MemoryStore, RegistryConfig, router};
use registry_dns::StaticResolver;

pub const ORIGIN: &str = "https://registry.aithos.world";

/// A router whose DNS answers empty for every name: fine for everything that
/// is not about certification, and the "nothing declared" world for what is.
pub fn app() -> Router {
    app_with(StaticResolver::new())
}

/// A router over the DNS this test describes. Same split as `MemoryStore`
/// against the AWS store: the handlers under test are the real ones.
pub fn app_with(resolver: StaticResolver) -> Router {
    router(
        Arc::new(MemoryStore::new()),
        Arc::new(resolver),
        RegistryConfig {
            origin: ORIGIN.to_string(),
            revalidate_interval_seconds: 3600,
        },
    )
}

/// The record data a zone publishes to declare `agent_id` (§3.2), spelled
/// through the shared constants so no test invents its own dialect of it.
pub fn zone_record(agent_id: &str) -> String {
    format!("v={}; k={agent_id}", registry_core::TXT_VERSION)
}

/// The query name for one certified domain, through the one implementation.
pub fn query_name(domain: &str) -> String {
    registry_core::Domain::parse(domain)
        .expect("test domain")
        .query_name()
}

pub struct Key(p256::ecdsa::SigningKey);

impl Key {
    pub fn new() -> Self {
        Key(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
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
        let sig: Signature = self.0.sign(input);
        Base64UrlUnpadded::encode_string(&sig.to_bytes())
    }
}

pub fn card_body(version: &str) -> Value {
    json!({
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "description": "A card used by the HTTP test suite.",
        "name": "Test Agent",
        "skills": [{"description": "Does one thing.", "id": "s1", "name": "Skill", "tags": ["demo"]}],
        "supportedInterfaces": [
            {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": "https://agent.example/a2a"}
        ],
        "version": version,
    })
}

/// Assemble a signed card, exactly as a browser client would.
pub fn signed_card(version: &str, keys: &[&Key]) -> Value {
    let body = card_body(version);
    let payload = a2a_card::canonical::canonicalize(&body).unwrap();
    let signatures: Vec<Value> = keys
        .iter()
        .map(|k| {
            let header = json!({"alg": "ES256", "typ": "JOSE", "kid": k.kid()});
            let protected = Base64UrlUnpadded::encode_string(
                &a2a_card::canonical::canonicalize(&header).unwrap(),
            );
            let input = a2a_card::canonical::signing_input(&protected, &payload);
            json!({"protected": protected, "signature": k.sign(&input)})
        })
        .collect();
    let mut card = body;
    card.as_object_mut()
        .unwrap()
        .insert("signatures".into(), Value::Array(signatures));
    card
}

/// Build the publication proof that §6.2 requires alongside a card.
pub fn proof(key: &Key, agent_id: &str, card_digest: &str) -> Value {
    let payload = json!({
        "action": "publish",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": "2026-08-25T12:00:00.000Z",
        "registryOrigin": ORIGIN,
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
pub fn write_body(card: &Value, keys: &[&Key]) -> Value {
    write_body_for(&keys[0].kid(), card, keys, keys[0])
}

pub fn write_body_for(agent_id: &str, card: &Value, keys: &[&Key], _signer: &Key) -> Value {
    // Some tests submit a card the registry must refuse. The card is checked
    // before the proof is, so a placeholder digest here never masks the reason
    // such a test is asserting on.
    let digest = a2a_card::validate_value(card.clone())
        .map(|c| c.digest)
        .unwrap_or_else(|_| "sha256:not-a-valid-card".to_string());
    json!({
        "agentCard": card,
        "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>(),
        "proofs": keys.iter().map(|k| proof(k, agent_id, &digest)).collect::<Vec<_>>(),
    })
}

pub fn withdraw_body(key: &Key, agent_id: &str, card_digest: &str) -> Value {
    let payload = json!({
        "action": "withdraw",
        "agentId": agent_id,
        "cardDigest": card_digest,
        "issuedAt": "2026-08-25T12:00:00.000Z",
        "registryOrigin": ORIGIN,
    });
    let bytes = a2a_card::canonical::canonicalize(&payload).unwrap();
    let payload_b64 = Base64UrlUnpadded::encode_string(&bytes);
    let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
    let protected =
        Base64UrlUnpadded::encode_string(&a2a_card::canonical::canonicalize(&header).unwrap());
    let signature = key.sign(&a2a_card::canonical::signing_input(&protected, &bytes));
    json!({
        "withdrawal": {"protected": protected, "payload": payload_b64, "signature": signature},
        "keys": [key.jwk()],
    })
}

// --- request helpers -----------------------------------------------------

pub async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>, Response<Body>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (
        status,
        bytes.clone(),
        Response::from_parts(parts, Body::from(bytes)),
    )
}

pub async fn put(app: &Router, agent_id: &str, body: &Value) -> (StatusCode, Value) {
    put_with(app, agent_id, body, None).await
}

pub async fn put_with(
    app: &Router,
    agent_id: &str,
    body: &Value,
    if_match: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/agents/{agent_id}"))
        .header("content-type", "application/json");
    if let Some(v) = if_match {
        req = req.header("if-match", v);
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let (status, bytes, _) = send(app, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Send a request whose body is not necessarily valid JSON — the point of some
/// tests is what happens before anything parses it.
pub async fn send_raw(
    app: &Router,
    method: &str,
    path: &str,
    body: String,
) -> (StatusCode, Vec<u8>, Response<Body>) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    send(app, req).await
}

pub async fn get(app: &Router, path: &str) -> (StatusCode, Vec<u8>, Response<Body>) {
    get_with(app, path, &[]).await
}

pub async fn get_with(
    app: &Router,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, Vec<u8>, Response<Body>) {
    let mut req = Request::builder().uri(path);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    send(app, req.body(Body::empty()).unwrap()).await
}

pub async fn get_json(app: &Router, path: &str) -> (StatusCode, Value) {
    let (status, bytes, _) = get(app, path).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn delete(app: &Router, agent_id: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/agents/{agent_id}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, bytes, _) = send(app, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub fn header_of(res: &Response<Body>, name: &str) -> String {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

// --- certification helpers (DOMAIN-CERTIFICATION.md) ----------------------

/// The `PUT /v1/agents/{id}/domains` envelope, signed by `key`.
pub fn certify_body(key: &Key, agent_id: &str, domains: &[&str], issued_at: &str) -> Value {
    let payload = json!({
        "action": "certify-domains",
        "agentId": agent_id,
        "domains": domains,
        "issuedAt": issued_at,
        "registryOrigin": ORIGIN,
    });
    let bytes = a2a_card::canonical::canonicalize(&payload).unwrap();
    let header = json!({"alg": "ES256", "typ": "JOSE", "kid": key.kid()});
    let protected =
        Base64UrlUnpadded::encode_string(&a2a_card::canonical::canonicalize(&header).unwrap());
    let signature = key.sign(&a2a_card::canonical::signing_input(&protected, &bytes));
    json!({
        "certification": {
            "protected": protected,
            "payload": Base64UrlUnpadded::encode_string(&bytes),
            "signature": signature,
        },
        "keys": [key.jwk()],
    })
}

pub async fn put_domains(app: &Router, agent_id: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/agents/{agent_id}/domains"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, bytes, _) = send(app, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
