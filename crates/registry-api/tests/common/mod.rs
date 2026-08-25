//! HTTP test harness: a router over an in-memory store, and real signatures.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use registry_api::{MemoryStore, RegistryConfig, router};

pub const ORIGIN: &str = "https://registry.aithos.world";

pub fn app() -> Router {
    router(
        Arc::new(MemoryStore::new()),
        RegistryConfig {
            origin: ORIGIN.to_string(),
        },
    )
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

pub fn write_body(card: &Value, keys: &[&Key]) -> Value {
    json!({ "agentCard": card, "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() })
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

pub async fn get(app: &Router, path: &str) -> (StatusCode, Vec<u8>, Response<Body>) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    send(app, req).await
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
