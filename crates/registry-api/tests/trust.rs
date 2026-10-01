use aithos_catalog_signatures::{
    crypto::{self, Es256Signer, LocalKey},
    json as strict, pr117,
    verification::{Policy, Requirements},
};
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use registry_api::{
    Commit, MemoryStore, Store,
    store::{CertificationState, DomainRecord},
    trust::{self, HOST, ISSUER, SCHEMA, TrustIo, TrustState},
};
use registry_core::Jwk;
use registry_dns::{Resolver, StaticResolver};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
struct Io {
    key: LocalKey,
    responses: Mutex<BTreeMap<String, Vec<u8>>>,
}
#[async_trait]
impl TrustIo for Io {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        self.responses
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or("unknown URL".into())
    }
    async fn sign(&self, b: &[u8]) -> Result<[u8; 64], String> {
        self.key.sign_es256(b).map_err(|e| e.to_string())
    }
    fn kid(&self) -> &str {
        "did:web:registry.aithos.world#test"
    }
    fn did_document(&self) -> Value {
        self.key.did_document(ISSUER, self.kid()).unwrap()
    }
}
struct Fixture {
    store: Arc<MemoryStore>,
    io: Arc<Io>,
    dns: Arc<dyn Resolver>,
    agent: String,
    key: SigningKey,
    jwk: Value,
    request: Value,
    artifact: Vec<u8>,
    nonce: String,
}
fn sign(key: &SigningKey, header: Value, payload: &[u8]) -> (String, String) {
    let h = crypto::encode(&strict::canonical(&header).unwrap());
    let sig: Signature = key.sign(format!("{h}.{}", crypto::encode(payload)).as_bytes());
    (h, crypto::encode(&sig.to_bytes()))
}
fn jwk(key: &SigningKey) -> Value {
    let p = key.verifying_key().to_encoded_point(false);
    json!({"kty":"EC","crv":"P-256","x":crypto::encode(p.x().unwrap()),"y":crypto::encode(p.y().unwrap())})
}
impl Fixture {
    async fn new() -> Self {
        let store = Arc::new(MemoryStore::new());
        let key = SigningKey::from_slice(&[42; 32]).unwrap();
        let jwk = jwk(&key);
        let agent = Jwk::parse(&jwk).unwrap().thumbprint().to_string();
        store
            .commit(&Commit {
                agent_id: agent.clone(),
                expected_seq: None,
                seq: 1,
                card_digest: "sha256:registry-copy".into(),
                card_version: "0.2.0".into(),
                card_bytes: b"copy".to_vec(),
                keys: vec![jwk.clone()],
                authorized_kids: [agent.clone()].into(),
                created_at: "2026-10-01T00:00:00.000Z".into(),
                existing_created_at: None,
            })
            .await
            .unwrap();
        store
            .put_certification(
                &agent,
                &CertificationState {
                    requested: ["mathieucolla.com".into()].into(),
                    observed: vec![DomainRecord {
                        domain: "mathieucolla.com".into(),
                        certified_at: "2026-10-01T00:00:00.000Z".into(),
                        last_checked_at: "2026-10-01T00:00:00.000Z".into(),
                        consecutive_failures: 0,
                    }],
                    issued_at: Some("2026-10-01T00:00:00.000Z".into()),
                },
            )
            .await
            .unwrap();
        let host_key = SigningKey::from_slice(&[43; 32]).unwrap();
        let mut host_jwk = jwk_fn(&host_key);
        host_jwk["kid"] = json!("host-key");
        host_jwk["alg"] = json!("ES256");
        host_jwk["use"] = json!("sig");
        let nonce = crypto::encode(&[7; 32]);
        let now = OffsetDateTime::now_utc();
        let host_id = "f072a0c1-d945-4a9c-b4ce-d805a4a50eab";
        let proof = "11111111-1111-4111-8111-111111111111";
        let artifact = b"{\"name\":\"exact bytes\", \"signatures\":[]}".to_vec();
        let url = format!("{HOST}/agents/{host_id}/agent-card.json");
        let claims = json!({"iss":HOST,"aud":"https://registry.aithos.world","jti":proof,"iat":now.unix_timestamp(),"exp":now.unix_timestamp()+600,"nonce":nonce,"hostedAgentId":host_id,"registryAgentId":agent,"domain":"mathieucolla.com","cardUrl":url,"cardDigest":strict::digest(&artifact),"managementRevision":3});
        let b = strict::canonical(&claims).unwrap();
        let (h, sig) = sign(
            &host_key,
            json!({"alg":"ES256","typ":"aithos-host-control+jwt","kid":"host-key"}),
            &b,
        );
        let receipt = format!("{h}.{}.{sig}", crypto::encode(&b));
        let mut responses = BTreeMap::new();
        responses.insert(
            format!("{HOST}/.well-known/jwks.json"),
            serde_json::to_vec(&json!({"keys":[host_jwk]})).unwrap(),
        );
        responses.insert(url.clone(), artifact.clone());
        responses.insert(
            format!("{HOST}/v1/agents/{host_id}/control-proofs/{proof}"),
            serde_json::to_vec(&json!({"active":true,"receipt":receipt})).unwrap(),
        );
        let io = Arc::new(Io {
            key: LocalKey::generate(),
            responses: Mutex::new(responses),
        });
        let dns = StaticResolver::new()
            .observed("_a2a.mathieucolla.com", &[&format!("v=A2A1; k={agent}")]);
        let entry = json!({"identifier":"urn:air:mathieucolla.com:agent:meeting","type":"application/a2a-agent-card+json","url":url,"version":"0.2.0"});
        let payload = json!({"action":"issue-host-domain-trust-v1","agentId":agent,"registryOrigin":"https://registry.aithos.world","seq":1,"domain":"mathieucolla.com","nonce":nonce,"entryDigest":strict::digest(&strict::canonical(&entry).unwrap()),"receiptDigest":strict::digest(receipt.as_bytes()),"issuedAt":now.format(&Rfc3339).unwrap(),"expiresAt":(now+time::Duration::seconds(600)).format(&Rfc3339).unwrap()});
        let mut this = Self {
            store,
            io,
            dns: Arc::new(dns),
            agent,
            key,
            jwk,
            request: json!({"entry":entry,"receipt":receipt}),
            artifact,
            nonce,
        };
        this.consent(payload);
        this
    }
    fn consent(&mut self, p: Value) {
        let bytes = strict::canonical(&p).unwrap();
        let (h, s) = sign(
            &self.key,
            json!({"alg":"ES256","typ":"JOSE","kid":self.agent}),
            &bytes,
        );
        self.request["consent"] =
            json!({"protected":h,"payload":crypto::encode(&bytes),"signature":s,"key":self.jwk});
    }
    fn router(&self) -> Router {
        trust::router(TrustState {
            store: self.store.clone(),
            resolver: self.dns.clone(),
            io: self.io.clone(),
            origin: "https://registry.aithos.world".into(),
        })
    }
    async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (StatusCode, Value) {
        let response = self
            .router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        body.map(|b| serde_json::to_vec(b).unwrap())
                            .unwrap_or_default(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn issue(&self) -> (StatusCode, Value) {
        self.call(
            "POST",
            &format!("/v1/experimental/trust/agents/{}/issuances", self.agent),
            Some(&self.request),
        )
        .await
    }
}
fn jwk_fn(k: &SigningKey) -> Value {
    jwk(k)
}
#[tokio::test]
async fn end_to_end_signed_contribution_idempotency_and_online_status() {
    let f = Fixture::new().await;
    let (status, out) = f.issue().await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let report = pr117::verify_entry(
        &out["entry"],
        &serde_json::from_value(out["entry"]["signatures"][0].clone()).unwrap(),
        &f.artifact,
        &f.io.did_document(),
        &Policy::new([ISSUER.into()], OffsetDateTime::now_utc()),
        &Requirements {
            contributor: Some(ISSUER.into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(report.accepted, "{report:?}");
    if let Ok(dir) = std::env::var("TRUST_TEST_VECTOR_DIR") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("entry.json"),
            serde_json::to_vec(&out["entry"]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("did.json"),
            serde_json::to_vec(&f.io.did_document()).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("artifact.bin"), &f.artifact).unwrap();
    }

    assert!(!report.publisher_authorized);
    assert_eq!(
        f.issue().await.1,
        out,
        "retry returns original signed bytes"
    );
    let url = format!("/trustmanifest/{}", f.agent);
    assert_eq!(f.call("GET", &url, None).await.0, StatusCode::OK);
    let evidence = &out["entry"]["trustManifests"][ISSUER]["extensions"][SCHEMA];
    assert_eq!(evidence["transparency"]["requiresOnlineRevalidation"], true);
    f.store
        .withdraw(&f.agent, 1, "2026-10-01T01:00:00.000Z")
        .await
        .unwrap();
    assert_eq!(f.call("GET", &url, None).await.0, StatusCode::GONE);
    let historical = format!(
        "/v1/experimental/trust/agents/{}/issuances/{}",
        f.agent, f.nonce
    );
    assert_eq!(f.call("GET", &historical, None).await.1, out);
}
#[tokio::test]
async fn rejects_entry_tampering_and_stale_host_card() {
    let mut f = Fixture::new().await;
    f.request["entry"]["identifier"] = json!("urn:air:mathieucolla.com:agent:other");
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
    let f = Fixture::new().await;
    f.io.responses.lock().unwrap().insert(
        f.request["entry"]["url"].as_str().unwrap().into(),
        b"changed".to_vec(),
    );
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
    assert!(
        f.store
            .get_trust(&f.agent, &f.nonce)
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn rejects_removed_dns_and_revoked_host_receipt() {
    let mut f = Fixture::new().await;
    let dns = StaticResolver::new().observed("_a2a.mathieucolla.com", &[]);
    f.dns = Arc::new(dns);
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
    let f = Fixture::new().await;
    {
        let mut responses = f.io.responses.lock().unwrap();
        let key = responses
            .keys()
            .find(|k| k.contains("/control-proofs/"))
            .unwrap()
            .clone();
        responses.insert(key, b"{\"active\":false}".to_vec());
    }
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn store_fences_withdrawal_and_certification_changes() {
    let f = Fixture::new().await;
    let agent = f.store.get_agent(&f.agent).await.unwrap().unwrap();
    let cert = f.store.get_certification(&f.agent).await.unwrap();
    let c = trust::TrustCommit {
        agent,
        certification: cert.clone(),
        id: f.nonce.clone(),
        envelope: json!({}),
    };
    let mut changed = cert;
    changed.issued_at = Some("2026-10-01T01:00:00.000Z".into());
    changed.observed.clear();
    f.store.put_certification(&f.agent, &changed).await.unwrap();
    assert!(matches!(
        f.store.commit_trust(&c).await,
        Err(registry_api::StoreError::Conflict)
    ));
    let mut c = c;
    c.certification = changed;
    f.store
        .withdraw(&f.agent, 1, "2026-10-01T01:00:00.000Z")
        .await
        .unwrap();
    assert!(matches!(
        f.store.commit_trust(&c).await,
        Err(registry_api::StoreError::Conflict)
    ));
}

#[tokio::test]
async fn rejects_expired_consent_and_tampered_receipt_even_with_fresh_consent() {
    let mut f = Fixture::new().await;
    let mut p =
        strict::parse(&crypto::decode(f.request["consent"]["payload"].as_str().unwrap()).unwrap())
            .unwrap();
    p["issuedAt"] = json!(
        (OffsetDateTime::now_utc() - time::Duration::minutes(20))
            .format(&Rfc3339)
            .unwrap()
    );
    p["expiresAt"] = json!(
        (OffsetDateTime::now_utc() - time::Duration::minutes(10))
            .format(&Rfc3339)
            .unwrap()
    );
    f.consent(p);
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
    let mut f = Fixture::new().await;
    let receipt = f.request["receipt"].as_str().unwrap();
    let mut parts: Vec<String> = receipt.split('.').map(String::from).collect();
    let mut claims = strict::parse(&crypto::decode(&parts[1]).unwrap()).unwrap();
    claims["domain"] = json!("evil.example");
    parts[1] = crypto::encode(&strict::canonical(&claims).unwrap());
    f.request["receipt"] = json!(parts.join("."));
    let mut p =
        strict::parse(&crypto::decode(f.request["consent"]["payload"].as_str().unwrap()).unwrap())
            .unwrap();
    p["receiptDigest"] = json!(strict::digest(
        f.request["receipt"].as_str().unwrap().as_bytes()
    ));
    f.consent(p);
    assert_eq!(f.issue().await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn removing_host_assertion_key_invalidates_current_issuance() {
    let f = Fixture::new().await;
    assert_eq!(f.issue().await.0, StatusCode::OK);
    f.io.responses.lock().unwrap().insert(
        format!("{HOST}/.well-known/jwks.json"),
        b"{\"keys\":[]}".to_vec(),
    );
    assert_eq!(
        f.call("GET", &format!("/trustmanifest/{}", f.agent), None)
            .await
            .0,
        StatusCode::GONE
    );
}
