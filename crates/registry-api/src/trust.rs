//! Experimental PR117 observation profile. Every acceptance requires online
//! DNS/status checks; no independent transparency witness is claimed.
use crate::{
    Problem, Store,
    store::{AgentRecord, CertificationState},
};
use aithos_catalog_signatures::{crypto, json as strict, pr117, verification};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    routing::{get, post},
};
use registry_core::{Domain, Jwk, Status, jws, rrset_names_agent};
use registry_dns::Resolver;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ISSUER: &str = "did:web:registry.aithos.world";
pub const HOST: &str = "https://agents.aithos.app";
pub const SCHEMA: &str = "https://registry.aithos.world/schemas/host-domain-observation/v1";
#[derive(Clone)]
pub struct TrustCommit {
    pub agent: AgentRecord,
    pub certification: CertificationState,
    pub id: String,
    pub envelope: Value,
}
#[async_trait]
pub trait TrustIo: Send + Sync {
    /// Only configured origins; bounded exact bytes, no redirects or private IPs.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
    async fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], String>;
    fn kid(&self) -> &str;
    fn did_document(&self) -> Value;
}
#[derive(Clone)]
pub struct TrustState {
    pub store: Arc<dyn Store>,
    pub resolver: Arc<dyn Resolver>,
    pub io: Arc<dyn TrustIo>,
    pub origin: String,
}
impl TrustState {
    fn issuer(&self) -> String {
        format!("did:web:{}", self.origin.trim_start_matches("https://"))
    }
}
fn bad(detail: impl std::fmt::Display) -> Problem {
    Problem::new(400, "TRUST_INVALID", detail.to_string())
}
fn unavailable(_: impl std::fmt::Display) -> Problem {
    Problem::new(
        503,
        "TRUST_UNAVAILABLE",
        "trust evidence could not be checked",
    )
}
fn conflict() -> Problem {
    Problem::new(
        409,
        "TRUST_CONFLICT",
        "evidence changed; obtain a new proof and retry",
    )
}
fn check(ok: bool, message: &str) -> Result<(), Problem> {
    if ok { Ok(()) } else { Err(bad(message)) }
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, Problem> {
    v[k].as_str()
        .ok_or_else(|| bad(format!("missing string: {k}")))
}
fn token(s: &str) -> bool {
    s.len() == 43 && crypto::decode(s).is_ok_and(|b| b.len() == 32 && crypto::encode(&b) == s)
}
fn digest(v: &Value) -> Result<String, Problem> {
    Ok(strict::digest(&strict::canonical(v).map_err(bad)?))
}
fn timestamp(t: i64) -> Result<String, Problem> {
    OffsetDateTime::from_unix_timestamp(t)
        .map_err(bad)?
        .format(&Rfc3339)
        .map_err(bad)
}

pub fn router(state: TrustState) -> Router {
    Router::new()
        .route("/.well-known/did.json", get(document))
        .route("/schemas/host-domain-observation/v1", get(schema))
        .route(
            "/v1/experimental/trust/agents/{agent}/issuances",
            post(issue),
        )
        .route(
            "/v1/experimental/trust/agents/{agent}/issuances/{issuance}",
            get(issuance),
        )
        .route(
            "/v1/experimental/trust/agents/{agent}/issuances/{issuance}/status",
            get(status),
        )
        .route("/trustmanifest/{agent}", get(latest))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::map_response(
            |mut r: axum::response::Response| async move {
                r.headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
                r
            },
        ))
        .with_state(state)
}
async fn document(State(s): State<TrustState>) -> Json<Value> {
    Json(s.io.did_document())
}
async fn schema() -> Json<Value> {
    Json(
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":SCHEMA,"title":"Experimental Aithos domain and hosting observations","type":"object","required":["experimental","registryAgentId","domain","hostReceipt","dns","consent","transparency"],"properties":{"experimental":{"const":true},"transparency":{"type":"object","properties":{"independentWitness":{"const":false},"requiresOnlineRevalidation":{"const":true}},"required":["independentWitness","requiresOnlineRevalidation"]}}}),
    )
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    entry: Value,
    receipt: String,
    consent: Consent,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    protected: String,
    payload: String,
    signature: String,
    key: Value,
}

/// Strict compact receipt verification against keys fetched from the configured
/// hosting origin. No attacker-provided jku, issuer or key endpoint is followed.
pub fn verify_host(
    receipt: &str,
    jwks: &Value,
    now: i64,
    origin: &str,
    agent: &str,
    domain: &str,
    nonce: &str,
) -> Result<Value, Problem> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let parts: Vec<_> = receipt.split('.').collect();
    check(parts.len() == 3, "malformed host receipt")?;
    let header = strict::parse(&crypto::decode(parts[0]).map_err(bad)?).map_err(bad)?;
    check(
        header.as_object().is_some_and(|o| o.len() == 3)
            && header["alg"] == "ES256"
            && header["typ"] == "aithos-host-control+jwt",
        "wrong host receipt header",
    )?;
    let kid = text(&header, "kid")?;
    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| bad("missing host keys"))?;
    let keys: Vec<_> = keys.iter().filter(|k| k["kid"] == kid).collect();
    check(keys.len() == 1, "ambiguous or missing host key")?;
    let key = keys[0];
    check(
        key["kty"] == "EC"
            && key["crv"] == "P-256"
            && key["alg"] == "ES256"
            && key["use"] == "sig"
            && key.get("d").is_none(),
        "wrong host key",
    )?;
    let mut point = vec![4];
    point.extend(crypto::decode(text(key, "x")?).map_err(bad)?);
    point.extend(crypto::decode(text(key, "y")?).map_err(bad)?);
    let public = VerifyingKey::from_sec1_bytes(&point).map_err(bad)?;
    let sig = Signature::from_slice(&crypto::decode(parts[2]).map_err(bad)?).map_err(bad)?;
    public
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(bad)?;
    let c = strict::parse(&crypto::decode(parts[1]).map_err(bad)?).map_err(bad)?;
    check(
        c["iss"] == HOST
            && c["aud"] == origin
            && c["registryAgentId"] == agent
            && c["domain"] == domain
            && c["nonce"] == nonce,
        "host receipt subject mismatch",
    )?;
    let iat = c["iat"]
        .as_i64()
        .ok_or_else(|| bad("missing receipt iat"))?;
    let exp = c["exp"]
        .as_i64()
        .ok_or_else(|| bad("missing receipt exp"))?;
    check(
        iat <= now && iat > now - 600 && exp > now && exp <= iat + 600,
        "host receipt expired or future",
    )?;
    let id = text(&c, "hostedAgentId")?;
    let proof = text(&c, "jti")?;
    let uuid = |s: &str| {
        s.len() == 36
            && s.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
                }
            })
    };
    check(uuid(id) && uuid(proof), "invalid hosting ID")?;
    check(
        c["cardUrl"] == format!("{HOST}/agents/{id}/agent-card.json"),
        "unexpected hosted card URL",
    )?;
    check(
        c["managementRevision"].as_u64().is_some_and(|v| v > 0),
        "missing hosting revision",
    )?;
    Ok(c)
}
async fn fetched_json(s: &TrustState, url: &str) -> Result<Value, Problem> {
    strict::parse(&s.io.fetch(url).await.map_err(unavailable)?).map_err(unavailable)
}
async fn hosting_active(s: &TrustState, c: &Value, receipt: &str) -> Result<bool, Problem> {
    let url = format!(
        "{HOST}/v1/agents/{}/control-proofs/{}",
        text(c, "hostedAgentId")?,
        text(c, "jti")?
    );
    let status = fetched_json(s, &url).await?;
    Ok(status["active"] == true && status["receipt"] == receipt)
}
async fn issue(
    state: State<TrustState>,
    path: Path<String>,
    body: Bytes,
) -> Result<Json<Value>, Problem> {
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        issue_inner(state, path, body),
    )
    .await
    .map_err(unavailable)?
}
async fn issue_inner(
    State(s): State<TrustState>,
    Path(agent): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, Problem> {
    check(token(&agent), "invalid registry identity")?;
    let value = strict::parse(&body).map_err(bad)?;
    let req: Request = serde_json::from_value(value.clone()).map_err(bad)?;
    let record = s
        .store
        .get_agent(&agent)
        .await?
        .ok_or_else(Problem::not_found)?;
    check(record.status == Status::Active, "agent is withdrawn")?;
    let consent_bytes = crypto::decode(&req.consent.payload).map_err(bad)?;
    let p = strict::parse(&consent_bytes).map_err(bad)?;
    check(
        strict::canonical(&p).map_err(bad)? == consent_bytes,
        "consent is not JCS",
    )?;
    let key = Jwk::parse(&req.consent.key)?;
    let header = jws::parse_protected(&req.consent.protected)?;
    check(
        record.authorized_kids.contains(&header.kid),
        "consent key is not authorized",
    )?;
    jws::verify_detached(
        &header,
        &req.consent.protected,
        &req.consent.signature,
        &consent_bytes,
        &key,
    )?;
    let expected = [
        "action",
        "agentId",
        "registryOrigin",
        "seq",
        "domain",
        "nonce",
        "entryDigest",
        "receiptDigest",
        "issuedAt",
        "expiresAt",
    ];
    check(
        p.as_object().is_some_and(|o| {
            o.len() == expected.len() && expected.iter().all(|k| o.contains_key(*k))
        }),
        "unexpected consent fields",
    )?;
    check(
        p["action"] == "issue-host-domain-trust-v1"
            && p["agentId"] == agent
            && p["registryOrigin"] == s.origin
            && p["seq"].as_u64() == Some(record.seq),
        "consent context mismatch",
    )?;
    check(
        p["entryDigest"] == digest(&req.entry)?
            && p["receiptDigest"] == strict::digest(req.receipt.as_bytes()),
        "consent artifact mismatch",
    )?;
    let domain = Domain::parse(text(&p, "domain")?)?;
    let domain_name = text(&p, "domain")?;
    let nonce = text(&p, "nonce")?;
    check(token(nonce), "invalid nonce")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let issued = verification::timestamp(text(&p, "issuedAt")?)
        .map_err(bad)?
        .unix_timestamp();
    let expires = verification::timestamp(text(&p, "expiresAt")?)
        .map_err(bad)?
        .unix_timestamp();
    check(
        issued <= now && issued > now - 600 && expires > now && expires <= issued + 600,
        "consent expired or future",
    )?;
    let id = nonce.to_string();
    let request_digest = digest(&value)?;
    if let Some(existing) = s.store.get_trust(&agent, &id).await? {
        check(
            existing["requestDigest"] == request_digest,
            "nonce already used for different evidence",
        )?;
        return Ok(Json(existing));
    }
    let certification = s.store.get_certification(&agent).await?;
    check(
        certification.requested.contains(domain_name)
            && certification
                .observed
                .iter()
                .any(|d| d.domain == domain_name),
        "domain is not currently certified",
    )?;
    let jwks = fetched_json(&s, &format!("{HOST}/.well-known/jwks.json")).await?;
    let host = verify_host(
        &req.receipt,
        &jwks,
        now,
        &s.origin,
        &agent,
        domain_name,
        nonce,
    )?;
    verification::validate_entry(&req.entry).map_err(bad)?;
    check(
        req.entry["type"] == "application/a2a-agent-card+json"
            && req.entry["url"] == host["cardUrl"]
            && req.entry.get("data").is_none(),
        "entry does not identify hosted card",
    )?;
    let identifier = text(&req.entry, "identifier")?;
    check(
        identifier.starts_with(&format!("urn:air:{domain_name}:agent:")),
        "entry publisher does not match the proven domain",
    )?;
    check(
        req.entry.get("trustManifest").is_none()
            && req.entry.get("trustManifests").is_none()
            && req.entry.get("signatures").is_none(),
        "submit the unsigned catalog entry",
    )?;
    let artifact =
        s.io.fetch(text(&host, "cardUrl")?)
            .await
            .map_err(unavailable)?;
    let card_digest = strict::digest(&artifact);
    check(host["cardDigest"] == card_digest, "hosted card changed")?;
    if let Some(d) = req.entry.get("digest") {
        check(d == &card_digest, "entry digest mismatch")?;
    }
    let answers = s
        .resolver
        .txt(&domain.query_name())
        .await
        .map_err(unavailable)?;
    check(
        rrset_names_agent(&answers, &agent),
        "DNS does not name registry identity",
    )?;
    let dns_at = OffsetDateTime::now_utc().unix_timestamp();
    check(
        hosting_active(&s, &host, &req.receipt).await?,
        "hosting receipt is no longer active",
    )?;
    let expiration = expires.min(host["exp"].as_i64().unwrap());
    let signed_at = OffsetDateTime::now_utc().unix_timestamp();
    check(expiration > signed_at, "proof expired during validation")?;
    let evidence = json!({"experimental":true,"registryAgentId":agent,"registrySeq":record.seq,
        "registryCardDigest":record.card_digest,"domain":domain_name,"hostReceipt":req.receipt,
        "dns":{"query":domain.query_name(),"records":answers,"observedAt":timestamp(dns_at)?,"resolverProfile":"registry-recursive-no-dnssec-assertion"},
        "consent":req.consent,"consentAcceptedAt":timestamp(signed_at)?,
        "transparency":{"independentWitness":false,"requiresOnlineRevalidation":true},
        "claim":"Domain declaration and hosted-agent management control observed at the stated times; no legal ownership or safety assertion."});
    let issuer = s.issuer();
    let mut entry = req.entry;
    entry["digest"] = json!(card_digest);
    entry["trustManifests"] = json!({issuer.clone():{"trustSchema":{"identifier":SCHEMA,"version":"1.0.0"},"extensions":{SCHEMA:evidence}}});
    pr117::validate_manifest(&entry["trustManifests"][&issuer]).map_err(bad)?;
    let mut paths = pr117::release_paths(&entry);
    paths.push(vec!["trustManifests".into(), issuer.clone()]);
    let mut signature = pr117::Signature {
        signer: issuer.clone(),
        profile: "did-web-v1".into(),
        paths,
        issued_at: timestamp(signed_at)?,
        expires_at: Some(timestamp(expiration)?),
        jws: String::new(),
    };
    let payload = pr117::payload(&entry, &signature, pr117::Scope::Entry).map_err(bad)?;
    let protected =
        crypto::encode(&strict::canonical(&json!({"alg":"ES256","kid":s.io.kid()})).map_err(bad)?);
    let input = format!("{protected}.{}", crypto::encode(&payload));
    let signed = s.io.sign(input.as_bytes()).await.map_err(unavailable)?;
    signature.jws = format!("{protected}..{}", crypto::encode(&signed));
    crypto::verify(&payload, &signature.jws, &issuer, &s.io.did_document()).map_err(unavailable)?;
    entry["signatures"] = json!([signature]);
    let root = format!(
        "{}/v1/experimental/trust/agents/{agent}/issuances/{id}",
        s.origin
    );
    let envelope = json!({"dialect":"ai-catalog-pr117-51df07b","experimental":true,"issuanceId":id,
        "requestDigest":request_digest,"entry":entry,"statusUrl":format!("{root}/status"),"issuanceUrl":root,
        "expiresAt":timestamp(expiration)?,"hostClaims":host});
    check(
        strict::canonical(&envelope).map_err(bad)?.len() < 250_000,
        "issuance too large",
    )?;
    // Signing is not publication: the atomic store fence decides publication.
    match s
        .store
        .commit_trust(&TrustCommit {
            agent: record,
            certification,
            id: id.clone(),
            envelope: envelope.clone(),
        })
        .await
    {
        Ok(()) => Ok(Json(envelope)),
        Err(crate::StoreError::Conflict) => {
            if let Some(existing) = s.store.get_trust(&agent, &id).await?
                && existing["requestDigest"] == request_digest
            {
                return Ok(Json(existing));
            }
            Err(conflict())
        }
        Err(e) => Err(e.into()),
    }
}
async fn issuance(
    State(s): State<TrustState>,
    Path((agent, id)): Path<(String, String)>,
) -> Result<Json<Value>, Problem> {
    check(token(&agent) && token(&id), "invalid issuance address")?;
    s.store
        .get_trust(&agent, &id)
        .await?
        .map(Json)
        .ok_or_else(Problem::not_found)
}
async fn current(s: &TrustState, agent: &str, v: &Value) -> Result<bool, Problem> {
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        current_inner(s, agent, v),
    )
    .await
    .map_err(unavailable)?
}
async fn current_inner(s: &TrustState, agent: &str, v: &Value) -> Result<bool, Problem> {
    let now = OffsetDateTime::now_utc();
    if verification::timestamp(text(v, "expiresAt")?).map_err(unavailable)? <= now {
        return Ok(false);
    }
    let Some(record) = s.store.get_agent(agent).await? else {
        return Ok(false);
    };
    let evidence = &v["entry"]["trustManifests"][s.issuer()]["extensions"][SCHEMA];
    if record.status != Status::Active
        || evidence["registrySeq"].as_u64() != Some(record.seq)
        || evidence["registryCardDigest"] != record.card_digest
    {
        return Ok(false);
    }
    let domain = Domain::parse(text(evidence, "domain")?)?;
    let cert = s.store.get_certification(agent).await?;
    if !cert.requested.contains(text(evidence, "domain")?)
        || !cert.observed.iter().any(|d| d.domain == evidence["domain"])
    {
        return Ok(false);
    }
    let answers = match s.resolver.txt(&domain.query_name()).await {
        Ok(v) => v,
        Err(registry_dns::ResolveError::NoRecords) => return Ok(false),
        Err(e) => return Err(unavailable(e)),
    };
    if !rrset_names_agent(&answers, agent) {
        return Ok(false);
    }
    let host = &v["hostClaims"];
    let receipt = text(evidence, "hostReceipt")?;
    if !hosting_active(s, host, receipt).await? {
        return Ok(false);
    }
    let bytes =
        s.io.fetch(text(host, "cardUrl")?)
            .await
            .map_err(unavailable)?;
    if strict::digest(&bytes) != host["cardDigest"] {
        return Ok(false);
    }
    // Re-read local state after external work; this is a time-bounded observation,
    // never a claim of an atomic snapshot across DNS and two services.
    Ok(s.store.get_agent(agent).await?.as_ref() == Some(&record)
        && s.store.get_certification(agent).await? == cert
        && OffsetDateTime::now_utc()
            < verification::timestamp(text(v, "expiresAt")?).map_err(unavailable)?)
}
async fn status(
    State(s): State<TrustState>,
    Path((agent, id)): Path<(String, String)>,
) -> Result<Json<Value>, Problem> {
    let v = s
        .store
        .get_trust(&agent, &id)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(Json(
        json!({"current":current(&s,&agent,&v).await?,"checkedAt":timestamp(OffsetDateTime::now_utc().unix_timestamp())?,"experimental":true,"independentWitness":false}),
    ))
}
async fn latest(
    State(s): State<TrustState>,
    Path(agent): Path<String>,
) -> Result<Json<Value>, Problem> {
    let v = s
        .store
        .get_trust(&agent, "LATEST")
        .await?
        .ok_or_else(Problem::not_found)?;
    if !current(&s, &agent, &v).await? {
        return Err(Problem::new(
            410,
            "TRUST_STALE",
            "obtain a fresh ownership receipt and issuance",
        ));
    }
    Ok(Json(v))
}
