//! The HTTP surface of `SPEC.md` §6 and §7.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use serde::Deserialize;
use serde_json::{Value, json};

use a2a_card::CanonicalCard;
use registry_core::{
    AgentState, DetachedJws, Outcome, Status, evaluate_withdrawal, evaluate_write,
};

use crate::problem::Problem;
use crate::store::{AgentRecord, Commit, Store};

/// Limits of `SPEC.md` §8.
pub const MAX_CARD_BYTES: usize = 256 * 1024;
/// The largest request body accepted, checked before anything parses it.
///
/// A card is capped at 256 KiB canonical; the envelope adds keys and JSON
/// whitespace, so this leaves generous room. Applying it first is the point:
/// parsing and validating a body only to discover it was too large is exactly
/// the work an attacker wants done, and none of it needs a signature.
pub const MAX_BODY_BYTES: usize = 512 * 1024;
pub const MAX_KEYS: usize = 8;
pub const MAX_SIGNATURES: usize = 8;
pub const DEFAULT_PAGE: usize = 25;
pub const MAX_PAGE: usize = 100;

/// The content type of a certified Agent Card.
const A2A_JSON: &str = "application/a2a+json";
/// Immutable artifacts: addressed by digest, so they can never change.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Mutable pointers: short-lived, because they follow the current version.
const SHORT: &str = "public, max-age=60";

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Canonical HTTPS origin, with no trailing slash. It appears in
    /// withdrawal payloads, so a request signed for one registry cannot be
    /// replayed against another.
    pub origin: String,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub config: Arc<RegistryConfig>,
}

pub fn router(store: Arc<dyn Store>, config: RegistryConfig) -> Router {
    let state = AppState {
        store,
        config: Arc::new(config),
    };
    Router::new()
        .route("/v1/agents", get(list_agents))
        .route(
            "/v1/agents/{agent_id}",
            put(put_agent).get(get_agent).delete(delete_agent),
        )
        .route(
            "/v1/agents/{agent_id}/agent-card.json",
            get(get_current_card),
        )
        .route("/v1/agents/{agent_id}/jwks.json", get(get_jwks))
        .route("/v1/agents/{agent_id}/versions", get(list_versions))
        .route(
            "/v1/agents/{agent_id}/versions/{digest}/agent-card.json",
            get(get_version_card),
        )
        .route("/v1/registry", get(manifest))
        .fallback(not_found)
        // Every refusal this service makes is an RFC 9457 problem — except the
        // ones it does not make itself. A body over the limit is refused by the
        // layer below, a bad `?limit=` by an extractor, an unroutable path by
        // the router: all of them answered in plain text, so a client parsing
        // `code` got nothing exactly when it most needed to know why. This
        // rewrites any error response that is not already a problem document.
        .layer(axum::middleware::map_response(as_problem))
        // Applied **after** every `.route()`. `Router::layer` wraps only the
        // routes registered before it, so the same call placed above this list
        // silently protects nothing — which is exactly what it did until an
        // auditor measured it and found axum's 2 MiB default governing instead.
        // The check in `parse_envelope` applies the same bound a second time,
        // for the Lambda path, which does not pass through this layer at all.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Whether a digest is in the exact form the registry publishes.
fn is_canonical_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        // Lowercase hex, not "lowercase or a digit": the looser test admitted
        // `[g-z]`, so a wider key space than §7.3 states reached the store.
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

async fn not_found() -> Problem {
    Problem::new(404, "NOT_FOUND", "no such endpoint")
}

/// Rewrite a non-problem error response into one.
///
/// Only the shape changes; the status is whatever produced it. Bodies of
/// framework rejections are short and safe to quote — they say what the client
/// sent, not what the service holds.
async fn as_problem(response: Response) -> Response {
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/problem+json"))
    {
        return response;
    }

    let (parts, body) = response.into_parts();
    let detail = match axum::body::to_bytes(body, 4096).await {
        Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).trim().to_string(),
        _ => status
            .canonical_reason()
            .unwrap_or("the request was refused")
            .to_string(),
    };

    let code = match status.as_u16() {
        413 => "CARD_TOO_LARGE",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_ALLOWED",
        400 => "JSON_INVALID",
        _ => "REQUEST_REFUSED",
    };
    Problem::new(parts.status.as_u16(), code, detail).into_response()
}

// --- writes --------------------------------------------------------------

async fn put_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let (card, keys, proofs) = parse_write_body(&body)?;

    let current = state.store.get_agent(&agent_id).await?;

    // A withdrawn entry is terminal, and saying so beats reporting a
    // precondition the caller could never satisfy. Checked before `If-Match`
    // for that reason.
    if let Some(record) = &current
        && record.status == Status::Withdrawn
    {
        return Err(Problem::new(
            410,
            "WITHDRAWN",
            "this agent was withdrawn by its key holder; the identifier is not reusable",
        ));
    }

    if let Some(record) = &current {
        check_if_match(&headers, &record.card_digest)?;
    } else if headers.contains_key(header::IF_MATCH) {
        return Err(Problem::new(
            412,
            "PRECONDITION_FAILED",
            "If-Match was supplied but this agent does not exist yet",
        ));
    }

    let agent_state = current.as_ref().map(to_agent_state).transpose()?;
    let accepted = evaluate_write(
        &agent_id,
        &card,
        &keys,
        &proofs,
        &state.config.origin,
        agent_state.as_ref(),
    )?;

    // An identical resubmission is already published: answer with the current
    // record rather than writing the same bytes again.
    if accepted.outcome == Outcome::Unchanged {
        let record = current.expect("an unchanged write implies an existing record");
        return Ok((
            StatusCode::OK,
            axum::Json(agent_json(&record, &state.config)),
        )
            .into_response());
    }

    let now = now_rfc3339();
    let commit = Commit {
        agent_id: agent_id.clone(),
        expected_seq: current.as_ref().map(|r| r.seq),
        seq: current.as_ref().map_or(1, |r| r.seq + 1),
        card_digest: accepted.card_digest.clone(),
        card_version: accepted.card_version.to_string(),
        card_bytes: card.bytes.clone(),
        // What the registry verified, never what it was handed.
        keys: accepted.keys.clone(),
        authorized_kids: accepted.authorized_kids.clone(),
        created_at: now,
        existing_created_at: current.as_ref().map(|r| r.created_at.clone()),
    };

    let record = state.store.commit(&commit).await?;
    let status = if accepted.is_creation() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut response = (status, axum::Json(agent_json(&record, &state.config))).into_response();
    if accepted.is_creation() {
        let location = format!("/v1/agents/{agent_id}");
        if let Ok(v) = location.parse() {
            response.headers_mut().insert(header::LOCATION, v);
        }
    }
    Ok(response)
}

async fn delete_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    body: Bytes,
) -> Result<Response, Problem> {
    let (withdrawal, keys) = parse_withdraw_body(&body)?;
    let record = state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    let agent_state = to_agent_state(&record)?;

    evaluate_withdrawal(
        &agent_state,
        &state.config.origin,
        &withdrawal.protected,
        &withdrawal.payload,
        &withdrawal.signature,
        &keys,
    )?;

    let record = state
        .store
        .withdraw(&agent_id, record.seq, &now_rfc3339())
        .await?;
    Ok((
        StatusCode::OK,
        axum::Json(agent_json(&record, &state.config)),
    )
        .into_response())
}

// --- public reads --------------------------------------------------------

async fn get_current_card(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let record = state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    if record.status == Status::Withdrawn {
        return Err(gone());
    }
    let bytes = state
        .store
        .get_card_bytes(&agent_id, &record.card_digest)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(card_response(&headers, bytes, &record.card_digest, SHORT))
}

async fn get_version_card(
    State(state): State<AppState>,
    Path((agent_id, digest)): Path<(String, String)>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    // One version, one URL. The stores strip an optional `sha256:` prefix when
    // building their keys, so `.../versions/<hex>/…` and
    // `.../versions/sha256:<hex>/…` resolved the same object — two permanent,
    // `immutable`-cached URLs for one artifact, each stamped with its own ETag.
    // The canonical form is the one every response emits.
    // Axum decodes path parameters before a handler sees them, so `%3A` and
    // `:` arrive identical here while remaining two distinct URIs — `:` is a
    // *reserved* character, so they are not equivalent under RFC 3986
    // normalization. Checking the decoded value alone therefore left the second
    // spelling reachable, and every version path is cached `immutable`: one
    // artifact, two permanent cache entries, which is exactly what §7.3
    // forbids.
    if uri.path().contains('%') {
        return Err(Problem::new(
            404,
            "NOT_FOUND",
            "a version is addressed by its digest written literally, not percent-encoded",
        ));
    }
    if !is_canonical_digest(&digest) {
        return Err(Problem::new(
            404,
            "NOT_FOUND",
            "a version is addressed by its full digest, `sha256:` prefix included",
        ));
    }

    // The object is written before the transaction that commits it, so a
    // failed commit leaves one behind. Requiring the version record first
    // means the registry only ever answers for what it actually published —
    // otherwise a card that lost a rotation race would stay downloadable to
    // anyone holding its digest.
    state
        .store
        .find_version(&agent_id, &digest)
        .await?
        .ok_or_else(Problem::not_found)?;

    // Historical versions stay readable after a withdrawal: the record of what
    // was published is not erased, only its status changes.
    let bytes = state
        .store
        .get_card_bytes(&agent_id, &digest)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(card_response(&headers, bytes, &digest, IMMUTABLE))
}

async fn get_jwks(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Response, Problem> {
    // §6.5 requires a withdrawn entry to stop serving its card *and* its key
    // set. Serving the keys on would let a copy of the withdrawn card keep
    // looking verifiable, which is most of what withdrawing it was for.
    let record = state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    if record.status == Status::Withdrawn {
        return Err(gone());
    }

    let keys = state
        .store
        .get_keys(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/jwk-set+json"),
            (header::CACHE_CONTROL, SHORT),
        ],
        serde_json::to_string(&json!({ "keys": keys })).unwrap_or_default(),
    )
        .into_response())
}

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Response, Problem> {
    let record = state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok((
        [(header::CACHE_CONTROL, SHORT)],
        axum::Json(agent_json(&record, &state.config)),
    )
        .into_response())
}

async fn list_versions(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Response, Problem> {
    state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    let limit = q.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let page = state
        .store
        .list_versions(&agent_id, limit, q.cursor.as_deref())
        .await?;

    let items: Vec<Value> = page
        .items
        .iter()
        .map(|v| {
            json!({
                "seq": v.seq,
                "cardDigest": v.card_digest,
                "cardVersion": v.card_version,
                "signingKids": v.signing_kids,
                "createdAt": v.created_at,
                "agentCardUrl": format!(
                    "{}/v1/agents/{}/versions/{}/agent-card.json",
                    state.config.origin, agent_id, v.card_digest
                ),
            })
        })
        .collect();

    let mut body = json!({ "versions": items });
    if let Some(cursor) = page.next_cursor {
        body["nextCursor"] = json!(cursor);
    }
    // Same freshness as every other projection of state that moves. Only one
    // of the four API-served reads carried this; the other three told a browser
    // or an intermediary proxy nothing at all, and relied on the edge's own
    // default TTL to stand in for a header the origin should send.
    Ok(([(header::CACHE_CONTROL, SHORT)], axum::Json(body)).into_response())
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn list_agents(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Response, Problem> {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let page = state.store.list_agents(limit, q.cursor.as_deref()).await?;
    let items: Vec<Value> = page
        .items
        .iter()
        .map(|r| agent_json(r, &state.config))
        .collect();
    let mut body = json!({ "agents": items });
    if let Some(cursor) = page.next_cursor {
        body["nextCursor"] = json!(cursor);
    }
    // Same freshness as every other projection of state that moves. Only one
    // of the four API-served reads carried this; the other three told a browser
    // or an intermediary proxy nothing at all, and relied on the edge's own
    // default TTL to stand in for a header the origin should send.
    Ok(([(header::CACHE_CONTROL, SHORT)], axum::Json(body)).into_response())
}

async fn manifest(State(state): State<AppState>) -> Response {
    let body = json!({
        "origin": state.config.origin,
        "a2a": {
            "version": "1.0.1",
            "commit": "3303592588e388e62e0f69f701af531d2f4e3991",
        },
        "canonicalization": "RFC 8785",
        "signatures": { "format": "RFC 7515", "algorithms": ["ES256", "EdDSA", "RS256"] },
        "keyIdentifiers": "RFC 7638",
        // The presence-table digest is the one field that lets a second
        // implementation confirm it pinned the same table this one did — which
        // §11 makes the basis of any interoperability claim. Without it the
        // manifest says which A2A commit was read, not what was derived from it.
        "presenceTable": {
            "digest": a2a_card::schema::table_digest(),
            "derivedFrom": "a2a.proto",
        },
        // §11 makes passing the published vectors the basis of any
        // interoperability claim, and §7.5 asks the manifest to point at them.
        // They are not served from this origin — a URL invented here would be a
        // link that 404s, which is worse than none — so the manifest names where
        // they actually are.
        "testVectors": {
            "repository": "https://github.com/aithos-protocol/registry",
            "path": "vectors/",
        },
        "limits": {
            "requestBodyBytes": MAX_BODY_BYTES,
            "cardBytes": MAX_CARD_BYTES,
            "keysPerRequest": MAX_KEYS,
            "signaturesPerCard": MAX_SIGNATURES,
            "validationIssuesReported": a2a_card::presence::MAX_ISSUES,
        },
        "claim": "An entry states that its Agent Card was published by the holder of a \
                  key, and that every version since was signed by a key authorized by \
                  that lineage. It is not a claim about any domain or organization.",
    });
    // The manifest describes the implementation, not any entry's state, so it
    // is the one read here that could be cached for longer — but it changes on
    // deploy, and a stale one misdescribes the service answering the request.
    ([(header::CACHE_CONTROL, SHORT)], axum::Json(body)).into_response()
}

// --- helpers -------------------------------------------------------------

fn gone() -> Problem {
    Problem::new(
        410,
        "WITHDRAWN",
        "this entry was withdrawn by its key holder",
    )
}

fn card_response(
    headers: &HeaderMap,
    bytes: Vec<u8>,
    digest: &str,
    cache: &'static str,
) -> Response {
    let etag = format!("\"{digest}\"");
    let common = [
        (header::CONTENT_TYPE, A2A_JSON.to_string()),
        (header::CACHE_CONTROL, cache.to_string()),
        (header::ETAG, etag.clone()),
    ];

    // §7.1 says the validator is good for `If-None-Match`, and it was not: this
    // origin always sent the full body. Cards are the largest thing served and
    // a current card changes rarely, so the endpoint that says "revalidate
    // after sixty seconds" was answering every revalidation with a full copy.
    //
    // Weak comparison, as RFC 9110 §13.1.2 requires for this header — the
    // opposite of `If-Match`, which needs strong comparison because it guards a
    // write.
    if if_none_match_matches(headers, &etag) {
        return (StatusCode::NOT_MODIFIED, common).into_response();
    }
    (common, bytes).into_response()
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if value.trim() == "*" {
        return true;
    }
    value
        .split(',')
        .map(|candidate| candidate.trim().trim_start_matches("W/"))
        .any(|candidate| candidate == etag)
}

fn agent_json(record: &AgentRecord, config: &RegistryConfig) -> Value {
    json!({
        "agentId": record.agent_id,
        "status": match record.status { Status::Active => "ACTIVE", Status::Withdrawn => "WITHDRAWN" },
        "seq": record.seq,
        "cardDigest": record.card_digest,
        "cardVersion": record.card_version,
        "authorizedKids": record.authorized_kids,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
        "agentCardUrl": format!("{}/v1/agents/{}/agent-card.json", config.origin, record.agent_id),
        "jwksUrl": format!("{}/v1/agents/{}/jwks.json", config.origin, record.agent_id),
    })
}

fn to_agent_state(record: &AgentRecord) -> Result<AgentState, Problem> {
    Ok(AgentState {
        agent_id: record.agent_id.clone(),
        status: record.status,
        card_digest: record.card_digest.clone(),
        card_version: semver::Version::parse(&record.card_version).map_err(|e| {
            Problem::new(
                500,
                "INTERNAL",
                format!("stored version is not semver: {e}"),
            )
        })?,
        authorized_kids: record.authorized_kids.clone(),
    })
}

fn check_if_match(headers: &HeaderMap, current_digest: &str) -> Result<(), Problem> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let value = value.to_str().unwrap_or_default().trim();
    // RFC 9110 §13.1.1: `If-Match` compares strongly, so a weak validator never
    // matches. Stripping the `W/` would quietly weaken the concurrency guard
    // §6.4 offers.
    let matches = value == "*"
        || value
            .split(',')
            .map(str::trim)
            .filter(|t| !t.starts_with("W/"))
            .map(|t| t.trim_matches('"'))
            .any(|t| t == current_digest);
    if matches {
        Ok(())
    } else {
        Err(Problem::new(
            412,
            "PRECONDITION_FAILED",
            format!("If-Match does not name the current digest {current_digest}"),
        ))
    }
}

struct Withdrawal {
    protected: String,
    payload: String,
    signature: String,
}

fn parse_write_body(body: &[u8]) -> Result<(CanonicalCard, Vec<Value>, Vec<DetachedJws>), Problem> {
    let root = parse_envelope(body)?;
    let obj = root.as_object().expect("checked in parse_envelope");
    reject_unknown(obj, &["agentCard", "keys", "proofs"])?;

    let agent_card = obj
        .get("agentCard")
        .cloned()
        .ok_or_else(|| Problem::json_invalid("`agentCard` is absent").at("/agentCard"))?;
    if agent_card
        .get("signatures")
        .and_then(Value::as_array)
        .is_some_and(|a| a.len() > MAX_SIGNATURES)
    {
        return Err(Problem::new(
            422,
            "CARD_INVALID",
            format!("a card may carry at most {MAX_SIGNATURES} signatures"),
        )
        .at("/agentCard/signatures"));
    }

    let card = a2a_card::validate_value(agent_card)?;
    if card.bytes.len() > MAX_CARD_BYTES {
        return Err(Problem::new(
            413,
            "CARD_TOO_LARGE",
            format!(
                "the canonical card is {} bytes; the limit is {MAX_CARD_BYTES}",
                card.bytes.len()
            ),
        ));
    }

    let keys = take_keys(obj)?;

    let entries = obj
        .get("proofs")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            Problem::json_invalid("`proofs` is absent, not an array, or empty").at("/proofs")
        })?;
    if entries.len() > MAX_KEYS {
        return Err(Problem::new(
            422,
            "TOO_MANY_KEYS",
            format!("at most {MAX_KEYS} publication proofs may be submitted"),
        )
        .at("/proofs"));
    }
    let proofs = entries
        .iter()
        .enumerate()
        .map(|(i, v)| detached_jws(v, &format!("/proofs/{i}")))
        .collect::<Result<Vec<_>, _>>()?;

    Ok((card, keys, proofs))
}

/// Read a transmitted detached JWS — `protected`, `payload`, `signature` —
/// from a named member of the request envelope.
fn detached_jws(value: &Value, pointer: &str) -> Result<DetachedJws, Problem> {
    let inner = value.as_object().ok_or_else(|| {
        Problem::json_invalid("a detached JWS must be an object").at(pointer.to_string())
    })?;
    let field = |name: &str| -> Result<String, Problem> {
        inner
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                Problem::json_invalid(format!("`{name}` is absent or not a string"))
                    .at(format!("{pointer}/{name}"))
            })
    };
    Ok(DetachedJws {
        protected: field("protected")?,
        payload: field("payload")?,
        signature: field("signature")?,
    })
}

fn parse_withdraw_body(body: &[u8]) -> Result<(Withdrawal, Vec<Value>), Problem> {
    let root = parse_envelope(body)?;
    let obj = root.as_object().expect("checked in parse_envelope");
    reject_unknown(obj, &["withdrawal", "keys"])?;

    let w = obj
        .get("withdrawal")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Problem::json_invalid("`withdrawal` is absent or not an object").at("/withdrawal")
        })?;
    let field = |name: &str| -> Result<String, Problem> {
        w.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                Problem::json_invalid(format!("`{name}` is absent or not a string"))
                    .at(format!("/withdrawal/{name}"))
            })
    };
    let withdrawal = Withdrawal {
        protected: field("protected")?,
        payload: field("payload")?,
        signature: field("signature")?,
    };
    let keys = take_keys(obj)?;
    Ok((withdrawal, keys))
}

fn parse_envelope(body: &[u8]) -> Result<Value, Problem> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Problem::new(
            413,
            "CARD_TOO_LARGE",
            format!(
                "the request body is {} bytes; the limit is {MAX_BODY_BYTES}",
                body.len()
            ),
        ));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| Problem::json_invalid("the request body is not valid UTF-8"))?;
    // The same strict profile as the card itself: a duplicate member decided
    // by parser order has no place in a request that authorizes a write.
    let root = a2a_card::strict::parse(text)?;
    if !root.is_object() {
        return Err(Problem::json_invalid(
            "the request body must be a JSON object",
        ));
    }
    Ok(root)
}

fn take_keys(obj: &serde_json::Map<String, Value>) -> Result<Vec<Value>, Problem> {
    let keys = obj
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| Problem::json_invalid("`keys` is absent or not an array").at("/keys"))?;
    if keys.is_empty() {
        return Err(Problem::json_invalid("`keys` is empty").at("/keys"));
    }
    if keys.len() > MAX_KEYS {
        return Err(Problem::new(
            422,
            "TOO_MANY_KEYS",
            format!("at most {MAX_KEYS} keys may be submitted"),
        )
        .at("/keys"));
    }
    Ok(keys.clone())
}

fn reject_unknown(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> Result<(), Problem> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Problem::json_invalid(format!(
                "member {key:?} is not part of this request"
            ))
            .at(format!("/{key}")));
        }
    }
    Ok(())
}

/// RFC 3339 UTC with millisecond precision, as `SPEC.md` §1 requires.
/// The current instant, at fixed millisecond precision.
///
/// Fixed width matters because this string is the listing index's sort key
/// (`{updatedAt}#{agentId}`, read in descending byte order). `time`'s RFC 3339
/// formatter drops trailing zeros and omits the fraction entirely at a whole
/// second, so `…:00Z`, `…:00.5Z` and `…:00.550Z` are three widths — and `Z`
/// (0x5A) sorts above `.` (0x2E) and above every digit, so an entry updated on
/// a whole second sorted *newer* than one updated half a second later. §7.4's
/// "newest first" was wrong for any two entries touched within the same second.
///
/// Fixed width also means every timestamp the registry serves has the same
/// shape, which matters for clients that compare them as strings — which the
/// sort key itself demonstrates is a reasonable thing to do.
fn now_rfc3339() -> String {
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
