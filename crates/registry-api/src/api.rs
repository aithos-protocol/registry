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
use registry_core::{AgentState, Status, evaluate_withdrawal, evaluate_write};

use crate::problem::Problem;
use crate::store::{AgentRecord, Commit, Store};

/// Limits of `SPEC.md` §8.
pub const MAX_CARD_BYTES: usize = 256 * 1024;
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
        .with_state(state)
}

// --- writes --------------------------------------------------------------

async fn put_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    let (card, keys) = parse_write_body(&body)?;

    let current = state.store.get_agent(&agent_id).await?;

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
    let accepted = evaluate_write(&agent_id, &card, &keys, agent_state.as_ref())?;

    let now = now_rfc3339();
    let commit = Commit {
        agent_id: agent_id.clone(),
        expected_seq: current.as_ref().map(|r| r.seq),
        seq: current.as_ref().map_or(1, |r| r.seq + 1),
        card_digest: accepted.card_digest.clone(),
        card_version: accepted.card_version.to_string(),
        card_bytes: card.bytes.clone(),
        keys,
        authorized_kids: accepted.authorized_kids.clone(),
        created_at: now,
    };

    let record = state.store.commit(&commit).await?;
    let status = if accepted.is_creation {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut response = (status, axum::Json(agent_json(&record, &state.config))).into_response();
    if accepted.is_creation {
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
) -> Result<Response, Problem> {
    let record = state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    if record.status == Status::Withdrawn {
        return Err(Problem::new(
            410,
            "WITHDRAWN",
            "this entry was withdrawn by its key holder",
        ));
    }
    let bytes = state
        .store
        .get_card_bytes(&agent_id, &record.card_digest)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(card_response(bytes, &record.card_digest, SHORT))
}

async fn get_version_card(
    State(state): State<AppState>,
    Path((agent_id, digest)): Path<(String, String)>,
) -> Result<Response, Problem> {
    // Historical versions stay readable after a withdrawal: the record of what
    // was published is not erased, only its status changes.
    let bytes = state
        .store
        .get_card_bytes(&agent_id, &digest)
        .await?
        .ok_or_else(Problem::not_found)?;
    Ok(card_response(bytes, &digest, IMMUTABLE))
}

async fn get_jwks(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Response, Problem> {
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
) -> Result<Response, Problem> {
    state
        .store
        .get_agent(&agent_id)
        .await?
        .ok_or_else(Problem::not_found)?;
    let versions = state.store.list_versions(&agent_id).await?;
    let items: Vec<Value> = versions
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
    Ok(axum::Json(json!({ "versions": items })).into_response())
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
    Ok(axum::Json(body).into_response())
}

async fn manifest(State(state): State<AppState>) -> Response {
    axum::Json(json!({
        "origin": state.config.origin,
        "a2a": {
            "version": "1.0.1",
            "commit": "3303592588e388e62e0f69f701af531d2f4e3991",
        },
        "canonicalization": "RFC 8785",
        "signatures": { "format": "RFC 7515", "algorithms": ["ES256", "EdDSA", "RS256"] },
        "keyIdentifiers": "RFC 7638",
        "limits": {
            "cardBytes": MAX_CARD_BYTES,
            "keysPerRequest": MAX_KEYS,
            "signaturesPerCard": MAX_SIGNATURES,
        },
        "claim": "An entry states that its Agent Card was published by the holder of a \
                  key, and that every version since was signed by a key authorized by \
                  that lineage. It is not a claim about any domain or organization.",
    }))
    .into_response()
}

// --- helpers -------------------------------------------------------------

fn card_response(bytes: Vec<u8>, digest: &str, cache: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, A2A_JSON.to_string()),
            (header::CACHE_CONTROL, cache.to_string()),
            (header::ETAG, format!("\"{digest}\"")),
        ],
        bytes,
    )
        .into_response()
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
    let matches = value == "*"
        || value
            .split(',')
            .map(|t| t.trim().trim_start_matches("W/").trim_matches('"'))
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

fn parse_write_body(body: &[u8]) -> Result<(CanonicalCard, Vec<Value>), Problem> {
    let root = parse_envelope(body)?;
    let obj = root.as_object().expect("checked in parse_envelope");
    reject_unknown(obj, &["agentCard", "keys"])?;

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
    Ok((card, keys))
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
            "UNUSED_KEY",
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
fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    let truncated = now
        .replace_nanosecond(now.nanosecond() / 1_000_000 * 1_000_000)
        .unwrap_or(now);
    truncated.format(&Rfc3339).unwrap_or_default()
}
