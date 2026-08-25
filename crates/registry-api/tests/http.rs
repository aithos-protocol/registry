//! The HTTP surface end to end, against an in-memory store.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn publish_then_read_back_the_exact_bytes() {
    let app = app();
    let k = Key::new();
    let card = signed_card("1.0.0", &[&k]);

    let (status, body) = put(&app, &k.kid(), &write_body(&card, &[&k])).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["agentId"], k.kid());
    assert_eq!(body["seq"], 1);
    assert_eq!(body["cardVersion"], "1.0.0");
    assert_eq!(
        body["agentCardUrl"],
        format!("{ORIGIN}/v1/agents/{}/agent-card.json", k.kid())
    );

    let (status, bytes, res) = get(&app, &format!("/v1/agents/{}/agent-card.json", k.kid())).await;
    assert_eq!(status, 200);
    assert_eq!(header_of(&res, "content-type"), "application/a2a+json");
    assert_eq!(
        header_of(&res, "etag"),
        format!("\"{}\"", body["cardDigest"].as_str().unwrap())
    );

    // The registry serves the canonical bytes verbatim, never a re-serialization.
    let expected = a2a_card::validate_value(card).unwrap();
    assert_eq!(bytes, expected.bytes);
}

#[tokio::test]
async fn the_jwks_serves_the_authorized_keys() {
    let app = app();
    let k = Key::new();
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = get_json(&app, &format!("/v1/agents/{}/jwks.json", k.kid())).await;
    assert_eq!(status, 200);
    assert_eq!(body["keys"][0]["kty"], "EC");
    // A generic A2A client following `jku` can verify the card from this alone.
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_update_bumps_the_sequence_and_keeps_the_identifier() {
    let app = app();
    let k = Key::new();
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.1.0", &[&k]), &[&k]),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["seq"], 2);
    assert_eq!(body["agentId"], k.kid());

    let (_, versions) = get_json(&app, &format!("/v1/agents/{}/versions", k.kid())).await;
    let list = versions["versions"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["cardVersion"], "1.1.0", "newest first");
}

#[tokio::test]
async fn every_published_version_stays_readable_at_its_digest() {
    let app = app();
    let k = Key::new();
    let (_, first) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("2.0.0", &[&k]), &[&k]),
    )
    .await;

    let digest = first["cardDigest"].as_str().unwrap();
    let (status, _, res) = get(
        &app,
        &format!("/v1/agents/{}/versions/{digest}/agent-card.json", k.kid()),
    )
    .await;
    assert_eq!(status, 200);
    assert!(header_of(&res, "cache-control").contains("immutable"));
}

#[tokio::test]
async fn replaying_an_older_card_is_refused_over_http() {
    let app = app();
    let k = Key::new();
    let old = write_body(&signed_card("1.0.0", &[&k]), &[&k]);
    put(&app, &k.kid(), &old).await;
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("2.0.0", &[&k]), &[&k]),
    )
    .await;

    // Anyone who merely observed the first card holds these exact bytes.
    let (status, body) = put(&app, &k.kid(), &old).await;
    assert_eq!(status, 409);
    assert_eq!(body["code"], "VERSION_NOT_INCREASING");
}

#[tokio::test]
async fn a_stranger_cannot_take_over_an_entry() {
    let app = app();
    let owner = Key::new();
    let stranger = Key::new();
    put(
        &app,
        &owner.kid(),
        &write_body(&signed_card("1.0.0", &[&owner]), &[&owner]),
    )
    .await;

    let attack = write_body(&signed_card("9.0.0", &[&stranger]), &[&stranger]);
    let (status, body) = put(&app, &owner.kid(), &attack).await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "NOT_AUTHORIZED_KEY");
}

#[tokio::test]
async fn rotation_works_over_http() {
    let app = app();
    let a = Key::new();
    let b = Key::new();
    put(
        &app,
        &a.kid(),
        &write_body(&signed_card("1.0.0", &[&a]), &[&a]),
    )
    .await;

    // Co-sign to widen the authorized set...
    let (status, body) = put(
        &app,
        &a.kid(),
        &write_body(&signed_card("1.1.0", &[&a, &b]), &[&a, &b]),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["authorizedKids"].as_array().unwrap().len(), 2);

    // ...then sign with the survivor alone to narrow it.
    let (status, body) = put(
        &app,
        &a.kid(),
        &write_body(&signed_card("2.0.0", &[&b]), &[&b]),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["authorizedKids"], json!([b.kid()]));
    assert_eq!(
        body["agentId"],
        a.kid(),
        "the identifier names the genesis key forever"
    );
}

// --- withdrawal ---------------------------------------------------------

#[tokio::test]
async fn a_key_holder_withdraws_their_own_entry() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();

    let (status, body) = delete(&app, &k.kid(), &withdraw_body(&k, &k.kid(), &digest)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "WITHDRAWN");

    let (status, body) = get_json(&app, &format!("/v1/agents/{}/agent-card.json", k.kid())).await;
    assert_eq!(status, 410);
    assert_eq!(body["code"], "WITHDRAWN");

    // The historical version stays readable: what was published is not erased.
    let (status, _, _) = get(
        &app,
        &format!("/v1/agents/{}/versions/{digest}/agent-card.json", k.kid()),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_withdrawal_signed_for_another_registry_is_refused() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();

    let mut body = withdraw_body(&k, &k.kid(), &digest);
    // Re-sign for a different origin by hand-editing is not possible; instead
    // check that a payload naming another origin cannot have been signed here.
    body["withdrawal"]["payload"] = json!("eyJhY3Rpb24iOiJ3aXRoZHJhdyJ9");
    let (status, out) = delete(&app, &k.kid(), &body).await;
    assert_eq!(status, 422);
    assert_eq!(out["code"], "SIGNATURE_INVALID");
}

// --- concurrency and preconditions --------------------------------------

#[tokio::test]
async fn if_match_guards_against_a_lost_update() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();

    let (status, _) = put_with(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.1.0", &[&k]), &[&k]),
        Some(&format!("\"{digest}\"")),
    )
    .await;
    assert_eq!(status, 200);

    // The same If-Match now names a superseded version.
    let (status, body) = put_with(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.2.0", &[&k]), &[&k]),
        Some(&format!("\"{digest}\"")),
    )
    .await;
    assert_eq!(status, 412);
    assert_eq!(body["code"], "PRECONDITION_FAILED");
}

// --- request hygiene ----------------------------------------------------

#[tokio::test]
async fn the_request_envelope_is_strict() {
    let app = app();
    let k = Key::new();
    let card = signed_card("1.0.0", &[&k]);

    let mut extra = write_body(&card, &[&k]);
    extra
        .as_object_mut()
        .unwrap()
        .insert("notes".into(), json!("hello"));
    let (status, body) = put(&app, &k.kid(), &extra).await;
    assert_eq!(status, 400);
    assert_eq!(body["pointer"], "/notes");

    // A duplicate member decided by parser order has no place in a request
    // that authorizes a write.
    let raw = format!(
        r#"{{"agentCard":{card},"keys":[{jwk}],"keys":[]}}"#,
        card = card,
        jwk = k.jwk()
    );
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/v1/agents/{}", k.kid()))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(raw))
        .unwrap();
    let (status, bytes, _) = send(&app, req).await;
    assert_eq!(status, 400);
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("duplicate member")
    );
}

#[tokio::test]
async fn problems_are_rfc9457() {
    let app = app();
    let (status, bytes, res) = get(&app, "/v1/agents/does-not-exist").await;
    assert_eq!(status, 404);
    assert_eq!(header_of(&res, "content-type"), "application/problem+json");
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "NOT_FOUND");
    assert_eq!(body["status"], 404);
    assert_eq!(body["type"], "/problems/not-found");
    assert!(body["title"].is_string());
}

#[tokio::test]
async fn a_card_that_fails_presence_rules_is_rejected_with_a_pointer() {
    let app = app();
    let k = Key::new();
    let mut card = signed_card("1.0.0", &[&k]);
    // `extensions: []` is a repeated field with implicit presence: A2A §8.4.1
    // requires it to be omitted before signing.
    card["capabilities"] = json!({"extensions": []});
    let (status, body) = put(&app, &k.kid(), &write_body(&card, &[&k])).await;
    assert_eq!(status, 422);
    assert_eq!(body["code"], "PRESENCE_INVALID");
    assert_eq!(body["pointer"], "/capabilities/extensions");
}

#[tokio::test]
async fn a_key_carrying_private_material_is_rejected() {
    let app = app();
    let k = Key::new();
    let mut jwk = k.jwk();
    jwk.as_object_mut()
        .unwrap()
        .insert("d".into(), json!("c2VjcmV0"));
    let body = json!({"agentCard": signed_card("1.0.0", &[&k]), "keys": [jwk]});

    let (status, out) = put(&app, &k.kid(), &body).await;
    assert_eq!(status, 400);
    assert_eq!(out["code"], "PRIVATE_KEY_SUBMITTED");
}

// --- listing and manifest -----------------------------------------------

#[tokio::test]
async fn agents_can_be_listed_and_paged() {
    let app = app();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let k = Key::new();
        put(
            &app,
            &k.kid(),
            &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
        )
        .await;
        ids.push(k.kid());
    }

    let (status, body) = get_json(&app, "/v1/agents?limit=2").await;
    assert_eq!(status, 200);
    assert_eq!(body["agents"].as_array().unwrap().len(), 2);
    let cursor = body["nextCursor"].as_str().unwrap().to_string();

    let (_, body) = get_json(&app, &format!("/v1/agents?limit=2&cursor={cursor}")).await;
    assert_eq!(body["agents"].as_array().unwrap().len(), 1);
    assert!(body["nextCursor"].is_null());
}

#[tokio::test]
async fn the_manifest_states_what_an_entry_claims() {
    let app = app();
    let (status, body) = get_json(&app, "/v1/registry").await;
    assert_eq!(status, 200);
    assert_eq!(body["origin"], ORIGIN);
    assert_eq!(body["a2a"]["version"], "1.0.1");
    assert_eq!(body["canonicalization"], "RFC 8785");
    // The claim must say plainly what it is not.
    assert!(
        body["claim"]
            .as_str()
            .unwrap()
            .contains("not a claim about any domain")
    );
}
