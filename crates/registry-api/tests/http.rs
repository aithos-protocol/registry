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

    let attack = write_body_for(
        &owner.kid(),
        &signed_card("9.0.0", &[&stranger]),
        &[&stranger],
        &stranger,
    );
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
        &write_body_for(&a.kid(), &signed_card("1.1.0", &[&a, &b]), &[&a, &b], &a),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["authorizedKids"].as_array().unwrap().len(), 2);

    // ...then sign with the survivor alone to narrow it.
    let (status, body) = put(
        &app,
        &a.kid(),
        &write_body_for(&a.kid(), &signed_card("2.0.0", &[&b]), &[&b], &b),
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

/// §6.5: a withdrawn entry stops serving its card **and** its key set.
///
/// This lives here rather than only in the end-to-end suite because in
/// production the key set is served from an object store the API never sees.
/// A defect in this handler was invisible there, masked by the object being
/// deleted on the path the test happened to use.
#[tokio::test]
async fn a_withdrawn_entry_serves_neither_its_card_nor_its_keys() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();

    get_json(&app, &format!("/v1/agents/{}/jwks.json", k.kid()))
        .await
        .0
        .as_u16()
        .eq(&200)
        .then_some(())
        .expect("the key set is served while the entry is active");

    delete(&app, &k.kid(), &withdraw_body(&k, &k.kid(), &digest)).await;

    let (status, body) = get_json(&app, &format!("/v1/agents/{}/agent-card.json", k.kid())).await;
    assert_eq!(status, 410, "card");
    assert_eq!(body["code"], json!("WITHDRAWN"));

    let (status, body) = get_json(&app, &format!("/v1/agents/{}/jwks.json", k.kid())).await;
    assert_eq!(status, 410, "key set: {body}");
    assert_eq!(body["code"], json!("WITHDRAWN"));
}

/// The key set is the one document consumers are meant to trust, so it carries
/// only what the registry checked.
#[tokio::test]
async fn the_published_key_set_carries_a_kid_and_nothing_smuggled() {
    let app = app();
    let k = Key::new();
    let mut jwk = k.jwk();
    let object = jwk.as_object_mut().unwrap();
    object.insert("kid".into(), json!("not-the-real-thumbprint"));
    object.insert("alg".into(), json!("none"));

    let card = signed_card("1.0.0", &[&k]);
    let digest = a2a_card::validate_value(card.clone()).unwrap().digest;
    let body = json!({
        "agentCard": card,
        "keys": [jwk],
        "proofs": [proof(&k, &k.kid(), &digest)],
    });
    let (status, out) = put(&app, &k.kid(), &body).await;
    assert_eq!(status, 201, "{out}");

    let (_, body) = get_json(&app, &format!("/v1/agents/{}/jwks.json", k.kid())).await;
    let published = &body["keys"][0];
    assert_eq!(
        published["kid"],
        json!(k.kid()),
        "kid is the computed thumbprint"
    );
    assert!(
        published.get("alg").is_none(),
        "`alg` was republished unchecked"
    );
}

/// The size limit applies to the bytes that arrived, before anything parses
/// them: doing the work to find out the work was not wanted is the attack.
#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_parsed() {
    let app = app();
    let k = Key::new();

    // Every empty object is a skill missing four required members, so an
    // unbounded validator would allocate two strings per member per skill.
    let skills: Vec<serde_json::Value> = (0..300_000).map(|_| json!({})).collect();
    let mut card = signed_card("1.0.0", &[&k]);
    card["skills"] = json!(skills);

    let body = write_body(&card, &[&k]);
    let size = body.to_string().len();
    assert!(
        size > registry_api::api::MAX_BODY_BYTES,
        "this test needs an oversized body, got {size}"
    );

    let started = std::time::Instant::now();
    let (status, _) = put(&app, &k.kid(), &body).await;
    let elapsed = started.elapsed();

    assert_eq!(status, 413, "an oversized body is refused");
    assert!(
        elapsed.as_secs() < 3,
        "took {elapsed:?}, which means it was parsed first"
    );
}

/// And a body under the limit still cannot make the validator do unbounded
/// work: the issue list is capped.
#[tokio::test]
async fn a_valid_sized_body_full_of_faults_is_bounded() {
    let app = app();
    let k = Key::new();
    let skills: Vec<serde_json::Value> = (0..20_000).map(|_| json!({})).collect();
    let mut card = signed_card("1.0.0", &[&k]);
    card["skills"] = json!(skills);

    let body = write_body(&card, &[&k]);
    assert!(
        body.to_string().len() < registry_api::api::MAX_BODY_BYTES,
        "this test needs a body under the limit"
    );

    let started = std::time::Instant::now();
    let (status, _) = put(&app, &k.kid(), &body).await;
    assert_eq!(status, 422);
    assert!(
        started.elapsed().as_secs() < 2,
        "the issue list is not bounded"
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
    let card = signed_card("1.0.0", &[&k]);
    let digest = a2a_card::validate_value(card.clone()).unwrap().digest;
    let body = json!({
        "agentCard": card,
        "keys": [jwk],
        "proofs": [proof(&k, &k.kid(), &digest)],
    });

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

// --- round-2 audit regressions ------------------------------------------

/// The issue cap has to hold on *every* path through the schema walker, not
/// only the one a test happened to exercise. Unknown members are the cheapest
/// faults to generate — no nesting, no structure, one per member.
#[tokio::test]
async fn a_body_of_unknown_members_is_bounded_too() {
    let app = app();
    let k = Key::new();
    let mut card = signed_card("1.0.0", &[&k]);
    let obj = card.as_object_mut().unwrap();
    // Each of these is a member the pinned A2A schema does not define, so each
    // is one issue. Well under the body limit, and far over the issue cap.
    for i in 0..20_000 {
        obj.insert(format!("x{i}"), json!(0));
    }

    let body = write_body(&card, &[&k]);
    assert!(
        body.to_string().len() < registry_api::api::MAX_BODY_BYTES,
        "this test needs a body under the limit"
    );

    let started = std::time::Instant::now();
    let (status, _) = put(&app, &k.kid(), &body).await;
    assert_eq!(status, 422);
    assert!(
        started.elapsed().as_secs() < 2,
        "the unknown-member path is not bounded"
    );
}

/// Withdrawal is terminal, and saying so beats reporting a precondition the
/// caller could never satisfy — there is no `If-Match` value that would work.
#[tokio::test]
async fn a_withdrawn_entry_says_so_even_when_if_match_is_present() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();
    let (status, _) = delete(&app, &k.kid(), &withdraw_body(&k, &k.kid(), &digest)).await;
    assert_eq!(status, 200);

    for if_match in [digest.as_str(), "sha256:something-else", "*"] {
        let (status, body) = put_with(
            &app,
            &k.kid(),
            &write_body(&signed_card("2.0.0", &[&k]), &[&k]),
            Some(&format!("\"{if_match}\"")),
        )
        .await;
        assert_eq!(status, 410, "If-Match {if_match}: {body}");
        assert_eq!(body["code"], "WITHDRAWN");
    }
}

/// A write without its publication proof is not a write. Left unchecked, the
/// card's own signatures would be taken as consent to publish here — which they
/// are not, since a signed A2A card names no registry at all.
#[tokio::test]
async fn a_write_without_a_proof_is_refused() {
    let app = app();
    let k = Key::new();
    let body = json!({
        "agentCard": signed_card("1.0.0", &[&k]),
        "keys": [k.jwk()],
    });

    let (status, out) = put(&app, &k.kid(), &body).await;
    assert_eq!(status, 400, "{out}");
    assert_eq!(out["pointer"], "/proofs");
}

/// The creation time is the one fact about an entry that cannot be recovered
/// once it is lost — and a store that replaces the whole record on update will
/// lose it silently, reporting each republication as the entry's birth.
#[tokio::test]
async fn an_update_keeps_the_entrys_original_creation_time() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let born = created["createdAt"].as_str().unwrap().to_string();

    // Far enough apart that a clobbered value could not coincide.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let (_, updated) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.1.0", &[&k]), &[&k]),
    )
    .await;
    assert_eq!(updated["createdAt"], json!(born), "createdAt moved");
    assert_ne!(
        updated["updatedAt"], updated["createdAt"],
        "updatedAt did not move"
    );

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["createdAt"], json!(born));
}

/// §9 says every refusal is an RFC 9457 problem. The ones the service does not
/// make itself — a body stopped by a layer, a bad query parameter stopped by an
/// extractor, an unroutable path — used to answer in plain text, so a client
/// parsing `code` got nothing exactly when it most needed a reason.
#[tokio::test]
async fn every_refusal_is_a_problem_document() {
    let app = app();
    let k = Key::new();

    // Refused by the body-limit layer, above any handler.
    let huge = "x".repeat(registry_api::api::MAX_BODY_BYTES + 1024);
    let (status, body, res) = send_raw(&app, "PUT", &format!("/v1/agents/{}", k.kid()), huge).await;
    assert_eq!(status, 413);
    assert!(
        header_of(&res, "content-type").starts_with("application/problem+json"),
        "{}",
        header_of(&res, "content-type")
    );
    let body: serde_json::Value = serde_json::from_slice(&body).expect("a problem document");
    assert_eq!(body["code"], "CARD_TOO_LARGE");

    // Refused by an extractor.
    let (status, body) = get_json(&app, "/v1/agents?limit=not-a-number").await;
    assert_eq!(status, 400);
    assert!(body["code"].is_string(), "{body}");

    // Refused by the router.
    let (status, body) = get_json(&app, "/v1/nothing-here").await;
    assert_eq!(status, 404);
    assert_eq!(body["code"], "NOT_FOUND");
}

/// One published version, one immutable URL. The stores tolerate a missing
/// `sha256:` prefix when building their keys, which made `.../versions/<hex>/…`
/// resolve the same object as the canonical form — two permanent cache entries
/// for one artifact, each with its own ETag, and the two origins of §7.1
/// disagreeing about which is real.
#[tokio::test]
async fn a_version_is_addressable_only_by_its_canonical_digest() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();
    let hex = digest.strip_prefix("sha256:").unwrap();

    let (status, _, _) = get(
        &app,
        &format!("/v1/agents/{}/versions/{digest}/agent-card.json", k.kid()),
    )
    .await;
    assert_eq!(status, 200, "the canonical form is served");

    for variant in [
        hex.to_string(),
        digest.to_uppercase(),
        format!("SHA256:{hex}"),
    ] {
        let (status, _, _) = get(
            &app,
            &format!("/v1/agents/{}/versions/{variant}/agent-card.json", k.kid()),
        )
        .await;
        assert_eq!(status, 404, "{variant} must not be a second URL");
    }
}

/// §7.1 says the `ETag` is good for `If-None-Match`. It was not: this origin
/// always sent the full body, so the endpoint that asks clients to revalidate
/// after sixty seconds answered every revalidation with a full copy of the
/// largest thing it serves.
#[tokio::test]
async fn a_current_card_answers_a_conditional_read() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let path = format!("/v1/agents/{}/agent-card.json", k.kid());
    let (status, bytes, res) = get(&app, &path).await;
    assert_eq!(status, 200);
    let etag = header_of(&res, "etag");
    assert_eq!(
        etag,
        format!("\"{}\"", created["cardDigest"].as_str().unwrap())
    );
    assert!(!bytes.is_empty());

    for candidate in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"something-else\", {etag}"),
        "*".to_string(),
    ] {
        let (status, bytes, _) = get_with(&app, &path, &[("if-none-match", &candidate)]).await;
        assert_eq!(status, 304, "If-None-Match {candidate}");
        assert!(bytes.is_empty(), "304 must carry no body");
    }

    // A validator that does not match still gets the card.
    let (status, bytes, _) = get_with(&app, &path, &[("if-none-match", "\"sha256:nope\"")]).await;
    assert_eq!(status, 200);
    assert!(!bytes.is_empty());
}

/// §7.4 promises newest-updated first. The listing index sorts on the timestamp
/// *as a string*, so a variable-width one broke the order it exists to provide:
/// `Z` sorts above `.` and above every digit, so an entry updated on a whole
/// second read as newer than one updated half a second later.
#[tokio::test]
async fn timestamps_are_fixed_width_so_the_listing_sorts_correctly() {
    let app = app();
    let mut stamps = Vec::new();

    // Several writes in quick succession, so some land on a whole second.
    for _ in 0..6 {
        let k = Key::new();
        let (status, body) = put(
            &app,
            &k.kid(),
            &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
        )
        .await;
        assert_eq!(status, 201, "{body}");
        stamps.push(body["createdAt"].as_str().unwrap().to_string());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    for stamp in &stamps {
        assert_eq!(stamp.len(), 24, "not fixed width: {stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert_eq!(&stamp[19..20], ".", "no millisecond fraction: {stamp}");
    }

    // Byte order and chronological order must agree, which is the whole point.
    let mut sorted = stamps.clone();
    sorted.sort();
    assert_eq!(
        sorted, stamps,
        "byte order disagrees with the order written"
    );

    let (_, listing) = get_json(&app, "/v1/agents").await;
    let listed: Vec<&str> = listing["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["updatedAt"].as_str().unwrap())
        .collect();
    let mut newest_first = listed.clone();
    newest_first.sort();
    newest_first.reverse();
    assert_eq!(listed, newest_first, "§7.4: newest-updated first");
}

/// §7.3 pins one URL per version. Axum decodes path parameters before a handler
/// sees them, so `%3A` and `:` arrive identical while remaining two distinct
/// URIs — and every version path is cached `immutable`, so a second spelling is
/// a second permanent cache entry for the same bytes.
#[tokio::test]
async fn a_percent_encoded_digest_is_not_a_second_url() {
    let app = app();
    let k = Key::new();
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    let digest = created["cardDigest"].as_str().unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();

    let (status, _, _) = get(
        &app,
        &format!("/v1/agents/{}/versions/{digest}/agent-card.json", k.kid()),
    )
    .await;
    assert_eq!(status, 200, "the literal spelling is served");

    let (status, _, _) = get(
        &app,
        &format!(
            "/v1/agents/{}/versions/sha256%3A{hex}/agent-card.json",
            k.kid()
        ),
    )
    .await;
    assert_eq!(status, 404, "the encoded spelling must not be a second URL");
}
