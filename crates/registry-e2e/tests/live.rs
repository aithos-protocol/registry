//! End-to-end tests against a deployed registry.
//!
//! Every test here is `#[ignore]`d. They are meant to be run deliberately —
//! after a deployment, before promoting a change, or while debugging — not on
//! every commit:
//!
//! ```sh
//! REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
//!   cargo test -p registry-e2e -- --ignored --test-threads=1
//! ```
//!
//! They need no AWS credentials: every endpoint is public and each run
//! generates its own keys.
//!
//! **These tests write to a real, append-only registry.** Nothing they publish
//! can ever be deleted, so each run creates as few entries as possible and ends
//! by withdrawing them. That is not tidiness for its own sake — the withdrawal
//! path is otherwise the one part of the product no test would ever exercise
//! against real infrastructure.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
#[ignore = "runs against a deployed environment; set REGISTRY_E2E_ORIGIN"]
async fn the_manifest_answers() {
    let (origin, client) = (origin(), client());

    // Reaches Lambda through CloudFront and API Gateway, and touches no
    // storage: if this fails, nothing below is worth diagnosing.
    let response = get(&client, &origin, "/v1/registry").await;
    response.expect(200, "manifest");

    let body = response.json();
    assert_eq!(
        body["origin"],
        json!(origin),
        "the deployed origin must match REGISTRY_ORIGIN"
    );
    assert_eq!(
        body["a2a"]["commit"],
        json!("3303592588e388e62e0f69f701af531d2f4e3991")
    );
    assert_eq!(body["canonicalization"], json!("RFC 8785"));
}

/// One agent, walked through its whole life.
///
/// Deliberately a single test rather than several: each independent test would
/// leave its own permanent entry behind.
#[tokio::test]
#[ignore = "runs against a deployed environment; set REGISTRY_E2E_ORIGIN"]
async fn an_entry_lives_its_whole_life() {
    let (origin, client) = (origin(), client());
    let genesis = Key::new();
    let backup = Key::new();
    let agent_id = genesis.kid();

    // --- publish ---------------------------------------------------------

    let (first_card, first_bytes) = sign_card(card_body("1.0.0", "lifecycle"), &[&genesis]);
    let created = put(
        &client,
        &origin,
        &agent_id,
        &write_body(&first_card, &[&genesis]),
    )
    .await;
    created.expect(201, "first publication");

    let created = created.json();
    let first_digest = created["cardDigest"].as_str().unwrap().to_string();
    assert_eq!(
        created["agentId"],
        json!(agent_id),
        "the entry is named by its genesis key"
    );
    assert_eq!(created["seq"], json!(1));

    // The assertion the whole suite exists for. The bytes served from S3
    // through CloudFront must be exactly the bytes that were signed: it proves
    // the write path, the object key layout, and that nothing re-serialized
    // the card on the way through.
    let served = get_until(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/agent-card.json"),
        |r| r.status == 200,
        "current card at the edge",
    )
    .await;
    assert_eq!(
        served.bytes, first_bytes,
        "the served card is not byte-identical to the signed card"
    );
    assert_eq!(served.content_type, "application/a2a+json");

    // Hash what was received rather than believe a header. The registry could
    // claim any digest it liked; only the bytes settle it — and the static path
    // is answered by an object store that computes its own ETag anyway.
    assert_eq!(
        a2a_card::canonical::digest(&served.bytes),
        first_digest,
        "the served bytes do not hash to the digest the registry reported"
    );

    // The JWKS is what lets a generic A2A client following `jku` verify the
    // card without knowing anything about this registry.
    let jwks = get_until(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/jwks.json"),
        |r| r.status == 200,
        "jwks at the edge",
    )
    .await;
    assert_eq!(jwks.json()["keys"][0]["kty"], json!("EC"));

    // --- rotate ----------------------------------------------------------

    // Co-signing widens the authorized set. This also proves the set survives
    // a round trip through a DynamoDB string set.
    let (second_card, _) = sign_card(card_body("1.1.0", "add backup key"), &[&genesis, &backup]);
    let updated = put(
        &client,
        &origin,
        &agent_id,
        &write_body(&second_card, &[&genesis, &backup]),
    )
    .await;
    updated.expect(200, "co-signed update");
    assert_eq!(
        updated.json()["authorizedKids"].as_array().unwrap().len(),
        2
    );

    // Signing with the survivor alone narrows it again.
    let (third_card, third_bytes) = sign_card(card_body("2.0.0", "retire genesis key"), &[&backup]);
    let rotated = put(
        &client,
        &origin,
        &agent_id,
        &write_body(&third_card, &[&backup]),
    )
    .await;
    rotated.expect(200, "rotation");

    let rotated = rotated.json();
    let current_digest = rotated["cardDigest"].as_str().unwrap().to_string();
    assert_eq!(rotated["authorizedKids"], json!([backup.kid()]));
    assert_eq!(
        rotated["agentId"],
        json!(agent_id),
        "the identifier still names the genesis key"
    );

    // --- the retired key is refused --------------------------------------

    let (rogue, _) = sign_card(card_body("3.0.0", "retired key"), &[&genesis]);
    put(
        &client,
        &origin,
        &agent_id,
        &write_body(&rogue, &[&genesis]),
    )
    .await
    .expect(403, "write signed only by the retired key")
    .expect_code("NOT_AUTHORIZED_KEY");

    // --- history holds ---------------------------------------------------

    // Every published version stays readable at its own digest, forever.
    get_until(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/versions/{first_digest}/agent-card.json"),
        |r| r.status == 200,
        "first version by digest",
    )
    .await;

    let versions = get(&client, &origin, &format!("/v1/agents/{agent_id}/versions")).await;
    versions.expect(200, "version history");
    let list = versions.json();
    let list = list["versions"].as_array().unwrap();
    assert_eq!(list.len(), 3, "three publications, three versions");
    assert_eq!(list[0]["cardVersion"], json!("2.0.0"), "newest first");

    // The current card at the edge must have followed the rotation.
    let served = get_until(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/agent-card.json"),
        |r| r.status == 200 && a2a_card::canonical::digest(&r.bytes) == current_digest,
        "current card after rotation",
    )
    .await;
    assert_eq!(served.bytes, third_bytes);

    // --- withdraw --------------------------------------------------------

    // Both cleanup and coverage: nothing else exercises this path live.
    let withdrawn = delete(
        &client,
        &origin,
        &agent_id,
        &withdraw_body(&backup, &origin, &agent_id, &current_digest),
    )
    .await;
    withdrawn.expect(200, "withdrawal");
    assert_eq!(withdrawn.json()["status"], json!("WITHDRAWN"));

    // The current card stops being served. That path is answered at the edge,
    // so it converges rather than flipping the instant the write returns.
    get_until(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/agent-card.json"),
        |r| r.status == 404 || r.status == 410,
        "current card after withdrawal",
    )
    .await;

    get(&client, &origin, &format!("/v1/agents/{agent_id}"))
        .await
        .expect(200, "the record survives withdrawal");

    // ...but what was published is not erased.
    get(
        &client,
        &origin,
        &format!("/v1/agents/{agent_id}/versions/{first_digest}/agent-card.json"),
    )
    .await
    .expect(200, "a published version outlives the withdrawal");
}

/// Every way a write should be refused, on one throwaway entry.
#[tokio::test]
#[ignore = "runs against a deployed environment; set REGISTRY_E2E_ORIGIN"]
async fn writes_are_refused_for_the_right_reasons() {
    let (origin, client) = (origin(), client());
    let owner = Key::new();
    let stranger = Key::new();
    let agent_id = owner.kid();

    let (first, _) = sign_card(card_body("1.0.0", "refusals"), &[&owner]);
    let first_body = write_body(&first, &[&owner]);
    let created = put(&client, &origin, &agent_id, &first_body).await;
    created.expect(201, "first publication");
    let digest = created.json()["cardDigest"].as_str().unwrap().to_string();

    // An identifier is the thumbprint of its genesis key, so it cannot be
    // claimed by someone else's key.
    let (theirs, _) = sign_card(card_body("1.0.0", "squat"), &[&stranger]);
    put(
        &client,
        &origin,
        &owner.kid(),
        &write_body(&theirs, &[&stranger]),
    )
    .await
    .expect(403, "another key writing to an existing entry")
    .expect_code("NOT_AUTHORIZED_KEY");

    // A version that does not move forward is refused. This is the replay
    // defence: the body below is byte-identical to one anybody could have
    // observed, and it is still validly signed.
    put(&client, &origin, &agent_id, &first_body)
        .await
        .expect(409, "replay of an observed card")
        .expect_code("VERSION_NOT_INCREASING");

    // Private key material is refused before anything is stored.
    let mut leaky = owner.jwk();
    leaky
        .as_object_mut()
        .unwrap()
        .insert("d".into(), json!("bm90LWEtcmVhbC1rZXk"));
    let (next, _) = sign_card(card_body("1.1.0", "leaky key"), &[&owner]);
    put(
        &client,
        &origin,
        &agent_id,
        &json!({"agentCard": next, "keys": [leaky]}),
    )
    .await
    .expect(400, "a JWK carrying private material")
    .expect_code("PRIVATE_KEY_SUBMITTED");

    // A card whose field-presence rules were not applied cannot be signed
    // reproducibly, so it is refused with the exact member at fault.
    let mut bad_card = card_body("1.2.0", "presence");
    bad_card["capabilities"] = json!({"extensions": []});
    bad_card["signatures"] = json!([{"protected": "eyJ9", "signature": "AA"}]);
    let response = put(
        &client,
        &origin,
        &agent_id,
        &json!({"agentCard": bad_card, "keys": [owner.jwk()]}),
    )
    .await;
    response.expect(422, "a card that skipped the presence rules");
    assert_eq!(
        response.json()["pointer"],
        json!("/capabilities/extensions")
    );

    // Leave the entry withdrawn rather than active.
    delete(
        &client,
        &origin,
        &agent_id,
        &withdraw_body(&owner, &origin, &agent_id, &digest),
    )
    .await
    .expect(200, "withdrawal");
}
