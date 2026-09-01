//! Domain certification over HTTP, against the in-memory store and a static
//! resolver: the handler under test is the real one, and the DNS is whatever
//! world each test describes (`DOMAIN-CERTIFICATION.md` §5–§6).

mod common;

use common::*;
use registry_dns::{ResolveError, StaticResolver};
use serde_json::json;

const T1: &str = "2026-09-01T09:00:00.000Z";
const T2: &str = "2026-09-01T10:00:00.000Z";

/// Create an entry and return its key — certification needs an agent to hang
/// off, but these tests are not about publication.
async fn agent(app: &axum::Router) -> Key {
    let k = Key::new();
    let (status, body) = put(
        app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    k
}

#[tokio::test]
async fn a_certification_is_accepted_when_every_domain_declares_the_agent() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new()
            .observed(&query_name("acme.com"), &[&zone_record(&k.kid())])
            .observed(&query_name("acme.fr"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com", "acme.fr"], T1),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let domains = body["domains"].as_array().unwrap();
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[0]["domain"], "acme.com");
    assert_eq!(domains[1]["domain"], "acme.fr");
    assert!(domains[0]["certifiedAt"].is_string());
    assert!(domains[0]["lastCheckedAt"].is_string());

    // And the read path serves the same projection.
    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["domains"], body["domains"]);
}

#[tokio::test]
async fn an_absent_record_refuses_and_stores_nothing() {
    let app = app();
    let k = agent(&app).await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "DNS_RECORD_ABSENT");
    assert_eq!(body["domains"][0]["domain"], "acme.com");
    assert_eq!(body["domains"][0]["outcome"], "absent");

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["domains"], json!([]), "nothing was stored");
}

/// §5.5: atomic. One missing domain refuses the whole set, and the problem
/// document says which one, so a four-domain request never needs bisecting.
#[tokio::test]
async fn one_absent_domain_of_three_stores_nothing_and_names_itself() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new()
            .observed(&query_name("a.example.com"), &[&zone_record(&k.kid())])
            .observed(&query_name("c.example.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(
            &k,
            &k.kid(),
            &["a.example.com", "b.example.com", "c.example.com"],
            T1,
        ),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "DNS_RECORD_ABSENT");

    let outcomes: Vec<(&str, &str)> = body["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["domain"].as_str().unwrap(),
                d["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            ("a.example.com", "observed"),
            ("b.example.com", "absent"),
            ("c.example.com", "observed"),
        ]
    );

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(
        read_back["domains"],
        json!([]),
        "atomic means nothing landed"
    );
}

#[tokio::test]
async fn a_failed_resolution_is_unresolved_not_absent() {
    let k = Key::new();
    let app = app_with(StaticResolver::new().failing(
        &query_name("acme.com"),
        ResolveError::Failed("SERVFAIL".into()),
    ));
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "DNS_UNRESOLVED");
    assert_eq!(body["domains"][0]["outcome"], "unresolved");
}

/// When absent and unresolved both occur, the code is the actionable one:
/// retrying cannot conjure a record that is not there.
#[tokio::test]
async fn absent_wins_over_unresolved_in_a_mixed_refusal() {
    let k = Key::new();
    let app = app_with(StaticResolver::new().failing(
        &query_name("b.example.com"),
        ResolveError::Failed("timeout".into()),
    ));
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["a.example.com", "b.example.com"], T1),
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(body["code"], "DNS_RECORD_ABSENT", "{body}");
    assert_eq!(body["domains"][0]["outcome"], "absent");
    assert_eq!(body["domains"][1]["outcome"], "unresolved");
}

/// A record naming some other agent is no better than no record: the zone
/// speaks, but not about this entry.
#[tokio::test]
async fn a_record_for_another_agent_is_absent() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record("SomeOtherAgent")]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(body["code"], "DNS_RECORD_ABSENT", "{body}");
}

#[tokio::test]
async fn a_stranger_cannot_certify_someone_elses_entry() {
    let k = Key::new();
    let stranger = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&stranger, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "NOT_AUTHORIZED_KEY");
}

#[tokio::test]
async fn a_replayed_certification_is_refused() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    let first = certify_body(&k, &k.kid(), &["acme.com"], T1);
    let (status, _) = put_domains(&app, &k.kid(), &first).await;
    assert_eq!(status, 200);

    // The exact same signed operation again — what anyone who observed the
    // first request holds.
    let (status, body) = put_domains(&app, &k.kid(), &first).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "CERTIFICATION_NOT_INCREASING");

    // And an older one, which is the rollback this rule exists to refuse.
    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], "2026-09-01T08:00:00.000Z"),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "CERTIFICATION_NOT_INCREASING");
}

#[tokio::test]
async fn the_empty_set_removes_every_certification() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;

    put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;

    let (status, body) = put_domains(&app, &k.kid(), &certify_body(&k, &k.kid(), &[], T2)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["domains"], json!([]));

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["domains"], json!([]));
}

#[tokio::test]
async fn a_withdrawn_agent_answers_gone() {
    let app = app();
    let k = agent(&app).await;
    let (_, created) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    let digest = created["cardDigest"].as_str().unwrap().to_string();
    delete(&app, &k.kid(), &withdraw_body(&k, &k.kid(), &digest)).await;

    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 410, "{body}");
    assert_eq!(body["code"], "WITHDRAWN");
}

/// Withdrawal stops the domains being served, like the card and the JWKS.
#[tokio::test]
async fn withdrawal_stops_serving_the_domains() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    let (_, created) = put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;

    let digest = created["cardDigest"].as_str().unwrap().to_string();
    let (status, withdrawn) = delete(&app, &k.kid(), &withdraw_body(&k, &k.kid(), &digest)).await;
    assert_eq!(status, 200);
    assert_eq!(withdrawn["domains"], json!([]));

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["domains"], json!([]));
}

/// The trap of §11.1 in the implementation handoff: `commit` replaces the
/// agent item, so a certification stored on it would vanish at the next
/// publication — silently. This is the one test that catches it.
#[tokio::test]
async fn publishing_after_certifying_keeps_the_domains() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;

    // A new version, and then the same bytes again (the Unchanged path).
    let next = write_body(&signed_card("1.1.0", &[&k]), &[&k]);
    let (status, updated) = put(&app, &k.kid(), &next).await;
    assert_eq!(status, 200);
    assert_eq!(
        updated["domains"].as_array().map(Vec::len),
        Some(1),
        "publication erased the certification: {updated}"
    );
    let (_, unchanged) = put(&app, &k.kid(), &next).await;
    assert_eq!(unchanged["domains"].as_array().map(Vec::len), Some(1));

    let (_, read_back) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(read_back["domains"][0]["domain"], "acme.com");
}

/// §6: `certifiedDomains`, and never `requestedDomains`, whatever the member
/// is called. The projection shows exactly what §4.2 defines and nothing else.
#[tokio::test]
async fn the_projection_shows_observed_shape_and_nothing_more() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;

    let (_, body) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    let entry = body["domains"][0].as_object().unwrap();
    let mut members: Vec<&str> = entry.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(members, ["certifiedAt", "domain", "lastCheckedAt"]);
    assert!(
        !body.to_string().contains("equested"),
        "the requested set leaked into the projection: {body}"
    );
}

/// The listing never carries the member: one certification read per row is a
/// price §7.4 never asked for, and an absent member is not a claim of none.
#[tokio::test]
async fn the_listing_omits_the_domains_member() {
    let k = Key::new();
    let app = app_with(
        StaticResolver::new().observed(&query_name("acme.com"), &[&zone_record(&k.kid())]),
    );
    put(
        &app,
        &k.kid(),
        &write_body(&signed_card("1.0.0", &[&k]), &[&k]),
    )
    .await;
    put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;

    let (_, listing) = get_json(&app, "/v1/agents").await;
    assert!(listing["agents"][0].get("domains").is_none(), "{listing}");
}

#[tokio::test]
async fn the_manifest_announces_the_certification_profile() {
    let app = app();
    let (_, body) = get_json(&app, "/v1/registry").await;
    let cert = &body["domainCertification"];
    assert_eq!(cert["record"], registry_core::DNS_LABEL);
    assert_eq!(cert["version"], registry_core::TXT_VERSION);
    assert_eq!(cert["maxDomains"], registry_core::MAX_DOMAINS);
    assert_eq!(cert["revalidateIntervalSeconds"], 3600);
    assert_eq!(cert["removalAfterFailedPasses"], 3);
}

#[tokio::test]
async fn an_agent_with_no_certification_serves_an_empty_list() {
    let app = app();
    let k = agent(&app).await;
    let (_, body) = get_json(&app, &format!("/v1/agents/{}", k.kid())).await;
    assert_eq!(body["domains"], json!([]));
}

#[tokio::test]
async fn the_certify_envelope_is_strict() {
    let app = app();
    let k = agent(&app).await;

    let mut body = certify_body(&k, &k.kid(), &["acme.com"], T1);
    body.as_object_mut()
        .unwrap()
        .insert("notes".into(), json!("hello"));
    let (status, out) = put_domains(&app, &k.kid(), &body).await;
    assert_eq!(status, 400, "{out}");
    assert_eq!(out["pointer"], "/notes");
}

#[tokio::test]
async fn an_unknown_agent_is_not_found() {
    let app = app();
    let k = Key::new();
    let (status, body) = put_domains(
        &app,
        &k.kid(),
        &certify_body(&k, &k.kid(), &["acme.com"], T1),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["code"], "NOT_FOUND");
}

/// Domain rules travel through HTTP with their own codes — the CLI's local
/// validation and the registry's refusal must be the same rule.
#[tokio::test]
async fn domain_rule_refusals_carry_their_codes() {
    let app = app();
    let k = agent(&app).await;

    for (domains, code) in [
        (vec!["Acme.com"], "DOMAIN_SYNTAX_INVALID"),
        (vec!["github.io"], "DOMAIN_IS_PUBLIC_SUFFIX"),
        (
            vec!["b.example.com", "a.example.com"],
            "DOMAINS_NOT_CANONICAL",
        ),
    ] {
        let (status, body) =
            put_domains(&app, &k.kid(), &certify_body(&k, &k.kid(), &domains, T1)).await;
        assert_eq!(status, 422, "{domains:?}: {body}");
        assert_eq!(body["code"], code, "{domains:?}");
    }

    let nine: Vec<String> = (1..=9).map(|i| format!("d{i}.example.com")).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    let (status, body) = put_domains(&app, &k.kid(), &certify_body(&k, &k.kid(), &nine, T1)).await;
    assert_eq!(status, 422);
    assert_eq!(body["code"], "TOO_MANY_DOMAINS", "{body}");
}
