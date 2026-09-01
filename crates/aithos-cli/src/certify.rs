//! `aithos certify` — ask the registry to certify domains for an entry
//! (`DOMAIN-CERTIFICATION.md`), and the client-side resolution both this
//! command and `verify` share.
//!
//! The command resolves locally first and reports what it sees, so a
//! publisher waiting on propagation learns it from their own resolver rather
//! than from a rejected request. It sends the signed payload only once every
//! domain is visible from here — the registry still resolves everything
//! itself (§5.5); this is a courtesy check, not the proof.

use std::collections::BTreeMap;

use a2a_card::canonical::{b64url, canonicalize, signing_input};
use registry_core::Domain;
use registry_dns::{HickoryResolver, ResolveError, Resolver};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::keyfile::PrivateKey;

/// What this client's own resolver says about one domain's declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sighting {
    /// A record at `_a2a.<D>` names the agent.
    Declares,
    /// The name answered; no record names the agent. The zone line needs to
    /// be added (or has not propagated to this resolver yet).
    Absent,
    /// Nothing could be concluded from here.
    Unresolved(String),
}

/// Resolve the declaration state of each domain for `agent_id`, from this
/// machine's resolver, concurrently.
pub fn sight_from_here(agent_id: &str, domains: &[Domain]) -> Result<Vec<(Domain, Sighting)>> {
    let resolver = HickoryResolver::from_system()
        .map_err(|e| Error::msg(format!("this machine's resolver is unusable: {e}")))?;

    // The CLI is otherwise blocking; DNS is the one async island, so the
    // runtime lives exactly as long as the lookups do.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::msg(format!("starting the resolver runtime: {e}")))?;

    let results = runtime.block_on(async {
        let lookups = domains.iter().map(|domain| {
            let resolver = &resolver;
            async move {
                match resolver.txt(&domain.query_name()).await {
                    Ok(records) => {
                        if registry_core::rrset_names_agent(&records, agent_id) {
                            Sighting::Declares
                        } else {
                            Sighting::Absent
                        }
                    }
                    Err(ResolveError::NoRecords) => Sighting::Absent,
                    Err(ResolveError::Failed(why)) => Sighting::Unresolved(why),
                }
            }
        });
        futures_util::future::join_all(lookups).await
    });

    Ok(domains.iter().cloned().zip(results).collect())
}

/// The signed `certify-domains` operation (§5.2), over the already-sorted set.
pub fn certification(
    key: &PrivateKey,
    registry: &str,
    agent_id: &str,
    domains: &[Domain],
) -> Result<Value> {
    let payload = json!({
        "action": registry_core::CERTIFY_ACTION,
        "agentId": agent_id,
        "domains": domains.iter().map(Domain::as_str).collect::<Vec<_>>(),
        "issuedAt": now_fixed_ms(),
        "registryOrigin": registry,
    });
    let bytes = canonicalize(&payload)?;
    let header = json!({ "alg": "ES256", "typ": "JOSE", "kid": key.kid()? });
    let protected = b64url(&canonicalize(&header)?);
    Ok(json!({
        "protected": protected,
        "payload": b64url(&bytes),
        "signature": key.sign(&signing_input(&protected, &bytes)),
    }))
}

/// The registry stores `issuedAt` in a fixed-width millisecond form and
/// refuses one that does not exceed the last, so the client emits exactly
/// that form: two invocations in the same second still differ, and nothing
/// is lost to truncation on the other side.
fn now_fixed_ms() -> String {
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

/// Parse and canonicalize the `--domains` input: every element validated
/// under §5.4 (refused locally, with the registry's own rules), the set
/// sorted and deduplicated. Order and repetition in a command line are not
/// meaning; the signed payload requires the one canonical form of the set.
pub fn parse_domains(raw: &[String]) -> Result<Vec<Domain>> {
    let mut set = BTreeMap::new();
    for element in raw {
        // `--domains ""` is how the whole set is removed; splitting also
        // leaves empty strings behind for a trailing comma.
        if element.is_empty() {
            continue;
        }
        let domain =
            Domain::parse(element).map_err(|e| Error::msg(format!("--domains: {}", e.detail)))?;
        set.insert(domain.as_str().to_string(), domain);
    }
    if set.len() > registry_core::MAX_DOMAINS {
        return Err(Error::msg(format!(
            "{} domains; a certification names at most {}",
            set.len(),
            registry_core::MAX_DOMAINS
        )));
    }
    Ok(set.into_values().collect())
}

/// The zone lines a publisher pastes, for the domains whose declaration is
/// not visible yet (Appendix A).
pub fn zone_lines(agent_id: &str, missing: &[&Domain]) -> String {
    let mut out = String::new();
    for domain in missing {
        out.push_str(&format!(
            "  {}.   IN   TXT   \"v={}; k={agent_id}\"\n",
            domain.query_name(),
            registry_core::TXT_VERSION,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_sorted_deduplicated_and_validated() {
        let parsed = parse_domains(&[
            "acme.fr".to_string(),
            "acme.com".to_string(),
            "acme.fr".to_string(),
        ])
        .unwrap();
        let names: Vec<&str> = parsed.iter().map(Domain::as_str).collect();
        assert_eq!(names, ["acme.com", "acme.fr"], "sorted, deduplicated");
    }

    #[test]
    fn the_empty_set_is_expressible() {
        assert!(parse_domains(&["".to_string()]).unwrap().is_empty());
        assert!(parse_domains(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_bad_domain_is_refused_locally_with_the_registry_rule() {
        let err = parse_domains(&["Acme.com".to_string()]).unwrap_err();
        assert!(err.to_string().contains("lowercase"), "{err}");
        let err = parse_domains(&["github.io".to_string()]).unwrap_err();
        assert!(err.to_string().contains("public suffix"), "{err}");
    }

    #[test]
    fn nine_domains_are_refused_before_any_network() {
        let nine: Vec<String> = (1..=9).map(|i| format!("d{i}.example.com")).collect();
        let err = parse_domains(&nine).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");
    }

    /// The CLI and the registry must agree exactly, so this drives the real
    /// admission rules rather than asserting on the shape of what was
    /// produced — the same bargain `card.rs` makes for publication.
    #[test]
    fn a_certification_satisfies_the_registry_rules() {
        use std::collections::BTreeSet;
        const REGISTRY: &str = "https://registry.example";

        let key = PrivateKey::generate();
        let agent_id = key.kid().unwrap();
        let domains = parse_domains(&["acme.com".to_string()]).unwrap();
        let operation = certification(&key, REGISTRY, &agent_id, &domains).unwrap();

        let state = registry_core::AgentState {
            agent_id: agent_id.clone(),
            status: registry_core::Status::Active,
            card_digest: "sha256:current".into(),
            card_version: semver::Version::new(1, 0, 0),
            authorized_kids: BTreeSet::from([agent_id.clone()]),
        };
        let accepted = registry_core::evaluate_certification(
            &state,
            REGISTRY,
            None,
            operation["protected"].as_str().unwrap(),
            operation["payload"].as_str().unwrap(),
            operation["signature"].as_str().unwrap(),
            &[key.public_jwk()],
        )
        .expect("the CLI's operation must satisfy the registry's rules");
        assert_eq!(accepted.domains.len(), 1);
    }

    /// And one minted for another registry must not open here — the same
    /// property the withdrawal construction pins.
    #[test]
    fn a_certification_does_not_travel_between_registries() {
        use std::collections::BTreeSet;

        let key = PrivateKey::generate();
        let agent_id = key.kid().unwrap();
        let domains = parse_domains(&["acme.com".to_string()]).unwrap();
        let operation =
            certification(&key, "https://elsewhere.example", &agent_id, &domains).unwrap();

        let state = registry_core::AgentState {
            agent_id: agent_id.clone(),
            status: registry_core::Status::Active,
            card_digest: "sha256:current".into(),
            card_version: semver::Version::new(1, 0, 0),
            authorized_kids: BTreeSet::from([agent_id.clone()]),
        };
        let err = registry_core::evaluate_certification(
            &state,
            "https://registry.example",
            None,
            operation["protected"].as_str().unwrap(),
            operation["payload"].as_str().unwrap(),
            operation["signature"].as_str().unwrap(),
            &[key.public_jwk()],
        )
        .unwrap_err();
        assert_eq!(err.code, registry_core::Code::SignatureInvalid);
        assert!(err.detail.contains("registryOrigin"), "{}", err.detail);
    }

    #[test]
    fn zone_lines_are_pasteable_and_fully_qualified() {
        let domains = parse_domains(&["acme.com".to_string()]).unwrap();
        let missing: Vec<&Domain> = domains.iter().collect();
        let lines = zone_lines("AGENT_ID", &missing);
        assert!(
            lines.contains(&format!(
                "{}.   IN   TXT   \"v={}; k=AGENT_ID\"",
                domains[0].query_name(),
                registry_core::TXT_VERSION
            )),
            "{lines}"
        );
    }
}
