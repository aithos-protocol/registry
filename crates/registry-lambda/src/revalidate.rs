//! The hourly revalidation of certified domains (`DOMAIN-CERTIFICATION.md`
//! §7).
//!
//! The decision is pure and lives in [`next_observed`]; the driver around it
//! resolves and writes. Split that way for the same reason as everything else
//! here: the rules are tested without AWS or a network, and the driver stays
//! too thin to hide a rule in.
//!
//! What a pass may do: update `lastCheckedAt`, return a domain to `observed`
//! when its record is visible again, and remove one after **three
//! consecutive** failed passes. What it may never do: touch `requested` — the
//! registry is not deciding anything here, it is reporting what it can no
//! longer observe, and only a signed operation changes what was asked for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use registry_api::store::DomainRecord;
use registry_dns::Resolver;

/// How many consecutive failed passes remove a domain from `observed`.
///
/// Three, because one failing pass is far more likely a resolver hiccup than
/// a revoked declaration, and the cost of the delay is bounded and published
/// while the cost of flapping is a certification that appears and disappears
/// for reasons no reader can see (§7).
pub const REMOVAL_AFTER_FAILED_PASSES: u8 = 3;

/// What one pass concluded for one agent.
#[derive(Debug, PartialEq, Eq)]
pub struct PassOutcome {
    /// The new `observed` list, in `requested` order.
    pub observed: Vec<DomainRecord>,
    /// Domains removed by this pass — each one is an event worth a log line
    /// and a metric, never a routine.
    pub removed: Vec<String>,
}

/// Fold one pass's resolutions into the stored observations.
///
/// `sighted` holds, for each requested domain, whether §3.3 matched this
/// pass. Every requested domain is expected to be present in it — the driver
/// resolves exactly the requested set.
pub fn next_observed(
    requested: &BTreeSet<String>,
    observed: &[DomainRecord],
    sighted: &BTreeMap<String, bool>,
    now: &str,
) -> PassOutcome {
    let current: BTreeMap<&str, &DomainRecord> =
        observed.iter().map(|d| (d.domain.as_str(), d)).collect();

    let mut next = Vec::new();
    let mut removed = Vec::new();
    for domain in requested {
        let seen = sighted.get(domain).copied().unwrap_or(false);
        match (current.get(domain.as_str()), seen) {
            // Observed and already listed: freshness moves, the counter
            // resets, and `certifiedAt` keeps the start of the continuous
            // run — that is what the member means (§4.2).
            (Some(existing), true) => next.push(DomainRecord {
                domain: domain.clone(),
                certified_at: existing.certified_at.clone(),
                last_checked_at: now.to_string(),
                consecutive_failures: 0,
            }),
            // Observed and not listed: the record returned by itself, which
            // is the whole point of keeping the request (§4.3). A new
            // continuous run starts now.
            (None, true) => next.push(DomainRecord {
                domain: domain.clone(),
                certified_at: now.to_string(),
                last_checked_at: now.to_string(),
                consecutive_failures: 0,
            }),
            // Failed and listed: count, and remove only at the threshold.
            // Below it nothing else changes — `lastCheckedAt` records the
            // last *successful* observation, so a failing pass must not
            // advance it.
            (Some(existing), false) => {
                let failures = existing.consecutive_failures.saturating_add(1);
                if failures >= REMOVAL_AFTER_FAILED_PASSES {
                    removed.push(domain.clone());
                } else {
                    next.push(DomainRecord {
                        domain: domain.clone(),
                        certified_at: existing.certified_at.clone(),
                        last_checked_at: existing.last_checked_at.clone(),
                        consecutive_failures: failures,
                    });
                }
            }
            // Failed and not listed: nothing was published, nothing changes.
            (None, false) => {}
        }
    }

    PassOutcome {
        observed: next,
        removed,
    }
}

/// Resolve one agent's requested set and report which domains matched §3.3.
///
/// Concurrent across the domains of one agent, sequential across agents: the
/// worst case per agent is one resolution timeout, and the pass as a whole
/// stays boring.
pub async fn sight_requested(
    resolver: &Arc<dyn Resolver>,
    agent_id: &str,
    requested: &BTreeSet<String>,
) -> BTreeMap<String, bool> {
    let lookups = requested.iter().map(|domain| {
        let resolver = Arc::clone(resolver);
        // A stored domain that no longer parses is a damaged register: treat
        // it as unobserved and let the three-pass rule retire it, rather than
        // crashing the pass for every other agent.
        let query = registry_core::Domain::parse(domain)
            .map(|parsed| parsed.query_name())
            .ok();
        let domain = domain.clone();
        async move {
            let seen = match query {
                None => false,
                Some(name) => match resolver.txt(&name).await {
                    Ok(records) => registry_core::rrset_names_agent(&records, agent_id),
                    Err(_) => false,
                },
            };
            (domain, seen)
        }
    });
    futures_util::future::join_all(lookups)
        .await
        .into_iter()
        .collect()
}

/// What one revalidation pass did, across every agent it visited.
#[derive(Debug, Default)]
pub struct PassReport {
    /// Agents whose certification state was examined.
    pub examined: usize,
    /// `(agent, domain)` pairs removed by this pass — each already logged.
    pub removed: Vec<(String, String)>,
    /// Agents whose pass failed on a storage error; resolution failures are
    /// not here, they are what the counter is *for*.
    pub failed: Vec<String>,
}

/// One full revalidation pass (§7) over the given agents.
///
/// Storage-generic so the whole pass runs against `MemoryStore` in tests;
/// the sweeper hands it the real store, the real resolver and every agent id
/// it already enumerates for convergence.
pub async fn run_pass(
    store: &dyn registry_api::Store,
    resolver: &Arc<dyn Resolver>,
    agent_ids: &[String],
    now: &str,
) -> PassReport {
    use registry_api::StoreError;
    use registry_core::Status;

    let mut report = PassReport::default();
    for agent_id in agent_ids {
        let fail = |report: &mut PassReport, why: String| {
            tracing::error!(agent = %agent_id, %why, "revalidation pass failed for this agent");
            report.failed.push(agent_id.clone());
        };

        // Only ACTIVE agents revalidate (§7); a withdrawn entry's domains are
        // already gone from the read path (§5.7).
        let record = match store.get_agent(agent_id).await {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(e) => {
                fail(&mut report, e.to_string());
                continue;
            }
        };
        if record.status != Status::Active {
            continue;
        }

        let certification = match store.get_certification(agent_id).await {
            Ok(c) => c,
            Err(e) => {
                fail(&mut report, e.to_string());
                continue;
            }
        };
        // No certification, or one whose requested set is empty: nothing to
        // re-observe.
        let Some(issued_at) = certification.issued_at.clone() else {
            continue;
        };
        if certification.requested.is_empty() {
            continue;
        }
        report.examined += 1;

        let sighted = sight_requested(resolver, agent_id, &certification.requested).await;
        let outcome = next_observed(
            &certification.requested,
            &certification.observed,
            &sighted,
            now,
        );

        for domain in &outcome.removed {
            // A removal is an event, not a routine: this line is what the
            // metric filter counts, and what an operator greps for.
            tracing::warn!(
                agent = %agent_id,
                domain = %domain,
                "certified domain removed after three failed revalidation passes"
            );
        }

        if outcome.observed != certification.observed {
            match store
                .put_observations(agent_id, &issued_at, &outcome.observed)
                .await
            {
                Ok(()) => {}
                // A fresh certification landed while this pass was resolving:
                // its state is newer than these observations, so they die
                // here, unwritten — which is the condition's whole job.
                Err(StoreError::Conflict) => continue,
                Err(e) => {
                    fail(&mut report, e.to_string());
                    continue;
                }
            }
        }
        report
            .removed
            .extend(outcome.removed.into_iter().map(|d| (agent_id.clone(), d)));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(domain: &str, failures: u8) -> DomainRecord {
        DomainRecord {
            domain: domain.into(),
            certified_at: "2026-09-01T00:00:00.000Z".into(),
            last_checked_at: "2026-09-01T00:00:00.000Z".into(),
            consecutive_failures: failures,
        }
    }

    fn requested(domains: &[&str]) -> BTreeSet<String> {
        domains.iter().map(|s| s.to_string()).collect()
    }

    fn sighted(pairs: &[(&str, bool)]) -> BTreeMap<String, bool> {
        pairs.iter().map(|(d, s)| (d.to_string(), *s)).collect()
    }

    const NOW: &str = "2026-09-01T12:00:00.000Z";

    #[test]
    fn a_successful_pass_updates_freshness_and_keeps_the_run_start() {
        let out = next_observed(
            &requested(&["acme.com"]),
            &[record("acme.com", 0)],
            &sighted(&[("acme.com", true)]),
            NOW,
        );
        assert_eq!(out.observed[0].last_checked_at, NOW);
        assert_eq!(
            out.observed[0].certified_at, "2026-09-01T00:00:00.000Z",
            "certifiedAt is the start of the continuous run, not the last check"
        );
        assert!(out.removed.is_empty());
    }

    #[test]
    fn three_consecutive_failures_remove_a_domain_and_not_two() {
        let mut observed = vec![record("acme.com", 0)];
        let failing = sighted(&[("acme.com", false)]);
        let req = requested(&["acme.com"]);

        // Pass one and two: counted, kept, and freshness untouched.
        for expected_failures in [1, 2] {
            let out = next_observed(&req, &observed, &failing, NOW);
            assert!(out.removed.is_empty(), "removed at {expected_failures}");
            assert_eq!(out.observed[0].consecutive_failures, expected_failures);
            assert_eq!(
                out.observed[0].last_checked_at, "2026-09-01T00:00:00.000Z",
                "a failing pass must not advance lastCheckedAt"
            );
            observed = out.observed;
        }

        // Pass three: removed, and the removal is named.
        let out = next_observed(&req, &observed, &failing, NOW);
        assert!(out.observed.is_empty());
        assert_eq!(out.removed, ["acme.com"]);
    }

    #[test]
    fn a_success_in_the_middle_resets_the_counter() {
        let out = next_observed(
            &requested(&["acme.com"]),
            &[record("acme.com", 2)],
            &sighted(&[("acme.com", true)]),
            NOW,
        );
        assert_eq!(out.observed[0].consecutive_failures, 0);
        assert!(out.removed.is_empty());

        // And the count starts over afterwards.
        let out = next_observed(
            &requested(&["acme.com"]),
            &out.observed,
            &sighted(&[("acme.com", false)]),
            NOW,
        );
        assert_eq!(out.observed[0].consecutive_failures, 1);
    }

    #[test]
    fn a_returned_record_rejoins_with_a_fresh_run() {
        // Removed earlier (not in observed), requested still, visible again.
        let out = next_observed(
            &requested(&["acme.com"]),
            &[],
            &sighted(&[("acme.com", true)]),
            NOW,
        );
        assert_eq!(out.observed[0].domain, "acme.com");
        assert_eq!(out.observed[0].certified_at, NOW, "a new continuous run");
        assert!(out.removed.is_empty());
    }

    #[test]
    fn an_unpublished_domain_stays_unpublished_quietly() {
        let out = next_observed(
            &requested(&["acme.com"]),
            &[],
            &sighted(&[("acme.com", false)]),
            NOW,
        );
        assert!(out.observed.is_empty());
        assert!(
            out.removed.is_empty(),
            "nothing was removed: nothing was there"
        );
    }

    /// The whole pass, wired: MemoryStore and a static resolver, no AWS and
    /// no network — the same pair the HTTP suite trusts.
    #[tokio::test]
    async fn a_full_pass_counts_removes_and_restores() {
        use registry_api::MemoryStore;
        use registry_api::store::{CertificationState, Commit, Store};
        use registry_dns::StaticResolver;

        const AGENT: &str = "test-agent-thumbprint";
        const NOW: &str = "2026-09-01T12:00:00.000Z";

        let store = MemoryStore::new();
        store
            .commit(&Commit {
                agent_id: AGENT.into(),
                expected_seq: None,
                seq: 1,
                card_digest: "sha256:seed".into(),
                card_version: "1.0.0".into(),
                card_bytes: Vec::new(),
                keys: Vec::new(),
                authorized_kids: [AGENT.to_string()].into_iter().collect(),
                created_at: "2026-09-01T00:00:00.000Z".into(),
                existing_created_at: None,
            })
            .await
            .unwrap();
        store
            .put_certification(
                AGENT,
                &CertificationState {
                    requested: ["acme.com".to_string()].into_iter().collect(),
                    observed: vec![record("acme.com", 0)],
                    issued_at: Some("2026-09-01T09:00:00.000Z".into()),
                },
            )
            .await
            .unwrap();

        let ids = vec![AGENT.to_string()];

        // Three passes with the record gone: count, count, remove.
        let dark: Arc<dyn Resolver> = Arc::new(StaticResolver::new());
        for _ in 0..2 {
            let report = run_pass(&store, &dark, &ids, NOW).await;
            assert_eq!(report.examined, 1);
            assert!(report.removed.is_empty());
            assert!(report.failed.is_empty());
        }
        let report = run_pass(&store, &dark, &ids, NOW).await;
        assert_eq!(
            report.removed,
            [(AGENT.to_string(), "acme.com".to_string())]
        );
        let state = store.get_certification(AGENT).await.unwrap();
        assert!(state.observed.is_empty(), "removed from observed");
        assert_eq!(
            state.requested.len(),
            1,
            "requested is never touched by revalidation"
        );

        // The record returns: the certification comes back by itself, with a
        // fresh continuous run — no signature involved.
        let lit: Arc<dyn Resolver> = Arc::new(
            StaticResolver::new().observed(
                &registry_core::Domain::parse("acme.com")
                    .unwrap()
                    .query_name(),
                &[&format!("v={}; k={AGENT}", registry_core::TXT_VERSION)],
            ),
        );
        let report = run_pass(&store, &lit, &ids, NOW).await;
        assert!(report.removed.is_empty());
        let state = store.get_certification(AGENT).await.unwrap();
        assert_eq!(state.observed.len(), 1);
        assert_eq!(state.observed[0].certified_at, NOW);
    }

    #[test]
    fn requested_is_never_consulted_beyond_membership() {
        // A domain in `observed` but no longer in `requested` cannot happen by
        // construction; if state is damaged, the pass rebuilds from
        // `requested` and the orphan silently drains away.
        let out = next_observed(
            &requested(&["kept.example.com"]),
            &[
                record("kept.example.com", 0),
                record("orphan.example.com", 0),
            ],
            &sighted(&[("kept.example.com", true)]),
            NOW,
        );
        let names: Vec<&str> = out.observed.iter().map(|d| d.domain.as_str()).collect();
        assert_eq!(names, ["kept.example.com"]);
    }
}
