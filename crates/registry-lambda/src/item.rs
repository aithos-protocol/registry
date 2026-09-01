//! Conversion between DynamoDB items and the records of [`registry_api::store`].
//!
//! Pure in both directions, so the mapping is tested by round trip rather than
//! against a live table.

use std::collections::{BTreeSet, HashMap};

use aws_sdk_dynamodb::types::AttributeValue as Av;
use registry_api::store::{AgentRecord, CertificationState, DomainRecord, VersionRecord};
use registry_core::Status;

use crate::keys;

pub type Item = HashMap<String, Av>;

/// A malformed item. Reaching this means the table holds something this
/// version of the code did not write, so it is reported rather than guessed at.
#[derive(Debug, thiserror::Error)]
#[error("stored item is malformed: {0}")]
pub struct ItemError(String);

fn s(item: &Item, name: &str) -> Result<String, ItemError> {
    item.get(name)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| ItemError(format!("attribute {name:?} is absent or not a string")))
}

fn n(item: &Item, name: &str) -> Result<u64, ItemError> {
    item.get(name)
        .and_then(|v| v.as_n().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| ItemError(format!("attribute {name:?} is absent or not a number")))
}

fn ss(item: &Item, name: &str) -> Result<BTreeSet<String>, ItemError> {
    item.get(name)
        .and_then(|v| v.as_ss().ok())
        .map(|v| v.iter().cloned().collect())
        .ok_or_else(|| ItemError(format!("attribute {name:?} is absent or not a string set")))
}

pub fn status_str(status: Status) -> &'static str {
    match status {
        Status::Active => "ACTIVE",
        Status::Withdrawn => "WITHDRAWN",
    }
}

fn parse_status(raw: &str) -> Result<Status, ItemError> {
    match raw {
        "ACTIVE" => Ok(Status::Active),
        "WITHDRAWN" => Ok(Status::Withdrawn),
        other => Err(ItemError(format!("unknown status {other:?}"))),
    }
}

pub fn agent_item(record: &AgentRecord, keys_json: &str) -> Item {
    let mut item = Item::new();
    item.insert("pk".into(), Av::S(keys::agent_pk(&record.agent_id)));
    item.insert("sk".into(), Av::S(keys::CURRENT_SK.into()));
    item.insert("agentId".into(), Av::S(record.agent_id.clone()));
    item.insert("status".into(), Av::S(status_str(record.status).into()));
    item.insert("seq".into(), Av::N(record.seq.to_string()));
    item.insert("cardDigest".into(), Av::S(record.card_digest.clone()));
    item.insert("cardVersion".into(), Av::S(record.card_version.clone()));
    item.insert(
        "authorizedKids".into(),
        Av::Ss(record.authorized_kids.iter().cloned().collect()),
    );
    item.insert("keys".into(), Av::S(keys_json.to_string()));
    item.insert("createdAt".into(), Av::S(record.created_at.clone()));
    item.insert("updatedAt".into(), Av::S(record.updated_at.clone()));
    // Listing index. Withdrawn agents keep their entry: the registry does not
    // pretend an identifier never existed.
    item.insert("gsi1pk".into(), Av::S(keys::LIST_PK.into()));
    item.insert(
        "gsi1sk".into(),
        Av::S(keys::list_sk(&record.updated_at, &record.agent_id)),
    );
    item
}

pub fn agent_record(item: &Item) -> Result<AgentRecord, ItemError> {
    Ok(AgentRecord {
        agent_id: s(item, "agentId")?,
        status: parse_status(&s(item, "status")?)?,
        seq: n(item, "seq")?,
        card_digest: s(item, "cardDigest")?,
        card_version: s(item, "cardVersion")?,
        authorized_kids: ss(item, "authorizedKids")?,
        created_at: s(item, "createdAt")?,
        updated_at: s(item, "updatedAt")?,
    })
}

pub fn agent_keys(item: &Item) -> Result<Vec<serde_json::Value>, ItemError> {
    let raw = s(item, "keys")?;
    serde_json::from_str(&raw).map_err(|e| ItemError(format!("`keys` is not a JSON array: {e}")))
}

pub fn version_item(agent_id: &str, record: &VersionRecord) -> Item {
    let mut item = Item::new();
    item.insert("pk".into(), Av::S(keys::agent_pk(agent_id)));
    item.insert("sk".into(), Av::S(keys::version_sk(record.seq)));
    item.insert("seq".into(), Av::N(record.seq.to_string()));
    item.insert("cardDigest".into(), Av::S(record.card_digest.clone()));
    item.insert("cardVersion".into(), Av::S(record.card_version.clone()));
    item.insert(
        "signingKids".into(),
        Av::Ss(record.signing_kids.iter().cloned().collect()),
    );
    item.insert("createdAt".into(), Av::S(record.created_at.clone()));
    item
}

/// The digest index entry. It carries the whole version record rather than a
/// pointer, so a lookup by digest costs one read and cannot go stale relative
/// to the version item written in the same transaction.
pub fn digest_item(agent_id: &str, record: &VersionRecord) -> Item {
    let mut item = version_item(agent_id, record);
    item.insert("sk".into(), Av::S(keys::digest_sk(&record.card_digest)));
    item
}

pub fn version_record(item: &Item) -> Result<VersionRecord, ItemError> {
    Ok(VersionRecord {
        seq: n(item, "seq")?,
        card_digest: s(item, "cardDigest")?,
        card_version: s(item, "cardVersion")?,
        signing_kids: ss(item, "signingKids")?,
        created_at: s(item, "createdAt")?,
    })
}

// --- domain certification (DOMAIN-CERTIFICATION.md §4) --------------------
//
// The two list-shaped halves travel as JSON text, like the agent item's
// `keys`: DynamoDB never needs to look inside them — the one attribute a
// condition reads, `certificationIssuedAt`, is its own string — and one
// serialization means one round-trip test.

/// `requestedDomains` as stored: a JSON array of strings, sorted, possibly
/// empty (a string *set* cannot be empty, and the empty certification is a
/// state §5.2 explicitly allows).
pub fn requested_json(requested: &BTreeSet<String>) -> String {
    serde_json::to_string(&requested.iter().collect::<Vec<_>>()).expect("strings serialize")
}

/// `observed` as stored: a JSON array of §4.2 objects plus the failure
/// counter the revalidation pass owns.
pub fn observed_json(observed: &[DomainRecord]) -> String {
    let items: Vec<serde_json::Value> = observed
        .iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.domain,
                "certifiedAt": d.certified_at,
                "lastCheckedAt": d.last_checked_at,
                "consecutiveFailures": d.consecutive_failures,
            })
        })
        .collect();
    serde_json::to_string(&items).expect("plain values serialize")
}

pub fn certification_state(item: &Item) -> Result<CertificationState, ItemError> {
    let requested: Vec<String> = serde_json::from_str(&s(item, "requestedDomains")?)
        .map_err(|e| ItemError(format!("`requestedDomains` is not a JSON array: {e}")))?;

    let raw: Vec<serde_json::Value> = serde_json::from_str(&s(item, "observed")?)
        .map_err(|e| ItemError(format!("`observed` is not a JSON array: {e}")))?;
    let mut observed = Vec::with_capacity(raw.len());
    for entry in &raw {
        let text = |name: &str| {
            entry[name]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| ItemError(format!("`observed` entry has no {name:?}")))
        };
        observed.push(DomainRecord {
            domain: text("domain")?,
            certified_at: text("certifiedAt")?,
            last_checked_at: text("lastCheckedAt")?,
            consecutive_failures: entry["consecutiveFailures"]
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| ItemError("`observed` entry has no `consecutiveFailures`".into()))?,
        });
    }

    Ok(CertificationState {
        requested: requested.into_iter().collect(),
        observed,
        issued_at: Some(s(item, "certificationIssuedAt")?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_agent() -> AgentRecord {
        AgentRecord {
            agent_id: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".into(),
            status: Status::Active,
            seq: 3,
            card_digest: "sha256:abcd".into(),
            card_version: "1.2.0".into(),
            authorized_kids: ["k1".to_string(), "k2".to_string()].into_iter().collect(),
            created_at: "2026-08-25T10:00:00.000Z".into(),
            updated_at: "2026-08-25T11:00:00.000Z".into(),
        }
    }

    #[test]
    fn an_agent_record_round_trips() {
        let record = sample_agent();
        let keys = json!([{ "kty": "OKP" }]).to_string();
        let item = agent_item(&record, &keys);
        assert_eq!(agent_record(&item).unwrap(), record);
        assert_eq!(agent_keys(&item).unwrap().len(), 1);
    }

    #[test]
    fn a_withdrawn_agent_round_trips_and_stays_listed() {
        let mut record = sample_agent();
        record.status = Status::Withdrawn;
        let item = agent_item(&record, "[]");
        assert_eq!(agent_record(&item).unwrap().status, Status::Withdrawn);
        assert!(
            item.contains_key("gsi1pk"),
            "a withdrawn identifier is not erased"
        );
    }

    #[test]
    fn a_version_record_round_trips() {
        let record = VersionRecord {
            seq: 10,
            card_digest: "sha256:beef".into(),
            card_version: "2.0.0".into(),
            signing_kids: ["k2".to_string()].into_iter().collect(),
            created_at: "2026-08-25T11:00:00.000Z".into(),
        };
        let item = version_item("agent", &record);
        assert_eq!(item["sk"].as_s().unwrap(), &keys::version_sk(10));
        assert_eq!(version_record(&item).unwrap(), record);
    }

    #[test]
    fn the_digest_index_carries_the_same_record() {
        let record = VersionRecord {
            seq: 4,
            card_digest: "sha256:feed".into(),
            card_version: "1.0.0".into(),
            signing_kids: ["k".to_string()].into_iter().collect(),
            created_at: "2026-08-25T11:00:00.000Z".into(),
        };
        let indexed = digest_item("agent", &record);
        assert_eq!(
            indexed["sk"].as_s().unwrap(),
            &keys::digest_sk("sha256:feed")
        );
        assert_eq!(version_record(&indexed).unwrap(), record);
    }

    #[test]
    fn a_certification_state_round_trips_through_its_item_attributes() {
        let state = CertificationState {
            requested: ["acme.com".to_string(), "acme.fr".to_string()]
                .into_iter()
                .collect(),
            observed: vec![DomainRecord {
                domain: "acme.com".into(),
                certified_at: "2026-09-01T09:00:00.000Z".into(),
                last_checked_at: "2026-09-01T11:00:00.000Z".into(),
                consecutive_failures: 1,
            }],
            issued_at: Some("2026-09-01T09:00:00.000Z".into()),
        };

        let mut item = Item::new();
        item.insert(
            "requestedDomains".into(),
            Av::S(requested_json(&state.requested)),
        );
        item.insert("observed".into(), Av::S(observed_json(&state.observed)));
        item.insert(
            "certificationIssuedAt".into(),
            Av::S("2026-09-01T09:00:00.000Z".into()),
        );
        assert_eq!(certification_state(&item).unwrap(), state);
    }

    /// The empty certification is a real state (§5.2: an empty set removes
    /// everything) and a string *set* cannot hold it — which is why the lists
    /// travel as JSON text.
    #[test]
    fn the_empty_certification_round_trips() {
        let state = CertificationState {
            requested: Default::default(),
            observed: Vec::new(),
            issued_at: Some("2026-09-01T10:00:00.000Z".into()),
        };
        let mut item = Item::new();
        item.insert(
            "requestedDomains".into(),
            Av::S(requested_json(&state.requested)),
        );
        item.insert("observed".into(), Av::S(observed_json(&state.observed)));
        item.insert(
            "certificationIssuedAt".into(),
            Av::S("2026-09-01T10:00:00.000Z".into()),
        );
        assert_eq!(certification_state(&item).unwrap(), state);
    }

    #[test]
    fn a_malformed_certification_item_is_reported_not_guessed() {
        let mut item = Item::new();
        item.insert("requestedDomains".into(), Av::S("[]".into()));
        item.insert("observed".into(), Av::S("not json".into()));
        item.insert("certificationIssuedAt".into(), Av::S("t".into()));
        assert!(
            certification_state(&item)
                .unwrap_err()
                .to_string()
                .contains("observed")
        );
    }

    #[test]
    fn a_malformed_item_is_reported_not_guessed() {
        let mut item = agent_item(&sample_agent(), "[]");
        item.remove("cardDigest");
        assert!(
            agent_record(&item)
                .unwrap_err()
                .to_string()
                .contains("cardDigest")
        );

        let mut item = agent_item(&sample_agent(), "[]");
        item.insert("status".into(), Av::S("SOMETHING_ELSE".into()));
        assert!(
            agent_record(&item)
                .unwrap_err()
                .to_string()
                .contains("unknown status")
        );
    }
}
