//! Conversion between DynamoDB items and the records of [`registry_api::store`].
//!
//! Pure in both directions, so the mapping is tested by round trip rather than
//! against a live table.

use std::collections::{BTreeSet, HashMap};

use aws_sdk_dynamodb::types::AttributeValue as Av;
use registry_api::store::{AgentRecord, VersionRecord};
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

pub fn version_record(item: &Item) -> Result<VersionRecord, ItemError> {
    Ok(VersionRecord {
        seq: n(item, "seq")?,
        card_digest: s(item, "cardDigest")?,
        card_version: s(item, "cardVersion")?,
        signing_kids: ss(item, "signingKids")?,
        created_at: s(item, "createdAt")?,
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
