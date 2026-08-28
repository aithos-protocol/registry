//! Item and object key layout.
//!
//! Kept as pure functions so the layout can be tested without AWS, and so that
//! a change to it is visible in one place rather than scattered through
//! request builders.

/// Partition key for everything belonging to one agent.
pub fn agent_pk(agent_id: &str) -> String {
    format!("AGENT#{agent_id}")
}

/// The agent an item's partition key belongs to.
///
/// The inverse of [`agent_pk`]. The stream carries keys for every event,
/// including a `REMOVE` that has no image, so reading the identifier from the
/// key rather than the image is what lets every event name its agent.
pub fn agent_id_of_pk(pk: &str) -> Option<&str> {
    pk.strip_prefix("AGENT#").filter(|id| !id.is_empty())
}

/// Sort key of the mutable current-state item.
pub const CURRENT_SK: &str = "CURRENT";

/// Sort key of one immutable version item.
///
/// Zero-padded so that lexicographic sort order — the only order DynamoDB
/// offers on a string sort key — matches numeric order.
pub fn version_sk(seq: u64) -> String {
    format!("VERSION#{seq:020}")
}

/// Sort key of the digest index: answers "did this agent publish this exact
/// document" with a single lookup, which is what lets a historical read refuse
/// to serve an object whose commit never landed.
pub fn digest_sk(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("DIGEST#{hex}")
}

/// The single partition of the listing index.
pub const LIST_PK: &str = "LIST";

/// Sort key of the listing index: newest first when read in reverse, with the
/// identifier breaking ties so the order is total and a cursor can neither
/// skip nor repeat an entry.
pub fn list_sk(updated_at: &str, agent_id: &str) -> String {
    format!("{updated_at}#{agent_id}")
}

/// S3 key of one immutable card.
///
/// The `sha256:` prefix is dropped: a colon is legal in an S3 key but has to be
/// percent-encoded in a URL, and this object is meant to be served straight
/// from CloudFront.
pub fn card_object_key(agent_id: &str, digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("versions/{agent_id}/{hex}.json")
}

/// S3 key of the current-card pointer, overwritten on every publication.
///
/// Deliberately identical to the request path it answers, minus the leading
/// slash. CloudFront asks S3 for exactly that key, so the hot read path needs
/// no URL rewrite — no CloudFront Function, no Lambda@Edge, nothing to keep in
/// sync with the router.
pub fn current_card_key(agent_id: &str) -> String {
    format!("v1/agents/{agent_id}/agent-card.json")
}

/// S3 key of the current JWKS. Same reasoning as [`current_card_key`].
pub fn current_jwks_key(agent_id: &str) -> String {
    format!("v1/agents/{agent_id}/jwks.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_sort_keys_order_numerically() {
        let mut keys = [version_sk(2), version_sk(10), version_sk(1)];
        keys.sort();
        assert_eq!(keys, [version_sk(1), version_sk(2), version_sk(10)]);
    }

    #[test]
    fn digest_sort_keys_are_prefix_insensitive() {
        assert_eq!(digest_sk("sha256:dead"), digest_sk("dead"));
        assert!(digest_sk("sha256:dead").starts_with("DIGEST#"));
    }

    #[test]
    fn card_keys_drop_the_digest_prefix() {
        assert_eq!(
            card_object_key("abc", "sha256:dead"),
            "versions/abc/dead.json"
        );
        // Tolerate a bare hex digest, so a caller cannot produce two object
        // keys for one artifact.
        assert_eq!(card_object_key("abc", "dead"), "versions/abc/dead.json");
    }

    /// The hot read path is served straight from S3 by CloudFront, so the
    /// object key has to be the request path verbatim.
    #[test]
    fn current_object_keys_mirror_their_request_paths() {
        let request_path = "/v1/agents/abc/agent-card.json";
        assert_eq!(
            current_card_key("abc"),
            request_path.trim_start_matches('/')
        );
        assert_eq!(current_jwks_key("abc"), "v1/agents/abc/jwks.json");
    }

    #[test]
    fn listing_keys_are_total_ordered() {
        let a = list_sk("2026-08-25T10:00:00.000Z", "aaa");
        let b = list_sk("2026-08-25T10:00:00.000Z", "bbb");
        assert!(
            a < b,
            "identical timestamps must still order deterministically"
        );
    }
}
