//! The DNS half of domain certification (`DOMAIN-CERTIFICATION.md` §3, §5.4).
//!
//! Parsing and rules only. This crate stays pure, so resolution lives in
//! `registry-dns` and every function here works on data a caller already
//! holds. The registry, the CLI and any second implementation must agree on
//! these rules byte for byte, which is why they sit in the deterministic core
//! rather than beside the resolver.

use crate::error::{Code, RegistryError, Result};

/// The underscored node name a zone declares its agents under (§3.1).
///
/// This is the one place the string exists. It is not yet in the IANA
/// *Underscored and Globally Scoped DNS Node Names* registry; registration is
/// intended, and what actually freezes the name is the first zone that
/// publishes it — so it must never be spelled a second time in this workspace.
pub const DNS_LABEL: &str = "_a2a";

/// The exact value the first tag of every record must carry (§3.2).
pub const TXT_VERSION: &str = "A2A1";

/// The most domains one certification may name (§8).
pub const MAX_DOMAINS: usize = 8;

/// The most `TXT` records a resolver examines at one name (§8).
pub const MAX_TXT_RECORDS: usize = 32;

/// The most record data a resolver examines at one name, in octets (§8).
pub const MAX_TXT_BYTES: usize = 4096;

/// A domain validated under §5.4: A-label form, lowercase, no trailing dot.
///
/// The inner string is exactly what was submitted — validation refuses rather
/// than normalizes, because every conversion the registry performed would be a
/// choice made on the publisher's behalf (§5.4 on U-labels, and the same
/// division of labour as `SPEC.md` §5.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Domain(String);

impl Domain {
    /// Validate one element of `domains[]` under §5.4.
    pub fn parse(raw: &str) -> Result<Self> {
        let refuse = |detail: String| Err(RegistryError::new(Code::DomainSyntaxInvalid, detail));

        if raw.is_empty() {
            return refuse("a domain cannot be empty".into());
        }
        if !raw.is_ascii() {
            // §5.4: refused, never converted. Conversion is where homograph
            // confusion enters — the registry would be choosing which Unicode
            // string a stored name came from.
            return refuse(format!(
                "{raw:?} is not in A-label form; convert internationalized names with IDNA \
                 (punycode) yourself and submit the `xn--` result"
            ));
        }
        for (needle, what) in [
            ("://", "a scheme"),
            ("/", "a path"),
            (":", "a scheme or port"),
            ("@", "userinfo"),
            ("?", "a query"),
            ("#", "a fragment"),
        ] {
            if raw.contains(needle) {
                return refuse(format!(
                    "{raw:?} carries {what}; a certification names a bare domain"
                ));
            }
        }
        if raw.bytes().any(|b| b.is_ascii_whitespace()) {
            return refuse(format!("{raw:?} contains whitespace"));
        }
        if raw.ends_with('.') {
            return refuse(format!(
                "{raw:?} ends with a dot; submit the name without its root dot"
            ));
        }
        if raw.bytes().any(|b| b.is_ascii_uppercase()) {
            // Refused rather than lowered, deliberately: DNS names are
            // case-insensitive but the stored form is what §9 displays, and a
            // registry that edits what it was given is a registry whose stored
            // set is not what a key signed.
            return refuse(format!("{raw:?} is not lowercase"));
        }
        if raw.parse::<std::net::IpAddr>().is_ok() {
            return refuse(format!(
                "{raw:?} is an IP address literal, not a domain name"
            ));
        }
        if raw.len() > 253 {
            return refuse(format!(
                "{raw:?} is {} octets; a domain name is at most 253",
                raw.len()
            ));
        }
        for label in raw.split('.') {
            if label.is_empty() {
                return refuse(format!("{raw:?} contains an empty label"));
            }
            if label.len() > 63 {
                return refuse(format!(
                    "label {label:?} is {} octets; a label is at most 63",
                    label.len()
                ));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return refuse(format!(
                    "label {label:?} contains a character outside letters, digits and hyphen"
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return refuse(format!("label {label:?} begins or ends with a hyphen"));
            }
        }

        // §5.4's last rule, checked last so it only ever sees a syntactically
        // valid name. `psl::domain` is the whole Public Suffix List algorithm,
        // wildcard and exception rules included, over a list embedded at
        // compile time — the registry must not depend on a fetch at startup.
        // `None` means the name has no registrable part: it is a public suffix,
        // or sits so high in the public namespace that no single party
        // controls it, which is the situation the rule exists to refuse.
        if psl::domain(raw.as_bytes()).is_none() {
            return Err(RegistryError::new(
                Code::DomainIsPublicSuffix,
                format!(
                    "{raw:?} is a public suffix; a certification must name a domain a single \
                     party controls"
                ),
            ));
        }

        Ok(Self(raw.to_string()))
    }

    /// The validated name, exactly as submitted.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name whose `TXT` record set carries the declarations:
    /// [`DNS_LABEL`]`.<D>`.
    ///
    /// The prefix sits directly under the certified name and nowhere the
    /// publisher chooses — otherwise whoever controls one subdomain could have
    /// the parent certified.
    pub fn query_name(&self) -> String {
        format!("{DNS_LABEL}.{}", self.0)
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `k` value of one well-formed record, if it has one (§3.2–3.3).
///
/// `record` is the record data with its character-strings already
/// concatenated (RFC 7208 §3.3); concatenation is transport, so it belongs to
/// the resolver. Nothing here returns an error: §3.3 requires records that do
/// not parse to be **ignored**, never to fail the resolution — a domain
/// hosting several agents must not let one bad record deny all the others.
///
/// The record parses when every `;`-separated chunk is a `tag=value` pair
/// (ASCII space and horizontal tab around tags, `=` and `;` ignored, empty
/// chunks tolerated so a trailing `;` is not fatal) and its first tag is
/// exactly `v=A2A1`. Tag names are lowercase and case-sensitive, so `V=A2A1`
/// is an unrecognized tag — and an unrecognized *first* tag means `v` is not
/// first, so the record does not match. Unknown tags elsewhere are ignored, so
/// a later version of the profile can add one without invalidating deployed
/// zones. The value of `k` is returned as written: base64url is
/// case-sensitive, so the value is never normalized (only DNS *names* are
/// case-insensitive).
pub fn agent_id_in_record(record: &str) -> Option<&str> {
    let mut chunks = record.split(';');

    let (name, value) = split_tag(chunks.next()?)?;
    if name != "v" || value != TXT_VERSION {
        return None;
    }

    let mut agent_id = None;
    for chunk in chunks {
        if trim_wsp(chunk).is_empty() {
            continue;
        }
        // A chunk that is not `tag=value` makes the whole record one that
        // "does not parse" (§3.3): ignored, not partially read.
        let (name, value) = split_tag(chunk)?;
        if name == "k" && agent_id.is_none() {
            agent_id = Some(value);
        }
    }
    agent_id
}

/// Whether at least one record of the set names this agent (§3.3).
///
/// True as soon as one record matches. Malformed records, foreign `k` values
/// and unrecognized versions sharing the name change nothing.
pub fn rrset_names_agent(records: &[String], agent_id: &str) -> bool {
    records
        .iter()
        .any(|record| agent_id_in_record(record) == Some(agent_id))
}

/// §3.2: only ASCII space and horizontal tab are ignorable, and only around
/// tags and separators — never inside a value.
fn trim_wsp(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

fn split_tag(chunk: &str) -> Option<(&str, &str)> {
    let (name, value) = chunk.split_once('=')?;
    Some((trim_wsp(name), trim_wsp(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    // --- Domain::parse ---------------------------------------------------

    /// The one deliberate second spelling of the underscored name in this
    /// workspace: the constant's value is pinned here, and everything else —
    /// code, tests, the manifest, the CLI — goes through [`DNS_LABEL`] or
    /// [`Domain::query_name`]. The first zone that publishes a record is what
    /// freezes this string; this test is what notices an accidental edit.
    #[test]
    fn the_underscored_name_is_pinned() {
        assert_eq!(DNS_LABEL, "_a2a");
        assert_eq!(TXT_VERSION, "A2A1");
    }

    #[test]
    fn a_plain_registrable_domain_parses() {
        let d = Domain::parse("acme.com").unwrap();
        assert_eq!(d.as_str(), "acme.com");
        assert_eq!(d.query_name(), format!("{DNS_LABEL}.acme.com"));
    }

    #[test]
    fn a_deep_subdomain_parses_and_is_scoped_to_itself() {
        let d = Domain::parse("agents.europe.acme.co.uk").unwrap();
        assert_eq!(
            d.query_name(),
            format!("{DNS_LABEL}.agents.europe.acme.co.uk")
        );
    }

    #[test]
    fn a_u_label_is_refused_not_converted() {
        let err = Domain::parse("acmé.com").unwrap_err();
        assert_eq!(err.code, Code::DomainSyntaxInvalid);
        assert!(err.detail.contains("A-label"), "{}", err.detail);
        // The A-label form of the same name is fine.
        Domain::parse("xn--acm-dla.com").unwrap();
    }

    #[test]
    fn uppercase_is_refused_not_lowered() {
        assert_eq!(
            Domain::parse("Acme.com").unwrap_err().code,
            Code::DomainSyntaxInvalid
        );
    }

    #[test]
    fn urls_ports_paths_and_userinfo_are_refused() {
        for raw in [
            "https://acme.com",
            "acme.com/path",
            "acme.com:443",
            "user@acme.com",
            "acme.com?x=1",
            "acme.com#f",
        ] {
            assert_eq!(
                Domain::parse(raw).unwrap_err().code,
                Code::DomainSyntaxInvalid,
                "{raw}"
            );
        }
    }

    #[test]
    fn a_trailing_dot_is_refused() {
        assert_eq!(
            Domain::parse("acme.com.").unwrap_err().code,
            Code::DomainSyntaxInvalid
        );
    }

    #[test]
    fn ip_literals_are_refused() {
        for raw in ["192.168.0.1", "255.255.255.255"] {
            let err = Domain::parse(raw).unwrap_err();
            assert_eq!(err.code, Code::DomainSyntaxInvalid, "{raw}");
            assert!(err.detail.contains("IP address"), "{}", err.detail);
        }
    }

    #[test]
    fn label_and_name_lengths_are_bounded() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            Domain::parse(&long_label).unwrap_err().code,
            Code::DomainSyntaxInvalid
        );
        Domain::parse(&format!("{}.com", "a".repeat(63))).unwrap();

        let long_name = format!("{}.com", vec!["a".repeat(63); 4].join("."));
        assert!(long_name.len() > 253);
        assert_eq!(
            Domain::parse(&long_name).unwrap_err().code,
            Code::DomainSyntaxInvalid
        );
    }

    #[test]
    fn empty_labels_and_edge_hyphens_are_refused() {
        for raw in [
            "acme..com",
            ".acme.com",
            "-acme.com",
            "acme-.com",
            "a_b.com",
        ] {
            assert_eq!(
                Domain::parse(raw).unwrap_err().code,
                Code::DomainSyntaxInvalid,
                "{raw}"
            );
        }
    }

    #[test]
    fn public_suffixes_are_refused_including_multi_label_and_private_ones() {
        // "com" — an ICANN suffix; "co.uk" — multi-label; "github.io" — the
        // private section of the list, where one party controls the name but
        // strangers control its children, which is exactly the confusion §5.4
        // refuses to certify.
        for raw in ["com", "co.uk", "github.io"] {
            let err = Domain::parse(raw).unwrap_err();
            assert_eq!(err.code, Code::DomainIsPublicSuffix, "{raw}");
        }
        // One label below each of those is a name a single party controls.
        for raw in ["acme.com", "acme.co.uk", "acme.github.io"] {
            Domain::parse(raw).unwrap();
        }
    }

    #[test]
    fn a_bare_unknown_label_has_no_registrable_part() {
        // The PSL algorithm's prevailing `*` rule: an unknown top label is its
        // own suffix, so nothing at or above the suffix is certifiable.
        assert_eq!(
            Domain::parse("localhost").unwrap_err().code,
            Code::DomainIsPublicSuffix
        );
    }

    // --- record parsing ---------------------------------------------------

    #[test]
    fn a_minimal_record_names_its_agent() {
        let record = format!("v=A2A1; k={AGENT}");
        assert_eq!(agent_id_in_record(&record), Some(AGENT));
    }

    #[test]
    fn whitespace_around_tags_and_separators_is_ignored() {
        let record = format!("\tv = A2A1 ;  k\t=\t{AGENT} ");
        assert_eq!(agent_id_in_record(&record), Some(AGENT));
    }

    #[test]
    fn an_unknown_tag_is_ignored_not_fatal() {
        let record = format!("v=A2A1; note=hello; k={AGENT}; x=1");
        assert_eq!(agent_id_in_record(&record), Some(AGENT));
    }

    #[test]
    fn a_trailing_separator_is_tolerated() {
        let record = format!("v=A2A1; k={AGENT};");
        assert_eq!(agent_id_in_record(&record), Some(AGENT));
    }

    #[test]
    fn v_must_be_first_and_exact() {
        for record in [
            format!("k={AGENT}; v=A2A1"), // v not first
            format!("v=A2A2; k={AGENT}"), // unknown version
            format!("v=a2a1; k={AGENT}"), // the value of `v` is case-sensitive
            format!("V=A2A1; k={AGENT}"), // tag names are lowercase
            format!("k={AGENT}"),         // v absent
        ] {
            assert_eq!(agent_id_in_record(&record), None, "{record}");
        }
    }

    #[test]
    fn the_value_of_k_is_never_case_normalized() {
        // Same bytes, different case: base64url makes these different keys.
        let record = format!("v=A2A1; k={}", AGENT.to_ascii_lowercase());
        assert_ne!(agent_id_in_record(&record), Some(AGENT));
    }

    #[test]
    fn a_chunk_that_is_not_a_tag_value_pair_makes_the_record_unparsed() {
        let record = format!("v=A2A1; garbage; k={AGENT}");
        assert_eq!(agent_id_in_record(&record), None);
    }

    #[test]
    fn one_valid_record_wins_over_malformed_neighbours() {
        let records = vec![
            "not a record at all".to_string(),
            format!("v=A2A9; k={AGENT}"),
            format!("v=A2A1; k=some-other-agent-id"),
            format!("v=A2A1; k={AGENT}"),
        ];
        assert!(rrset_names_agent(&records, AGENT));
        assert!(!rrset_names_agent(&records[..3], AGENT));
    }

    #[test]
    fn an_empty_record_set_names_nobody() {
        assert!(!rrset_names_agent(&[], AGENT));
    }
}
