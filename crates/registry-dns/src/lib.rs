//! TXT resolution for domain certification (`DOMAIN-CERTIFICATION.md` §5.5).
//!
//! One trait, two implementations. [`HickoryResolver`] is the real one, used
//! by the registry's request path, by the revalidation pass and by the CLI.
//! [`StaticResolver`] answers from a map, which is what lets the whole HTTP
//! surface be tested with no network in sight — the same split as
//! `MemoryStore` against the AWS store.
//!
//! The contract preserves the one distinction §5.5 makes everything hang on:
//! a name that *answered* with nothing ([`ResolveError::NoRecords`] — NXDOMAIN
//! and NODATA are answers) against a name that could not be resolved
//! ([`ResolveError::Failed`] — SERVFAIL, timeout, a limit reached). Two
//! problem codes and two different publisher actions depend on it, so an
//! implementation that folds them together is wrong even when it looks
//! merely imprecise.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::proto::rr::{RData, RecordType};

use registry_core::{MAX_TXT_BYTES, MAX_TXT_RECORDS};

/// §8: resolution timeout per domain, total.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// §5.5: the most `CNAME`/`DNAME` redirections followed for one name.
pub const MAX_REDIRECTIONS: usize = 8;

/// Why a name yielded no usable record set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The name **answered** and no `TXT` record is there: NXDOMAIN and
    /// NODATA both land here, because both are authoritative statements that
    /// the record does not exist. The publisher's next step is to add it.
    #[error("the name answered with no TXT record")]
    NoRecords,
    /// Nothing can be concluded: SERVFAIL, timeout, truncation that TCP did
    /// not repair, or a limit of §5.5 reached. The caller's next step is to
    /// retry later, and nothing may be inferred about the record.
    #[error("resolution failed: {0}")]
    Failed(String),
}

/// The resolution contract.
///
/// `name` is the full query name without its root dot — what
/// [`registry_core::Domain::query_name`] returns. Each returned string is one
/// `TXT` record's data with its character-strings already concatenated, no
/// separator (RFC 7208 §3.3), so callers apply §3.2 parsing and never see
/// wire format.
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ResolveError>;
}

/// The real resolver, over hickory.
///
/// What §5.5 requires of it, and where each requirement lands:
/// - `QTYPE=TXT` only, never `ANY` — [`TokioResolver::lookup`] with
///   [`RecordType::TXT`] asks for exactly one type;
/// - the service's own recursive resolvers, never one named in a request —
///   this type is constructed once at boot from the environment
///   ([`HickoryResolver::from_system`]) or from an operator-supplied server
///   list ([`HickoryResolver::with_servers`]), and nothing request-shaped can
///   reach its configuration;
/// - TCP retry on truncation — hickory's UDP transport falls back to TCP by
///   itself, and every nameserver here is configured with both;
/// - at most 8 redirections — counted over the returned chain, see `txt`;
/// - bounded work — at most [`MAX_TXT_RECORDS`] records and [`MAX_TXT_BYTES`]
///   octets of record data are examined per name, and the whole lookup is
///   bounded by [`RESOLVE_TIMEOUT`].
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// A resolver over the system's configuration (`/etc/resolv.conf`) —
    /// in Lambda, the VPC resolver the platform provides.
    pub fn from_system() -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|e| format!("reading the system resolver configuration: {e}"))?;
        Self::apply_options(builder.options_mut());
        let inner = builder
            .build()
            .map_err(|e| format!("building the resolver: {e}"))?;
        Ok(Self { inner })
    }

    /// A resolver over explicit nameservers, each reached over UDP with TCP
    /// fallback. For development and for forcing a resolver in tests; the
    /// addresses come from the operator's environment, never from a request.
    pub fn with_servers(servers: &[IpAddr]) -> Result<Self, String> {
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            servers
                .iter()
                .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                .collect(),
        );
        let mut builder = TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        );
        Self::apply_options(builder.options_mut());
        let inner = builder
            .build()
            .map_err(|e| format!("building the resolver: {e}"))?;
        Ok(Self { inner })
    }

    fn apply_options(options: &mut hickory_resolver::config::ResolverOpts) {
        // Two attempts of two seconds fit inside the 5-second bound of §8
        // that `txt` enforces around the whole lookup.
        options.timeout = Duration::from_secs(2);
        options.attempts = 2;
        // Keep the CNAME/DNAME chain in the answer: the redirection limit of
        // §5.5 is counted over it, and stripped intermediates would make the
        // limit unenforceable.
        options.preserve_intermediates = true;
    }
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ResolveError> {
        // Fully qualified, so the search-domain machinery of a system
        // configuration can never rewrite the name being certified.
        let fqdn = format!("{name}.");

        let lookup = tokio::time::timeout(
            RESOLVE_TIMEOUT,
            self.inner.lookup(fqdn.as_str(), RecordType::TXT),
        )
        .await
        .map_err(|_| {
            ResolveError::Failed(format!("no answer within {}s", RESOLVE_TIMEOUT.as_secs()))
        })?
        .map_err(|e| {
            if e.is_no_records_found() {
                // NXDOMAIN and NODATA: the zone answered. §5.5 calls this
                // *absent*, and the distinction is load-bearing.
                ResolveError::NoRecords
            } else {
                ResolveError::Failed(e.to_string())
            }
        })?;

        let records = lookup.answers();

        // §5.5(4): at most 8 redirections. A recursive upstream follows the
        // chain and returns it; refusing a longer one here keeps the bound
        // true whatever the upstream's own limit is. DNAME (39) has no named
        // variant in hickory, so it arrives as `Unknown(39)` — and a recursor
        // that applied one also synthesized the CNAME that is counted anyway.
        const DNAME: RecordType = RecordType::Unknown(39);
        let redirections = records
            .iter()
            .filter(|r| matches!(r.record_type(), RecordType::CNAME | DNAME))
            .count();
        if redirections > MAX_REDIRECTIONS {
            return Err(ResolveError::Failed(format!(
                "{redirections} CNAME/DNAME redirections; at most {MAX_REDIRECTIONS} are followed"
            )));
        }

        // §8: bounded examination. Records beyond the caps are not examined,
        // and an anonymous caller chose the name, so the caps are the work
        // ceiling. Character-strings concatenate with no separator (RFC 7208
        // §3.3); bytes that are not UTF-8 are kept lossily — they can never
        // match §3.2's ASCII syntax where it matters, but a record whose only
        // oddity sits in an ignored unknown tag must still be matchable.
        let mut out = Vec::new();
        let mut budget = MAX_TXT_BYTES;
        for record in records {
            if out.len() == MAX_TXT_RECORDS {
                break;
            }
            let RData::TXT(txt) = &record.data else {
                continue;
            };
            let mut data = Vec::new();
            for part in &txt.txt_data {
                data.extend_from_slice(part);
            }
            if data.len() > budget {
                break;
            }
            budget -= data.len();
            out.push(String::from_utf8_lossy(&data).into_owned());
        }

        if out.is_empty() {
            // A chain that ends in no TXT record is an answer with nothing in
            // it, however it was transported.
            return Err(ResolveError::NoRecords);
        }
        Ok(out)
    }
}

/// A resolver that answers from a map. Tests describe the DNS they need;
/// nothing resolves.
#[derive(Default)]
pub struct StaticResolver {
    answers: HashMap<String, Result<Vec<String>, ResolveError>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// A name that answers with these records.
    pub fn observed(mut self, name: &str, records: &[&str]) -> Self {
        self.answers.insert(
            name.to_string(),
            Ok(records.iter().map(|r| r.to_string()).collect()),
        );
        self
    }

    /// A name that fails with this error.
    pub fn failing(mut self, name: &str, error: ResolveError) -> Self {
        self.answers.insert(name.to_string(), Err(error));
        self
    }
}

#[async_trait]
impl Resolver for StaticResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ResolveError> {
        // An unlisted name answers empty: the test described a world and this
        // name is not in it — which is what a real zone says about a name
        // nobody declared.
        self.answers
            .get(name)
            .cloned()
            .unwrap_or(Err(ResolveError::NoRecords))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_static_resolver_answers_what_it_was_told() {
        // Through `Domain::query_name`, so the underscored name is spelled in
        // exactly one place in the workspace.
        let name = |raw: &str| {
            registry_core::Domain::parse(raw)
                .expect("test domain")
                .query_name()
        };
        let resolver = StaticResolver::new()
            .observed(&name("acme.com"), &["v=A2A1; k=abc"])
            .failing(&name("acme.fr"), ResolveError::Failed("SERVFAIL".into()));

        assert_eq!(
            resolver.txt(&name("acme.com")).await.unwrap(),
            vec!["v=A2A1; k=abc".to_string()]
        );
        assert!(matches!(
            resolver.txt(&name("acme.fr")).await,
            Err(ResolveError::Failed(_))
        ));
        assert_eq!(
            resolver.txt(&name("unheard-of.example")).await,
            Err(ResolveError::NoRecords)
        );
    }

    /// Live resolution, deliberately `#[ignore]`d: the offline suite must not
    /// depend on the network. Run with `cargo test -p aithos-registry-dns --
    /// --ignored` from a machine with working DNS.
    #[tokio::test]
    #[ignore = "resolves real names over the network"]
    async fn the_real_resolver_distinguishes_answers_from_absence() {
        let resolver = HickoryResolver::from_system().expect("system resolver");

        // A name with a famously non-empty TXT record set.
        let records = resolver.txt("google.com").await.expect("google.com TXT");
        assert!(!records.is_empty());

        // `.invalid` is reserved (RFC 2606): the root answers NXDOMAIN, which
        // is an answer, not a failure. The name is spelled through the
        // constant so the underscored label exists in one place only.
        assert_eq!(
            resolver
                .txt(&format!("{}.nothing.invalid", registry_core::DNS_LABEL))
                .await,
            Err(ResolveError::NoRecords)
        );
    }
}
