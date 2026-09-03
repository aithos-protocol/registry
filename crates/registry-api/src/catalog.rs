//! The problem catalogue: one entry per code of `SPEC.md` §9 and
//! `DOMAIN-CERTIFICATION.md` §11.
//!
//! Every problem document carries `"type": "/problems/{slug}"`, and RFC 9457
//! §3.1.1 says that URI, dereferenced, *should* give human-readable
//! documentation for the code. It did not: the registry answered every refusal
//! with a URI that resolved to `404`, which is the one place the API already
//! promised documentation and the one place it had none.
//!
//! This table is what those pages are generated from, so a code cannot be
//! published without the page that explains it. It is the same table three
//! other things are checked against — `openapi.json`, the `Code` enums of
//! `registry-core` and `a2a-card`, and the markdown tables of §9 and §11 — by
//! `tests/openapi.rs`. Adding a code in one place and not the others fails the
//! offline suite.
//!
//! `status` is the status the specification pairs with the code, not whatever
//! a call site happened to pass. Where the two disagree the specification is
//! right and the call site is the defect, which is exactly what the test says.

/// One code, and what a person who landed on its page needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProblemDoc {
    pub code: &'static str,
    pub status: u16,
    /// The `title` member of the problem document.
    pub title: &'static str,
    /// What the registry is saying.
    pub meaning: &'static str,
    /// What the caller does about it. Never "contact support": there is no
    /// operator to contact, which is the whole design.
    pub remedy: &'static str,
}

impl ProblemDoc {
    /// The kebab-case slug in the `type` URI, matching `Problem::slug`.
    pub fn slug(&self) -> String {
        self.code.to_ascii_lowercase().replace('_', "-")
    }
}

pub fn lookup(code: &str) -> Option<&'static ProblemDoc> {
    CATALOG.iter().find(|d| d.code == code)
}

pub const CATALOG: &[ProblemDoc] = &[
    ProblemDoc {
        code: "JSON_INVALID",
        status: 400,
        title: "Invalid JSON",
        meaning: "The body is not valid I-JSON, or it repeats a member. Parsing is strict because a document that two parsers read differently cannot be canonicalized to one set of bytes, and the signature is over those bytes.",
        remedy: "Send I-JSON with no duplicate member.",
    },
    ProblemDoc {
        code: "PRIVATE_KEY_SUBMITTED",
        status: 400,
        title: "Private key material submitted",
        meaning: "A JWK in the request carried private material. The registry has no use for one and never stores one.",
        remedy: "Send the public JWK only. Treat the key you sent as exposed and rotate it: co-sign one version with the old key and a new one, then publish again signed by the new key alone.",
    },
    ProblemDoc {
        code: "NOT_AUTHORIZED_KEY",
        status: 403,
        title: "Not signed by an authorized key",
        meaning: "No signature came from a key in the entry's current authorized set. There is no operator who can override this, and no account recovery: the key is the account.",
        remedy: "Sign with a key listed in the entry's JWKS. If every authorized key is lost, the entry cannot be changed by anyone, ever — which is why a second key is registered before it is needed.",
    },
    ProblemDoc {
        code: "NOT_FOUND",
        status: 404,
        title: "Not found",
        meaning: "No such entry. On the card and key-set paths this also answers for a withdrawn entry, because withdrawal deletes the published object rather than leaving a tombstone.",
        remedy: "Read the record at `/v1/agents/{agentId}` when the difference between withdrawn and never-published matters; it states the status plainly.",
    },
    ProblemDoc {
        code: "AGENT_ID_MISMATCH",
        status: 409,
        title: "Identifier does not match the signing key",
        meaning: "The `agentId` in the path equals no signing `kid`. An identifier is the RFC 7638 thumbprint of the genesis key, so a mismatch means the request is addressed to an entry these keys do not control.",
        remedy: "Publish to the thumbprint of the key that signed, or sign with the key that owns the address.",
    },
    ProblemDoc {
        code: "VERSION_NOT_INCREASING",
        status: 409,
        title: "Card version does not move forward",
        meaning: "The card's `version` is not strictly greater than the published one. Identical bytes at the same version succeed and change nothing; different bytes at the same version are this.",
        remedy: "Raise the version before signing — `aithos publish … --bump patch` does it.",
    },
    ProblemDoc {
        code: "WITHDRAWN",
        status: 410,
        title: "Entry was withdrawn",
        meaning: "The key holder withdrew this entry. Withdrawal is terminal and the identifier is never reusable, so nothing will ever be published here again.",
        remedy: "Nothing restores it. Published versions remain readable at their digest; a new entry means a new key and a new address.",
    },
    ProblemDoc {
        code: "PRECONDITION_FAILED",
        status: 412,
        title: "Precondition failed",
        meaning: "The `If-Match` digest is not the current one, so the version you meant to replace is no longer the version that is published.",
        remedy: "Re-read the record, decide against what is actually there, and retry.",
    },
    ProblemDoc {
        code: "CARD_TOO_LARGE",
        status: 413,
        title: "Agent Card is too large",
        meaning: "The request body or the card exceeds the limit of §8. The body limit is checked before parsing, and so before any signature is verified: everything after it costs memory and CPU proportional to the input, and an anonymous caller reaches all of it.",
        remedy: "Card 256 KiB, request body 512 KiB. The manifest at `/v1/registry` carries the current values.",
    },
    ProblemDoc {
        code: "CARD_INVALID",
        status: 422,
        title: "Agent Card is invalid",
        meaning: "The card violates the pinned A2A schema. The `pointer` member names the offending location.",
        remedy: "`aithos card check <file>` reports the same issue locally, before you sign anything.",
    },
    ProblemDoc {
        code: "PRESENCE_INVALID",
        status: 422,
        title: "Field presence rules were not applied",
        meaning: "The card breaks the field-presence rules of §5.2 — the table derived by hand from the pinned `a2a.proto`, whose digest is in the manifest. Two implementations reading the same commit can still disagree about one field, and that yields two canonical documents and two signatures over what looks like the same card.",
        remedy: "Compare your digest of the presence table with the one in `/v1/registry`. `aithos card check` applies the same rules.",
    },
    ProblemDoc {
        code: "SIGNATURE_INVALID",
        status: 422,
        title: "Signature is invalid",
        meaning: "A JWS failed verification against the key its `kid` names.",
        remedy: "Check that the signed bytes are `BASE64URL(UTF8(JCS(…)))` of what you meant to sign — canonicalization applied after signing is the usual cause.",
    },
    ProblemDoc {
        code: "KID_NOT_THUMBPRINT",
        status: 422,
        title: "Key identifier is not the key's thumbprint",
        meaning: "A `kid` is not the RFC 7638 thumbprint of the key that verifies its signature. This single rule carries the whole authorization design: the thumbprint is a digest of the key material, so a public key submitted in a plain request body cannot be swapped for another.",
        remedy: "Compute `kid` from the key rather than choosing it.",
    },
    ProblemDoc {
        code: "ALG_NOT_ALLOWED",
        status: 422,
        title: "Algorithm is not allowed",
        meaning: "The `alg` in a protected header is outside the allowlist.",
        remedy: "Use `ES256`, `EdDSA` or `RS256`. The manifest lists what this registry accepts.",
    },
    ProblemDoc {
        code: "UNUSED_KEY",
        status: 422,
        title: "A submitted key signs nothing",
        meaning: "A JWK in `keys` is referenced by no signature. The published key set is the set that signed, so a key that signed nothing has no business in it.",
        remedy: "Send only the keys that actually signed.",
    },
    ProblemDoc {
        code: "TOO_MANY_KEYS",
        status: 422,
        title: "Too many keys submitted",
        meaning: "More JWKs than §8 allows.",
        remedy: "Eight per request. Widening an authorized set beyond that is a sign the set is being used as a directory rather than as a set of holders.",
    },
    ProblemDoc {
        code: "DUPLICATE_KEY",
        status: 422,
        title: "The same key was submitted twice",
        meaning: "Two entries in `keys` are the same key.",
        remedy: "Deduplicate. A key counts once however many times it is sent.",
    },
    ProblemDoc {
        code: "KEY_INVALID",
        status: 422,
        title: "A submitted key is malformed",
        meaning: "A JWK is structurally invalid, or its parameters are out of range — an RSA modulus outside 2048–4096 bits, for instance.",
        remedy: "Emit the JWK from a library rather than by hand.",
    },
    ProblemDoc {
        code: "UNPROVEN_KEY",
        status: 422,
        title: "A signing key did not ask for this publication",
        meaning: "A key signed the card but produced no publication proof. This is not bookkeeping: a card's signing payload is public the moment the card is published, so anyone can append a signature to someone else's card without invalidating the original. Were one proof enough, an attacker could open an entry in their own name whose published key set names a holder who never asked for it.",
        remedy: "One proof per key entering the authorized set — the set of proof signers must equal the set of card signers.",
    },
    ProblemDoc {
        code: "CURSOR_INVALID",
        status: 400,
        title: "Pagination cursor is not valid",
        meaning: "The cursor did not come from this registry, or it names an entry the registry no longer holds. Answering the first page instead would silently restart a listing a client believed it was continuing.",
        remedy: "Start the listing again without a cursor.",
    },
    ProblemDoc {
        code: "CONFLICT",
        status: 409,
        title: "The agent changed concurrently",
        meaning: "Another write landed between the snapshot this request was evaluated against and the commit. The two invariants of §6 are checked against a snapshot, so committing them is conditional on that snapshot still being current.",
        remedy: "Re-read and retry. Nothing was written.",
    },
    ProblemDoc {
        code: "METHOD_NOT_ALLOWED",
        status: 405,
        title: "Method not allowed",
        meaning: "The method is not defined for this path.",
        remedy: "See `/v1/openapi.json` for what each path accepts.",
    },
    ProblemDoc {
        code: "INTERNAL",
        status: 500,
        title: "The registry could not complete this request",
        meaning: "A failure inside the registry. The detail is deliberately vague here and specific in the log: naming tables and indexes in a public response describes the inside of the service to anyone who provokes an error.",
        remedy: "Retry. Nothing was committed — writes are conditional, so a failure is not a partial write.",
    },
    ProblemDoc {
        code: "RATE_LIMITED",
        status: 429,
        title: "Too many requests",
        meaning: "Too many requests from this address, or against this agent. This one arrives with media type `application/json` rather than `application/problem+json`: the edge firewall's body types do not include the latter and it refuses a header overriding the content type. A client keying on `code` reads it; one keying on the media type alone does not.",
        remedy: "Back off and retry. Publication is rare by design — a few people, a few times a year.",
    },
    ProblemDoc {
        code: "FORBIDDEN",
        status: 403,
        title: "Not reachable this way",
        meaning: "The request did not arrive through the registry's public hostname. The API origin is not a public entrance.",
        remedy: "Use the canonical origin, which the manifest states.",
    },
    ProblemDoc {
        code: "REQUEST_REFUSED",
        status: 400,
        title: "Request refused",
        meaning: "A refusal with no more specific code. Seeing this is worth reporting: §9 is meant to be exhaustive, and a refusal that falls through to it is a gap in the table rather than a fact about your request.",
        remedy: "Open an issue with the request shape that produced it.",
    },
    ProblemDoc {
        code: "DOMAIN_SYNTAX_INVALID",
        status: 422,
        title: "Domain syntax is invalid",
        meaning: "A domain is not a lowercase A-label. U-labels, uppercase and trailing dots are all refused rather than normalized, because normalizing would mean the registry certified a name the key holder did not sign.",
        remedy: "Convert to A-label form (punycode) and lowercase before signing.",
    },
    ProblemDoc {
        code: "DOMAIN_IS_PUBLIC_SUFFIX",
        status: 422,
        title: "Domain is a public suffix",
        meaning: "The domain is a public suffix, such as `co.uk`. Certifying one would state that an agent holds a namespace shared by everyone under it.",
        remedy: "Certify a name you register, one label below the suffix.",
    },
    ProblemDoc {
        code: "DOMAINS_NOT_CANONICAL",
        status: 422,
        title: "Domain list is not sorted",
        meaning: "`domains` is unsorted or holds a duplicate. JCS orders object members but not array elements, so array order is signed as submitted; requiring one order makes the payload a deterministic function of the set.",
        remedy: "Sort ascending by code point and deduplicate before signing.",
    },
    ProblemDoc {
        code: "TOO_MANY_DOMAINS",
        status: 422,
        title: "Too many domains",
        meaning: "More domains than the profile allows.",
        remedy: "Eight per entry. The manifest carries the current limit.",
    },
    ProblemDoc {
        code: "CERTIFICATION_NOT_INCREASING",
        status: 409,
        title: "Certification does not move forward",
        meaning: "`issuedAt` is not strictly greater than the last accepted certification, so this request is a replay or lost a race.",
        remedy: "Re-issue with a current timestamp.",
    },
    ProblemDoc {
        code: "DNS_RECORD_ABSENT",
        status: 422,
        title: "DNS record absent",
        meaning: "The name resolved, and no TXT record at `_a2a.<domain>` named this agent. Nothing was written: a certification the registry cannot observe is not one it will publish. The `domains` member reports the outcome for every domain in the request, so four domains do not have to be bisected to find the one that failed.",
        remedy: "Publish `_a2a.<domain>. IN TXT \"v=A2A1; k=<agentId>\"` in that zone, wait for it to propagate, and run the command again — it reads DNS from your own machine first and tells you before sending anything.",
    },
    ProblemDoc {
        code: "DNS_UNRESOLVED",
        status: 422,
        title: "DNS resolution failed",
        meaning: "`SERVFAIL`, a timeout, or a resolution limit reached. Separate from an absent record because nothing can be concluded: the record may well be there. A single code for both would make the command line guess.",
        remedy: "Retry. A transient failure does not un-ask a certification — the hourly pass restores a domain by itself once its record resolves again.",
    },
];

// --- the published pages -------------------------------------------------
//
// Rendered here rather than in the generator, so the offline suite can assert
// that the files checked into `site/problems/` are what this catalogue
// produces. The generator (`examples/gen-site.rs`) only writes them out.
//
// Plain HTML with an inline stylesheet: these are served from the object store
// with no build step, and a page explaining why a request failed is a poor
// place to depend on a script loading.

const STYLE: &str = "\
:root{color-scheme:light dark;--fg:#16181d;--dim:#5b6270;--bg:#fbfbfa;--card:#fff;--line:#e4e4e1;--accent:#8a3d1e}\
@media(prefers-color-scheme:dark){:root{--fg:#e8e8e6;--dim:#9aa1ae;--bg:#16181d;--card:#1d2027;--line:#2c313a;--accent:#e0a080}}\
*{box-sizing:border-box}\
body{margin:0;padding:3rem 1.25rem;background:var(--bg);color:var(--fg);\
font:16px/1.65 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}\
main{max-width:44rem;margin:0 auto}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;\
background:var(--card);border:1px solid var(--line);border-radius:4px;padding:.1em .35em}\
.status{display:inline-block;font-family:ui-monospace,monospace;font-size:.8rem;letter-spacing:.04em;\
color:var(--accent);border:1px solid var(--line);border-radius:999px;padding:.15rem .6rem;background:var(--card)}\
h1{font-size:1.55rem;line-height:1.25;margin:.9rem 0 .3rem;font-weight:620}\
h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);\
margin:2rem 0 .4rem;font-weight:600}\
p{margin:.4rem 0}\
.code{font-family:ui-monospace,monospace;color:var(--dim);font-size:.92rem;margin:0}\
footer{margin-top:3rem;padding-top:1.25rem;border-top:1px solid var(--line);color:var(--dim);font-size:.88rem}\
a{color:inherit;text-decoration-color:var(--line);text-underline-offset:3px}\
a:hover{text-decoration-color:var(--accent)}\
ul{padding-left:0;list-style:none;margin:.5rem 0}\
li{padding:.5rem 0;border-bottom:1px solid var(--line)}\
li a{font-family:ui-monospace,monospace;font-size:.92rem}\
li span{color:var(--dim);font-size:.9rem}";

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Turn the backtick spans of the catalogue's prose into `<code>`.
fn ticks(s: &str) -> String {
    let escaped = escape(s);
    let mut out = String::with_capacity(escaped.len());
    for (i, part) in escaped.split('`').enumerate() {
        if i % 2 == 1 {
            out.push_str("<code>");
            out.push_str(part);
            out.push_str("</code>");
        } else {
            out.push_str(part);
        }
    }
    out
}

/// The page served at `/problems/{slug}`.
pub fn render_page(doc: &ProblemDoc) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{code} — Aithos Registry</title><style>{style}</style></head>\n\
<body><main>\n\
<p class=\"status\">HTTP {status}</p>\n\
<h1>{title}</h1>\n\
<p class=\"code\">{code}</p>\n\
<h2>What this means</h2>\n<p>{meaning}</p>\n\
<h2>What to do</h2>\n<p>{remedy}</p>\n\
<footer>An <a href=\"https://datatracker.ietf.org/doc/html/rfc9457\">RFC 9457</a> \
problem type of the \
<a href=\"https://aithos-protocol.github.io/registry/\">Aithos Agent Card Registry</a>. \
The normative rules are in <a href=\"https://github.com/aithos-protocol/registry/blob/main/SPEC.md\">SPEC.md</a> §9; \
the HTTP surface is described by <a href=\"/v1/openapi.json\">openapi.json</a>. \
<a href=\"/problems/\">All problem types</a>.</footer>\n\
</main></body></html>\n",
        code = escape(doc.code),
        status = doc.status,
        title = escape(doc.title),
        meaning = ticks(doc.meaning),
        remedy = ticks(doc.remedy),
        style = STYLE,
    )
}

/// The index served at `/problems/`.
pub fn render_index() -> String {
    let mut rows = String::new();
    for doc in CATALOG {
        rows.push_str(&format!(
            "<li><a href=\"/problems/{slug}\">{code}</a> <span>· {status} · {title}</span></li>\n",
            slug = doc.slug(),
            code = escape(doc.code),
            status = doc.status,
            title = escape(doc.title),
        ));
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Problem types — Aithos Registry</title><style>{STYLE}</style></head>\n\
<body><main>\n\
<h1>Problem types</h1>\n\
<p>Every refusal this registry makes is an \
<a href=\"https://datatracker.ietf.org/doc/html/rfc9457\">RFC 9457</a> document carrying one of \
these codes, and its <code>type</code> member links to the page below.</p>\n\
<p>Two refusals carry no code and must be handled by status alone: a <code>429</code> from the \
gateway's own throughput limit, and a <code>403</code> from the edge for a method a cached read \
path does not serve.</p>\n\
<ul>\n{rows}</ul>\n\
<footer>Normative in \
<a href=\"https://github.com/aithos-protocol/registry/blob/main/SPEC.md\">SPEC.md</a> §9 and \
<a href=\"https://github.com/aithos-protocol/registry/blob/main/DOMAIN-CERTIFICATION.md\">DOMAIN-CERTIFICATION.md</a> §11. \
The HTTP surface is described by <a href=\"/v1/openapi.json\">openapi.json</a>.</footer>\n\
</main></body></html>\n"
    )
}
