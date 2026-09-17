//! `openapi.json` describes this service; these tests are why that stays true.
//!
//! The document is written by hand, for the same reason the field-presence
//! table of `SPEC.md` §5.2 is: a description generated from an implementation
//! documents that implementation, mistakes included, and stops being a second
//! opinion about what the protocol says. What a hand-written description costs is drift, and
//! drift is silent — nobody notices a route that is missing from a document
//! until a client generated from it cannot call it.
//!
//! So the document is checked against four other things, each of which is the
//! authority on its own part:
//!
//! - the router, for which operations exist;
//! - the catalogue, for the problem codes;
//! - `SPEC.md` §9 and `DOMAIN-CERTIFICATION.md` §11, for what those codes are
//!   normatively said to be;
//! - the pages under `site/`, for what is actually published at the `type` URI
//!   every problem document carries.
//!
//! Three of these read source or markdown as text rather than as data. That is
//! deliberate and worth naming: axum exposes no list of registered routes, and
//! the two `Code` enums expose no iterator over their variants, so a test that
//! wanted to compare against them would have to hold its own copy — which is
//! one more list to drift. Reading the definition is uglier and cannot go
//! quietly stale.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use registry_api::catalog::{CATALOG, render_index, render_page};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn openapi() -> Value {
    let path = repo_root().join("openapi.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).expect("openapi.json is not valid JSON")
}

// --- the router ----------------------------------------------------------

/// Every `(METHOD, path)` the router registers, read from its own source.
///
/// `.route("<path>", get(h).put(h))` — the path is the first string literal of
/// the call, the methods are the `name(` heads that follow it.
fn router_operations() -> BTreeSet<(String, String)> {
    const SOURCE: &str = include_str!("../src/api.rs");
    const VERBS: [&str; 6] = ["get", "put", "post", "delete", "patch", "head"];

    let mut found = BTreeSet::new();
    for start in SOURCE.match_indices(".route(").map(|(i, _)| i) {
        // The router's own commentary talks about `.route()`. A line that is a
        // comment is not a registration, and treating it as one would make this
        // test fail on prose.
        let line_start = SOURCE[..start].rfind('\n').map_or(0, |i| i + 1);
        if SOURCE[line_start..start].trim_start().starts_with("//") {
            continue;
        }
        let rest = &SOURCE[start..];
        // The call ends at the first `)` that closes it; the arguments hold no
        // unbalanced parenthesis, and no string literal in them contains one.
        let mut depth = 0usize;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let call = &rest[..end];

        let open = call
            .find('"')
            .expect("a route registration with no path literal");
        let close = open + 1 + call[open + 1..].find('"').expect("unterminated path");
        let path = &call[open + 1..close];
        let handlers = &call[close..];

        for verb in VERBS {
            // `get(` as a whole word, so `widget(` never counts as `get(`.
            let needle = format!("{verb}(");
            let mut from = 0;
            while let Some(i) = handlers[from..].find(&needle) {
                let at = from + i;
                let preceded_by_word = at > 0
                    && handlers[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if !preceded_by_word {
                    found.insert((verb.to_ascii_uppercase(), shape(path)));
                }
                from = at + needle.len();
            }
        }
    }
    assert!(
        found.len() > 5,
        "parsed {} routes from api.rs — the parser, not the router, is what broke",
        found.len()
    );
    found
}

/// A path with its parameter names erased: `/v1/agents/{agent_id}` and
/// `/v1/agents/{agentId}` are the same URL shape.
///
/// They are compared this way because the two names are not meant to be equal.
/// axum's is a Rust binding, snake_case by its own convention; the document's
/// is what a reader and a generated client see, camelCase like every other
/// member of this API. What must correspond is the operation, not the spelling
/// of a local variable — and `openapi_paths_declare_their_own_parameters`
/// below is what keeps the document's own names honest.
fn shape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for c in path.chars() {
        match c {
            '{' => {
                depth += 1;
                out.push_str("{}");
            }
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn document_operations(doc: &Value) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, _) in item.as_object().expect("path item") {
            if method == "parameters" {
                continue;
            }
            found.insert((method.to_ascii_uppercase(), shape(path)));
        }
    }
    found
}

#[test]
fn every_route_is_described_and_every_description_is_a_route() {
    let router = router_operations();
    let document = document_operations(&openapi());

    let undocumented: Vec<_> = router.difference(&document).collect();
    let invented: Vec<_> = document.difference(&router).collect();

    assert!(
        undocumented.is_empty(),
        "these operations exist and openapi.json does not describe them: {undocumented:?}"
    );
    assert!(
        invented.is_empty(),
        "openapi.json describes these operations and the router has no such route: {invented:?}"
    );
}

// --- the problem codes ---------------------------------------------------

fn documented_codes(doc: &Value) -> BTreeSet<String> {
    doc["components"]["schemas"]["ProblemCode"]["enum"]
        .as_array()
        .expect("ProblemCode.enum")
        .iter()
        .map(|v| v.as_str().expect("a code").to_string())
        .collect()
}

fn catalogue_codes() -> BTreeSet<String> {
    CATALOG.iter().map(|d| d.code.to_string()).collect()
}

#[test]
fn openapi_lists_exactly_the_catalogue() {
    let documented = documented_codes(&openapi());
    let catalogued = catalogue_codes();
    assert_eq!(
        documented,
        catalogued,
        "openapi.json's ProblemCode and the catalogue disagree; missing from the document: {:?}, missing from the catalogue: {:?}",
        catalogued.difference(&documented).collect::<Vec<_>>(),
        documented.difference(&catalogued).collect::<Vec<_>>(),
    );
}

/// Codes an error enum can produce, read from its `as_str` arms.
fn enum_codes(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (i, _) in source.match_indices("=> \"") {
        let rest = &source[i + 4..];
        if let Some(end) = rest.find('"') {
            let literal = &rest[..end];
            if !literal.is_empty()
                && literal
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
            {
                found.insert(literal.to_string());
            }
        }
    }
    found
}

#[test]
fn the_catalogue_explains_every_code_the_crates_can_emit() {
    let catalogued = catalogue_codes();
    let mut emittable = enum_codes(include_str!("../../registry-core/src/error.rs"));
    emittable.extend(enum_codes(include_str!("../../a2a-card/src/error.rs")));
    assert!(
        emittable.len() > 15,
        "read {} codes from the error enums — the reader is what broke",
        emittable.len()
    );

    let unexplained: Vec<_> = emittable.difference(&catalogued).collect();
    assert!(
        unexplained.is_empty(),
        "these codes can be returned and have no catalogue entry, so their `type` URI would 404: {unexplained:?}"
    );
}

// --- the specification ---------------------------------------------------

/// `| 410 | `WITHDRAWN` | … |` rows, from a markdown problem table.
fn spec_table(markdown: &str) -> BTreeMap<String, u16> {
    let mut found = BTreeMap::new();
    for line in markdown.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 3 {
            continue;
        }
        let Ok(status) = cells[0].parse::<u16>() else {
            continue; // the header, the rule, and the one row whose status is `—`
        };
        let code = cells[1].trim_matches('`');
        if code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            found.insert(code.to_string(), status);
        }
    }
    found
}

#[test]
fn the_catalogue_agrees_with_the_specification() {
    let root = repo_root();
    let mut normative = spec_table(&read(&root.join("SPEC.md")));
    normative.extend(spec_table(&read(&root.join("DOMAIN-CERTIFICATION.md"))));
    assert!(
        normative.len() > 25,
        "read {} rows from the specification tables — the reader is what broke",
        normative.len()
    );

    let catalogued: BTreeMap<String, u16> = CATALOG
        .iter()
        .map(|d| (d.code.to_string(), d.status))
        .collect();

    // `REQUEST_REFUSED` is the one row §9 gives no status: it is the fallthrough.
    let mut missing = Vec::new();
    let mut wrong = Vec::new();
    for (code, status) in &normative {
        match catalogued.get(code) {
            None => missing.push(code.clone()),
            Some(ours) if ours != status => {
                wrong.push(format!("{code}: §9 says {status}, catalogue says {ours}"))
            }
            _ => {}
        }
    }
    assert!(
        missing.is_empty(),
        "specified with no catalogue entry: {missing:?}"
    );
    assert!(wrong.is_empty(), "status disagreements: {wrong:?}");

    let unspecified: Vec<_> = catalogued
        .keys()
        .filter(|c| !normative.contains_key(*c) && *c != "REQUEST_REFUSED")
        .collect();
    assert!(
        unspecified.is_empty(),
        "catalogued but in neither problem table, so the specification does not say these exist: {unspecified:?}"
    );
}

// --- the published pages -------------------------------------------------

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn every_type_uri_resolves_to_a_committed_page() {
    let problems = repo_root().join("site/problems");
    let mut stale = Vec::new();

    for doc in CATALOG {
        let path = problems.join(doc.slug());
        if !path.exists() {
            stale.push(format!("{} (missing)", doc.slug()));
            continue;
        }
        if read(&path) != render_page(doc) {
            stale.push(doc.slug());
        }
    }
    let index = problems.join("index.html");
    if !index.exists() || read(&index) != render_index() {
        stale.push("index.html".into());
    }

    assert!(
        stale.is_empty(),
        "these pages are not what the catalogue renders — run `cargo run -p registry-api --example gen-site`: {stale:?}"
    );

    // The other direction: a page for a code that no longer exists would be
    // served at a `type` URI nothing produces.
    let slugs: BTreeSet<String> = CATALOG.iter().map(|d| d.slug()).collect();
    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(&problems).expect("site/problems") {
        let name = entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name != "index.html" && !slugs.contains(&name) {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "pages for codes that no longer exist: {orphans:?}"
    );
}

#[test]
fn openapi_paths_declare_their_own_parameters() {
    let doc = openapi();
    let mut undeclared = Vec::new();

    for (path, item) in doc["paths"].as_object().expect("paths") {
        // Declared on the path item, or on the operation. Both are legal, and
        // this document uses the first.
        let mut declared = BTreeSet::new();
        let mut collect = |value: &Value| {
            for parameter in value.as_array().into_iter().flatten() {
                let resolved = match parameter["$ref"].as_str() {
                    Some(reference) => {
                        let name = reference.rsplit('/').next().expect("a component name");
                        doc["components"]["parameters"][name].clone()
                    }
                    None => parameter.clone(),
                };
                if resolved["in"] == "path"
                    && let Some(name) = resolved["name"].as_str()
                {
                    declared.insert(name.to_string());
                }
            }
        };
        collect(&item["parameters"]);
        for (method, operation) in item.as_object().expect("path item") {
            if method != "parameters" {
                collect(&operation["parameters"]);
            }
        }

        for segment in path.split('/') {
            if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
                && !declared.contains(name)
            {
                undeclared.push(format!(
                    "{path} uses {{{name}}} and declares no such parameter"
                ));
            }
        }
    }

    assert!(undeclared.is_empty(), "{undeclared:?}");
}
