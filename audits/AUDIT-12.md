# Audit — round 12

**Method:** one independent auditor, blind, fresh context — a production
go/no-go validation round across the whole stack, told that round 11 found no
MAJOR and instructed to either confirm that with its name on it or break it.
Weighted by its own judgement; verification by execution throughout; live
probes strictly read-only.

---

## Verdict

Attacked the write-admission and publication-proof construction, the JWS/JWK
crypto, RFC 8785 canonicalization and strict parsing, the read-path
convergence machinery, the AWS store, the HTTP surface, the
IAM/WAF/CloudFront/alarm infrastructure, the CI/release pipelines, and the
CLI's key custody — by execution wherever possible — and found no defect that
rises to MAJOR, and nothing substantiated as a genuine minor defect either.
Nearly every subtle hazard is not only handled but pinned by a test that
would fail if the handling regressed.

## Major findings

None. Specifically tried and failed: publication-proof forgery and entry
pre-emption (the one-proof-per-signer, set-equality, genesis-or-authorized,
registry+agent+digest-bound rule closes the scraped-card, appended-signature,
cross-registry and cross-card replays); algorithm confusion, `alg:none`,
Ed25519 small orders, RSA zero-padding; canonicalization divergence (official
vectors including the UTF-16 surrogate ordering case, differential check
against a second implementation, nested duplicate members, the ±2^53 gate);
resurrection of a withdrawn entry through the two-writer machinery (seq
stamps, the pre-write re-read, both fail-closed orderings); anonymous
cost/availability (512 KiB pre-parse cap on both paths, bounded issue
collection, the three WAF rules with the read limit below the stage
throttle).

## Minor findings

None substantiated. Three deliberate, documented tradeoffs re-examined and
left as decided: the client-side `jku` fetch (an operator tool, equivalent to
curl), the stage throttle shared with the one uncached read projection
(mitigated by the read limit), and `NEW_IMAGE` on a stream whose consumer
ignores the image (efficiency only — `KEYS_ONLY` would shave a copy).

## Checked and sound

Full suite green, clippy `-D warnings` clean, fmt clean, `terraform
fmt`/`validate` clean. The presence table checked message-by-message against
the pinned proto, digest pinned by test and served live. Error-code mapping
matches §9 exactly, framework-shaped refusals included. Conditional
transactions, idempotency token, cursor guards, consistent reads; the memory
store mirrors the same contract. IAM least-privilege and append-only;
CloudFront behaviour ordering, conditional-header handling, edge secret in
constant time, only 404 reshaped. CI/release pin the toolchain, build the
Lambda natively on arm64 with an architecture assertion, attest provenance,
first-party actions only on the key-handling path. CLI key custody: 0600 via
`create_new`, standard PBES2/A256GCM with authenticated header and iteration
ceiling, zeroized scalar, path-traversal refusal, atomic writes only after
acceptance.

## Go / no-go

Given only what the repository controls — code, infrastructure as written,
and pipelines — nothing in it should block a production go-live.
