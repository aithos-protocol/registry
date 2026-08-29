# Audit — round 11

**Method:** one independent auditor, blind, fresh context, across the whole
stack — write admission, JWS/JWK, canonicalization, convergence machinery,
IAM and edge configuration, CI and release workflows, and the CLI — weighted
by its own judgement. Told that recent rounds found no MAJOR and that a clean
report was a plausible outcome. Ran on the tree after the 2026-08-29
repository audit's fixes (verify-by-URL, transport-error hint, attested
lambda artifact in CI, scheduled cargo-deny, budget ACTUAL, MSRV alignment).

---

## Verdict

**No major defect.** The write-admission logic (card-signature verification,
proof-set == signer-set, genesis and lineage rules, version monotonicity,
digest no-op), the JWS/JWK layer (algorithm confusion, `alg:none`, key
substitution, Ed25519 identity point and small orders, RSA zero-padding), the
canonicalization path (RFC 8785 vectors plus a differential check against a
second implementation), the two-writer convergence machinery, the IAM grants
and the edge gate all held under call-by-call checking and execution.
`cargo test --all`, `clippy --all-targets -- -D warnings`, `fmt --check`,
`terraform fmt -check` and `validate` all pass. Read-only live probes matched
the spec everywhere probed — and confirmed independently that the deployed
dev build is older than this tree (its manifest names a repository path this
tree no longer contains, and it still serves the percent-encoded version URL
the current code refuses), which is the repository audit's C1 seen from the
outside.

## Major findings

None.

## Minor findings

- **m1** `as_problem` mapped every framework-generated 400 to `JSON_INVALID`,
  but a rejected query string (`GET /v1/agents?limit=abc`) never reaches the
  JSON layer — §9 scopes `JSON_INVALID` to the request *body*, so the answer
  blamed a body that was never at fault. Confirmed by execution against the
  in-process router. Fixed: framework 400s fall to `REQUEST_REFUSED`, the §9
  catch-all; the body paths keep building their own problems first.

## Checked and sound

RFC 8785 vectors and the A2A §8.4.1 worked example by execution; the strict
parser at the I-JSON boundaries (2^53, big-integer-to-double, subnormals as
documented); the `jku` validator against sixteen adversarial inputs; the
presence table byte-for-byte against the pinned proto and its live digest;
the full write/rotation/withdrawal/replay rule set including the round-2
regressions; HTTP semantics (strict envelope, pre-parse size limit, bounded
issue collection, validator comparisons, one-URL-per-version, withdrawn
serves neither, `createdAt` preservation); the reconciler's convergence,
resurrection-window double-read and fail-closed orderings; the AWS store's
conditional transactions, idempotency token and cursor guards; the CLI's
keyfile JWE, iteration ceiling, IV guard, anchor exit-code semantics and
bounded fetches; Terraform IAM, WAF and alarms; read-only live probes of the
active and withdrawn entries, listing, forged cursors, and the edge gate.
The RSA public exponent's byte length is unbounded at parse time; with the
modulus cap and verify-time checks it is a non-issue and no action is taken.
