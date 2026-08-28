# Audit — round 8

**Method:** one independent auditor, blind, pointed first at *error, failure and
reporting paths everywhere* — since the last several defects here have been in
what the code does when something below it fails, not in what it does when it
succeeds — and told that a report with no MAJOR findings was an expected
outcome.

**Cross-check.** The convergence machinery came back clean for the first time:
every interleaving the auditor could construct is handled, every call has a
grant, and no function returns `Ok` to mean "I could not do this". The one MAJOR
is a contradiction *created by the round-7 m8 fix*, which made §9 absolute —
"every refusal is a problem document" — without the deployment being able to
honour it at the edge.

---

## Verdict

The convergence machinery, the write-admission rules, the IAM grants and the
CloudFront behaviour ordering all hold up. The one MAJOR lives entirely outside
the Rust: the two refusal paths the design leans on hardest — WAF rate blocking
and the gateway throttle — return non-2xx responses carrying no `code`, which §9
states absolutely that a client may rely on. Everything else is bounded.

## Major findings

### M1 — The deployed refusal paths outside the Lambda are not RFC 9457, so §9's "a client may rely on `code` on any non-2xx" is false
`infra/guardrails.tf`, `infra/compute.tf` · reasoned from the configuration, not executed (no AWS access); the application-side half was verified in Rust

The Rust side takes §9 seriously — `as_problem` exists solely to rewrite
framework rejections, and a 405, an unroutable path, a malformed `?limit=` and
an over-limit body all come back as `application/problem+json` with a `code`.
Three deployed paths sit outside it:

1. **WAF block.** All three rate rules use a bare `action { block {} }`, so the
   answer is CloudFront's HTML error page.
2. **Gateway throttle.** `429` with `{"message":"Too Many Requests"}` — JSON, but
   no `code`, no `type`, not `problem+json`.
3. **Edge method rejection** on the GET-only ordered behaviours.

A publisher's CI retries a `PUT` a hundred times after a transient failure; the
101st is blocked. Their client, written against §9, parses the body, fails, and
reports "unknown error" instead of "rate limited, back off" — during the
incident when the machine-readable reason matters most. Nothing is exposed and
nothing is corrupted; the guarantee as written simply does not hold.

## Minor findings

- **m1** `withdraw()` deletes in the order `publish()` argues against, twenty lines above, and inherits none of that reasoning.
- **m2** `now_rfc3339` emits variable-width fractional seconds, and the listing sort key is that string: `Z` sorts above `.` and above every digit, so an entry updated on a whole second sorts *newer* than one updated half a second later — an inversion of §7.4 for any two entries touched within the same second. The doc comment claims millisecond precision "as §1 requires"; §1 requires nothing of the sort and the code does not deliver it.
- **m3** Axum decodes path parameters before `is_canonical_digest` sees them, so `sha256%3A<hex>` returns `200` with `immutable` caching — a second permanent cache entry for one artifact, which §7.3 forbids in as many words. The repo's own test covers bare hex, uppercase and `SHA256:`, but not the encoded form.
- **m4** The sweep can cover nothing and report success: a `gsi1` row whose `agentId` is unreadable is dropped silently, and `agents = 0, "read path matches the register"` is logged at INFO with every detector quiet. This is the one component whose job is to notice silence.
- **m5** The two `Store` backends disagree about a forged version cursor: the AWS store hands any numeric value to `set_exclusive_start_key` without checking the version exists, so `?cursor=999999` returns a page from an arbitrary position, while the in-memory store raises `BadCursor`.
- **m6** `.terraform.lock.hcl` pins only `hashicorp/aws`, though `versions.tf` requires `hashicorp/random`. Reproduced: `terraform init` installs and records a version nobody reviewed, and `-lockfile=readonly` would fail.

## Checked and sound

Reconciler convergence walked against a publication and a withdrawal committing
at each of the seven call sites in `converge`; the `served > seq` guard and the
pre-write re-read between them close every ordering hazard except the one the
code documents. IAM call by call, with `copy_source` encoding checked and
`SdkError::into_service_error` read in the SDK source to confirm it cannot
panic. CloudFront ordering and the read-only behaviours. Problem-document
coverage inside the service verified by test, including the 405 keeping its
`Allow` header. Strict parsing to 200 000 nesting levels; the RFC 8785 vectors
including UTF-16 sort order; the presence table field by field and its pinned
digest; the JWK and JWS profiles; the CLI's `jku` binding by thumbprint, the
`--jwks` anchor gating the exit status, `agent_of` never returning early, the
JWE `iv` check and `p2c` cap. `terraform fmt`/`validate` clean; 160 tests green.
