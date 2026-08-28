# Audit — round 9

**Method:** one independent auditor, blind, across the whole stack, weighted by
its own judgement after reading the code, with the areas that have historically
hidden defects here named as orientation: failure and reporting paths, the two
writers on the S3 pointers, `SPEC.md` promising what the deployment does not
deliver, and parsing or HTTP semantics that produce a *different* result rather
than a rejection. Told explicitly that a report with no MAJOR findings was an
expected and valuable outcome.

---

## Verdict

**No MAJOR defect.** The write-admission rules, the presence table, the
canonicalization path, the two-writer convergence logic and the three IAM
policies all held up under call-by-call checking. `terraform fmt -check` clean,
`terraform validate` passes, the Rust suite green. What was found is a cluster
of `SPEC.md`-versus-deployment mismatches — all in the direction of the spec
describing something the deployed shape does not offer — plus a few bounded
asymmetries. The reconciler/sweeper residual races are real but every one the
auditor could construct is explicitly reasoned about in the code and self-heals
within one sweep interval.

## Major findings

None.

## Minor findings

- **m1** §7.1 offers a route to the withdrawn/never-existed distinction the deployed shape does not have: the API origin cannot be reached for the card and JWKS paths at all — the behaviour table routes them to the object store unconditionally, and the raw gateway hostname is refused by the edge gate. The §7.3 record route works, so the guarantee is deliverable; the sentence naming a second route is not, and two handlers are dead code in production as a consequence.
- **m2** The component that delivers §6.5's "MUST stop serving" is not specified, and the cross-reference to it dangles: §6 ends at §6.5 and nothing describes the reconciler, the sweeper, the pointer objects or their timing. The actual guarantee is weaker than the flat MUST — the stream path is at-most-once, the backstop is hourly — and the spec states no bound at all.
- **m3** `evaluate_withdrawal` does not apply §5.6's unused-key rule though it shares the helper that would: a `DELETE` body may carry eight JWKs of which seven sign nothing, parsed and silently ignored. A rule enforced on one of its two callers.
- **m4** The two `Store` backends disagree on the listing tie-break — ascending by identifier in memory, descending in the deployed backend — and every HTTP test runs against the memory store, so the ordering that ships is the one nothing exercises. Relatedly the deployed backend can emit a `nextCursor` whose page is empty.
- **m5** `as_problem` emits `REQUEST_REFUSED`, which appears nowhere in §9, and `Problem::title()` has no arm for `METHOD_NOT_ALLOWED`, `INTERNAL`, `RATE_LIMITED` or `FORBIDDEN` — so those documents carry the generic "Request rejected" — while still carrying an arm for a code §6.1 abolished.
- **m6** *(not verified — no AWS access)* The `/v1/agents/*/versions/*` behaviour pairs `CachingOptimized`, which keys on the path alone, with an origin request policy that forwards `If-None-Match`, to an origin that varies on it. If CloudFront can store the resulting bodiless 304 against a key that excludes the conditional header, one conditional request would poison an `immutable`-cached version URL with an empty response.

## Checked and sound

The presence table against the pinned proto, message by message, and its pinned
digest. RFC 8785 including the `weird` vector that distinguishes UTF-16
code-unit ordering from UTF-8 byte order. IAM call by call for all three roles,
with nothing missing and nothing surplus that matters. Every pointer-writer
interleaving the auditor could construct: stream-vs-stream serialised by
per-partition ordering, sweep-vs-stream fenced by the sequence guard and the
pre-write re-read, both partial-write shapes detected because the two pointers
are inspected independently, and both write orders confirmed to be the
fail-closed ones. Failure reporting end to end — `handle` converting collected
failures into an `Err`, `sweep` collecting rather than aborting, `Repairs::len()`
counting failures, the sweeper logging before returning, `sweep_agent_ids`
refusing an unreadable row — and the alarm set covering all three functions.
HTTP semantics by probe: `405` keeping its `Allow` header, `If-Match` strong and
`If-None-Match` weak across every form, a withdrawn entry's full status matrix,
forged cursors as `CURSOR_INVALID` rather than 500s, and all four non-canonical
digest spellings as 404. Idempotency and replay. Keys and crypto. The CLI at
rest and on the wire. Terraform `fmt` and `validate` against the locked provider.
