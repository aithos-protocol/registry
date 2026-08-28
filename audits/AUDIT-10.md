# Audit — round 10

**Method:** one independent auditor, blind, across the whole stack, weighted by
its own judgement, with `SPEC.md` §6.6 — written the round before — named as
something to check against what the code actually does. Told that the previous
round found no MAJOR and that a clean report was an expected outcome.

---

## Verdict

**No MAJOR defect.** The write-admission rules, the presence table checked field
by field against the pinned proto, the JWS/JWK profile, the digest and URL
canonicalisation, the two-writer convergence logic and the IAM grants call by
call all hold up. §6.6's description of convergence matches the code, including
the residual window it admits to, and the alarm that watches for drift was
verified empirically to match the JSON the sweeper emits. What remains is a set
of minor divergences, one of which means the live suite currently fails.

## Major findings

None.

## Minor findings

- **m1** The live e2e suite fails: it sends an envelope with no `proofs` and asserts `PRIVATE_KEY_SUBMITTED`, but the envelope is parsed before any key is, so the answer is `JSON_INVALID`. Verified against the in-memory router. `writes_are_refused_for_the_right_reasons` is red on every deployment run — on a suite whose whole value is that a red result is believed — and the run leaves a permanent entry behind at the point it aborts.
- **m2** WAF rate blocks are served as `application/json`, not `application/problem+json`: the body enum has no problem type and no header overrides it. §9 lists rate blocks as problem documents, and the media type is what RFC 9457 makes the identifying signal — so a client dispatching on it misclassifies a `RATE_LIMITED` refusal exactly during an incident.
- **m3** `README.md` presents as an open "known gap" the thing the reconciler and sweeper now *are*, and `infra/README.md` asserts "the runtime role grants no `DeleteObject`" — true of the API role, false of the other two, whose `s3:DeleteObject` on `v1/*` is exactly how withdrawal is honoured. Reported not as a documentation gap but because both texts assert *safety properties* that are no longer the ones in force.
- **m4** The two `Store` backends disagree about when a cursor exists: the deployed one derives it from `LastEvaluatedKey`, which DynamoDB returns whenever the limit was reached, so it can hand out a cursor whose page is empty; the memory store never does, and every HTTP test runs against the memory store.
- **m5** The version-cursor existence check is the one eventually-consistent read in a store that is consistent everywhere else it matters, so a cursor the registry issued moments earlier can come back `CURSOR_INVALID` — the store reporting a client error for input it produced itself.
- **m6** `aithos verify <https url>` buffers an unbounded body and decodes it lossily, in contrast to the `jku` fetch which is carefully bounded for exactly this reason. The lossy decode also means the digest printed is of the mangled document.

## Checked and sound

`SPEC.md` §6.6 against `reconciler.rs`, clause by clause, including the
sweep/stream interleavings for withdrawal-during-sweep and publish-during-sweep
— both land inside the single-round-trip residual window the spec states and are
repaired by the next pass. Alarm wiring verified empirically by reproducing the
subscriber configuration and confirming the metric filter matches the emitted
JSON. IAM call by call. The presence table and its pinned digest. Write
admission spot-checked, including that `cardDigest` in the proof covers
`signatures[]` so neither stripping nor appending a co-signature gets past it.
URL and digest canonicalisation, including that `CachingOptimized` strips query
strings so no query variant makes a second cache entry, and that `/versions/*`
deliberately forwards no conditional header to an origin that varies on one.
HTTP semantics executed: the 405 keeping its `Allow` header through the problem
rewrite, `HEAD` content length, `If-None-Match` weak and `If-Match` strong
across every form. Listing order, with the two backends agreeing.
`terraform fmt` and `validate`. The CLI key-file JWE end to end.
