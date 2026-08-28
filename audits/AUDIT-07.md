# Audit — round 7

**Method:** one independent auditor, blind, across the whole stack, pointed
first at the read-path convergence machinery — the component that had produced a
MAJOR in each of the three previous rounds — and told explicitly that a comment
claiming a property is a place to look rather than a reason to move on.

**Cross-check.** One MAJOR, and it is a defect *introduced by the round-6 m2
fix*: making the sweep collect per-agent failures instead of aborting was right
for the scheduled pass and wrong for the stream path, which shares the same
function. Third consecutive round in which a fix to this component created the
next round's finding — which is why the fix this time came with the test that
would have caught it.

---

## Verdict

One MAJOR. `Reconciler::handle` calls `sweep`, which never returns `Err`, then
discards the `failed` list — so a convergence failure on the stream path is
swallowed, the record is checkpointed and lost, and none of the three detectors
built for that case (five retries, the SQS failure destination, the
`reconciler-errors` alarm) can fire. The write-admission core, the JWK/JWS
layer, the pinned presence table and all three IAM policies are sound; IAM was
checked call by call and no gap was found.

## Major findings

### M1 — The reconciler silently discards every convergence failure: no retry, no DLQ message, no alarm, no log line
`crates/registry-lambda/src/reconciler.rs:145` · verified by a throwaway integration test against the real `Reconciler` with a `CommittedState` that errors

```rust
let repairs = self.sweep(source, &ids).await?;   // the `?` is unreachable
Ok(repairs.len())                                // `failed` is dropped
```

`sweep` collects per-agent errors into `Repairs::failed` and returns `Ok` —
correct for the sweeper, whose handler inspects `failed`. `handle` never reads
it, and `Repairs::len()` excludes it. The doc comment three lines above says the
opposite: *"Errors propagate so that Lambda retries the batch… failing loudly is
the point."*

Observed: `handle -> Ok(0)` with
`failed: ["abc: simulated backend failure reading abc"]`.

A publisher withdraws; the `DeleteObject` returns `503 SlowDown`; `converge`
fails; `handle` returns `Ok(0)`; the Lambda exits successfully. The ESM advances
its checkpoint so `maximum_retry_attempts` never engages; the failure
destination receives nothing so the DLQ alarm stays quiet; `AWS/Lambda Errors`
records nothing so the reconciler alarm stays quiet; and the text is never
logged, so there is nothing to find afterwards either. Withdrawal is terminal,
so no later record redoes the delete: the CDN serves the withdrawn card *and*
its JWKS until the next scheduled sweep — during which a retained copy of the
withdrawn card keeps verifying via `jku`, the exact outcome §6.5 exists to
prevent.

## Minor findings

- **m1** `Repairs::len()` counts only `republished + withdrawn`, and that is what the drift metric filter reads — so a pass that repaired nothing and failed on five agents logs `repaired=0`: no drift, according to the one signal that watches for it.
- **m2** Two-writer safety is check-then-act, and the comment asserts atomicity is impossible "without conditional writes on the objects" — S3 has supported those since late 2024.
- **m3** The sweeper, which M1 makes the sole recovery path, materialises every agent id in memory and walks them serially at three to four round trips each inside a 300 s timeout — a few thousand agents per pass.
- **m4** The per-IP read limit is sized against one address: two compliant addresses at 10 rps each consume the entire stage-wide 20 rps and deny every publication.
- **m5** CLI `verify` bypasses `check_registry`, accepts a bare `http://` target, and returns a local file whenever `Path::new(target).exists()` — so `aithos verify <agentId>` in a directory containing a file of that name reads the file and prints no `from` line saying so.
- **m6** `Cache-Control` is set on one of the four API-served read endpoints; the other three rely on the edge's default TTL and tell a browser or proxy nothing.
- **m7** An `Err` from the sweeper triggers Lambda's two automatic async retries of the entire pass.
- **m8** Three problem codes are returned that §9 does not list: `CONFLICT`, `CURSOR_INVALID`, `INTERNAL`.

## Checked and sound

IAM call by call for all three roles, with no gap found — including
`CopyObject` needing `GetObject` on the source and `PutObject` on the
destination, `DeleteObject` without `DeleteObjectVersion` under versioning, and
`ListBucket` for the 404/403 distinction `pointer_state` depends on. The full
pointer-pair state enumeration: every combination of {absent, matching, stale}
for both pointers under both committed states reaches either a correct no-op or
a repairing action, and the `served > seq` veto can only fire on a legitimately
newer pointer. Digest-only convergence shown sound because the authorized set is
the set of card signers and `signatures[]` is inside `cardBytes`. `TRIM_HORIZON`
replay safe because `action_for` reads only `dynamodb.Keys`. CloudFront ordering
and the non-enumerable `ListBucket` grant. The edge gate against a forged
header. DynamoDB encoding, conditional writes, the request token, cursor
pinning. Alarms against their metrics — all sound except `reconciler-errors`,
defeated by M1. The presence table field by field; the pinned digest; the strict
JSON profile; the JWK and JWS profiles; `to_public`. HTTP conditional semantics:
weak comparison for `If-None-Match`, strong for `If-Match`, 304 carrying no body
and not rewritten by the problem layer. `build-lambda.sh`.
