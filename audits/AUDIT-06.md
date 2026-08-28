# Audit — round 6

**Method:** one independent auditor, blind, across the whole stack, pointed
first at the read-path convergence machinery — the component that had produced
MAJOR findings in each of the two previous rounds — and told explicitly that
several past defects here were introduced by the fix for a previous one.

**Cross-check.** One MAJOR, and it is a genuine gap in the two-writer design
rather than a regression of a specific earlier fix: the anti-rollback sequence
guard is structurally unable to veto the transition that matters most. The
protocol core, the client and the deployed surface came back clean.

---

## Verdict

The convergence machinery is well-built: IAM is complete call by call for all
three roles, the stream path reads committed state rather than record content,
the anti-rollback stamp is on both pointers, and the presence table matches the
pinned `a2a.proto` field for field. One real defect in the two-writer design:
the sweeper can republish a card and JWKS that the stream reconciler has just
correctly deleted for a withdrawn entry. Everything else is bounded.
`terraform fmt -check` clean, `terraform validate` succeeds, `cargo test
--workspace` green.

## Major findings

### M1 — The sweeper can resurrect a withdrawn entry; the sequence guard cannot stop it, and the stream cannot heal it
`crates/registry-lambda/src/reconciler.rs:244,287-293` · verified by replicating `sweep_inner`'s exact match in a scratch test, and by reading `AwsStore::withdraw`

The guard is `if served > seq { continue }`, where an absent pointer scores `0`
— the smallest possible value, so absence can never win the comparison. Absence
is precisely what withdrawal produces. Compounding it, `withdraw` sets `status`
and `updatedAt` but **does not advance `seq`**, so nothing else in the state
would let the guard notice.

Interleaving, no prior drift required:

1. Agent A is `ACTIVE` at `seq 6`, both pointers converged at `(d6, 6)`.
2. The sweeper reads A → `Active { seq: 6, card_digest: d6 }`.
3. The key holder withdraws. The record flips to `WITHDRAWN`, still `seq 6`. The
   stream reconciler — a different Lambda, concurrent — deletes both pointers.
   Correct; §6.5 satisfied.
4. The sweeper's HEADs now return `None`/`None`. Not converged;
   `served = max(0,0) = 0`; `0 > 6` is false.
5. The sweeper republishes the withdrawn card and its key set.

Withdrawal is terminal, so **no further stream record for A will ever exist**.
Only the next scheduled sweep removes them — up to an hour, plus the 60 s edge
TTL — and it reports the removal as a repair, firing `sweep-repairs` with "A
stream record was lost": a misdiagnosis of a state the sweeper itself created.
The comment claiming self-healing does not hold here, because the withdrawal's
stream record was consumed *before* the losing write landed.

The window is one read→write gap, so the per-withdrawal probability is small.
But it is unguarded by construction rather than by luck, and the sequence stamp
existed precisely to make the two writers safe.

## Minor findings

- **m1** `publish` writes the card pointer before the JWKS pointer, so a partial failure serves the new card with the pre-rotation key set — a verifier accepts a signature from a key the publisher just retired. The other order fails closed.
- **m2** `sweep_inner` aborts the whole pass on the first error, and the sweep has no continuation: every agent after the failing one is skipped that round, with a hard 300 s timeout and no checkpoint.
- **m3** The repair count still never reaches the alarm on a failing sweep: `main.rs` `?`-returns on the error, so the `tracing::error!(repaired = …)` line never runs and the metric filter sees nothing.
- **m4** `card::agent_of` gives up on the whole signature list if the *first* entry lacks `protected` — the same failure the comment beside it says was fixed for `jku`. `publish` then creates a second, unrelated entry.
- **m5** `find_version` and `list_versions` are eventually-consistent reads while `get_agent` is consistent, so a `GET .../versions/{digest}/agent-card.json` immediately after the `201` that created it can return `404` — on a path cached `immutable`.
- **m6** The API origin never evaluates `If-None-Match`; §7.1 says the validator is good for it.
- **m7** Deleting a pointer under versioning leaves a delete marker nothing expires.
- **m8** `aithos verify --jwks <file>` falls back to the card's own `jku` when the file yields zero keys — the verdict stays correct, the network request does not.

## Checked and sound

IAM call by call for all three roles, including `ListBucket` for 404-vs-403 and
the DLQ `sqs:SendMessage`; `CopyObject` with `MetadataDirective::Replace` not
inheriting the immutable cache header; the stream filter agreeing with
`action_for`; the identifier read from `Keys` so a `REMOVE` still names its
agent; `TRIM_HORIZON` replay idempotent because convergence reads committed
state; the GSI projection and that only `CURRENT` items carry `gsi1pk`; the
publish-vs-publish anti-rollback direction; CloudFront behaviour ordering walked
path by path and the `s3:ListBucket` grant confirmed non-enumerable; the edge
gate; alarms matching their metrics, including the HTTP-API `5xx` shape and
`treat_missing_data = breaching`; DynamoDB encoding, conditional writes and the
request token; cursor pinning; path-injection safety; the strict JSON profile
including escaped duplicate members and a BOM; JCS UTF-16 ordering; the presence
table message by message; the full JWS and JWK profile; §9's code→status pairs;
the CLI's key handling at rest and `verify --jwks` refusing the `jku` fallback.
