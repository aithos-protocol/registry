# Audit — round 4

**Method:** two independent auditors, blind, from the code and `SPEC.md` only.

**Cross-check.** The protocol side came back **clean** — the first such verdict
— and specifically confirmed that round 3's `proofs` construction closes the
class it was built for. Every MAJOR this round is in the sweeper introduced by
round 3's own B-M1 fix. That is the loop hazard materializing: not a reversal of
an earlier decision, but a new component with its own defects.

---

## A — protocol, HTTP surface, client

### Verdict
**No MAJOR.** Every authorization path fails closed: creation, update,
rotation, withdrawal, replay, cross-registry and cross-entry lifting,
co-signature append, ES256 malleability, pre-emption by stripping a backup key's
signature. Each confirmed by execution against the real router and the real
write rules. The set of proof signers, the set of card signers and the set of
submitted keys are forced equal, so the published `authorizedKids` and JWKS can
only name keys that individually signed a payload naming this registry, this
`agentId` and this exact card digest.

### A — minor findings
- **A-m1** `aithos publish` parses the card with `serde_json`, not the strict profile. A file containing `"name": "My Agent", "name": "Impostor"` is rejected by `aithos card check` and **signed** without a word by `publish` — serde_json keeps the last member — and `write_atomically` then overwrites the author's source file with it. The registry cannot catch it: the duplicate is gone by the time it sees the card.
- **A-m2** `--offline` cannot be completed without the private key, which is the point of the flag: the printed follow-up command needs the same key file.
- **A-m3** `fetch_record` maps every non-2xx — including `410 WITHDRAWN` and any 5xx — to "this entry does not exist", so the local diagnostic is wrong exactly when it matters.
- **A-m4** An RSA key above 4096 bits parses, yields a thumbprint and therefore an `agentId`, and can then never sign anything; the ceiling is the `rsa` crate's, is in neither §8 nor the manifest, and surfaces as a message blaming the key's validity.
- **A-m5** Both `digest_sk` and `card_object_key` strip an optional `sha256:` prefix, so one stored version is addressable at two `immutable`-cached URLs with two different ETags.

### A — checked and sound
Write admission, proof binding, replay and rollback, withdrawal, ES256
malleability (the comment's reasoning holds), the JWS profile, key handling and
thumbprints, canonicalization against an independent RFC 8785 implementation
over 4 000 generated documents, the presence table re-derived by hand,
`PRESENCE_INVALID` pointers, the whole HTTP surface against panics and path
abuse, concurrency in both stores.

---

## B — infrastructure and operations

### Verdict
The write path is genuinely tight. The failures are all in the read-path repair
machinery: the sweeper cannot complete a sweep in the one situation it exists
for, it is blind to the JWKS pointer entirely, and it writes from a pre-walk
snapshot with no ordering guard.

### B-M1 — The sweeper aborts on the first absent pointer: no `s3:ListBucket`, so S3 answers 403 rather than 404
`infra/compute.tf`, `crates/registry-lambda/src/reconciler.rs` · verified by executing `Reconciler::sweep` against a replayed 403

`current_pointer_digest` treats absence as `is_not_found()`. S3 only
distinguishes absent from forbidden for a caller holding `s3:ListBucket`;
without it a HEAD on a missing key returns 403, which lands in `Unhandled`. The
sweep therefore fails on exactly the object it came to create, repairing nothing
for that agent or any agent after it, and alarming hourly without ever clearing.
This is the same rule the bucket-policy comment invokes by name — applied to the
CloudFront principal and not to the sweeper.

### B-M2 — The sweep never inspects the JWKS pointer, so drift confined to it is permanent and reported as converged
`crates/registry-lambda/src/reconciler.rs` · verified by asserting the requests `sweep` issues

`withdraw` deletes the card then the JWKS; `publish` copies the card then puts
the JWKS. Neither is atomic, and the convergence test reads only the card
pointer. A withdrawal whose JWKS delete failed leaves the withdrawn entry's key
set served forever, while every sweep logs "read path matches the register". The
same shape after a rotation serves the new card beside a key set the publisher
rotated away from.

### B-M3 — The sweeper writes from a pre-walk snapshot with no ordering guard, and can undo the stream reconciler
`crates/registry-lambda/src/aws_store.rs`, `crates/registry-lambda/src/reconciler.rs` · verified by executing `sweep`

`sweep_targets()` paginates the whole GSI before any write, and the GSI cannot
be read consistently. `publish` then issues an unconditional copy/put with
nothing in the pointer metadata carrying `seq`.

- Scenario A (verified): snapshot reads A as ACTIVE/D; the publisher withdraws;
  the stream deletes both pointers; the sweep **re-creates the withdrawn card
  and its JWKS**. Withdrawal is terminal, so nothing removes them again.
- Scenario B: snapshot reads D1; an update commits D2; the sweep rewrites the
  pointer to D1 and the JWKS to the pre-update key set — a rollback of the
  public read path with no key at all, republishing a rotated-away key for up to
  an hour.

Both fire `-sweep-repairs` with "A stream record was lost", which is false.

### B — minor findings
- **B-m1** The read limit (20 000/5min ≈ 66 rps) sits above what the stage throttle can serve (20 rps), so one address legal under every rule can saturate the shared throttle and deny every write.
- **B-m2** `writes-per-agent` aggregates on `uri_path` with only `LOWERCASE`; WAF does not URL-decode and the router does, so `%4E…` is a second rate key for one agent.
- **B-m3** The same 403/404 trap in the API: a genuinely missing `versions/` object surfaces as a 500 rather than a 404.
- **B-m4** The idempotency token does not cover `updatedAt`, which is one of the item's attributes, so a token replayed with different parameters is a 500.
- **B-m5** The DLQ comment claims the destination "keeps the record", contradicting the same file elsewhere.
- **B-m6** Nothing observes a sweep that never runs.
- **B-m7** Rotating the edge secret is an outage: seconds for the Lambda, minutes for the distribution.

### B — checked and sound
Write authorization and the proof construction; the JWS profile and RSA cost
ceiling; private-member rejection and the rebuilt JWKS; cursor pinning; the body
limit layer applied after every route; the edge gate as the outermost layer,
constant-time, unspoofable from outside; CloudFront ordering including
`/errors/*`; the custom error response scoped to 404 only; the transaction's
conditions and `cancellation_reasons` handling; the stream filter matching
`action_for`'s own ignore rule; Terraform `fmt`/`validate`; the CLI at rest.
