# Audit — round 3

**Method:** two independent auditors, blind, from the code and `SPEC.md` only.
Neither saw `audits/`. **A** took the protocol core, the HTTP surface and the
CLI; **B** took the deployed shape.

**Cross-check against rounds 1–2.** A independently re-derived the residue of
round-2's A-M2: the publication proof closed the hole for the genesis signer and
left it open for every co-signer. That is a completion, not a reversal. B found
that round-2's B-M4 fix (a dead-letter destination) does not do what its comment
claims. Nothing here reverses a decision recorded in `LEDGER.md`.

---

## A — protocol core, HTTP surface, client

### Verdict
No path found to create, update, rotate or withdraw an entry without the
corresponding private key. The signature core held everywhere. What did not
hold: the proof constrains only the *proof signer*, not the rest of the key set
it installs.

### A-M1 — The proof constrains only the proof signer, so any key that ever co-signed a published card can be enrolled into a stranger's entry
`crates/registry-core/src/write.rs:129,164,230` · confirmed by execution

The new authorized set is every verified *card* signature. The proof is checked
against one of them. A card signature covers the card minus `signatures[]`, so
that payload is public the moment the card is published, and anyone can append
their own signature without invalidating the existing ones.

Executed against the real router:

1. Alice publishes normally → `201`.
2. Mallory GETs the published card.
3. Mallory strips `signatures[]`, canonicalizes the remainder, signs it with her
   own key, and appends her signature next to Alice's. Alice's still verifies.
4. Mallory `PUT`s to her *own* `agentId` with `keys: [A_pub, M_pub]` and a proof
   signed by her key.

Result: `201 Created`, `authorizedKids = [kidA, kidM]`, and
`GET /v1/agents/{kidM}/jwks.json` republishes Alice's public key as currently
authorized there. §6.1 names precisely this — "an entry appears for a key holder
who never asked for one" — as the reason the proof exists.

Not obtained: no takeover of the victim's entry, no rollback, no ability to
change the mirrored content. The victim can withdraw the parasitic entry,
because their key is in its authorized set.

### A — minor findings
- **A-m1** Reachable arithmetic underflow in `Jwk::parse`: `n.len()*8 - leading_zeros` underflows on an empty modulus. Panics the handler under overflow checks; wraps past the 2048-bit floor without them. Reached before any signature or authorization check.
- **A-m2** `choose_prover` returns the genesis key before consulting `authorizedKids`, so after a rotation away from it, re-adding it emits a write the registry refuses.
- **A-m3** The client cannot withdraw at all, though §6.5 exists so a publisher needs no operator.
- **A-m4** Refusals made by a layer or extractor (413, bad `?limit=`, 405, 404) answer in plain text, so §9's `413 CARD_TOO_LARGE` is never emitted on the path that produces it.
- **A-m5** The presence-table digest is published as an interoperability fact but pinned by nothing; its test asserts only that it equals itself.
- **A-m6** An integer literal beyond `u64` never reaches the range check — it arrives as a double.
- **A-m7** `aithos verify` will fetch any host a hostile card's `jku` names.

### A — checked and sound
Proof payload re-canonicalization and member binding; cross-registry,
cross-agent and cross-card replay; the `alg` allowlist before key resolution;
`kid`-is-thumbprint before any signature work; ES256 fixed-width R‖S; Ed25519
`verify_strict` plus small-order rejection; RSA minimal-encoding; private-member
rejection; `to_public` rebuilding the published JWKS; the full presence table
against `a2a.proto`, message by message; the strict JSON profile; replay,
rollback and idempotent resubmission; withdrawal binding and terminality;
conditional commits in both stores.

---

## B — infrastructure and operations

### Verdict
The reconciler's dead-letter path cannot restore what it discards, and the
premise the whole guardrail design rests on — "reads are served from the edge,
they cost almost nothing" — is false for four of the seven public endpoints.

### B-M1 — The dead-letter path cannot replay what it dropped, so a withdrawn card can stay served forever
`infra/compute.tf` · reasoned from AWS's documented behaviour

For a stream source, Lambda sends the failure destination a document describing
the *batch* — `shardId`, `startSequenceNumber`, `endSequenceNumber` — not the
record. The only way back to the record is the stream itself, which retains 24
hours. The reconciler is deliberately denied any read of the table, so it cannot
be re-run against committed state, and withdrawal is terminal, so nothing will
ever overwrite the pointers a dropped withdrawal left behind. §6.5's "MUST stop
serving" becomes permanently false for that entry.

### B-M2 — Four of the seven public endpoints are uncached Lambda invocations, and no WAF rule counts a read
`infra/edge.tf:95`, `infra/guardrails.tf` · read

The default behaviour is `Managed-CachingDisabled` and catches `/v1/registry`,
`/v1/agents`, `/v1/agents/{id}`, `/v1/agents/{id}/versions` and every
404-producing path — so the `Cache-Control: public, max-age=60` those handlers
set is discarded. Both WAF rules scope down to PUT/DELETE, so a GET is never
counted. One address issuing `GET /v1/agents?limit=100` continuously produces a
Lambda invocation and a DynamoDB query per request against a single-partition
index, bounded only by a stage-wide throttle that denies publishers at the same
time — and throttled queries surface as 500s, giving an anonymous caller control
of the operator's pager.

### B — minor findings
- **B-m1** The API access log records `$context.identity.sourceIp`, which behind CloudFront is an edge server, not the publisher.
- **B-m2** The `audit` CI job is permanently red: `rustsec/audit-check` reads `.cargo/audit.toml`, which does not exist, so the documented RUSTSEC exception in `deny.toml` never applies.
- **B-m3** `ACCOUNT-SETUP.md`'s permission set omits `wafv2`, `sqs`, `sns`, `budgets`, `events`, and instructs attaching a permissions boundary no role sets — which would make `iam:CreateRole` fail.
- **B-m4** The edge gate fails open: a missing secret means no gate, announced only by a warning nothing alarms on.
- **B-m5** A `TRIM_HORIZON` replay transiently republishes withdrawn cards; withdrawal issues no invalidation.
- **B-m6** `TransactWriteItems` carries no `ClientRequestToken`, so an SDK retry of a committed transaction returns 409 for a write that succeeded.
- **B-m7** `reconciler-dropped` watches `IteratorAge > 5min`, which a `batch_size = 1` discard never reaches.
- **B-m8** `keyfile`'s comment claims no unwipeable copy of the secret is made; `decrypt` returns one inside a `Value`.
- **B-m9** A dead `s3:GetObject` grant on `v1/*` for the API role.
- **B-m10** Two thirds of reconciler invocations are no-ops: all three items of a write are delivered, only `CURRENT` matters.
- **B-m11** `aithos publish` overwrites the input card non-atomically and through `from_utf8_lossy`.
- **B-m12** The bucket holding the append-only corpus has neither `prevent_destroy` nor deletion protection, while the table has both.

### B — checked and sound
CloudFront behaviour ordering and the `/errors/*` collision analysis; cache
policy against what each route needs; S3 exposure, OAC and the `SourceArn`
pin; reconciler ordering and IAM scoping prefix by prefix; write authorization
and conditional writes; idempotent retry; orphan gating; the published JWKS
rebuilt from verified material; CLI `jku` handling and key file at rest;
Terraform `fmt`/`validate`, native S3 locking, PITR and deletion protection.
