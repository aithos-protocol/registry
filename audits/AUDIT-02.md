# Audit — round 2

**Method:** two independent auditors, fresh context, working blind from the code
and `SPEC.md` only. Neither was shown `audits/` — not the round-1 report and not
the ledger — so their findings are not shaped by what was already believed to be
fixed. **A** took the protocol core and the HTTP surface; **B** took the
deployed shape: Terraform, IAM, CloudFront, the stream reconciler, the CLI at
rest.

Splitting the round this way was deliberate: round 1 probed the cryptographic
core hard and found it sound, so a second identical pass was unlikely to pay.

**Cross-check against round 1.** Both auditors independently found that the
round-1 M3 fix does not work: `Router::layer` was called before `.route()`, so
the 512 KiB `DefaultBodyLimit` applies to no route at all. A independently
re-derived M3's amplification on a path the round-1 fix never covered. Round-1
M2 (rebuilt JWKS) and m4 (bounded `jku` fetch) were both re-probed by an auditor
who had never seen them and found sound. No finding here reverses a round-1
decision; see `LEDGER.md`.

---

## A — protocol core and HTTP surface

### Verdict

Attacked the write-admission path, JWS/JWK verification, the strict-JSON /
presence / canonicalization core, and the HTTP surface, as an anonymous caller
and as a hostile key holder. The core replay defence holds: the card signature
covers `version`, so no observed signature can be reused to update, roll back,
or widen the authorized set of an *existing* entry. Withdrawal binding holds,
withdrawal is terminal, and the presence table matches `a2a.proto` field for
field. What did not hold: Ed25519 verification is non-strict, so a fixed
well-known `agentId` is world-writable with no key at all; the *creation* rule
accepts a replayed signature, so anyone can register an entry for a key they do
not hold and choose its authorized set; and the 2048-bit RSA floor is trivially
bypassed.

### A-M1 — Non-strict Ed25519 verification makes a fixed, well-known `agentId` world-writable
`crates/registry-core/src/jws.rs:210`, `crates/registry-core/src/jwk.rs:101` · confirmed by execution

`verify_ed25519` calls `VerifyingKey::verify`, not `verify_strict`.
ed25519-dalek's non-strict path uses the cofactorless equation and performs no
small-order / torsion check, and `Jwk::parse` accepts any 32 bytes that
decompress. The identity point is therefore a valid registry key.

With no key material anywhere: take `A = 0x01 00 … 00` (canonical encoding of
the identity point); its RFC 7638 thumbprint is the constant
`eV9frzBXPTP92MWWMpoFOh0WI_kJLvGlhcNs15APU_s`. For **any** message,
`R = identity, S = 0` satisfies `[S]B = R + [h]A`, so the 64-byte signature
`0x01 00 … 00 || 00 … 00` verifies over any signing input.

Observed, three unrelated anonymous parties in sequence against the real router:

```
stranger A creates   -> 201 Created
stranger B updates   -> 200 OK   cardVersion="2.0.0"
stranger C withdraws -> 200 OK   status="WITHDRAWN"
```

§3.1's "the key is the account" does not hold for this key class: there is no
account. The `agentId` is a constant an attacker can squat, publish and hand
off. P-256 is unaffected — `VerifyingKey::from_encoded_point` rejects identity
and off-curve points.

### A-M2 — Creation accepts a replayed signature: an anonymous caller can register an entry for a key it does not hold, and pick its authorized set
`crates/registry-core/src/write.rs:112` · confirmed by execution

`signing_payload` strips the top-level `signatures` member, so a signature
covers the card *minus* its signature array. Nothing in the protected header or
the payload binds the `agentId`, the registry origin, or which signatures
accompany the card. §6.2(4) only requires the path to equal the `kid` of *some*
signing key.

**(a) Cloning another publisher's key into a new entry.** Victim X (genesis key
A) registers backup key B per §3.4 by publishing v2.0.0 co-signed by A and B.
Both the card and B's public JWK are on anonymous endpoints. An attacker
fetches them, deletes A's entry from `signatures[]` — B's signature still
verifies, the payload is untouched — and `PUT /v1/agents/{kid_B}`:

```
attacker PUT /v1/agents/NPD0AEJhRXyecqFVaDwAk2JIzFQZwkCsgNURAukoq6c -> 201 Created
authorizedKids: ["NPD0AEJhRXyecqFVaDwAk2JIzFQZwkCsgNURAukoq6c"]
```

Two entries serve the same card at two `agentId`s. §1 states the entry's claim
is "This Agent Card was published by the holder of key `<thumbprint>`" — the
holder of B published nothing here.

**(b) Pre-emption with a downgraded key set** — the sharper version. Any A2A
card signed per §8.4 and served on the publisher's own site is usable. The
attacker registers it here *first*, keeping only A's signature:

```
[preempt]  -> 201 Created   authorizedKids = ["<kid_A>"]   (B silently dropped)
victim publishes their real, co-signed card -> 409 VERSION_NOT_INCREASING
```

The attacker chose the entry's genesis, `createdAt`, `seq 1` and its authorized
key set, dropping the backup key the publisher deliberately registered. Until
the publisher notices and burns a version bump, key B is not authorized — and if
A is lost the entry is frozen permanently (§3.4: "the registry offers no
recovery path and MUST NOT offer one"). The same trick works across registries:
nothing in a card signature names one.

The equivalent move against an *existing* entry is correctly refused — appending
an attacker signature to a victim's current card gives `409
VERSION_NOT_INCREASING`, because `version` lives inside the signed payload. The
gap is creation only.

### A-M3 — The 2048-bit RSA floor is bypassed by zero-padding the modulus, and the registry then republishes the padded key
`crates/registry-core/src/jwk.rs:115` · confirmed by execution

```rust
let bits = n.len() * 8 - n.first().map_or(0, |b| b.leading_zeros() as usize);
```

Only the leading zeros of the **first byte** are discounted. Prepend whole zero
bytes and the computed size is the encoding length, not the modulus.

A real 512-bit RSA key, left-padded to 257 bytes, driven through the router:

```
real modulus: 64 bytes = 512 bits
Jwk::parse(padded) -> Ok("rfj2G9452dX52oVmahJ2PNCgqddC8QsEiQM5MZuDl-A")
PUT with 512-bit RSA key -> 201 Created
published JWKS modulus: 257 bytes (2056 apparent bits), real bits = 512
```

`RsaPublicKey::new` strips the padding, so RS256 signatures verify normally.
§5.5's stated minimum does not hold, and `to_public` rebuilds from the stored
bytes, so `GET /jwks.json` serves the padded modulus: a consumer measuring the
published key sees 2056 bits. A 512-bit modulus is factorable in minutes, after
which anyone can update, rotate and withdraw that entry.

### A — minor findings

- **A-m1** The request body limit is not applied; axum's 2 MiB default governs. `api.rs:64` — `Router::layer` is called on an empty router, before every `.route()`. Confirmed: a 3 MiB body is refused by axum's *default* limit, and a 600 KiB body is fully buffered and reaches the handler before `parse_envelope` rejects it.
- **A-m2** `MAX_ISSUES = 50` is not enforced on the unknown-member path. `presence.rs:42` (and the `Ty::Map` loop at 145) push without a bound check. A 524,010-byte body of unknown top-level members produced **48,649 issues, ~19.4 MiB peak heap, 65 ms CPU**, and `From<CardError> for Problem` clones the whole vector to read `issues.first()`. A ~38× anonymous memory amplifier. The round-1 test exercises `skills`, which is the one path that *is* capped.
- **A-m3** Version ordering is not SemVer 2.0.0 precedence. `write.rs:149` — the `semver` crate's `Ord` includes build metadata; SemVer §10 requires it ignored. Confirmed: current `1.0.0`, submitting `1.0.0+b` is accepted as an update.
- **A-m4** ES256 signatures are accepted in both low-S and high-S form. `jws.rs:189`. Not an RFC 7518 violation, but one observed card yields unlimited distinct valid encodings, which feeds A-M2(a) and defeats the byte-identity premise behind `Outcome::Unchanged`.
- **A-m5** One RSA key yields many `agentId`s — same root cause as A-M3, the thumbprint is over the re-encoded padded `n`.
- **A-m6** JWK structural errors are reported as `CARD_INVALID` (422). §9 defines that code as "Card violates the pinned A2A schema"; a malformed `keys[]` entry is not that.
- **A-m7** A withdrawn entry answers `412` instead of `410` when `If-Match` is present. `api.rs:97` — `check_if_match` runs before `evaluate_write`'s withdrawn check.
- **A-m8** `/v1/registry` omits what §7.5 requires: the presence-table digest, the link to the test vectors, and the body limit. The presence-table digest is what would let a second implementation confirm it pinned the same table.
- **A-m9** `ETag` *is* the card digest (`api.rs:379` emits `"sha256:<hex>"`), while §7.1 says it must not be parsed as one. Trains clients into exactly the behaviour the spec forbids.
- **A-m10** The withdrawal payload accepts extra members, and `issuedAt` is never parsed or bounded, while §6.5 says the payload "is exactly" that object.
- **A-m11** `jku` validation is both too strict and too loose: `contains('@')` rejects a legitimate path or query, `starts_with("https://")` accepts `https:///path` and any control character.

### A — checked and sound

Presence table vs `a2a.proto`, message by message, including both `oneof`
markers and `default_is_omittable`. Strict JSON profile §5.1 (duplicate members,
non-I-JSON integers, `1e400`, lone surrogates, astral pairs, trailing content,
nesting depth) applied to envelope, card, protected headers and withdrawal
payloads. Replay and rollback against an existing entry. Lineage and rotation,
including the disjointness check placed *before* the digest shortcut. Header
profile §5.5 and the algorithm allowlist applied before any key is resolved.
Key hygiene: private members rejected first; `to_public` rebuilds from verified
material — verified in the padded-RSA run that only `kty/crv/coords/kid/use`
came back. Withdrawal §6.5 end to end. Store contract, including
digest-scoped-by-agent and orphan gating. Envelope handling and `If-Match`
strong comparison. RSA cost bounded by the crate's 4096-bit ceiling. Problem
documents, backend detail suppression, cursor errors as 400.

---

## B — infrastructure and operations

### Verdict

Attacked the deployed shape: the CloudFront behaviour table and its ordering,
what an anonymous caller reaches at each origin, the IAM grants on both roles,
the stream reconciler under retry and partial failure, and the DynamoDB item
encoding under a normal update. The write-authorization logic, the
conditional-commit design, the OAC / bucket-policy scoping and the CLI's `jku`
fetch held up well; the ordering trap the comments warn about is correctly
handled. What did not hold: the WAF write throttle is on only one of the two
reachable front doors; the custom 404 page is routed to the wrong origin;
`createdAt` is destroyed on every update in the AWS store; and a discarded
stream record permanently breaks the §6.5 guarantee with no DLQ.

### B-M1 — The only per-IP write throttle sits on CloudFront, but the API Gateway origin is directly reachable
`infra/compute.tf:194-223`, `infra/edge.tf:53-63`, `infra/guardrails.tf:16-93` · read, not executed against AWS

`aws_apigatewayv2_api.registry` is created without
`disable_execute_api_endpoint`, so its default `execute-api` endpoint is live
and public. The CloudFront custom origin sends no shared-secret `custom_header`
and the Lambda reads none — nothing distinguishes a request that came through
the distribution. WAFv2 cannot attach to an HTTP (v2) API at all, so the
`writes-per-ip` rule exists solely at the edge.

An attacker who learns the origin hostname issues `PUT` against it directly with
freshly generated keypairs. WAF never sees it. The only remaining bound is the
*stage-wide* 20 rps / 50 burst throttle, so the same flood simultaneously 429s
every legitimate publisher arriving via CloudFront. `guardrails.tf` states
plainly that the API throttle "does not tell an attacker from a publisher" and
that the WAF rule "is the part that distinguishes them"; that part is bypassable.

20 writes/s is ~1.7M permanent entries/day, and the registry is append-only by
design — no `DeleteItem`, no `DeleteObject`, no TTL — so every accepted junk
entry is paid for forever.

### B-M2 — The custom 404 page is fetched from the API origin, so the S3 error object is unreachable and every 404 costs a Lambda invocation
`infra/edge.tf:133-138`, `infra/storage.tf:113-125` · behaviour table read; CloudFront resolution reasoned from AWS's documented rule

CloudFront resolves `response_page_path` through the ordinary cache-behaviour
table. The three ordered behaviours are `/v1/agents/*/versions/*`,
`/v1/agents/*/agent-card.json` and `/v1/agents/*/jwks.json`.
`/errors/not-found.json` matches none, so it falls to the **default** behaviour
— target `api`, `Managed-CachingDisabled`.

1. `aws_s3_object.not_found` is dead weight: the error-page request goes to API
   Gateway, whose router has no such route, so the fetch itself 404s and
   CloudFront falls back to its own generic page. The stated contract — one
   error format from either origin — holds nowhere.
2. The error page is never cached. `error_caching_min_ttl = 5` caches the
   *generated* response under the originally requested URL, so a flood of
   distinct URLs produces one origin fetch each: S3 miss → 404 → error-page
   fetch → `$default` route → **Lambda invocation**. Reads are deliberately not
   rate-limited on the premise that they never reach that code. An anonymous
   caller flips both, and those invocations consume the same 20 rps stage
   throttle as writes.

### B-M3 — `createdAt` is overwritten on every update; the record's creation time is permanently lost
`crates/registry-lambda/src/aws_store.rs:114-188` · read; `Put`-inside-`TransactWriteItems` full-replacement semantics not executed

`commit()` sets `record.created_at = commit.created_at`, which `api.rs` sets to
`now_rfc3339()` for *every* write. A `Put` inside `TransactWriteItems` replaces
the entire item. The comment claiming the re-read "reports the original creation
time" is inverted: the re-read returns the item that was just clobbered.

The reference implementation does the opposite and says so — `memory.rs:49-51`
preserves `existing.created_at`. Publish v1.0.0 on day 1 and v1.1.0 on day 60:
`GET /v1/agents/{id}` then reports `createdAt == updatedAt == day 60`, and the
day-1 value is gone. No test in `registry-api/tests` or `registry-e2e` mentions
`createdAt`, so the divergence between the two stores is invisible to CI.

### B-M4 — A discarded stream record permanently breaks the withdrawal guarantee, and nothing can repair it
`infra/compute.tf:177-190`, `crates/registry-lambda/src/reconciler.rs:130-144` · read; ESM discard semantics not executed

The event source mapping sets `maximum_retry_attempts = 5` and declares no
`destination_config`. For a DynamoDB Streams ESM, exhausting the retries
**discards** the record and advances the iterator.

A publisher withdraws; the reconciler's `DeleteObject` hits `503 SlowDown` (or a
brief throttle, or an IAM propagation gap during a deploy). Five retries burn in
well under a minute and the record is discarded. Both pointer objects stay in
the bucket and CloudFront keeps serving them indefinitely — §6.5 requires the
registry to stop serving both, and calls out that flipping a flag alone "defeats
the one purpose of withdrawal".

Recovery is worse than the failure. Withdrawal is terminal, so nothing will ever
overwrite those objects. The reconciler is driven only by the stream and is
deliberately denied any read of the table, so it cannot be re-run against
committed state, and there is no reconciliation sweep. With no DLQ the record's
content is gone; the operator gets a generic alarm and must find the agent in
CloudWatch logs and delete two objects by hand.

The same mechanism silently loses publications: a discarded `Publish` leaves the
edge serving the previous card forever.

### B-M5 — There is no per-`agentId` write rate limit anywhere
`infra/guardrails.tf:27-86` · verified: the ACL contains exactly one rule, aggregating on `IP`

§8 states "Write rate limits are per source address and per `agentId`." Only the
source-address half exists. A botnet with a few hundred addresses, each under
100 writes / 5 min, aims every request at one victim `agentId`; each request is
authenticated only after up to 8 signature verifications on a 512 MB Lambda. The
per-IP rule never trips. With B-M1, none of it needs to touch CloudFront.

### B — minor findings

- **B-m1** The API role still holds `s3:PutObject` on the whole bucket including `v1/*`, which the next comment says belongs to the reconciler. By the README's own standard ("withholding the permission is a stronger guarantee than not calling the API"), the guarantee is not being made.
- **B-m2** The 512 KiB `DefaultBodyLimit` layer is applied to zero routes — same finding as A-m1, reached independently. Verified with a throwaway test: a 1 MiB body reached the handler and was rejected by `parse_envelope`'s own check.
- **B-m3** No write is ever logged, anywhere. Three `tracing::` sites in total; no API Gateway access logs, no CloudFront logging. For a registry whose entries are permanent and whose stated threat is bulk junk publication, there is no record of which address published which entry.
- **B-m4** The `-errors` alarm cannot see the failure it names. It watches `AWS/Lambda Errors`, which counts faults and timeouts; a `StoreError::Backend` becomes a 500 *response* from a successful invocation. The most likely write-path failure is invisible to the alarm described as "the write path is failing".
- **B-m5** A forged listing cursor returns 500. `aws_store.rs:359-376` validates only that four attributes are present, then passes them to DynamoDB; a `ValidationException` maps to `Backend` → 500. `store.rs:25-28` says exactly why this must not happen.
- **B-m6** The CLI creates key files at the umask default and chmods afterwards. Between the two calls the private JWK exists at typically 0644 — with `--no-passphrase`, plaintext P-256 private material. `OpenOptions::mode(0o600).create_new(true)` also replaces the racy `path.exists()` check.
- **B-m7** `deny.toml` is never executed. No workflow invokes `cargo deny`; the `audit` job uses `rustsec/audit-check`, which reads `.cargo/audit.toml`. The documented RUSTSEC-2023-0071 exception is not in force even though `rsa 0.9.10` is in `Cargo.lock`.
- **B-m8** `build-lambda.sh` announces success before checking the architecture, and picks `bootstrap` by traversal order rather than freshness.
- **B-m9** The anonymous record endpoint does a strongly consistent read. Three unauthenticated, unthrottled, uncached routes pay double RCU.
- **B-m10** CDN JWKS returns 404 for a withdrawn agent where §7.2 says 410 with no carve-out, unlike §7.1.
- **B-m11** Orphaned `versions/` objects are never collected; the lifecycle rule is filtered to `prefix = "v1/"`.
- **B-m12** `starting_position = "LATEST"` makes any ESM recreation silently lossy: every record committed in the gap is skipped with no error and no alarm.

### B — checked and sound

CloudFront behaviour ordering, including that `/versions/` cannot appear in a
legitimate S3-served path and that `..` is a literal segment to S3. Cache policy
vs. what each route needs, including `max-age=60` bounding withdrawal staleness
at the edge. S3 exposure: full public access block, OAC with `signing_behavior =
always`, bucket policy pinned to this distribution's ARN — no confused deputy.
Reconciler ordering: one `pk` per agent, `batch_size = 1`, parent shards drained
first, so a re-delivery cannot resurrect a superseded card. Reconciler IAM
scoping, prefix by prefix. Write authorization and concurrency: withdrawn
checked first, `Unchanged` placed after the lineage check, conditional
`TransactWriteItems`, `cancellation_reasons` inspected per item. Idempotent
retry writes nothing. Orphan objects gated by the `DIGEST#` item. Published
JWKS rebuilt via `to_public`. CLI `jku` handling and key file at rest (PBES2
salt construction, protected header as AAD, finite iteration cap). Terraform
`fmt -check` and `validate` clean; native S3 locking; PITR, deletion protection,
`prevent_destroy`. No credentials in tfvars; `.gitignore` covers state and
`.env*`.
