# Audit — round 5

**Method:** two independent auditors, blind. One was pointed at the read-path
repair machinery specifically, since every MAJOR in round 4 was there; the other
at the protocol core and the client, with the write-admission rules explicitly
deprioritized as already well attacked.

**Cross-check.** Round 5's infra M1 is a defect *introduced by round 4's own
fix*: changing the sweep to read each agent consistently made it call `GetItem`,
which its policy did not grant. Two consecutive rounds of defects in one
component is the signal that the component's shape was wrong, not just its
details — which is what the round-5 fix addresses by removing the second source
of truth entirely.

---

## Read-path repair machinery

### Verdict
The repair machinery does not work in the deployed shape, and a `TRIM_HORIZON`
replay — the recovery the mapping is explicitly configured for — deterministically
republishes withdrawn entries' cards and key sets. The rest of the stack held.

### M1 — The sweeper cannot read the register: every sweep fails on the first agent
`infra/compute.tf:243`, `crates/registry-lambda/src/aws_store.rs:409` · verified by reading the IAM document against the call, plus an executed probe

The role grants `dynamodb:Query` on `gsi1` and nothing else.
`CommittedState::state_of` — called for every agent — goes through
`get_agent_item`, a `GetItem` on the **table**, which the index ARN would not
cover even if the action were listed. `sweep` propagates with `?` on the first
agent, before any S3 call. Executed with five agent ids: the whole sweep aborts
at `agent0`, no S3 request is attempted, accumulated `Repairs` are discarded.

The sweeper is, by the design's own argument, the only recovery for a discarded
stream record. It does not exist. `sweeper-errors` fires on the first hour after
deploy and never clears — and an alarm red from day one is an alarm that gets
muted, while `SweepRepairs` reads 0 forever, which reads as "the read path never
drifts".

### M2 — A stream replay from the horizon republishes withdrawn entries' cards and JWKS
`infra/compute.tf:335`, `crates/registry-lambda/src/reconciler.rs:348` · verified by reading `action_for`/`handle` against replay semantics

Per-partition ordering guarantees the *final* state, not the intermediate ones.
`handle` applies every record unconditionally: no comparison against the
pointer's stamped `seq`, no read of committed state, no way to tell a fresh
record from a 20-hour-old one.

If the mapping is recreated (stream ARN change, manual delete, taint) and agent
A published at 09:00 and was withdrawn at 11:00, a 15:00 replay reaches A's
publish record first and writes both pointers back. The edge serves a withdrawn
entry's card **and** its JWKS until the replay reaches the withdraw record,
plus the 60 s edge TTL. Serving a withdrawn agent's JWKS is the specific harm
§6.5 and §7.2 exist to prevent: it makes a retained copy of the withdrawn card
look verifiable again.

### Minor findings
- **m1** `403` is treated as absence, which in the `Withdrawn` branch inverts the meaning: a permission failure reads as a withdrawn entry correctly purged while its card and key set stay served.
- **m2** Check-then-act on S3 with no conditional write: the HEAD pair and the write pair are not atomic and carry no precondition, so the `seq` stamp narrows the window rather than closing it — and the comment claims otherwise.
- **m3** A partially failed sweep reports zero repairs: every `?` discards the `Repairs` accumulated so far, so the alarm meaning "a stream record was lost" stays quiet on a sweep that found drift.
- **m4** The sweep walks the register oldest-updated first — the worst order, since the agents likeliest to have drifted are the recently-changed ones, and they are also the first casualties of the 300 s timeout.
- **m5** `cloudfront-viewer-address` is a CloudFront-generated header, not a viewer header, so `AllViewerExceptHostHeader` never forwards it and the log field is always empty.
- **m6** The edge gate stops a direct origin request's *effect*, not its cost: the stage throttle is applied before the integration, so a flood at the `execute-api` hostname still denies writes arriving through the edge.
- **m7** `writes-per-agent` case-folds a case-sensitive identifier, merging distinct `agentId`s onto one rate key — blunter, never sharper.
- **m8** `publish` writes the card before the key set, so a rotation briefly serves the new card beside the retired key set.

### Checked and sound
The write-authorization core in full; conditional writes and the idempotency
token; cursor pinning; path and key safety; CloudFront behaviour ordering walked
path by path; the `s3:ListBucket` grant to CloudFront confirmed genuinely
unreachable as an enumeration path; bucket hardening; the stream filter and GSI
projection; the `api_5xx` alarm observing the failure it names; the log metric
filter matching what the JSON subscriber emits; the edge gate implementation;
Terraform `fmt`/`validate`; `cargo deny`; `build-lambda.sh`.

---

## Protocol core and client

### Verdict
The write-admission core, the presence table and the canonicalization pipeline
held up under everything thrown at them. The one real hole is in the client.

### M1 — `aithos verify --jwks` reports success (exit 0) for a card signed by a key not in the supplied trusted set
`crates/aithos-cli/src/verify.rs:102`, `crates/aithos-cli/src/main.rs:588` · confirmed by execution

The trusted set is consulted only as a lookup by `kid`. If the signature names a
`kid` the operator did not supply, the tool fetches the key from the URL inside
the card being checked and treats a successful verification as a pass. The exit
status is byte-identical to the genuine case, so any `aithos verify … && deploy`
accepts the attacker's card. Executed end to end with an attacker key and an
unrelated trusted key: `ok … via key named by the card`, `EXIT=0`.

### Minor findings
- **m1** A corrupt key file panics instead of being reported: `decrypt` passes the file's `iv` straight to `Nonce::from_slice`, which asserts on length. Reachable by disk corruption or by anyone who can write but not read the key file.
- **m2** `publish` overwrites the operator's card file before it knows the write is acceptable — and `agent_of` reads the entry identifier from the input card's own `jku`, so a card from a third party can steer where the operator's key signs.
- **m3** The CLI cannot publish to a non-HTTPS registry and blames the signature when it can't: `sign` stamps a `jku` and §5.5 requires HTTPS, so the publisher is sent to look at their key.
- **m4** The client's version pre-flight uses `semver`'s `Ord` while the registry uses precedence, so `1.0.0+b` over `1.0.0` is signed and forwarded rather than caught locally.
- **m5** `1e-400` parses to `0.0` and canonicalizes to `0` — a different value, silently.
- **m6** `agent_of` returns from the whole function on the first signature lacking a `jku`, so a co-signed card loses its entry association and `publish` quietly creates a second entry.
- **m7** `is_canonical_digest` accepts `[g-z]`.
- **m8** An unrecognised listing cursor silently restarts pagination in the in-memory store.
- **m9** `HTTPS://` in a `jku` is refused, though RFC 3986 §3.1 makes the scheme case-insensitive.

### Checked and sound
The presence table re-derived against `a2a.proto`, all 20 messages; the table
digest's dedup shown unable to hide a change; RFC 8785 verified differentially
including UTF-16 key ordering; the strict parse against duplicates, surrogates,
non-finite numbers and depth; thumbprints and key handling; the JWS profile;
write admission spot-checked; §9 status semantics against the table; resource
asymmetry bounded; client key handling at rest; `publish` never signing anything
derived from the registry's response.
