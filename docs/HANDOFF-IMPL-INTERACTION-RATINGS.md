# Implementation handoff — interaction ratings V0

**Date:** 2026-09-17

**Repository:** `aithos-protocol/registry` (`agents-card-registery-2`)

**Starting branch:** `agent-ranks`, published on GitHub

**Reviewed baseline:** `74357167fbbb5a606453f09e4ceefb0870522fa1` (specification 0.0.5 plus the independent review)

**Audience:** a development session with no prior conversation context

Implement the feature end to end in this repository: the agent-side JavaScript
library, the separate ratings API and durable journal, executable vectors,
two-agent demonstration, CI, deployment configuration and operator documentation.
The goal is a small, reliable pilot that design partners can actually install
and exercise. Continue beyond the feasibility experiment into the implementation;
an API sketch, mocked demo or in-memory-only service is not the finished product.

This file is an implementation brief. It does not claim that any runtime exists.
The defaults below resolve the review into a concrete starting plan; incorporate
the resulting decisions into the normative specification before relying on them.

## 1. Starting safely, and what to read

Use the published `agent-ranks` branch, including this handoff. Verify the remote
is `https://github.com/aithos-protocol/registry.git`, inspect Git status and existing
worktrees, and create a development branch such as
`codex/implement-interaction-ratings` from the current `origin/agent-ranks`.
Do not start from `main` and accidentally omit the design branch.

At handoff time, the checkout at
`/Volumes/Math17/aithos/R&D/agents-card-registery-2` is on `indexed-entries` and has
unrelated staged, unstaged and untracked work. Preserve it. The design worktree
was `/private/tmp/aithos-agent-ranks-spec`; this temporary path is not required
to survive. A new isolated worktree from the published branch is sufficient.
Record the actual starting commit, and inspect any later changes before proceeding.

Read these files in order:

1. [Feature overview](interaction-ratings.md), then all of [RANKS.md](../RANKS.md).
2. [Independent 0.0.5 review](../audits/INTERACTION-RATINGS-V0.0.5-REVIEW.md),
   including its three self-contained reproduction scripts and source pins.
3. [Planned vectors](../vectors/ranks/README.md),
   [audit ledger](../audits/LEDGER.md), [CONTRIBUTING.md](../CONTRIBUTING.md)
   and [SECURITY.md](../SECURITY.md).
4. [Registry specification](../SPEC.md), especially identity, canonicalization,
   signatures, write rules and the separation of ratings from the registry core.
5. The existing pure validation code, HTTP/store boundaries and CI described
   in section 4 below; [infrastructure README](../infra/README.md) and
   [production runbook](../infra/RUNBOOK-PROD.md) for deployment conventions.

The [older design handoff](HANDOFF-DESIGN-RANKS.md) and
[0.0.4 review](../audits/INTERACTION-RATINGS-V0-REVIEW.md) are historical.
Do not restore their production agreements, acceptance callbacks or failure
ratings. Do not copy old runbook commands, account assumptions or Git-lock
workarounds without checking their applicability to the current environment.

`RANKS.md` remains the normative wire contract. If implementation resolves an
ambiguity, update the spec, overview, vectors and ledger together. Keep the
independent review unchanged as historical evidence. Do not silently implement
a second protocol in code or use this handoff to override an unchanged MUST.

## 2. Product contract to preserve

Agents independently evaluate the other participant's contribution around an
existing complete A2A artifact, including its business metadata. The evaluator
supplies the score. Aithos records the signed declaration and returns a signed
confirmation from a public chained journal.

| Decision | Required behavior |
| --- | --- |
| Subject | One existing complete artifact per rating, even when several artifacts belong to one task. No artifact means no rating. |
| Directions | Receiver rates producer; producer rates receiver. Neither author needs the other's rating or artifact countersignature. |
| Score | Number in 0..1, at most six decimal places; no stars, automatic evaluator or implied success probability. |
| Identity | Ed25519 public-key thumbprint. The SDK/library exchanges signed context automatically; A2A does not supply a mandatory caller DID. |
| Reference | Producer identity plus a fresh random UUID, retained with its private salt across supported reads and retries. Native `artifactId` alone is insufficient. |
| Observation | Each author signs its own complete captured version. Different peer observations remain admitted and counted when targeted. |
| Unknown receiver | Producer may submit `rated: null`; it remains permanently absent from agent aggregates. No later identity inference or reassignment. |
| Unknown producer | Receiver cannot rate without verified producer context and a valid reference. |
| Immutability | One author slot per log and artifact reference. Exact valid retry returns the original package; a changed statement conflicts. |
| Public service | No account, service API key, registry enrollment or domain requirement. Both signatures and the journal can be checked independently. |
| Privacy | Bodies, business metadata, salts, private keys and peer announcements stay out of public submissions and logs. Public native artifact IDs must be opaque. |
| Delivery | Missing identity or an unavailable ratings service does not automatically refuse ordinary A2A business work. |

The application-facing target remains:

```javascript
import aithos from "aithos-ranking-a2a";

// ... before relevant A2A exchanges ...
aithos.init(supportedSurface, { privateKey });

// ... the agent computes score for its captured artifact ...
const confirmation = await aithos.rank(artifact, score);
```

`init` synchronously installs the supported integration and returns void;
`rank` returns a promise for the verified confirmation package. Define
`supportedSurface` precisely for each role. A server construction descriptor or
wrapper is acceptable when demonstrated and documented; a hidden requirement
for developer-written signing, metadata or acceptance callbacks is not.
The example's `await` must be placed safely in the producer lifecycle (section 5).

No UI, dashboard, moderation system, identity recovery, key rotation, retrospective
linking, peer notifications, background receipt archive, Merkle tree, production
agreement, failure rating or universal SDK adapter is required. False declarations,
invented exchanges and Sybil identities remain explicit V0 limits. Preserve the
distinction between authenticity of a declaration and truth of an exchange.

## 3. Close the four review findings first

Use these defaults for the initial implementation. They narrow the supported
adapter, not the A2A protocol itself. Only broaden them when a concrete partner
need and executable evidence justify the extra path.

| Finding | Initial implementation decision | Evidence needed to close it |
| --- | --- | --- |
| AIR5-01: exact integration/capture/persistence | Pin JS SDK 1.1.0 and HTTPS JSON-RPC. Start with a producer executor publishing complete artifacts in one full terminal Task event. Document actual client and server initialization types, private context persistence and safe rating placement. | Real two-role integration, original producer object, client decoding/copies, restart recovery of supported stored context, mutation rejection and service-outage delivery test. |
| AIR5-02: instance/retry/recovery | One relevant SendMessage exchange and one intended receiver per task. Each native artifact ID denotes one immutable output in that task. A revision or new delivery exchange starts a new task/reference; rereading a stored output preserves its reference/salt. Interrupted-task continuation is initially unsupported. | Repeated publication/read, clone/serialization, concurrent local rank, native ID reused in another task, lost-response and restart scenarios. |
| AIR5-03: SDK tenant/task scope | Initial adapter accepts an empty tenant and requires task IDs unique across all owners sharing a handler/event bus. Unsupported tenant/lifecycle use must never silently acquire valid rating context. | Reproduce the released-SDK constraints, enforce the advertised adapter boundary, and keep simultaneous supported requests isolated. |
| AIR5-04: sum serialization | Preserve exact integer accumulation and half-up means; choose and document a conservative aggregate bound that round-trips to the intended decimal JSON. | The review's extreme-number regression plus boundary tests in Rust and JS. |

A simple option for AIR5-04 is an explicit pilot ceiling of 1,000,000 journal
entries: scores are at most 1, so every role-specific `sumUnits` is at most
10^12. Enforce the ceiling in the atomic head update and use the specified
operational error when capacity is exhausted. This avoids introducing an
aggregate database just to check a bound. Record the chosen limit and behavior
in the spec; do not silently impose it only in code.

For SDK request retries, distinguish three operations:

- Reposting the exact signed rating reuses the same author slot and receipt.
- Reading/retransmitting a saved artifact preserves its original reference.
- Sending a new initial A2A request without an existing task ID can produce a
  new task. A repeated identity UUID does not make production idempotent.
  Preserve an application's existing request deduplication, but do not invent
  a generic business-request deduplicator or claim one exists.

`getTask` recovery is supported only with the retained verified task/correlation
context. Recovery from an arbitrary downloaded artifact or an unobserved response
is not supported. A producer restart must recover its durable artifact reference,
salt and frozen peer context; a receiver restart needs its saved local context
or returns a clear context error. Loss of the optional rating retry cache after
restart does not remove the service's immutable author-slot protection.

These are engineering defaults for the launch session. Resolve the exact adapter
types, context storage and runtime pin with a working slice, then revise
`RANKS.md` to the next draft version and align the overview/vector checklist.
The review is conditional GO, not existing conformance evidence.

## 4. Fit within this repository

Implement the feature in this repository and its delivery tooling, while keeping
the registry's card ownership semantics and ratings journal separate. No card
schema change, registry identity-lineage change, automatic agent registration,
new registry CLI command or modification of stored signed card bytes is needed.

The existing code offers patterns, not a ready-made ratings service:

- `crates/a2a-card/src/strict.rs` and `canonical.rs`: strict JSON and canonical
  representation. Reuse only helpers whose semantics match the ratings profile;
  the artifact projection is not the card presence algorithm.
- `crates/registry-core/src/jwk.rs` and `jws.rs` at the baseline: thumbprints and
  strict verification. Registry card JWS rules are not identical to the closed
  ratings envelope. Avoid coupling ratings to genesis-key authorization.
- `crates/registry-api/src/{api,store,memory,problem}.rs`: pure/store/HTTP
  boundaries and offline integration-test patterns.
- `crates/registry-lambda/src/aws_store.rs`: conditional transaction and
  uncertain-response handling patterns. Its per-agent commit is not a global log.
- `.github/workflows/ci.yml`, `infra/`: pinned toolchain, Lambda packaging,
  provenance, Terraform, least-privilege roles and operational conventions.

Suggested layout (new paths, not existing components):

| Path | Responsibility |
| --- | --- |
| `crates/ratings-core/` | Pure closed schemas, score units, signatures, snapshot/entry hashes, admission rules, comparison and aggregate rules. No network or clock access. |
| `crates/ratings-api/` | Separate HTTP router, store/signer interfaces, memory test implementation and local server entry point. |
| `crates/ratings-lambda/` | Production signer loading, DynamoDB adapter and ratings Lambda bootstrap. |
| `packages/aithos-ranking-a2a/` | Typed Node/JS package, SDK adapter, local context management, signing/submission/receipt verification. |
| `examples/interaction-ratings/` | Two actual SDK agents, evaluator-supplied scores and a reproducible local integration runner. |
| `vectors/ranks/` | Committed executable fixtures shared by Rust and JS. |
| `ratings-openapi.json` | The ratings service contract, separately checked against its router/spec. |
| `infra/ratings/` | Isolated ratings resources and Terraform state configuration. |

Names may follow existing repository conventions, but preserve these boundaries.
Keep AWS dependencies out of the pure core and the JS package. Avoid a broad
crypto refactor; if a shared helper must change, retain all registry regression
tests and explain its compatibility. Root `openapi.json` remains the registry's
contract; ratings endpoints belong to the separate description and service.

## 5. First milestone: a real adapter slice

Reproduce the audit scripts from their embedded copies, with their exact SDK pin.
Then replace the mechanism-only harness with a small installable library slice
and two real SDK applications. Pin a supported Node runtime and package lockfile;
Node 23.9.0 was the audit environment, not a production-runtime recommendation.

Establish these concrete integration contracts:

1. **Client initialization.** Choose the actual supported `Client` or construction
   wrapper. A retained mutable interceptor config works; an arbitrary client
   with missing config is not already instrumentable through an official
   `addInterceptor` method. Preserve existing hooks and method behavior.
2. **Server initialization.** Expose the application-owned executor, Agent Card
   and required store surface at construction/init. Decorate the executor/event
   bus through supported public objects; do not rely silently on private fields.
   If a descriptor is needed, show its full TypeScript type in the docs.
3. **Activation.** The library handles optional extension advertisement, request
   and response activation and metadata. The client must observe the relevant
   response header through the supported transport integration. A signed Agent
   Card must be authored/signed with its advertised extension through the normal
   card-authoring path; never mutate a signed published card after the fact.
4. **Capture.** Stamp/freeze the original complete producer artifact before SDK
   cloning and delivery, then independently capture the receiver's decoded
   object. Save scope, role, verified peer declaration, correlation, ref, salt
   and snapshot. A WeakMap alone is not the persistent context store.
5. **Durability.** Define how private context lives alongside the application's
   durable task/artifact storage. The plain SDK `TaskStore.load/save` interface
   does not provide a cross-process compare-and-set operation. A local lock is
   sufficient only for an explicitly supported single-writer producer deployment;
   multiple writers require a demonstrated atomic storage primitive. State this
   choice at initialization instead of pretending all stores are interchangeable.
6. **Safe publication.** The event bus returns void before asynchronous storage
   finishes. Gate response eligibility on successful persistence without waiting
   for Aithos. A store failure must not lead to silently minting another reference.
7. **Safe rating.** Awaiting `rank` inside a still-running executor can delay the
   blocking A2A response. Demonstrate a producer placement that lets delivery
   finish while handling both promise resolution and rejection. Do not hide a
   floating promise or an unhandled rejection behind the two-call example.

Any local persistence configuration belongs to documented initialization/setup,
not extra per-artifact business calls. Do not serialize private context into
public Agent Cards or copy it wholesale into transport metadata.

The missing-identity path must still serve ordinary business requests. The
producer may keep local context and later rate with `rated: null`; the adapter
must not create a trusted identity from an invalid signature. An unsupported
rating path returns a clear local error without adding an automatic access gate.

**Milestone evidence:** both roles can initialize, exchange a complete artifact,
resolve their own captured context and construct their separate signed payloads.
Exercise cloning, concurrent calls, durable producer restart and outage-safe
delivery. This closes the integration choices; continue with the full service.

## 6. Pure rules, cryptography and executable vectors

Implement the exact closed schemas and validation order from `RANKS.md`.
Reject duplicate JSON members before conversion to a generic object; enforce
canonical base64url, JCS header/payload bytes, Unicode, timestamp, key, score,
size and role rules. Use decimal/integer score conversion with a proven exact
round trip, rather than trusting binary multiplication by one million.

Ed25519 verification must reject weak/small-order keys and invalid/noncanonical
signatures. The review demonstrated that a generic Node `crypto.verify` call
alone does not meet that requirement in its tested runtime. Select a maintained
implementation, pin it and prove strict behavior with shared adversarial vectors.
Apply the same checks to peer identities, ratings and service confirmations.
Derive `x` from the private seed and compare it; never trust a supplied public
component without checking. No private key leaves its owner.

Implement the artifact projection explicitly: ordered parts, all business
metadata, prescribed optional defaults and only the exact reserved exclusions.
Hash decoded salt bytes. Do not fetch URL parts. Reject a lost `data:null`
oneof/empty part in the initial JS path; nested null and empty text remain valid.

Turn the entire vector checklist into concrete input/output fixtures with fixed
test keys, salts, UUIDs and times. Include canonical payload bytes, signing input,
signatures, thumbprints, artifact digest, rating ID, record/entry hashes and an
anchored journal prefix. Make Rust and JS consume the same fixtures; have one
implementation sign and the other verify. Audit scripts with symbolic identities
are useful reproductions, not valid wire fixtures or a production verifier.

Provide a small executable verification example that checks a receipt and journal
prefix independently of the service's summary. A permanent monitoring application
or a new registry CLI command is unnecessary.

## 7. Ratings API and durable append

Implement every endpoint and error in `RANKS.md` §§6–9, including original receipt
lookup, artifact listing, fixed-prefix comparison, full journal pages and both
agent-role means. Unknown identities yield empty views; nullable targets never
enter any agent aggregate. HTTP success means a durable commit already happened.

For the first AWS implementation, prefer a dedicated DynamoDB table with a
single log head and immutable entries. The small submitted envelopes allow
keeping the complete confirmation package in the committed entry; no S3 journal
publication or asynchronous reconciler is needed for the pilot.

An illustrative layout per `LOG#<logId>` partition is:

- `HEAD`: size, head hash and immutable service identity/configuration binding.
- `ENTRY#<zero-padded-position>`: exact submission and original signed receipt.
- `SLOT#<producer>#<artifactUuid>#<rater>`: admitted rating ID and entry pointer.
- `RATING#<ratingId>`: entry pointer for direct lookup.

Use an unambiguous encoding for compound keys and a width covering the documented
position limit. One hot head is an accepted low-volume serialization point;
do not introduce distributed ordering machinery.

The append algorithm must be demonstrably equivalent to:

1. Strictly validate the whole submission, including on a retry.
2. Read the slot authoritatively. Identical payload returns its original package;
   another valid payload in that slot returns `409 RATING_EXISTS`.
3. Read the current head, derive the candidate next entry and sign its receipt.
4. Atomically condition on that head and absent slot/entry/rating pointer, then
   store the package, pointers and new head. Put the head condition on the same
   update action; do not issue two transaction actions on the same item.
5. Return the package only after commit. A head race rebuilds the candidate
   against the new head. An uncertain commit result is reconciled through the
   slot/head before returning success, conflict or unknown/unavailable status.

Stored slot uniqueness is permanent. DynamoDB's temporary request-token window
is not a substitute. Keep a stable token only for an identical transaction;
rebuilding its entry/head changes the transaction. See the official
[transaction API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).

Use authoritative base-table reads for admission, commit reconciliation and
fixed-prefix data. [DynamoDB consistency rules](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html)
do not allow strongly consistent GSI reads. Resolve `through` once, read immutable
entries through that position and derive the view from that prefix. Follow all
storage pages before claiming no matching item exists; an empty filtered storage
page is not the end of the journal. Full-prefix derivation is acceptable at pilot
volume; no materialized aggregate subsystem is required.

Implement a memory store with the same transaction semantics for fast tests,
then test the real storage adapter with concurrent writers and injected lost
responses/failures. Missing required entries or unavailable storage must not
be reported as an empty successful result. Current means, comparisons and heads
must not inherit stale immutable-card cache behavior.

Load a distinct durable Ed25519 service key; pin its public identity. Restarts
must reuse the key and journal. Fail on a key/log mismatch rather than creating
a new key or silently resetting a journal. Receipt signing can precede a candidate
transaction internally, but no uncommitted receipt may escape through a response,
log, index or public object store.

## 8. Complete the library and two-agent demonstration

Finish `rank` around the proven adapter: validate captured context and current
input, compute its own snapshot, freeze one signed statement per author slot,
submit, validate the exact acknowledged payload and service identity/hashes,
then return the complete confirmation package. The retry cache is keyed by
the slot, not only object identity. Simultaneous equivalent calls share the
frozen payload/time; changed score, observation or target never replaces it.

Use bounded transport retries of that frozen submission. Distinguish local
ineligibility, explicit service rejection and unknown acceptance. Do not convert
a timeout to definitive rejection or generate a new ref/timestamp to retry.
No durable client receipt archive or background retry daemon is required.

Package the library with public types, pinned supported SDK/runtime versions,
explicit unsupported-path errors and local key onboarding instructions. The
registry CLI's P-256 key format is not the input. Provide a local service override
with an explicitly pinned test log identity; the public default origin/log must
come from the actual deployment, never from a guessed URL or a test key.

The demo runs producer and receiver as separate processes with separate keys,
using the packaged library and real SDK JSON-RPC transport. Both compute their
own score variables. Run both submission orders, show the returned receipts,
read the artifact's ratings and each role's summary, and verify a retained receipt
against the full prefix. A fresh checkout must be able to run it from documented
commands. Local HTTP is acceptable for a clearly labeled localhost harness;
the hosted pilot verifies the actual HTTPS path.

Use `npm pack` and install the resulting tarball in a clean fixture application
so the demo cannot pass only because it imports unpublished source internals.
Record package name availability/ownership before any npm release; distribute
the tested tarball to a pilot if registry publication is not yet available.

## 9. Acceptance scenarios

The full vector checklist remains required. At minimum, preserve this end-to-end
matrix, using real cryptography and HTTP where the scenario crosses those layers:

| Scenario | Expected evidence |
| --- | --- |
| Receiver alone rates 0.77 | One durable entry, valid receipt, producer count 1/mean 0.77 immediately. |
| Producer also rates 0.25 | Separate receipt and receiver count 1/mean 0.25; works in either order. |
| Honest distinct captured observations | Both notes retained and counted; reciprocal comparison is divergent. Construct distinct pre-capture snapshots, not a post-capture mutation that the library should reject. |
| Missing receiver identity | Business artifact delivered; producer note has null target and enters no agent aggregate. |
| Later receiver note after null | Producer's original note stays null/unilateral; no automatic attribution. |
| Invalid identity/signature/log/key | Correct error or unknown-receiver behavior; no false trusted target and no invalid public note. |
| Duplicate and simultaneous calls | One slot/position/contribution, original receipt on identical retry; changed payload conflicts. |
| Lost POST or storage response | Reconcile the committed result; no extra entry, new timestamp or false replacement. |
| Multiple artifacts and reused native IDs | One stable reference per output, separate refs across tasks; parallel requests never mix peers. |
| Reload/serialization/restart | Supported persisted instances keep ref/salt/context; unsupported bare copies fail clearly. |
| Mutation, missing output, incomplete/unsupported input | Local rejection; no invented failure rating or silent codec-loss commitment. |
| Aithos unavailable | A2A delivery continues; rating failure/unknown outcome is handled without an unhandled promise. |
| Journal alteration/fork examples | Altered signatures/hashes fail; incompatible retained views are detectable when compared. No claim of automatic global fork detection. |
| Fixed-prefix views | Concurrent later appends do not change old pages, comparison or means; recomputation agrees with every view. |
| Durability/concurrency faults | No success before commit, no orphan visible receipt, no reused position, no silent journal reset. |
| Existing registry regression | Card bytes, signatures, domains, ownership and existing public endpoints retain their behavior. |

## 10. CI, deployment and operational completion

Extend CI with the package build/type checks, executable Rust/JS vectors, offline
HTTP tests, the packaged two-agent demonstration and Terraform validation for
the ratings root. Keep the current Rust checks, dependency policy, OpenAPI lint
and `a2a-card` WASM build. Define documented root npm scripts such as
`typecheck`, `test:ratings` and `test:ratings:e2e`; do not invent green check names
without running them. The baseline CI's Lambda artifact job only builds main
pushes: provide a verifiable way to build the ratings artifact for the exact
pilot revision without assuming a feature-branch artifact already exists.

Existing Rust checks include:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
rustup target add wasm32-unknown-unknown
cargo build -p aithos-a2a-card --target wasm32-unknown-unknown
cargo deny check bans licenses sources advisories
```

Validate both Terraform roots when present, with backend-free validation for CI.
Keep live tests explicitly opt-in, scoped to disposable test identities and the
intended pilot service. The existing public registry is append-only; do not run
its live write suite merely as an incidental ratings check.

Provide a dedicated ratings deployment with a configured HTTPS origin, separate
table/signer, body and POST rate limits, logs without submitted secrets, basic
error/conflict/capacity metrics, budget controls and a restoration procedure.
Follow the repository's AWS/runtime conventions, verify the actual target account
and region, and use a distinct Terraform state. No rewrite of registry tables or
destructive migration is part of this feature.

Keep signing material in an appropriate secret store with a documented loading
path and least-privilege access. Do not put a private seed in Git, a demo default,
Terraform state via a secret-value resource, command output or public artifacts.
Pin and verify the public service key in the deployed library configuration.
Separate development and production keys/journals; key rollover creates a new
log under the V0 contract.

Build and identify the exact service zip and npm tarball by commit/checksum;
retain provenance consistent with the existing release process. Add a ratings
runbook with install, configure, start, smoke, concurrency/retry verification,
backup/restore and code rollback steps. Rolling back code must retain every
acknowledged entry and the same signer. Never serve a restored older prefix as
the current complete journal while acknowledged entries remain unrecovered.

Complete local implementation, tests, deployable artifacts and a concrete
Terraform plan before seeking any missing deployment decision. Deployment and
package publication use the environment, credentials and authorization supplied
to the development session. If the target origin/account, service signer or npm
ownership is missing, state the exact remaining input; do not guess a production
target or silently label “deployment ready” as “deployed.” Once configured and
authorized, deploy the pilot and exercise both roles against its real HTTPS URL.
No account creation or service API key is required for partner rating calls.

## 11. Documentation and definition of done

Keep the feature's very short English summary and its code example before the
detailed explanation. Replace `supportedSurface` with actual runnable setup
examples for both roles and explain the producer's safe async placement. Document
key onboarding, SDK limits, private context persistence, error behavior, service
configuration and the distinction between public signatures and private content
verification. Generate a separately validated ratings OpenAPI description and
document where the pilot exposes it; do not silently expand the registry API.

Record how AIR5-01 through AIR5-04 were resolved, linking each to implementation
and executed checks in the ledger or a new implementation report. A source-level
assumption, an in-memory simulation and a hosted test are different evidence.
Report them separately. Never mark an audit finding fixed just because the
corresponding paragraph or test TODO was added.

The delivery must include:

- Versioned spec/docs aligned with the actual supported adapter and wire contract.
- Working installable JS package, both SDK integration directions and durable
  supported producer context; no hidden per-artifact developer work.
- Separate persistent service, strict verification, immutable retry behavior,
  signed receipts, all read views and a checked atomic append implementation.
- Executable shared vectors, real two-agent E2E, storage fault/concurrency tests
  and passing relevant existing-registry regression checks.
- CI, reproducible service/package artifacts, Terraform and an operator runbook.
- A deployed and exercised pilot when its target is supplied; otherwise all
  preparation complete with the exact external blocker and remaining command.
- Committed/pushed development branch and a reviewable PR with test evidence,
  deployment state, known supported limits and commit/package identifiers.

Do not stop after closing the adapter feasibility question. Carry the agreed
scope through the library, service, durable storage, verification, packaging and
pilot validation. Handle routine engineering choices autonomously within these
boundaries, document them, and preserve unrelated work throughout.
