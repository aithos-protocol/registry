# Aithos Interaction Ratings — V0

**Status:** revised specification draft; not implemented
**Version:** 0.0.5
**Date:** 2026-09-17
**A2A baseline:** v1.0.1, the commit pinned by `SPEC.md` §2

For the short summary and feature overview, see
[`docs/interaction-ratings.md`](docs/interaction-ratings.md).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**
and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

This document is **additive**: a separate ratings service and an optional A2A
extension. It changes no registry endpoint, Agent Card schema, card
canonicalization rule or stored card byte. A rating is an individual evaluation;
this profile defines no global ranking of agents.

This revision supersedes 0.0.4's production agreements, failure ratings and
three-envelope submission. It follows the design-partner simplification after
[the independent review](audits/INTERACTION-RATINGS-V0-REVIEW.md). The historical
handoff and audit remain evidence of earlier designs, not current requirements.
Wire names below are proposals, not a deployed package or API.

## 1. Purpose and exact claim

The initial use case is B2B e-commerce, including evaluation of buyer/requester
agents by sellers and sellers by buyers. The service is public: no account,
API key, registry enrollment, domain or published Agent Card is required.

An admitted rating makes exactly this claim:

> This key holder assigned this score to the counterpart's contribution around
> this uniquely referenced artifact, in the locally observed version committed
> by this digest. The statement names the counterpart when known; otherwise it
> remains an unattributed artifact rating. The service acknowledged recording
> this declaration at this journal position.

The signature authenticates the declaration's author and contents. It does
not prove the exchange happened, the named target participated, delivery was
successful, or the evaluation is fair. There is no signed production agreement
and no requirement for the counterpart's rating or signature over the artifact.

### 1.1 What is rated

An existing **complete A2A artifact, including its content and business
metadata**, is the required subject. The score evaluates the other participant's
contribution around that artifact, not the signer's own work.

| Author's role | Rated role | Example meaning |
| --- | --- | --- |
| Receiver | Producer | Quality and usefulness of the received output. |
| Producer | Receiver | Quality of the request, supplied information and cooperation that led to the output. |

Producer/receiver are roles for this artifact. In the common buyer/seller flow,
the receiver is the requester and the producer is the provider. A quotation is
only an illustrative business artifact, not an A2A/AI Catalog concept or a
required pilot workflow. The library does not inspect business intent.

### 1.2 V0 boundary

- Each note references one artifact instance and commits to its author's local
  version. Distinct artifacts are rated separately, even within one task.
- One optional, immutable score in 0..1 per author and artifact reference.
- Each participant signs and submits independently in either order. A missing
  peer rating or different peer observation does not suppress a valid note.
- Unknown receivers may be left unnamed. Their artifact ratings do not affect
  any agent's reputation and are never retroactively attributed in V0.
- Public role-specific arithmetic means, a linear hash journal and signed
  confirmations. No free-text reviews, editing, deletion or automatic scoring.
- Client-side integration through `init(sdkInstance, { privateKey })` and
  `rank(artifact, score)`, with no acceptance callback or business-protocol call.
- First adapter: one pinned SDK/transport profile (§9), complete artifacts;
  fragmented artifact streaming and universal SDK compatibility are deferred.

No artifact means no rating: failed production, rejection, cancellation,
silence and timeouts have no standalone rating representation. A complete
artifact already produced/received may be rated regardless of a task's other
outcomes; task success is not proof of production consent. Discovery, messages
and task creation do not start a ratings-service transaction.

### 1.3 A2A, discovery and identity

A2A does not mandate a global agent DID, mutual discovery or a caller Agent
Card. A server can reply on the request's transport without knowing a public
agent identity for the caller. Transport authentication may identify an account
or application rather than the key used by this ratings profile.

Native `artifactId` is unique only **within a task**. A signed Agent Card plus
`artifactId` does not establish global uniqueness: the same card and ID may be
used in different tasks. `contextId` can group multiple tasks. An Agent Card is
also versioned descriptive data, not the stable reference chosen in §3.

A2A has no standard task-artifact signature field. Optional Agent Card
signatures authenticate the card. AI Catalog discovers resources and carries
optional trust metadata; it supplies neither runtime participation proof nor
artifact ratings. All additional identity exchange and rating signatures here
belong to the Aithos library. No open upstream proposal is a dependency.

## 2. Identity and signed objects

### 2.1 Participant identity

For V0, each participant uses one Ed25519 key pair. `agentId` is the RFC 7638
SHA-256 thumbprint of its public JWK, encoded as unpadded base64url. It is 43
characters, and every participant signature MUST have `kid == agentId`.

The initialization call accepts an existing private key. The library MAY
provide helpers to generate a new key locally or load an existing one. It
MUST NOT silently replace a missing, invalid or unreadable supplied key.
The operator manages durable key storage. The initial JS adapter accepts an
Ed25519 private JWK with exactly `kty`, `crv`, `x` and `d`; `d` is an unpadded
base64url 32-byte seed. It derives and checks `x` before use. Other private-key
formats require an explicit import helper. Existing P-256 registry CLI keys
are not directly compatible. This private input is never a public envelope.
Private keys MUST NOT be sent to the service or the counterpart.

There is no key rotation, delegation, identity recovery or revocation in V0.
A different key is a different ratings identity. This uses the registry's
thumbprint construction but **not** its genesis-key lineage or authorized-key
set. A registry identity whose keys have rotated MUST NOT be presented as
continuously authenticated by this profile. Registry publication, withdrawal,
and domain certification have no effect on V0 ratings.

### 2.2 Encoding rules

The profile identifier, also the proposed extension URI, is:

```text
https://aithos.world/ext/interaction-ratings/v0
```

It is a draft identifier, not an assertion of upstream registration or a live
service. All signed payloads below include `profile` with that exact value
and `type` with the value specified for the object.

Objects defined by this profile have closed schemas: shown fields are REQUIRED
unless explicitly optional; unknown members and JSON `null` are rejected
unless allowed below. This does not restrict unrelated A2A metadata.
Implementations MUST reject duplicate members, invalid Unicode and invalid
base64url, and MUST NOT silently repair signed values. Base64url is unpadded
and canonical: decoding and re-encoding MUST reproduce the same string.
Strings are not Unicode normalized. Timestamps use exactly
`YYYY-MM-DDTHH:mm:ss.sssZ` and MUST denote
valid UTC instants. Participant timestamps are self-declared, not trusted time.

`JCS` means RFC 8785 canonicalization. `UTF8` and `ASCII` produce bytes;
`||` is byte concatenation; `LF` is the single byte `0x0a`. Define:

```text
H(label, object) = "sha256:" || lowercase_hex(
  SHA-256(UTF8("aithos-ratings-v0/" || label) || LF || UTF8(JCS(object)))
)
```

Every hash using `H`, and every `artifactDigest`, uses `sha256:` followed by
exactly 64 lowercase hexadecimal characters. Profile-defined integer fields
MUST be in `0..9007199254740991`, with the narrower ranges stated below; this
does not prohibit negative numbers inside arbitrary artifact data/metadata.
Identity-valued fields MUST be canonical base64url encodings of 32 bytes;
only identities backed by an available public key can be recomputed as its
thumbprint. The service verifies the author, not ownership of a target ID.
Signed envelopes use small, explicitly defined objects. Artifact commitments
use the dedicated projection in §4, never a generic SDK serialization.

### 2.3 Signature envelope

`Signed(P)` is this object, using flattened JWS JSON serialization:

```json
{
  "jws": {
    "protected": "<base64url of canonical protected header>",
    "payload": "<base64url of canonical payload P>",
    "signature": "<base64url Ed25519 signature>"
  },
  "key": { "kty": "OKP", "crv": "Ed25519", "x": "<public key>" }
}
```

The protected header is exactly `{"alg":"EdDSA","typ":"JOSE","kid":"<thumbprint>"}`.
Its bytes and the payload bytes MUST equal their JCS encodings. Sign the RFC
7515 input `ASCII(protected || "." || payload)`. Only Ed25519 under RFC 8037 is
allowed; `none`, MACs, other algorithms, unprotected headers, `jku`, `crit` and
`b64` overrides are rejected. The JWK has exactly the three shown members;
`x` decodes to 32 bytes and the signature to 64 bytes. Private key material
MUST be rejected before storage or logging.

The verifier MUST check the thumbprint, the expected signer for the object,
the signature, and the payload schema and bindings. It MUST use strict
Ed25519 verification and reject weak/small-order keys, consistent with the
registry's existing verifier. An arbitrary supplied key is not an identity
substitute: its thumbprint must match the identity that is being verified.

### 2.4 Service identity

The service has a separate Ed25519 signing key. `logId` is its public JWK
thumbprint. One `logId` identifies one journal and one signing key for V0.
Both participants MUST use the same `logId` when using this profile together.

The ratings library is configured with a service HTTPS origin and its expected
`logId`; Aithos is the default deployment. Its public descriptor supplies the
public key. The key's thumbprint MUST match that expected identity. A key fetched
from an arbitrary URL is not by itself proof that its operator is Aithos.
Service key rollover requires a new journal in V0; histories MUST NOT be
silently combined or restarted under the old `logId`.

## 3. Automatic context and unique artifact references

### 3.1 Library-managed identity exchange

Each application initializes its supported SDK adapter **before** the relevant
exchange. Initialization derives its local public identity and installs hooks
for outgoing/incoming messages and artifact production/reception. It cannot
recover a missing peer key merely from a URL, task ID or message role.

For the initial request/response binding, the receiver's library generates a
random lowercase UUID v4 `requestId` for a new outgoing `SendMessage` call and
adds a signed identity declaration to the request's extension metadata:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "peer-identity",
  "logId": "<service thumbprint>",
  "requestId": "<request correlation UUID>",
  "agentId": "<announcing key thumbprint>",
  "role": "receiver"
}
```

The producer returns the same payload shape, with its own `agentId` and
`role: "producer"`, echoing `requestId`. The signer MUST equal `agentId`;
`logId` MUST match local configuration. A response announcement MUST match
the locally retained request correlation. Exact retried calls retain their
original identity envelope and correlation. This is technical correlation,
not a production agreement, business acceptance or a rating.

The producer verifies a received declaration before using its identity as a
rating target. The receiver verifies the producer declaration before assigning
a received artifact to that producer. The adapter associates declarations with
the actual SDK request/response and its enclosing task, not a process-global
"last peer". Concurrent exchanges MUST NOT mix identities or artifacts.

These signatures prove who signed the identity context. They do not establish
legal identity, fresh possession in the face of replay, business participation
or a trusted endpoint binding by themselves. Existing A2A transport security,
authentication and task access controls remain the application's responsibility.
Identity announcements are not a substitute authentication protocol, and the
ratings service does not receive or certify them as proof of an exchange.

If the producer receives no usable announcement, it can still produce an
artifact and return its own announcement using a fresh `requestId` retained
with that local context. Its receiver remains unknown. Retrospective bootstrap
from a bare artifact or a previously unobserved response is not supported by
the first adapter. Correlation IDs are distinct from artifact and rating IDs.

### 3.2 No mandatory identity gate

Missing, invalid or incompatible identity metadata MUST NOT be treated as a
verified peer identity. It MUST NOT automatically block the business request
or artifact delivery in this V0. The application decides whether to serve an
unidentified client under its existing access policy. A required identity
extension or automatic access-denial feature is not implemented by this design.

A producer with an unknown receiver can submit `rated: null` (§5). A receiver
without a verified producer context cannot rate that artifact through the
library, because it cannot establish the producer component of its reference.
A missing reference or incomplete artifact is different from a missing receiver:
no artifact rating is eligible without its reference and content commitment.

When both compatible adapters are active and the identity exchange succeeds,
both roles have the identities needed to rate. Neither must submit a rating
for the other's targeted note to be admitted.

### 3.3 One stable reference per artifact instance

Before exposing a complete produced artifact through the SDK, the producer's
library generates and attaches:

```json
{
  "producer": "<producer agentId>",
  "id": "<fresh lowercase UUID v4>"
}
```

This object is `artifactRef`. The UUID MUST use a cryptographically secure
random generator. The pair provides a producer namespace and negligible
accidental collision probability without a central allocator. It is not a DID.
The producer also generates a private random 32-byte `artifactSalt` once.

The library MUST retain the reference and salt with the produced artifact
before delivery. Retries, repeated reads and serialization of the same artifact
instance MUST preserve them. Creation/recovery of this mapping MUST be atomic
within the producer's actual task-store scope (including tenant/owner when
applicable), task ID and native artifact ID. Concurrent publication must not
mint two references for the same instance. Use the application's existing
artifact/task storage; no new production-acceptance store is needed.

A newly produced artifact, an intentional revised output or a new delivery
exchange requires a fresh reference and salt. Re-reading the existing delivery
does not. The supported pilot has one intended receiver per artifact instance;
forwarding into a new exchange creates a new instance under its new producer.
The receiver preserves the transmitted reference and salt exactly. It MUST NOT
replace them with its own UUID, hash, or values fetched from Aithos.

The producer component MUST equal the local producer identity when publishing,
and the verified producer identity when receiving. A mismatch makes the artifact
ineligible. The observed native `artifactId` need not equal the UUID in the
reference: they serve different purposes.

Distinct artifacts with identical business content still have distinct
references. Native IDs reused in other tasks/endpoints are not a collision in
this namespace. The service cannot prevent a dishonest author inventing or
reusing references; uniqueness is an adapter rule and a signed declaration,
not independent proof of a real-world artifact inventory.

### 3.4 A2A carriers and local capture

The extension is advertised in the Agent Card with `required: false`. An HTTP
client requests it through `A2A-Extensions`; an activating producer echoes the
URI in that response header. Initialization must establish activation early
enough for the chosen SDK's header handling.

Without peer activation, the producer may still keep reference/salt and its
snapshot in local artifact/task context for an unattributed note. It does not
claim a successful two-sided identity exchange or require the caller to process
Aithos metadata. Ordinary A2A handling remains subject to the application's
existing policy.

| Carrier | `metadata[extension-uri]` value |
| --- | --- |
| `SendMessageRequest` | `{identity: Signed(peer-identity)}` from the receiver. |
| Producer response `Task` | `{identity: Signed(peer-identity)}` from the producer, correlated with the request. |
| Complete `Artifact` | `{artifactRef, artifactSalt}`; salt is canonical unpadded base64url of 32 bytes. |

Artifacts carrying the extension also list its URI in `extensions`. The native
A2A `TaskStatus` has no metadata field. The adapter keeps origin, tenant, task,
request correlation, identity declarations and local artifact snapshot in its
own context; they are not extra arguments to `rank`. Task recovery preserves
identity context and artifact metadata under the existing access controls.

The producer adapter captures the complete output at the SDK publication
boundary; the receiver adapter captures what its SDK delivers. A provider call
to `rank` before that publication boundary is not yet eligible. Capture freezes
the reference, salt, counterpart when known and local snapshot before later
application mutations. The adapter MUST NOT replace its observed version with
the peer's version, or regenerate protocol metadata, to force matching hashes.
A supplied artifact that was mutated after capture MUST be rejected locally.

Copying an object through a supported serialization path must preserve its
context, or `rank` must return a context error. Bare object identity/WeakMap
state is not a durable recovery promise. The V0 does not infer eligibility
from arbitrary objects copied from the public internet.

## 4. The signed artifact observation

Every admitted note contains exactly one observation:

```json
{
  "artifactId": "<native ID in the author's local snapshot>",
  "artifactDigest": "sha256:<64 lowercase hex characters>"
}
```

The reference identifies the artifact instance; the digest commits to the
particular local version, including business metadata. Both are covered by the
same rating signature. Equal references with different local IDs or digests
are possible observations, not grounds for rewriting or rejecting either note.
A signature protects the declaration, not the truth of its claimed provenance.

### 4.1 Snapshot projection

Each caller's library constructs a private `ArtifactSnapshot` from its locally
observed complete artifact using the pinned A2A schema. It MUST reject unknown
artifact/part fields, invalid field types, missing required content and
ambiguous oneof values before projecting. `parts` MUST be nonempty. The snapshot
has exactly these members:

| Member | Value |
| --- | --- |
| `artifactId` | The artifact's required identifier. |
| `name`, `description` | The supplied strings, or `""` when absent. |
| `parts` | The ordered array of part projections defined below. |
| `metadata` | Every supplied top-level metadata member except the exact extension URI in §2.2; `{}` when absent or empty after exclusion. |
| `extensions` | The supplied URI array in its original order, excluding this profile's own URI; `[]` when absent. |

Each part projection contains exactly one content member from `text`, `raw`,
`url` or `data`, using the corresponding A2A ProtoJSON representation. `raw`
is standard padded base64 of the bytes, not base64url. It also contains
`metadata` (the complete part metadata, default `{}`), `filename` and
`mediaType` (strings, default `""`). Oneof presence is significant, including
an empty text string or a `data` value of `null`. Part order, array order and
all values inside metadata and structured data are preserved. Only absent
optional fields receive the defaults above; an invalid explicit null is not
silently replaced. Nested arbitrary JSON null values remain valid.

This is a profile-specific projection, not the Agent Card presence algorithm.
Canonicalization uses JCS after projection. SDK adapters MUST map their typed
objects to this projection explicitly and reject unsafe integers or values
that cannot be represented without loss in the JCS data model. They MUST NOT
silently drop business metadata or substitute the counterpart's digest.
Validation applies to the captured local representation; it is not a claim
that upstream SDK decoding preserved the wire bytes. Supported SDK inputs
must be tested for content/metadata preservation. A lost content alternative,
such as a decoder turning `data: null` into an empty part, MUST cause rejection
unless the adapter captured the complete value before that loss. General
cross-SDK equivalence is not a V0 requirement.

### 4.2 Commitment and accepted divergences

Both participants use the producer-generated `artifactSalt` transported with
this instance. Neither creates a new salt at rating time. Each computes its
own digest, never copying the peer's digest:

```text
artifactDigest = "sha256:" || lowercase_hex(SHA-256(
  UTF8("aithos-ratings-v0/artifact") || LF || artifactSalt
  || UTF8(JCS(ArtifactSnapshot))
))
```

The salt, artifact body and business metadata MUST NOT be sent to the service.
Anyone with the private snapshot and salt can verify the content commitment;
a public reader can verify the signed reference and digest, not reconstruct
the private artifact. The reserved namespace holds only protocol bookkeeping;
business fields MUST NOT be hidden there. `artifactRef` is independently covered
by the rating signature, while `artifactSalt` participates in this commitment.

A URL part commits to the URL and supplied metadata, not future downloaded
bytes. The library does not fetch remote content. JCS ignores object key order
and JSON formatting whitespace; whitespace inside text/metadata strings is
significant. Arrays and part order remain significant.

Different SDKs, transport conversions or application processing can cause
honest participants to observe different versions. V0 explicitly accepts this:
no cross-SDK equality guarantee, automatic fraud label or score suppression.
Each adapter still must sign its complete captured local representation and
must not silently discard business metadata. An unrepresentable or incomplete
local value is a local error, not an invented valid observation. Known codec
losses and unsupported inputs must be documented for the selected adapter.

## 5. Rating statement and attribution

Each participant independently signs this exact payload shape:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "rating",
  "logId": "<service thumbprint>",
  "artifactRef": { "producer": "<producer agentId>", "id": "<artifact UUID>" },
  "observation": {
    "artifactId": "<locally observed native artifact ID>",
    "artifactDigest": "sha256:<64 lowercase hex characters>"
  },
  "rater": "<author's agentId>",
  "rated": "<counterpart's agentId, or null when allowed>",
  "ratedRole": "producer",
  "score": 0.77,
  "issuedAt": "2026-09-17T10:00:06.000Z"
}
```

`rated` is REQUIRED but may be JSON `null` only in the producer-to-unknown-
receiver case. All other shown fields are required and non-null. `artifactRef`
and `observation` have exactly the members shown. The signer MUST equal `rater`.
The structural role rules are:

| Direction | Required bindings |
| --- | --- |
| Receiver rates producer | `ratedRole == "producer"`; `rated == artifactRef.producer`; `rater != rated`. |
| Producer rates identified receiver | `ratedRole == "receiver"`; `rater == artifactRef.producer`; `rated != rater`. |
| Producer rates artifact with unknown receiver | `ratedRole == "receiver"`; `rater == artifactRef.producer`; `rated == null`. |

The library MUST take a non-null target only from its verified local peer
context (§3), never infer it from an artifact ID, an Agent Card's name, an
unsigned public-key claim or another author's later rating. A null-target
note has a known author and artifact; only its receiver attribution is absent.
It is recorded publicly but contributes to no agent's received score.

The service verifies the author's signature and these internal bindings. It
has no peer signature proving the named target participated. A forged claim
about participation can therefore still be a validly signed declaration.
Third-party claims and invented artifacts cannot be excluded just by these
checks; V0 does not advertise verified bilateral transactions.

### 5.1 Score

`score` MUST be a finite JSON number in 0..1 with at most six fractional decimal
places. Extra precision is rejected, not rounded. Interpret the canonical
JSON decimal exactly: `scoreUnits = score * 1000000` must be an integer in
0..1000000, not a binary-float equality test. For example, 0, 0.1, 0.77 and 1
are valid; strings, missing scores and 0.1234567 are not.

The author/application computes the score. `rank` receives an explicit variable;
it does not run an evaluator, copy a peer score or infer a score from an SDK
status. Higher means better under the author's criteria. An absent score is
not zero; 0.77 is not a calibrated 77% success probability. The partner defines
its business rubric; no quotation schema or rubric ontology is required.

Signing authorizes public submission to the specified `logId`. Anyone holding
the signed submission may relay it there. It does not authorize changing its
target, reference, digest, score or other signed field.

### 5.2 Deferred identity correlation — feasible, outside V0

It is technically possible to define a later rule linking an initially
unattributed producer rating with a receiver's signed claim about the same
artifact reference. Such a rule would need explicit role/binding checks and
handling for multiple claimants. A common ID or digest alone does not prove
which key was the real receiver.

V0 MUST NOT implement that retrospective attribution. A `rated: null` note
remains null and excluded from every agent aggregate even if a receiver later
rates the producer. Listing both notes under one reference is possible; it
is not a reputation assignment. Any future association must be independently
verifiable from signed records and must never edit the original note/receipt.
Adding a unique ID to a note alone solves neither correlation nor participation.

## 6. Submission, uniqueness and retries

```http
POST /v0/ratings
Content-Type: application/json
```

The body has exactly one member:

```text
{ rating: Signed(rating-payload) }
```

There is no request/acceptance bundle, provider artifact signature, peer rating
or preliminary registration call. The service validates the closed schema,
limits, canonical encodings, strict author signature, log identity, score,
artifact reference/digest format and role bindings before applying uniqueness.
It cannot recompute the private artifact digest or check transport capture.

Define `ratingId = H("rating", decoded rating payload)`. This identifies the
statement, not its artifact. The service MUST atomically admit at most one
rating for `(logId, artifactRef.producer, artifactRef.id, rater)`:

- First rating in an author slot: `201 Created` and its confirmation.
- Same validated payload/ratingId: `200 OK`, original stored confirmation;
  no new entry, timestamp or score contribution.
- Different valid payload in the same slot: `409 RATING_EXISTS`, including
  changes to score, digest, native artifact ID, timestamp or `rated`.

The exact stored envelope is returned even if a retry uses another valid
signature encoding for the same payload. Validation is never skipped on retry.
A lost response does not mean rejection. The library retries its frozen signed
submission, never a new reference or newly timestamped rating. Repeated local
calls for a known recorded artifact return the original package when unchanged
or an already-rated error when changed; null-to-identified is a change too.

The counterpart retains its own author slot: the first rating does not reserve
an exclusive digest or prohibit the other direction. An identified peer's note
is admitted and counted without waiting for matching observations. There is
no production-acceptance binding and no `EXCHANGE_CONFLICT` error in this draft.
The service does not deduplicate real-world work presented under new references;
that requires anti-abuse mechanisms outside V0.

Slot reservation, exact submission, journal entry, original signed confirmation
and global head MUST become authoritative in one atomic durable commit. An
uncommitted candidate MUST NOT be acknowledged or publicly exposed. A lost
commit response must be reconciled against stored state before reporting a
conflict. Prewritten immutable blobs are permitted only when all reads and
acknowledgments are gated by committed durable references.

### 6.1 Comparing reciprocal declarations

For a targeted rating, its counterpart is a rating at the same `artifactRef`
whose `rater` equals its `rated`, whose `rated` equals its `rater`, and whose
`ratedRole` is the opposite role. This is deterministic from signed fields.
A null-target note has no counterpart in V0. Sharing a reference alone does
not satisfy reciprocal attribution; no "first receiver wins" inference exists.

The service can receive additional keys claiming to be receivers of the same
artifact. It cannot establish a two-participant limit without participation
proofs. Those claims do not change a producer's signed target or consume another
author's slot. They are not automatically paired with an unattributed note.

| Status | Meaning |
| --- | --- |
| `unilateral` | No eligible reciprocal note exists at the chosen journal prefix; this also applies to null-target notes. |
| `matching` | Reciprocal notes exist and their local `artifactId` and `artifactDigest` both match. |
| `divergent` | Reciprocal notes exist but at least one of those two fields differs. |

For divergent observations, `differingFields` contains the differing names in
this order: `artifactId`, `artifactDigest`; otherwise it is empty. Scores,
author times and signature bytes are not compared. Pairing MUST NOT use the
native artifact ID or content digest, since these are the values compared.

A later reciprocal note changes the derived view, not either original note
or confirmation. Both targeted scores count even when divergent. A difference
may reflect SDK behavior, mutation, salt substitution or a dishonest claim;
public comparison cannot identify its cause or the responsible party. Invalid
signatures are rejected, not labeled as an admitted divergence.

## 7. Public journal and signed confirmation

### 7.1 One linear journal per service identity

The journal is global to `logId`, not a separate chain per agent or artifact.
It contains one entry per accepted rating. Positions start at 1, increase by
exactly 1, and MUST NOT be reused. Define the empty journal anchor:

```text
G = H("genesis", {"profile": "https://aithos.world/ext/interaction-ratings/v0",
                  "logId": logId})
```

Entry `E[n]` has exactly:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "journal-entry",
  "logId": "<service thumbprint>",
  "position": 1,
  "previousHash": "<G for position 1; otherwise H(entry, E[n-1])>",
  "recordHash": "<H(record, complete submission bundle)>",
  "ratingId": "<ratingId>",
  "artifactRef": { "producer": "<producer agentId>", "id": "<artifact UUID>" },
  "recordedAt": "2026-09-17T10:00:07.000Z"
}
```

`recordHash = H("record", submission)` covers the complete stored
`{rating: Signed(rating-payload)}` object, including its key and signature.
`ratingId`, `artifactRef` and `logId` in the entry MUST equal the corresponding
values derived from that submission. Define `entryHash = H("entry", E[n])`.
`recordedAt` is the service's claimed registration time, not an independently
certified timestamp. Journal order follows positions, never participant times.

The service MUST retain the bundle, entry and original confirmation unchanged
and make them available through the public read API. An entry is never
removed, reordered or edited by a conformant implementation.

### 7.2 Confirmation returned to the caller

The service signs this payload with its `logId` key:

```text
{
  profile: "https://aithos.world/ext/interaction-ratings/v0",
  type: "rating-recorded",
  entry: E[n],
  entryHash: H("entry", E[n])
}
```

The successful POST response is exactly:

```text
{
  submission: <the stored one-envelope bundle>,
  confirmation: Signed(<rating-recorded payload>)
}
```

This is the **confirmation package**. It contains the author's signed rating
and artifact observation, and the service's signed acknowledgment. No signature
is taken as a substitute for validating the object it covers. It acknowledges
this declaration's recording, not that
the two participants agree on the result. Comparison remains a separate view.

Only the HTTP caller receives this response. The service does not notify the
counterpart, deliver callbacks, or require confirmation of receipt. Participants
choose whether and how to retain or share the package. V0 MUST return it to
the calling application; it requires no client receipt archive or monitoring.

### 7.3 What can be verified later

Given a retained confirmation package, a verifier can:

1. Verify the author's signature and semantic bindings (§§2–6).
2. Recompute `ratingId`, `recordHash` and `entryHash`.
3. Verify the service signature against the expected `logId` and check every
   reference in the entry against the submission bundle.
4. Fetch entries 1..n, check positions and hash links from `G`, and require the
   resulting hash to equal the retained hash at position n.

To compare an old anchor at n with a later anchor at m, fetch entries n+1..m
and require the chain to extend the old hash to the new one. Entry headers
suffice to check links; checking the notes themselves also requires their
bundles and signature verification. Public endpoints return both (§8).

A latest retained receipt for a given `logId` commits to the entire prefix
through its position, including earlier exchanges. One latest receipt per
exchange is possible but unnecessary for prefix checking alone. Replacing an
older trusted anchor with a newer one is safe only after verifying extension
from the old one. A receipt does not reconstruct missing notes or signatures.

These are verification rules, **not a requirement to build a separate verifier
application, background auditing or automatic client persistence in V0**.

### 7.4 Exact security boundary

Under the security assumptions of Ed25519 and SHA-256, the service cannot
forge a participant's rating without their private key, or supply a different
prefix matching a retained authentic hash. Changing a signed rating invalidates
its signature; changing a journal entry breaks consistency with affected anchors.
It does not invalidate otherwise authentic participant signatures elsewhere.

A hash chain alone does not stop the service from recomputing a different
history, suppressing a rating, or serving separate histories to different
readers. Retained anchors and comparison of views make incompatible histories
detectable **when those views are compared**. Without an external anchor or
comparison, a first-time reader cannot establish global completeness, freshness
or absence of forks. Refusal to serve data is an availability failure, not
automatic proof of a particular alternative history. No global fork detection,
independent timestamping or availability guarantee is claimed.

## 8. Public reads and aggregates

All endpoints use HTTPS and require no API key. The service MUST expose:

| Method and path | Result |
| --- | --- |
| `GET /v0/log` | `{profile, logId, key}`; public service descriptor. |
| `GET /v0/log/head` | `Signed({profile, type:"journal-head", logId, size, headHash})`. For size 0, `headHash == G`; otherwise it is the entry hash at `size`. |
| `GET /v0/ratings/{ratingId}` | Original confirmation package, or `404 NOT_FOUND`. |
| `GET /v0/artifacts/{producer}/{artifactUuid}/ratings?after=0&through=N&limit=100` | All ratings bearing this exact artifact reference, including unattributed ratings; grouping alone is not attribution. |
| `GET /v0/ratings/{ratingId}/comparison?through=N` | Comparison with the counterpart's rating at the chosen head, as defined below. |
| `GET /v0/log/entries?after=0&through=N&limit=100` | Consecutive confirmation packages after the specified position, bounded by the chosen head. |
| `GET /v0/agents/{agentId}/ratings?role=producer&after=0&through=N&limit=100` | Received ratings for that identity and rated role, in increasing journal position. |
| `GET /v0/agents/{agentId}/summary?through=N` | Counts and means for both rated roles, as of the chosen head. |

Path and query digest values include their `sha256:` prefix; clients MUST
percent-encode path parameters as needed. `role` is required for the filtered
list and is `receiver` or `producer`. `after` defaults to 0 and `limit` to
100; `limit` is 1..100. If `through` is omitted, the service snapshots its
current size. A supplied `through` MUST be between 0 and the current size;
`after` MUST be between 0 and `through`.

All listing responses are `{checkpoint, items, nextAfter}`. `checkpoint` is
a signed `journal-head` at `through`; `items` holds confirmation packages.
`nextAfter` is the last returned journal position when more matching entries
exist up to `through`, otherwise `null`. Subsequent pages MUST use the same
`through`. New appends MUST NOT change those pages. Unknown identities return
an empty list or zero counts, not an invented registration requirement. An
unknown artifact reference likewise returns an empty artifact-rating list.

The comparison response is exactly `{checkpoint, ratingId, status,
counterpartRatingId, differingFields}`. `status` and `differingFields` follow
§6.1; `counterpartRatingId` is the other participant's admitted rating ID,
or `null` for `unilateral`. The endpoint returns `404 NOT_FOUND` if the named
rating is absent from the chosen prefix. Fetching the referenced confirmation
packages allows anyone to check both signatures and compare the observations.
New appends can change the current comparison but MUST NOT change a comparison
at a fixed `through`. The original POST response remains unchanged.

For each rated role, the summary returns `{count, sum, average}` plus the
top-level `agentId`, `formula: "arithmetic-mean-v0"` and `checkpoint`.
`count` is the number of accepted ratings whose signed `rated` equals this
identity and whose `ratedRole` equals this group. Accumulate their `scoreUnits`
from §5 as `sumUnits`; expose `sum = sumUnits / 1000000`. Compute the mean
without cumulative binary floating-point error: round `sumUnits / count` to
the nearest integer with ties rounded up, then divide by 1000000 to obtain
`average`. This gives at most six fractional decimal places.
For count 0, sum is 0 and average is `null`. The two groups are named
`asReceiver` and `asProducer`. Count and `sumUnits` MUST remain within the
safe-integer bound in §2.2; the service MUST reject an append that would exceed
it rather than round silently. JSON serialization follows JCS; trailing zeros
are not significant and displays MUST NOT convert the scale to stars.

Every admitted rating with a non-null `rated` has equal weight, including
unilateral or divergent observations. Ratings with `rated: null` are excluded
from all agent counts and means, permanently in V0. Comparison is informational;
requiring a matching observation before counting would give the counterpart
a way to suppress an unfavorable rating.
No mean combines roles. The `rated` identity is taken only from the signed
payload; backend inference MUST NOT add another target. Displays MUST show
the count with the mean, identify the role, and show "Not yet rated" when count
is zero. History MUST expose score, author, nullable rated identity, rated role,
artifact reference, the author's observation, author time, service registration
time and comparison status as of the displayed head, with the underlying
evidence available. These are public subjective ratings, not a success rate
or a service-certified quality score.

Filtered pages, comparisons and summaries are convenience views. The signed
checkpoint does not by itself prove a filtered list is complete, that a peer
rating is absent, or that a comparison or mean is correct. Anyone can recompute
these views from the full journal prefix and compare them.

## 9. Limits, errors and library contract

### 9.1 Service limits and errors

The POST body is limited to 64 KiB before parsing; each decoded signed payload
to 8 KiB. Native `artifactId` is a nonempty UTF-8 string of at most 256 bytes.
Profile IDs are canonical UUIDs/thumbprints as specified. Public native IDs
must be opaque, not deliberate customer names or business descriptions.
Artifact bodies, private salts, identity announcements and arbitrary metadata
are not accepted as additional submission fields.

Errors use RFC 9457 `application/problem+json`: `type` is service origin plus
`/problems/<CODE>`, `status` matches HTTP, `title` is human-readable and an
optional `detail` is safe. Responses/logs must not disclose private key material
or raw rejected request bodies.

| Status | Code | Condition |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` | Malformed JSON, schema, encoding, path or query. |
| 413 | `PAYLOAD_TOO_LARGE` | Body or decoded payload limit exceeded. |
| 422 | `INVALID_SIGNATURE` | Invalid key, thumbprint, algorithm or signature. |
| 422 | `PRIVATE_KEY_SUBMITTED` | Private key material in an envelope. |
| 422 | `INVALID_EVIDENCE` | Invalid reference, observation, score or role bindings. |
| 422 | `WRONG_LOG` | Rating targets another service identity. |
| 409 | `RATING_EXISTS` | A different rating occupies this author/artifact slot. |
| 404 | `NOT_FOUND` | Requested rating is absent from the selected prefix. |
| 429 | `RATE_LIMITED` | Operational limit; `Retry-After` should be supplied. |
| 503 | `UNAVAILABLE` | Operation cannot safely complete. |

Operational rate/body limits do not require service accounts. No new endpoint
or problem code is added to the Agent Card Registry.

### 9.2 Two-call integration

The target JavaScript API is:

```javascript
import aithos from "aithos-ranking-a2a";

// ... initialize before the relevant A2A exchange ...
aithos.init(sdkInstance, { privateKey });

// ... existing agent logic computes score for its complete artifact ...
    const confirmation = await aithos.rank(artifact, score);
```

This is a proposed library, not an executable example or an existing package.
`init` receives the supported client/server integration surface, validates the
local key, configures the default service origin and pinned log identity, and
installs all identity, reference and snapshot hooks synchronously. It returns
no value on success and throws on invalid configuration; it needs no live
Aithos lookup. Initialization must finish before messages flow. The library
MUST NOT silently accept an unsupported SDK
surface. It must not require the developer to add an acceptance call, decision
callback, metadata builder, signing code or artifact-registration request.

The initial facade has one local signing identity and one service per process.
Repeated identical initialization is idempotent; incompatible reinitialization
is an error, not a silent identity replacement. Multi-agent process factories
are deferred. Key custody is local; generating/importing an Ed25519 key is
onboarding, not an Aithos account or an API credential.

`rank` resolves the captured context and MUST:

1. Establish the unique artifact reference, own role and counterpart if known.
   Reject missing/changed reference, incomplete/mutated artifact, unsupported
   representation, missing salt or missing producer context. A missing receiver
   alone produces an explicitly unattributed note; it must not invent a target.
2. Compute the local snapshot digest and validate the caller-supplied score.
3. Freeze and sign the payload, including the reference, version commitment,
   target (possibly null), role, score and log. Use the initialization key.
4. Submit and apply §6 retry rules; no new peer signature or note is requested.
5. Verify the service's confirmation, expected log, exact submitted payload,
   entry references/hashes and return the complete package to the application.

Its promise rejects with distinguishable local input/context errors, service
errors or unknown acceptance after transport failure. Successful packages make
`rated: null` explicit. A local retry cache must preserve the signed submission;
a durable client receipt archive/background retry queue is not a V0 requirement.
After a restart without local retry state, the author slot remains protected by
the service; no recovery guarantee or automatic re-attribution is implied.

Rating-service availability MUST NOT gate artifact production or delivery. The
application decides when to await/handle `rank` and whether to save the returned
confirmation. There are no peer notifications or automatic journal audits.

### 9.3 Initial supported profile and implementation gates

The first adapter candidate is `@a2a-js/sdk@1.1.0`, A2A v1.0.1 over HTTPS
JSON-RPC, using complete artifacts in non-streaming terminal task snapshots.
For this initial adapter, capture becomes eligible after the SDK publishes or
receives that terminal snapshot (`TASK_STATE_COMPLETED`, `TASK_STATE_FAILED`,
`TASK_STATE_CANCELED` or `TASK_STATE_REJECTED`),
provided the artifact itself is complete and was not assembled from unsupported
chunks. Interrupted/working task snapshots are outside that initial profile;
no inference of business consent is made from the terminal state. Its exact
client/server hook integration must be demonstrated before claiming support.
Changing the pin is an explicit documentation/lockfile change. Streaming chunks,
other transports and Python interoperability are not promised by this V0.
The rated object is a complete artifact, not necessarily the task's only output.

The SDK has separate client and server surfaces, not a universal mutable SDK
singleton. `sdkInstance` must be precisely mapped for each supported role by the
adapter. A prototype must show the two-call contract actually works at those
surfaces, especially that the producer's local artifact is captured before its
rating call. If a wrapper/constructor integration is necessary, document the
exact supported initialization form; do not claim arbitrary existing instances
can be instrumented without demonstrating it.

The audit found valid `data: null` decoding loss and different JS/Python chunk
assembly. The first adapter must either preserve such a complete value before
loss or explicitly reject it as unsupported/incomplete. It need not normalize
every other SDK's observations to equality. Pin and test supported part shapes,
metadata, copy/recovery paths, concurrent context capture, reference persistence,
retries, strict Ed25519 verification and both rating directions. List fixtures
in [`vectors/ranks/README.md`](vectors/ranks/README.md).

The journal is a separate transactional service, not the registry's existing
per-card storage. A pilot needs its own signer custody and pinned public key,
atomic append/head storage, POST rate limits and restore policy. At low volume,
scanning a bounded journal prefix is sufficient for correct summaries; no
materialized aggregate system or Merkle tree is required.

## 10. Limits and deferred work

Signatures prove authored declarations. They do not prove company identity,
actual delivery, honest evaluation, exclusive possession of an artifact or that
different keys belong to different operators. Public reference reuse and
fabricated receiver claims remain possible. Identity rotation, recovery,
Sybil resistance, moderation, retaliation controls, weighting and deduplication
of invented exchanges are outside V0.

The artifact reference distinguishes instances; the digest fixes each signed
local representation. Neither proves an output was commercially unique or
prevents its author assigning a fresh reference to a copy. Known SDK divergence
is accepted, not a fraud signal. No-artifact exchanges are absent entirely,
so received-score averages cannot measure a production success rate.

Public data includes rating authors, known targets, artifact references/native
IDs, digests, scores and timestamps. Bodies, business metadata and salts stay
private. A salt reduces guessing only while private; a hash is not encryption.
The adapter must preserve existing task access controls and not expose private
metadata through a public Agent Card. The operator knowingly enables public
signed submissions.

Mandatory caller identification, production consent, failed-production ratings,
retrospective target assignment, automatic peer notification, receipt archives,
background auditing and a global identity system are deferred. A possible later
identity-linking design is documented in §5.2, not implemented or counted today.

## References and review notes

- Pinned A2A v1.0.1 [`a2a.proto`](a2a.proto) and [`SPEC.md`](SPEC.md) §2:
  `Artifact.artifact_id` is task-scoped; `Task`, `Message`, `AgentCard` and
  `SendMessageRequest` define the carriers. No mandatory agent DID is defined.
- [A2A discovery](https://a2a-protocol.org/latest/topics/agent-discovery/),
  [authentication](https://a2a-protocol.org/latest/topics/enterprise-ready/#authentication)
  and [extensions](https://a2a-protocol.org/latest/topics/extensions/), checked
  2026-09-17. A required extension could reject unidentified callers, but that
  access policy is not part of this V0.
- [JS SDK 1.1.0 source](https://github.com/a2aproject/a2a-js/tree/eeffd69c983b6501cac912c693b69c034977455c):
  client interceptors and server execution/context hooks are different surfaces.
- [AI Catalog](https://github.com/Agent-Card/ai-catalog/tree/04a99cd1ac9a20dd6586c6196e87f5e4570303b1)
  describes catalog resources and optional trust metadata, not task-output
  ratings. No dependency on its open proposals or an upstream artifact signer.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html),
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html),
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html): signatures, key
  thumbprints and canonical JSON. [RFC 9162 §11.3](https://www.rfc-editor.org/rfc/rfc9162.html#section-11.3)
  motivates comparison of independent log views, not this profile's wire format.

The [independent audit](audits/INTERACTION-RATINGS-V0-REVIEW.md) reviewed 0.0.4.
This revision removes the production-acceptance retry problem and generic terms
agreement; it does not claim the replacement adapter, reference persistence or
journal has been implemented/audited. SDK integration, key verification and
atomic storage findings remain implementation gates. No conformance claim is
made until the planned checks execute against an actual implementation.
