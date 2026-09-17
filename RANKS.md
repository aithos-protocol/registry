# Aithos Interaction Ratings — V0

**Status:** first specification draft; not implemented
**Version:** 0.0.3
**Date:** 2026-09-17
**A2A baseline:** v1.0.1, the commit pinned by `SPEC.md` §2

For the short summary and feature overview, see
[`docs/interaction-ratings.md`](docs/interaction-ratings.md).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**
and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

This document is **additive**. It specifies a separate ratings service and an
optional A2A extension. It changes no registry endpoint, Agent Card schema,
card canonicalization rule, or stored card byte. Implementing the registry
does not require implementing this profile. The word *rating* means an
individual evaluation; this profile defines no ranking of agents.

This draft records the V0 decisions agreed after
[`docs/HANDOFF-DESIGN-RANKS.md`](docs/HANDOFF-DESIGN-RANKS.md). Where that
handoff differs, this document takes precedence. Wire names, limits and
cryptographic choices below are concrete proposals for implementation review,
not claims of deployed functionality.

## 1. Purpose and exact claim

The initial user is a B2B e-commerce company that needs to evaluate buyer
agents as well as seller agents. The service is public: no account, API key,
registry enrollment, or published Agent Card is required to submit a valid
rating or read ratings.

The claim made by an accepted rating is exactly:

> The holder of this participant key assigned this score to the other
> participant's contribution to an agreed production, based on the result
> declared by that key holder. Both participants signed the production
> agreement; each rating author signs their own result observation and score.
> The ratings service acknowledged recording this declaration at this position
> in its journal.

An authentic rating is attributable, not necessarily honest. An observation
is its author's declaration, not independent proof of delivery or failure.
Two matching observations establish that both keys signed the same result
description. Divergent observations establish a disagreement, not who caused
it or whether either participant committed fraud. Aithos records evaluations;
it does not certify commercial reliability.

### 1.1 What is rated

A rating evaluates a **participant's contribution to one agreed production**.
Its subject is either one designated final A2A artifact, **including its
business metadata**, or an explicit failure to produce that artifact after
accepting the request. The artifact content and metadata are bound to the
author's signed observation by a digest, without being published to the
ratings service. The two participants need not report the same observation.

| Rater | Rated participant | Meaning |
| --- | --- | --- |
| Requester | Provider | Usefulness and quality of the result, or handling of a declared production failure. |
| Provider | Requester | Clarity and feasibility of the request, necessary inputs, and cooperation in producing the result. |

These are protocol roles, not fixed buyer/seller identities. In the initial
quotation flow, the buyer is the requester and the seller is the provider.
The provider does not rate its own artifact. A quotation rating does not
establish that an order was paid or fulfilled.

### 1.2 V0 boundary

- One accepted production per A2A task; each participant declares its observed
  final artifact or production failure.
- One optional decimal score in the inclusive range 0..1 per participant for
  that result; higher means a better contribution under the evaluator's criteria.
- Either participant can rate independently; neither must approve the other's
  score. No editing, deletion, free-text review, or secondary scores.
- A disagreement between the two result observations is retained and exposed;
  it does not invalidate either signature or automatically exclude a score.
- Public evaluations and arithmetic means, separated by the rated role.
- Participant signatures, a linear hash journal, and signed confirmations.
- A library integrated into each participant's application, with a single
  rating call as the developer-facing goal. One SDK adapter for the first
  design partner. Multiple SDKs, Merkle trees,
  third-party monitors and federation are not prerequisites.

Ordinary conversations, pre-acceptance refusals, and silence or timeouts are
not eligible. A2A messages and tasks do not inherently promise an artifact.
This extension makes acceptance of a production explicit. A final artifact
does not need a native or prior provider signature: the rating call signs
the caller's observation of it.

### 1.3 Relationship to A2A and AI Catalog

The pinned A2A schema defines no standard signature field for task artifacts.
A2A's optional Agent Card signature authenticates the card, not task outputs.
All agreement and rating signatures below are supplied by the **Aithos
library and extension**, not automatically by A2A or its SDK.

AI Catalog's optional trust/signature mechanisms concern catalog resources;
its term "artifact" also includes Agent Cards, plugins and datasets. They
do not automatically sign A2A task outputs. V0 depends on neither AI Catalog
adoption nor a future upstream artifact-signing mechanism (see references).

## 2. Identity and signed objects

### 2.1 Participant identity

For V0, each participant uses one Ed25519 key pair. `agentId` is the RFC 7638
SHA-256 thumbprint of its public JWK, encoded as unpadded base64url. It is 43
characters, and every participant signature MUST have `kid == agentId`.

The primary rating call accepts an existing private key. The library MAY
provide helpers to generate a new key locally or load an existing one. It
MUST NOT silently replace a missing, invalid or unreadable supplied key.
The operator manages durable key storage.
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

Every hash using `H` below is a string of 71 characters. All JSON integer
fields MUST be in `0..9007199254740991`, with the narrower ranges stated below.
Signed envelopes use small, explicitly defined objects. Artifact commitments
use the dedicated projection in §4.5, never a generic SDK serialization.

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
Both participants MUST use the same `logId` for a production.

The SDK is configured with a service HTTPS origin and its expected `logId`;
Aithos is the default deployment. Its public descriptor supplies the public
key. The key's thumbprint MUST match that expected identity. A key fetched
from an arbitrary URL is not by itself proof that its operator is Aithos.
Service key rollover requires a new journal in V0; histories MUST NOT be
silently combined or restarted under the old `logId`.

## 3. Explicit production agreement

Two signatures establish agreement without requiring the requester to know a
server-assigned `taskId` in advance.

### 3.1 Production request

The requester signs:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "production-request",
  "logId": "<service thumbprint>",
  "exchangeId": "<random UUID v4>",
  "requester": "<requester agentId>",
  "provider": "<provider agentId>",
  "productionDigest": "sha256:<64 lowercase hex characters>",
  "issuedAt": "2026-09-17T10:00:00.000Z"
}
```

`exchangeId` MUST be a fresh lowercase UUID v4, reused only when retrying that
same production. Requester and provider MUST differ.

`productionDigest` commits to the private production terms, including what
final result is requested. The requester and provider agree the exact bytes
`termsBytes` and a fresh, random 32-byte `salt` through their A2A application:

```text
productionDigest = "sha256:" || lowercase_hex(SHA-256(
  UTF8("aithos-ratings-v0/production") || LF || salt || termsBytes
))
```

The application defines the terms' format. For example, they can be the exact
UTF-8 bytes of an agreed JSON quotation request. The provider MUST check the
digest against those bytes before accepting. It MUST NOT hash a reserialized
SDK object as a substitute. Terms and salt remain between the participants;
neither is included in a submission to the ratings service. The service
checks agreement on the digest, not the meaning or feasibility of the terms.

### 3.2 Production acceptance

After deciding to undertake the production, the provider signs:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "production-accepted",
  "requestDigest": "<H(request, decoded production-request payload)>",
  "taskId": "<A2A task id>",
  "issuedAt": "2026-09-17T10:00:01.000Z"
}
```

The signer MUST be the provider named in the referenced request. This
signature means the provider accepted that production, for those identities
and that log, and assigned it this task. The requester's signature and this
acceptance together form the **exchange receipt**.

A plain `SUBMITTED` or `WORKING` task status is not a substitute for this
acceptance. The application MUST trigger acceptance explicitly; the adapter
MUST NOT infer it from arbitrary messages or status changes. The provider
MUST return the signed acceptance to the requester before, or together with,
the result. There is no preliminary call to Aithos.

The provider MUST assign at most one accepted production to a task. Material
changes to the agreed production require a new task and a new agreement.
The service enforces the observed one-production-per-task rule at submission
time (§6); it cannot see agreements never submitted to it.

## 4. Participant observations and A2A transport

### 4.1 Each participant declares its own observation

At rating time, the library constructs an `observation` from the caller's
local final result. It is included directly in the signed rating (§5); there
is no separate provider-signed `production-result` prerequisite and no
requirement to obtain or approve the counterpart's rating.

The artifact variant is exactly:

```json
{
  "kind": "artifact",
  "taskState": "TASK_STATE_COMPLETED",
  "artifactId": "<locally observed designated final A2A artifact id>",
  "artifactDigest": "sha256:<64 lowercase hex characters>"
}
```

The failure variant is exactly:

```json
{
  "kind": "failure",
  "taskState": "TASK_STATE_FAILED"
}
```

| `kind` | Allowed `taskState` | Additional fields | Author's claim |
| --- | --- | --- | --- |
| `artifact` | `TASK_STATE_COMPLETED` | `artifactId` and `artifactDigest`, required | This is the final artifact the author produced or received, including its content and business metadata. |
| `failure` | `TASK_STATE_FAILED`, `TASK_STATE_CANCELED` or `TASK_STATE_REJECTED` | Neither `artifactId` nor `artifactDigest` | The accepted production explicitly ended without its designated final artifact, as observed by the author. |

A failure observation is signed as part of the rating, not represented by a
synthetic artifact. It requires an explicit terminal failure after the signed
acceptance: the provider's application declares that outcome, or the
requester's adapter observes that outcome in the task. The adapter MUST NOT
turn a timeout, disconnect, missing artifact, or every terminal status into
failure. Cancellation or rejection does not automatically warrant a low score.

The service cannot independently establish that an observed state occurred.
In particular, a requester-signed failure is **not** proof that the provider
signed or acknowledged failure. The same boundary applies to artifact delivery.

Each author MUST declare only one final observation in its immutable rating
for a production. The provider's application designates at most one final
artifact and SHOULD deliver the same final content to the requester. A
counterpart's conflicting declaration MUST NOT replace or block an otherwise
valid rating; both are retained and compared under §6.1. Their scores may
legitimately differ even when their artifact observations match.

An artifact commitment is scoped to the accepted production and thus to its
provider and task. Artifact IDs alone are not globally unique. Partial
artifacts and streaming chunks are not final results. Retrying a business
operation after a terminal failure requires a new task and agreement;
multiple independently rated final artifacts within a task are outside V0.

### 4.2 Eligibility by example

| Situation | Eligible in V0? |
| --- | --- |
| Direct A2A `Message` response, with no task | No. |
| Discussion or refusal before production acceptance | No. |
| `INPUT_REQUIRED` or `AUTH_REQUIRED` | Not yet; neither is a terminal result. |
| Accepted production, locally available final designated artifact | Yes; the caller signs its observation and score. No prior artifact signature is required. |
| Accepted production, explicit terminal failure observed as defined above | Yes; either participant may sign its own failure observation and score. |
| The counterpart has not rated, or reports a different result | Yes; classify the comparison without rejecting the caller's declaration. |
| `COMPLETED` without a designated artifact | No automatic eligibility or failure inference. |
| Timeout, disconnect, or missing signed production agreement | No. |

### 4.3 Extension declaration and activation

A supporting provider declares the extension in its Agent Card's
`capabilities.extensions`, using the URI in §2.2, `required: false`, and:

```json
{
  "serviceOrigin": "https://ratings.example.com",
  "logId": "<service thumbprint>",
  "provider": "<provider ratings agentId>"
}
```

These are the extension's exact `params`; the URL is illustrative. It has an
HTTPS origin only, with no path, query, fragment, credentials or trailing
slash. An application MUST obtain the provider's ratings identity from its
configured counterpart or its Agent Card, not from a rating about that agent.
The provider's acceptance proves possession of that key, not organizational
identity or ownership of the endpoint.

For HTTP bindings, request activation through `A2A-Extensions: <extension-uri>`.
A provider activating it MUST echo that URI in the response's `A2A-Extensions`
header. Other active extensions may also be listed. Unsupported or inactive
ratings MUST NOT prevent an otherwise valid business interaction; that
interaction simply produces no eligible agreement under this profile.

### 4.4 Metadata placement and local context

The adapter preserves signed envelopes' `protected`, `payload` and `signature`
strings exactly. It does not canonicalize the surrounding A2A object.

| Carrier | `metadata[extension-uri]` value |
| --- | --- |
| Requester's production `Message` | `{"request": Signed(request)}` |
| Provider `Task` acknowledging acceptance | `{"request": Signed(request), "acceptance": Signed(acceptance)}` |
| Final `Task` snapshot | The same agreement bundle; task state and artifacts remain in their normal A2A fields. |
| Designated final `Artifact` | `{"request": Signed(request), "acceptance": Signed(acceptance), "artifactSalt": "<base64url of the agreed 32 private bytes>"}` |
| Streaming `TaskStatusUpdateEvent` | The same agreement bundle as the corresponding `Task` snapshot. |

Here `Signed(...)` denotes a JSON object, not literal JSON syntax. Messages
and artifacts carrying the extension MUST also list its URI in `extensions`.
`TaskStatus` itself has **no metadata field** in the pinned A2A schema; use
`Task.metadata` or `TaskStatusUpdateEvent.metadata`, not an invented field.

The adapter keeps the signed agreement, agreed salt, enclosing task identity
and observed terminal result available locally. It preserves the actual final
artifact as produced or received before application code can accidentally
change the values to be rated. Artifact chunks are assembled before rating.
A final snapshot or a task lookup can recover missing context, but MUST NOT
silently replace an already captured local observation with a newer or
counterpart-supplied version merely to make the two declarations match.

The adapter MUST check the caller's key against the agreed identities, and
bind the local observation to the task named by the acceptance. It MUST check
that the input artifact is the designated final artifact observed in that
local context. These are local integrity checks, not a comparison against a
provider-signed artifact digest. A discrepancy between the two participants'
observations is handled by the service, not rejected as a local signature
failure. The service sees declarations only and cannot perform these transport
checks independently.

The agreement metadata supplies the task, both identities and the selected
log to `rank`. The shared salt MUST be obtained from the agreed private
production context (§§3.1, 4.5), and the artifact's `artifactSalt` MUST match
that context. It MUST NOT be copied into the public submission bundle.
For failure, the adapter exposes `{request, acceptance, observation}` as a
local input value, with the failure observation defined in §4.1. This value
is not a native A2A artifact or a signature by the other participant.

### 4.5 Artifact content and metadata commitment

Each caller's library constructs a private `ArtifactSnapshot` from its locally
observed final artifact using the pinned A2A schema. It MUST reject unknown
artifact/part fields, invalid field types, missing required content and
ambiguous oneof values before projecting. The snapshot has exactly these members:

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
silently drop business metadata or substitute the counterpart's digest. SDK
round-trip vectors are required before interoperability is claimed.

Both participants MUST use the **same** `artifactSalt`: the private 32-byte
salt agreed with the production terms in §3.1. Reusing it within this one
production is domain-separated by the distinct `production` and `artifact`
hash labels. It MUST NOT be reused for another production. Generating an
independent salt per caller would make identical artifacts appear different.
Each caller computes:

```text
artifactDigest = "sha256:" || lowercase_hex(SHA-256(
  UTF8("aithos-ratings-v0/artifact") || LF || artifactSalt
  || UTF8(JCS(ArtifactSnapshot))
))
```

The library attaches the shared salt and agreement evidence in the excluded
protocol metadata (§4.4). It MUST compute the digest itself before signing
an artifact observation; it MUST NOT trust a digest supplied by the counterpart.
The content and salt never go to the ratings service; the public observation
exposes only the digest. A verifier with the private artifact and salt can
check the binding; a public reader can check the signatures and recorded
digest without seeing that private content.

The excluded namespace contains protocol receipts and the private salt, not
business metadata. Its signed envelopes are verified independently. Applications
MUST NOT hide business fields inside that namespace. Other metadata, including
part metadata and other extensions' metadata, remains covered. Adding a
confirmation or another participant's rating MUST NOT change the business
snapshot or its digest.

For a part represented by `url`, the commitment covers the URL and any supplied
metadata, **not the bytes subsequently served by that URL**. The library does
not fetch remote content. Whitespace, object key order and the explicitly
normalized defaults are not content changes under this projection.

## 5. Rating statement

Each participant MAY sign and submit:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "rating",
  "logId": "<service thumbprint>",
  "exchangeId": "<UUID from production request>",
  "acceptanceDigest": "<H(acceptance, decoded production-accepted payload)>",
  "observation": {
    "kind": "artifact",
    "taskState": "TASK_STATE_COMPLETED",
    "artifactId": "<locally observed designated final artifact id>",
    "artifactDigest": "sha256:<64 lowercase hex characters>"
  },
  "rater": "<author's agentId>",
  "rated": "<counterpart's agentId>",
  "ratedRole": "provider",
  "score": 0.85,
  "issuedAt": "2026-09-17T10:00:06.000Z"
}
```

`ratedRole` is `provider` when the requester rates the provider, and
`requester` for the reverse direction. The identities MUST match the agreement
and differ. The signer MUST equal `rater`. `score` MUST be a finite JSON number
in the inclusive range 0..1, with at most six fractional decimal places.
The six-place precision is a proposed V0 wire limit, not a claim about
evaluation accuracy. Extra precision MUST be rejected, not silently rounded.
The reference chain MUST resolve to that exact agreement and service.
`observation` MUST be one of the two variants in §4.1. The one rating
signature covers the score, observation, identities and agreement binding
together; a separate signature on the artifact body is unnecessary.

`0` is the lowest evaluation and `1` the highest under the evaluator's stated
criteria; intermediate values express degrees of satisfaction. There are no
star labels or predefined human rating categories. For example, `0.85` is a
normalized evaluation, not automatically an 85% probability of future success.
An absent rating is distinct from a score of zero.

The partner defines the concrete business criteria before the pilot. The
agent or its developer computes and supplies `score`; the signing participant
owns the evaluation. A finer numeric scale does not make
different evaluators comparable or create an objective measure by itself.
The library MUST NOT derive a score solely from artifact presence, a terminal
status or the counterpart's evaluation. The score is an explicit argument to
the rating call (§9.2), not an inferred value or an instruction read from
counterpart-supplied metadata. The public signed statement includes that value.

For validation and aggregation, interpret the canonical JSON decimal value
exactly: `scoreUnits = score * 1000000` MUST be an integer in 0..1000000.
This is decimal arithmetic, not an equality test after binary floating-point
multiplication. Values such as `0`, `0.1`, `0.85` and `1` are valid; missing
scores, strings, negative numbers, numbers above 1 and `0.1234567` are not.

Signing a `rating` authorizes its **public submission** to the named `logId`.
It is not a private draft. Anyone holding the signed bundle can relay it to
that service; a second HTTP authentication layer is unnecessary. Publishing
the other participant's signature does not authorize creating a rating in
their name.

## 6. Submission, uniqueness and retry behavior

```http
POST /v0/ratings
Content-Type: application/json
```

The request is exactly this **submission bundle**:

```text
{
  request: Signed(production-request),
  acceptance: Signed(production-accepted),
  rating: Signed(rating)
}
```

The service MUST validate all three envelopes and their complete chain of
references, role bindings, observation schema, `logId` and limits before
accepting the bundle. It MUST NOT fetch A2A endpoints, artifacts, production
terms or keys from URLs. Embedded public keys suffice for these key-based
identities. A missing counterpart rating is not missing evidence.

Define these identifiers over decoded payloads, not signature encodings:

```text
requestDigest    = H("request", request payload)
acceptanceDigest = H("acceptance", acceptance payload)
ratingId         = H("rating", rating payload)
```

The service MUST atomically enforce:

1. `(requester, exchangeId)` binds one request and acceptance.
2. `(provider, taskId)` binds one accepted production.
3. `(provider, taskId, rater)` admits at most one rating.

The first accepted bundle fixes the agreement bindings. The other participant's
rating MUST carry the same request and acceptance payloads; its observation
and score are its own. The service MUST NOT require equal observations,
choose one as authoritative, or let the first rater reserve an exclusive
result digest. Different results from the two eligible authors are both
accepted and become an observable disagreement (§6.1).

Acceptance, uniqueness, journal append and confirmation persistence MUST be
one atomic durable commit. Concurrent submissions MUST NOT reserve the same
position or admit two ratings for one slot. A response MUST NOT acknowledge
an entry that has not committed.

- First acceptance of each author's rating: `201 Created`, with the
  confirmation package in §7.2, even if its observation differs from the peer's.
- Retry of the same validated `ratingId` and agreement payloads: `200 OK`,
  with the **original stored package**, no new entry and no new timestamp.
- A different rating for an occupied author slot, including a changed score
  or observation: `409 RATING_EXISTS`. It is not a second admitted observation.
- A different request or acceptance for an existing agreement binding:
  `409 EXCHANGE_CONFLICT`. This code MUST NOT be used merely because the
  counterpart's observation differs.

The service returns the stored bundle on retry even if a caller used another
valid signature encoding for the same payloads. Callers SHOULD retry the exact
original bytes. Following a timeout, acceptance is unknown until a retry or
lookup succeeds; callers MUST NOT create a new exchange to retry a rating.
No score revision, withdrawal or tombstone operation exists in V0. Rejected
attempts are not journal entries or public accusations against a participant.

### 6.1 Comparison of the two observations

Comparison is a deterministic view of the admitted ratings for one agreement
at a chosen journal position. It is not a mutable field in either rating,
journal entry or original confirmation.

| `status` | Meaning |
| --- | --- |
| `unilateral` | Only one participant's rating has been recorded in this journal prefix. No agreement or disagreement on the result can be inferred. |
| `matching` | Both participants rated, and their observations match under the rules below. Their scores may differ. |
| `divergent` | Both participants rated, and their observations differ under the rules below. Both declarations remain authentic if their signatures verify. |

Compare `kind` and `taskState`, then `artifactId` and `artifactDigest` when
both observations are artifacts. Matching failure observations therefore
require the same terminal state. Author identities, roles, scores, timestamps
and signature bytes MUST NOT be compared for this purpose. The agreement
already establishes that the observations concern the same production.

For `divergent`, `differingFields` lists the differing field names in this
fixed order: `kind`, `taskState`, `artifactId`, `artifactDigest`. Include the
last two only when both observations are artifacts. For `matching` and
`unilateral`, this list is empty. There is no claim about which private
content or metadata field caused a digest difference.

A second participant can change the derived status from `unilateral` to
`matching` or `divergent` by submitting its one rating. This MUST NOT modify
an earlier receipt, suppress either rating or retroactively invalidate it.
Both scores remain in their respective role aggregates (§8). No automatic
penalty, fraud label, credibility score or dispute resolution is defined.

A difference can reflect different observations, a bug, incorrect salt use or
a false declaration. Public digest comparison cannot distinguish these causes.
Repeated divergence is available for later analysis; its occurrence alone is
not evidence that either named participant is dishonest. A participant could
intentionally submit a divergent observation, so automatic blame would also
be open to abuse. Invalid cryptographic signatures are rejected before this
comparison; they are not an admitted disagreement.

## 7. Public journal and signed confirmation

### 7.1 One linear journal per service identity

The journal is global to `logId`, not a separate chain per agent or exchange.
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
  "exchangeId": "<exchangeId>",
  "recordedAt": "2026-09-17T10:00:07.000Z"
}
```

`recordHash` covers the exact three envelopes, including their keys and
signatures, as canonical JSON. Define `entryHash = H("entry", E[n])`.
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
  submission: <the stored three-envelope bundle>,
  confirmation: Signed(<rating-recorded payload>)
}
```

This is the **confirmation package**. It contains the author's signed rating
and observation, both participants' agreement evidence, and the service's
signed acknowledgment. No signature is taken as a substitute for validating
the object it covers. It acknowledges this declaration's recording, not that
the two participants agree on the result. Comparison remains a separate view.

Only the HTTP caller receives this response. The service does not notify the
counterpart, deliver callbacks, or require confirmation of receipt. Participants
choose whether and how to retain or share the package. V0 MUST return it to
the calling application; it requires no client receipt archive or monitoring.

### 7.3 What can be verified later

Given a retained confirmation package, a verifier can:

1. Verify all participant signatures and semantic bindings (§§2–6).
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
| `GET /v0/ratings/{ratingId}/comparison?through=N` | Comparison with the counterpart's rating at the chosen head, as defined below. |
| `GET /v0/log/entries?after=0&through=N&limit=100` | Consecutive confirmation packages after the specified position, bounded by the chosen head. |
| `GET /v0/agents/{agentId}/ratings?role=provider&after=0&through=N&limit=100` | Received ratings for that identity and rated role, in increasing journal position. |
| `GET /v0/agents/{agentId}/summary?through=N` | Counts and means for both rated roles, as of the chosen head. |

Path and query digest values include their `sha256:` prefix; clients MUST
percent-encode path parameters as needed. `role` is required for the filtered
list and is `requester` or `provider`. `after` defaults to 0 and `limit` to
100; `limit` is 1..100. If `through` is omitted, the service snapshots its
current size. A supplied `through` MUST be between 0 and the current size;
`after` MUST be between 0 and `through`.

Both listing responses are `{checkpoint, items, nextAfter}`. `checkpoint` is
a signed `journal-head` at `through`; `items` holds confirmation packages.
`nextAfter` is the last returned journal position when more matching entries
exist up to `through`, otherwise `null`. Subsequent pages MUST use the same
`through`. New appends MUST NOT change those pages. Unknown identities return
an empty list or zero counts, not an invented registration requirement.

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
`count` is the number of accepted ratings. Accumulate the integer `scoreUnits`
from §5 as `sumUnits`; expose `sum = sumUnits / 1000000`. Compute the mean
without cumulative binary floating-point error: round `sumUnits / count` to
the nearest integer with ties rounded up, then divide by 1000000 to obtain
`average`. This gives at most six fractional decimal places.
For count 0, sum is 0 and average is `null`. The two groups are named
`asRequester` and `asProvider`. Count and `sumUnits` MUST remain within the
safe-integer bound in §2.2; the service MUST reject an append that would exceed
it rather than round silently. JSON serialization follows JCS; trailing zeros
are not significant and displays MUST NOT convert the scale to stars.

Every admitted score has equal weight, including scores attached to failures
and to unilateral or divergent observations. Comparison is informational;
requiring a matching observation before counting would give the counterpart
a way to suppress an unfavorable rating.
No mean combines roles. Displays MUST show the count with the mean, identify
the role, and show "Not yet rated" when count is zero. History MUST expose
score, both identities, role, the author's observation, author time, service
registration time and comparison status as of the displayed head, with the
underlying evidence available. These are public
subjective ratings, not a success rate or a service-certified quality score.

Filtered pages, comparisons and summaries are convenience views. The signed
checkpoint does not by itself prove a filtered list is complete, that a peer
rating is absent, or that a comparison or mean is correct. Anyone can recompute
these views from the full journal prefix and compare them.

## 9. Limits, errors and SDK contract

### 9.1 Service limits and errors

The complete POST body MUST be at most 64 KiB, checked before parsing. Each
decoded signed payload MUST be at most 8 KiB. `taskId` and `artifactId` MUST
be nonempty UTF-8 strings of at most 256 bytes. Identifiers MUST be opaque and
MUST NOT deliberately contain customer names, order details or other business
content. Only the fields in this document are accepted; private terms, artifact
bodies and free-form metadata are not accepted as extra submission fields.

Errors use RFC 9457 `application/problem+json`, with `type` equal to the
service origin plus `/problems/<CODE>`, HTTP-matching `status`, a human-readable
`title`, and an optional safe `detail`. No error response contains private key
material or raw submission bodies.

| Status | Code | Condition |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` | Malformed JSON, schema, encoding, path or query. |
| 413 | `PAYLOAD_TOO_LARGE` | Body or decoded payload limit exceeded. |
| 422 | `INVALID_SIGNATURE` | Invalid key, thumbprint, algorithm or signature. |
| 422 | `PRIVATE_KEY_SUBMITTED` | An envelope includes private key material. |
| 422 | `INVALID_EVIDENCE` | Missing/mismatched agreement, invalid roles or malformed/ineligible observation. |
| 422 | `WRONG_LOG` | Signed request or rating targets another service identity. |
| 409 | `RATING_EXISTS` | Another rating occupies this participant's slot. |
| 409 | `EXCHANGE_CONFLICT` | Task, exchange, request or acceptance binding conflicts; not divergent result observations. |
| 404 | `NOT_FOUND` | Requested rating does not exist. |
| 429 | `RATE_LIMITED` | Operational request limit; `Retry-After` SHOULD be supplied. |
| 503 | `UNAVAILABLE` | The service cannot complete the operation safely. |

Operational limits are allowed without accounts; IP-based reputation is not
part of this profile. A 503 or lost response does not establish non-acceptance:
use the retry rules. No new problem code or endpoint is added to the registry.

### 9.2 Library responsibilities

The first implementation supplies one adapter for the partner's chosen SDK.
The library runs inside each participant's application. Its public rating
API is deliberately limited to importing the library and making one call:

```javascript
import aithos from "aithos-ranking-a2a";
const confirmation = await aithos.rank(privateKey, artifact, score);
```

This is the **target API**, not a published package or an executable example
with the current repository. `privateKey` is the caller's local Ed25519 key;
`artifact` is the final artifact handled by the integrated A2A adapter; `score`
is the caller's evaluation in 0..1. All three already exist in the application.
The library does not choose a score, run an LLM evaluator or read a score
chosen by the counterpart. It MUST reject a missing or invalid score.

The **library owns context resolution and signing**. The application MUST NOT
be required to assemble or pass receipt objects for an artifact rating.
`rank` uses the agreement and local observation context carried by the artifact
or captured by the integrated adapter (§4.4). The adapter MAY retrieve missing
task context through the already configured A2A client, using the original
provider identity and task ID; a bare `artifactId` is not a safe lookup key.
It MUST NOT overwrite an existing local observation with a later fetched
version. Missing agreement, mismatched local context or an unavailable agreed
salt makes an artifact rating ineligible. A missing or different counterpart
rating does not. A lookup never fabricates a missing agreement signature.

For that call, the library MUST:

1. Derive the caller's ratings identity from `privateKey`, validate the signed
   request and acceptance, and resolve the counterpart, task and rated role.
   A key belonging to neither participant is refused.
2. Validate the caller's local final-artifact context and shared salt, then
   compute its own digest over the artifact and business metadata (§4.5).
   It MUST NOT copy the counterpart's digest or require a prior artifact
   signature. Construct the caller's `observation` from that local result.
3. Build and sign the rating, covering the observation and supplied score
   together, without transmitting the private key, artifact body, business
   metadata or private salts.
4. Submit the three-envelope bundle to the configured service and enforce
   the exact retry semantics in §6. No peer acknowledgment or rating is needed.
5. Verify that the returned confirmation matches the expected log, submitted
   rating and stored bundle, then return the complete confirmation package.

The result is a promise for that package. Rejection MUST distinguish invalid
input/context, service rejection and unknown acceptance after a transport
failure. A local response check does not audit the full journal or establish
that the counterpart agrees with the observation. The library MUST preserve
the original signed submission for retries of that call; durable retry storage
across application restarts is not required by V0.

For a production failure there is no artifact. The same call accepts the
adapter's local `{request, acceptance, observation}` value as its second
argument, verifies the signed agreement and explicit terminal failure context,
and signs the caller's failure observation with the supplied score. It skips
only the artifact projection and digest step. It MUST NOT fabricate an A2A
artifact, infer failure from silence or a timeout, or treat an arbitrary error
object as eligible. No prior provider signature of the failure is required;
the caller's signed rating remains a declaration, not proof of a peer admission.
The third argument is still the caller's explicit score, not an automatic zero.

**What the two lines assume.** The participant applications have integrated
the A2A adapter, the service origin and expected `logId` are configured
(Aithos defaults for the normal path), and the private signing identities are
available for production agreement and rating. The adapter adds the agreement
evidence during the exchange and preserves each participant's local final
observation. It maps explicit acceptance and final-result decisions to §§3–4;
it does not infer consent from arbitrary messages or invent another key's
signature. The ratings call itself signs the caller's observation.

An unmodified A2A artifact is not guaranteed to carry a task ID, participant
identities or the required signed agreement. Importing the package and calling
it only at the end of an otherwise uninstrumented exchange cannot supply that
missing context. In that case `rank` MUST report ineligibility. This limitation
concerns identifying and binding the agreed exchange, **not** a native A2A
artifact-signing requirement. The goal is one application call to rate an
eligible result; the adapter's setup and SDK hook compatibility must be
demonstrated with the first partner before claiming a two-line complete
integration.

The application decides when to await or handle the rating promise. Business
request handling and artifact delivery MUST NOT depend on the ratings service
being reachable. Signing the agreement MUST NOT require a live service lookup
when log configuration is already known. No durable background queue, receipt
archive, peer notification or automatic auditor is required.

### 9.3 Required checks before implementation is called conformant

The planned vectors are listed in [`vectors/ranks/README.md`](vectors/ranks/README.md).
They cover a successful production, a declared failure, both rating directions,
invalid signatures and bindings, duplicate retries and concurrent writes,
mutation of each signed field, independent observation comparison, journal
tampering and retained-anchor checks.
Fixtures and tests are implementation work, not delivered by this draft.

A pilot additionally checks whether the actual SDK preserves signed envelopes
and the artifact projection through metadata and streaming, whether the adapter
can observe explicit acceptance and final-result decisions, whether the rating
call needs only the key, artifact and score, and whether the scoring criteria
are meaningful for the partner's use case.
There is no cross-SDK interoperability claim until independently exercised.

## 10. What this profile does not establish

This profile does not prove that a key belongs to a company or person, that
two identities have different operators, that an agreed interaction happened
outside their signed declarations, or that an evaluation is fair. Compromised
participant keys can produce apparently valid new statements; V0 has no
mechanism to determine when compromise occurred.

Collusion, Sybil identities, retaliation, moderation, corrections, reputation
weighting, identity age, IP/domain signals and cross-service deduplication are
outside V0. Publishing both ratings immediately accepts the retaliation risk.
Aithos itself could create new identities, but cannot impersonate an existing
participant whose private key it does not hold.

The signed production agreement and an eligible local final observation are
prerequisites. A provider that refuses to sign acceptance, or goes silent
before an eligible result is observed, can leave a production unrateable.
Once the agreement and local observation are available, withholding a
provider artifact signature or either participant's rating does not prevent
the other participant from rating. A later divergent observation does not
erase or exclude an existing score. Optional ratings and these eligibility
limits produce selection bias: the service cannot infer the total number or
success rate of all business interactions.

The service authenticates declarations, not their underlying observations.
A dishonest participant can sign an invented result or deliberately create a
disagreement. Even matching declarations may be collusive. V0 exposes what was
signed and whether the two result descriptions match; it does not identify
the dishonest party, verify private artifact contents or turn repeated
disagreement into an automatic reputational penalty.

The public journal exposes participant relationships, identifiers, timing,
scores, artifact digests and declared outcome states. It does not accept
production terms, salts, artifacts, business metadata, messages, product
details or amounts. A hash is not encryption; private salts reduce guessing
of production terms and artifact contents only while they remain private.
Participants MUST understand the public nature of signed rating submissions
before enabling the integration.

The linear journal makes verification proportional to the range downloaded.
An individual receipt is not a compact proof of every prior note. There is no
Merkle tree, blockchain, independent witness, global fork-detection mechanism,
content backup or availability guarantee. SDK automation of those concerns is
deliberately not required for this pilot.

## References and review notes

- A2A v1.0.1: [`a2a.proto`](a2a.proto), pinned by [`SPEC.md`](SPEC.md) §2;
  `Task`, `TaskState`, `Message`, `Artifact` and update events define the carrier
  fields. The [official extension guide](https://a2a-protocol.org/latest/topics/extensions/),
  checked 2026-09-17, documents declaration and `A2A-Extensions` activation.
- [A2A Artifact](https://a2a-protocol.org/latest/specification/#417-artifact)
  has no native signature field; [Agent Card Signing](https://a2a-protocol.org/latest/specification/#84-agent-card-signing)
  is optional and applies to the card. Checked 2026-09-17.
- [AI Catalog Trust Manifest](https://github.com/Agent-Card/ai-catalog/blob/main/specification/ai-catalog.md#trust-manifest)
  is optional and concerns catalog resources. As checked 2026-09-17,
  [AI Catalog PR #117](https://github.com/Agent-Card/ai-catalog/pull/117) is a
  draft about contributor trust metadata and signatures; [A2A PR #2240](https://github.com/a2aproject/A2A/pull/2240)
  is open and concerns discovery. Neither supplies native signing of A2A task
  outputs. These are research context, not dependencies of this profile.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html),
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) and
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) specify the signature,
  key identity and canonicalization building blocks.
- [RFC 9162 §11.3](https://www.rfc-editor.org/rfc/rfc9162.html#section-11.3)
  explains the need to compare log views. This profile borrows the transparency
  principle, not Certificate Transparency's wire format or Merkle construction.
- AI Catalog, ARD, AAIF and SCITT integration are deferred. This draft makes
  no compatibility claim and has no dependency on an open upstream proposal.

The implementation review must confirm the first partner's SDK/version and
business scoring criteria, and provision the real service origin and public
log key. These are deployment/integration inputs, not unresolved choices about
public visibility, bilateral scoring, immutable notes or eligible outcomes.
