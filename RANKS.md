# Aithos Interaction Ratings — V0

**Status:** first specification draft; not implemented
**Version:** 0.0.1
**Date:** 2026-09-17
**A2A baseline:** v1.0.1, the commit pinned by `SPEC.md` §2

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
> participant's contribution to an agreed production. Both participants signed
> the production agreement, and the provider signed its declared result. The
> ratings service acknowledged recording this signed evaluation at this
> position in its journal.

An authentic rating is attributable, not necessarily honest. A result receipt
is a provider's declaration, not an independent observation of delivery or
failure. Aithos records evaluations; it does not certify commercial reliability.

### 1.1 What is rated

A rating evaluates a **participant's contribution to one agreed production**.
Its subject is either one designated final A2A artifact or an explicit failure
to produce that artifact after accepting the request.

| Rater | Rated participant | Meaning |
| --- | --- | --- |
| Requester | Provider | Usefulness and quality of the result, or handling of a declared production failure. |
| Provider | Requester | Clarity and feasibility of the request, necessary inputs, and cooperation in producing the result. |

These are protocol roles, not fixed buyer/seller identities. In the initial
quotation flow, the buyer is the requester and the seller is the provider.
The provider does not rate its own artifact. A quotation rating does not
establish that an order was paid or fulfilled.

### 1.2 V0 boundary

- One accepted production and one designated final result per A2A task.
- One optional integer score from 1 to 5 per participant for that result.
- Either participant can rate independently; neither must approve the other's
  score. No editing, deletion, free-text review, or secondary scores.
- Public evaluations and arithmetic means, separated by the rated role.
- Participant signatures, a linear hash journal, and signed confirmations.
- One SDK adapter for the first design partner. Multiple SDKs, Merkle trees,
  third-party monitors and federation are not prerequisites.

Ordinary conversations, pre-acceptance refusals, unsigned results, and silence
or timeouts are not eligible. A2A messages and tasks do not inherently promise
an artifact. This extension makes acceptance of a production explicit.

## 2. Identity and signed objects

### 2.1 Participant identity

For V0, each participant uses one Ed25519 key pair. `agentId` is the RFC 7638
SHA-256 thumbprint of its public JWK, encoded as unpadded base64url. It is 43
characters, and every participant signature MUST have `kid == agentId`.

The library MUST generate a key locally when explicitly initializing a new
identity, and support loading it again. It MUST NOT silently replace a lost
or unreadable configured key. The operator manages durable key storage.
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
This profile signs small, explicitly defined objects; it does not reconstruct
signed bytes by serializing A2A SDK models.

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

## 4. Declared result and A2A transport

### 4.1 One result, signed by the provider

The provider signs a result payload. Its artifact variant is:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "production-result",
  "acceptanceDigest": "<H(acceptance, decoded production-accepted payload)>",
  "kind": "artifact",
  "taskState": "TASK_STATE_COMPLETED",
  "artifactId": "<designated final A2A artifact id>",
  "issuedAt": "2026-09-17T10:00:05.000Z"
}
```

Exactly two variants are allowed:

| `kind` | `taskState` | Additional field | Meaning |
| --- | --- | --- | --- |
| `artifact` | `TASK_STATE_COMPLETED` | `artifactId`, required | The provider declares the agreed final artifact available. |
| `failure` | `TASK_STATE_FAILED`, `TASK_STATE_CANCELED` or `TASK_STATE_REJECTED` | No `artifactId` | After acceptance, the provider explicitly declares that the agreed final artifact was not produced. |

The failure variant is a **signed failure receipt**, not a synthetic artifact.
For example:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "production-result",
  "acceptanceDigest": "<H(acceptance, decoded production-accepted payload)>",
  "kind": "failure",
  "taskState": "TASK_STATE_FAILED",
  "issuedAt": "2026-09-17T10:00:05.000Z"
}
```

Cancellation or rejection is eligible only after the signed acceptance and
with this explicit declaration. Neither automatically warrants a low score.
The application decides whether a terminal event matches this definition;
the adapter MUST NOT convert every terminal status into a production failure.

There MUST be exactly one result statement for an eligible production. Once
issued, it MUST NOT be replaced, including by changing failure to success.
Retrying the business operation after a terminal failure requires a new task.
Partial artifacts do not count as the designated final artifact. Multiple
independently evaluated final artifacts in one task are outside V0.

The signed result binds the reference `(provider, taskId, artifactId)`; A2A
artifact IDs are only unique within their task. **V0 does not hash or sign the
artifact body or arbitrary A2A metadata.** Changing a rated reference breaks
the evidence, but changing content behind that reference is not detected by
this profile. The provider MUST treat the designated artifact as final and
immutable. Content authentication is not part of the V0 claim.

Only the provider signs the result; the requester does not need to approve
its quality or countersign its existence before rating. The provider MUST
send the same signed result to the requester that it uses for its own rating.

### 4.2 Eligibility by example

| Situation | Eligible in V0? |
| --- | --- |
| Direct A2A `Message` response, with no task | No. |
| Discussion or refusal before production acceptance | No. |
| `INPUT_REQUIRED` or `AUTH_REQUIRED` | Not yet; neither is a terminal result. |
| Accepted production, final designated artifact, signed result | Yes, in both directions. |
| Accepted production, explicit signed failure as defined above | Yes, in both directions. |
| `COMPLETED` without a designated artifact | No automatic eligibility or failure inference. |
| Timeout, disconnect, or missing result signature | No; an observer's suspicion is not a provider-signed result. |

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
interaction simply produces no eligible rating evidence under this profile.

### 4.4 Metadata placement

The adapter carries signed bytes as opaque base64url strings inside the
envelopes below. It MUST preserve `protected`, `payload` and `signature`
strings exactly. It does not canonicalize the surrounding A2A object.

| Carrier | `metadata[extension-uri]` value |
| --- | --- |
| Requester's production `Message` | `{"request": Signed(request)}` |
| Provider `Task` acknowledging acceptance | `{"request": Signed(request), "acceptance": Signed(acceptance)}` |
| Final `Task` snapshot | Above, plus `"result": Signed(result)` |
| Designated final `Artifact` | `{"result": Signed(result)}` |
| Streaming `TaskStatusUpdateEvent` announcing acceptance/result | Same evidence available in the corresponding `Task` snapshot |

Here `Signed(...)` denotes a JSON object, not literal JSON syntax. Messages
and artifacts carrying the extension MUST also list its URI in `extensions`.
`TaskStatus` itself has **no metadata field** in the pinned A2A schema; use
`Task.metadata` or `TaskStatusUpdateEvent.metadata`, not an invented field.

The artifact result is issued only after assembly of the final artifact;
individual chunks, revisions and intermediate artifacts are not rated. The
adapter MUST check `taskId`, final `artifactId` and terminal status against
the enclosing task, and keep evidence available in final task snapshots so
that a stream interruption need not lose it. The service sees the submitted
evidence only; it cannot independently perform these transport checks.

## 5. Rating statement

Each participant MAY sign and submit:

```json
{
  "profile": "https://aithos.world/ext/interaction-ratings/v0",
  "type": "rating",
  "logId": "<service thumbprint>",
  "exchangeId": "<UUID from production request>",
  "resultDigest": "<H(result, decoded production-result payload)>",
  "rater": "<author's agentId>",
  "rated": "<counterpart's agentId>",
  "ratedRole": "provider",
  "score": 4,
  "issuedAt": "2026-09-17T10:00:06.000Z"
}
```

`ratedRole` is `provider` when the requester rates the provider, and
`requester` for the reverse direction. The identities MUST match the agreement
and differ. The signer MUST equal `rater`. `score` MUST be an integer in 1..5.
The reference chain MUST resolve to that exact agreement and service.

V0 uses this scale for the contribution described in §1.1:

| Score | Meaning |
| --- | --- |
| 1 | Very poor |
| 2 | Poor |
| 3 | Adequate |
| 4 | Good |
| 5 | Excellent |

The partner defines the concrete business criteria for applying this scale
before the pilot. A human, a business rule or an agent can choose the score;
the signing participant owns the evaluation. The library MUST NOT infer a
score from artifact presence, a terminal status, or the counterpart's score.
There is no claim that different evaluators have identical standards.

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
  result: Signed(production-result),
  rating: Signed(rating)
}
```

The service MUST validate all four envelopes and their complete chain of
references, role bindings, types, `logId` and limits before accepting the
bundle. It MUST NOT fetch A2A endpoints, artifacts, production terms or keys
from URLs. Embedded public keys suffice for these key-based identities.

Define these identifiers over decoded payloads, not signature encodings:

```text
requestDigest    = H("request", request payload)
acceptanceDigest = H("acceptance", acceptance payload)
resultDigest     = H("result", result payload)
ratingId         = H("rating", rating payload)
```

The service MUST atomically enforce:

1. `(requester, exchangeId)` binds one request and acceptance.
2. `(provider, taskId)` binds one accepted production and one result digest.
3. `(provider, taskId, rater)` admits at most one rating.

The first accepted bundle fixes these bindings. The other participant's
rating MUST carry the same request, acceptance and result payloads. A
different result from the same provider is a conflict, not a third rating.
The service MUST NOT decide between conflicting declarations by score.

Acceptance, uniqueness, journal append and confirmation persistence MUST be
one atomic durable commit. Concurrent submissions MUST NOT reserve the same
position or admit two ratings for one slot. A response MUST NOT acknowledge
an entry that has not committed.

- First acceptance: `201 Created`, with the confirmation package in §7.2.
- Retry of the same validated `ratingId` and evidence payloads: `200 OK`, with
  the **original stored package**, no new entry and no new timestamp.
- A different rating for an occupied slot: `409 RATING_EXISTS`.
- A different request, acceptance or result for an existing binding:
  `409 EXCHANGE_CONFLICT`.

The service returns the stored bundle on retry even if a caller used another
valid signature encoding for the same payloads. Callers SHOULD retry the exact
original bytes. Following a timeout, acceptance is unknown until a retry or
lookup succeeds; callers MUST NOT create a new exchange to retry a rating.
No score revision, withdrawal or tombstone operation exists in V0.

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

`recordHash` covers the exact four envelopes, including their keys and
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
  submission: <the stored four-envelope bundle>,
  confirmation: Signed(<rating-recorded payload>)
}
```

This is the **confirmation package**. It contains the author's signed rating,
both participants' agreement evidence, the provider's result and the service's
signed acknowledgment. No signature is taken as a substitute for validating
the object it covers.

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

For each rated role, the summary returns `{count, sum, average}` plus the
top-level `agentId`, `formula: "arithmetic-mean-v0"` and `checkpoint`.
`count` is the number of accepted ratings, `sum` their integer sum, and
`average = sum / count`, rounded to two decimal places with ties rounded up.
For count 0, sum is 0 and average is `null`. The two groups are named
`asRequester` and `asProvider`. If a JSON safe-integer bound would be exceeded,
the service MUST reject the operation rather than round an integer silently.

Every admitted score has equal weight, including scores attached to failures.
No mean combines roles. Displays MUST show the count with the mean, identify
the role, and show "Not yet rated" when count is zero. History MUST expose
score, both identities, role, declared result kind, author time and service
registration time, with the underlying evidence available. These are public
subjective ratings, not a success rate or a service-certified quality score.

Filtered pages and summaries are convenience views. The signed checkpoint
does not by itself prove a filtered list is complete or its mean is correct.
Anyone can recompute both from the full journal prefix and compare them.

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
| 422 | `INVALID_EVIDENCE` | Missing/mismatched agreement or result, invalid roles or ineligible result. |
| 422 | `WRONG_LOG` | Signed request or rating targets another service identity. |
| 409 | `RATING_EXISTS` | Another rating occupies this participant's slot. |
| 409 | `EXCHANGE_CONFLICT` | Task, exchange, acceptance or result binding conflicts. |
| 404 | `NOT_FOUND` | Requested rating does not exist. |
| 429 | `RATE_LIMITED` | Operational request limit; `Retry-After` SHOULD be supplied. |
| 503 | `UNAVAILABLE` | The service cannot complete the operation safely. |

Operational limits are allowed without accounts; IP-based reputation is not
part of this profile. A 503 or lost response does not establish non-acceptance:
use the retry rules. No new problem code or endpoint is added to the registry.

### 9.2 Library responsibilities

The first implementation supplies one adapter for the partner's chosen SDK.
Language and SDK version remain an implementation selection; this draft does
not promise existing SDK hook compatibility or a two-line integration.

The adapter MUST support local identity loading/initialization, explicit
request and acceptance, signing and collecting result evidence, and submitting
a chosen score. It MUST expose the complete confirmation package and distinguish
recorded, rejected and unknown submission outcomes. Illustrative application
code for the final operation is:

```python
confirmation = await ratings.rate(production, score=4)
```

Here `production` already contains the eligible agreement and result. The
function signs locally, submits, checks the returned package and returns it.
At minimum it MUST verify that the confirmation matches the configured log,
the submitted rating and the returned stored bundle. This local response
check does not audit the full journal.

The rating call is explicit and may wait for its acknowledgment. Business
request handling and artifact delivery MUST NOT depend on the ratings service
being reachable. Do not make signing the agreement depend on a live service
lookup when the log configuration is already known. The library MUST preserve
the original signed request for a retry; it need not implement a durable
background queue, archive receipts, notify peers, or run an auditor.

### 9.3 Required checks before implementation is called conformant

The planned vectors are listed in [`vectors/ranks/README.md`](vectors/ranks/README.md).
They cover a successful production, a declared failure, both rating directions,
invalid signatures and bindings, duplicate retries and concurrent writes,
mutation of each signed field, journal tampering and retained-anchor checks.
Fixtures and tests are implementation work, not delivered by this draft.

A pilot additionally checks whether the actual SDK preserves signed envelopes
through metadata and streaming, whether the application can mark acceptance
and the final result explicitly, and whether users understand the score scale.
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

Acceptance and result evidence are prerequisites. A provider that refuses to
accept, goes silent, or withholds its result signature can leave a production
unrateable. Once a participant holds all required evidence, it can submit its
rating directly without the counterpart's further permission. Optional ratings
and these eligibility limits produce selection bias: the service cannot infer
the total number or success rate of all business interactions.

The public journal exposes participant relationships, identifiers, timing,
scores and declared outcome states. It does not accept production terms,
salts, artifacts, messages, product details or amounts. A hash is not
encryption; the private salt reduces guessing of production terms only while
it remains private. Participants MUST understand the public nature of signed
rating submissions before enabling the integration.

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
