# Aithos Agent Card Registry V1

**Status:** specification draft
**Version:** 0.1.0
**Date:** 2026-08-25

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**
and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

## 1. What this is

A public registry that hosts A2A Agent Cards. Anyone can publish a card. The
card is signed by its owner's key. Only a holder of an authorized key can
change it.

The registry is a **byte store with a key-based authorization rule**. It has no
accounts, no passwords, no sessions and no tenants. The key is the account.

The claim made by a V1 entry is exactly:

> This Agent Card was published by the holder of key `<thumbprint>`, and every
> subsequent version has been signed by a key authorized by that lineage.

**This is not an identity claim.** V1 does not verify domains, organizations or
endpoints. A card named `Acme Support` proves nothing about Acme. Consumers and
user interfaces MUST treat the key thumbprint, not the `name` field, as the
identity of an entry.

Domain verification is deliberately out of scope for V1. Section 10 records how
it attaches later without breaking anything defined here.

## 2. Normative baseline

V1 pins:

- A2A `v1.0.1`, commit
  `3303592588e388e62e0f69f701af531d2f4e3991`, in particular
  §4.4.7 `AgentCardSignature` and §8.4 Agent Card Signing;
- JWS (RFC 7515) and the JOSE registries (RFC 7518);
- JCS (RFC 8785) and SHA-256;
- JWK Thumbprint (RFC 7638);
- Semantic Versioning 2.0.0, for the ordering rule in §6.4;
- RFC 9457 for error responses.

The pinned A2A commit fixes the field-presence table of §5.2. An A2A upgrade is
a new conformance profile until the presence table is re-derived and the test
vectors pass.

## 3. Identity model

### 3.1 The key is the account

Every write is authorized by a JWS signature inside the Agent Card's own
`signatures[]` array. There is no other authorization mechanism.

### 3.2 `kid` is the thumbprint

For every signature the registry accepts:

```text
protected.kid == BASE64URL(SHA-256(JCS(RFC 7638 thumbprint input of the JWK)))
```

This single rule is what makes the rest of the design work. Because `kid` is
inside the signed protected header, and `kid` is a cryptographic digest of the
key material, the public key that verifies a signature cannot be substituted.
The registry therefore does not need any second signed object to authenticate a
key set.

`BASE64URL` is unpadded throughout this document.

### 3.3 `agentId`

```text
agentId = kid of the genesis key
```

43 unpadded base64url characters. The client computes it offline, before its
first request, which is what allows `PUT` to a client-chosen URL and makes the
`jku` chicken-and-egg problem disappear.

`agentId` is a **genesis identifier**, like the first commit of a repository.
After key rotation it no longer names a currently authorized key. It never
changes.

### 3.4 The authorized key set

Each agent record carries a set of authorized `kid` values.

- On creation, the set is exactly the set of keys that signed the first version.
- On update, the new set is exactly the set of keys that signed the new version.

Adding a backup key therefore means publishing one version signed by **both**
the current key and the new one. Rotating away from a key means publishing a
version signed only by the keys that should remain.

If every authorized key is lost, the entry is frozen permanently. The registry
offers no recovery path and MUST NOT offer one, because it never holds key
material. Interfaces SHOULD push publishers to register a second key early.

## 4. Resources

### 4.1 Agent

```text
agentId                 // genesis kid, immutable
status                  // ACTIVE | WITHDRAWN
currentVersionDigest
authorizedKids[]        // current authorized set
createdAt
updatedAt
```

### 4.2 AgentCardVersion

Immutable as soon as it is created:

```text
agentId
seq                     // registry-assigned, strictly increasing from 1
cardVersion             // the A2A card's own `version` field
cardBytes               // exact canonical bytes, stored verbatim
cardDigest              // sha256:<lowercase hex> of cardBytes
signingKids[]
keys[]                  // the public JWKs that signed this version
createdAt
```

`cardBytes` is written once and served verbatim forever. The registry MUST NOT
re-serialize a stored card on read. Digests are `sha256:<lowercase-hex>`.

## 5. Card processing

### 5.1 Strict parsing

Request JSON is parsed strictly. V1 rejects duplicate object member names,
invalid UTF-8, isolated surrogates and numbers outside the RFC 8785 / I-JSON
domain.

These are not stylistic rules. A parser that silently keeps the last duplicate
member, or that rounds an integer above 2^53, produces a different canonical
form than the one the client signed. Rejecting them turns a confusing signature
failure into a precise error.

### 5.2 Field presence

Before canonicalization, A2A §8.4.1 rule 1 requires protobuf field-presence
semantics:

- an `optional` field that was not set is omitted;
- an `optional` field explicitly set to its default value is kept;
- a `REQUIRED` field is always present, default-valued or not;
- any other field whose value equals its default is omitted.

The registry validates that a submitted card already satisfies these rules and
rejects it otherwise. It does **not** transform the card. The transformation is
the publisher's responsibility, performed once, at authoring time.

Implementations derive a static presence table from the pinned `a2a.proto`.
This table is the only part of the system that cannot be obtained from an
off-the-shelf library.

### 5.3 Canonical bytes

```text
cardBytes = UTF8(JCS(agentCard))
cardDigest = "sha256:" || lowercase_hex(SHA-256(cardBytes))
```

`cardBytes` includes the `signatures` member. It is the exact artifact served
at the public card URL.

### 5.4 Signing payload

```text
payloadBytes = UTF8(JCS(agentCard without its top-level `signatures` member))
```

Because JCS is deterministic and per-member, removing one top-level member from
a canonical object and re-canonicalizing yields exactly the canonical form of
the remainder. No ambiguity is possible here.

### 5.5 Signature verification

For each entry of `signatures[]`:

```text
signingInput = ASCII(protected || "." || BASE64URL(payloadBytes))
```

The registry:

1. strict-decodes `protected` and requires exactly `alg`, `typ`, `kid`, and
   optionally `jku`; any other member, a non-empty `crit`, or `b64:false` is
   rejected;
2. requires `typ == "JOSE"`;
3. requires `alg` in the allowlist `{ES256, EdDSA, RS256}`, with RSA moduli of
   at least 2048 bits, and requires the algorithm to match the key type;
4. resolves `kid` to a JWK supplied in the request body and requires §3.2 to
   hold;
5. verifies the signature over `signingInput`.

`alg: none` and algorithm substitution are rejected by construction, since the
allowlist is checked before any key is resolved and `kid` binds the key type.

ES256 signatures are the 64-byte JOSE `R || S` form, not DER.

### 5.6 Submitted keys

Every JWK in the request body MUST be a public key. A JWK containing `d`, `p`,
`q`, `dp`, `dq`, `qi` or `k` is rejected with `PRIVATE_KEY_SUBMITTED` and MUST
NOT be stored or logged. This protects a publisher who pastes the wrong file.

Unused keys — present in the body but not referenced by any `kid` — are
rejected, so that the authorized set is never silently wider than intended.

### 5.7 `jku`

`jku` is OPTIONAL. When present it MUST be an absolute HTTPS URL with no
userinfo and no fragment.

Publishers are RECOMMENDED to set it to this registry's JWKS URL for the agent
(§7.2), because a generic A2A client that follows `jku` can then verify the
card with no knowledge of this registry. That is the cheapest interoperability
this design offers.

The registry serves the JWKS regardless of whether `jku` is set, and a verifier
MUST NOT treat `jku` as a trust anchor.

## 6. Write operations

### 6.1 Request body

```http
PUT /v1/agents/{agentId}
Content-Type: application/json
```

```json
{
  "agentCard": { "...": "a complete A2A AgentCard including signatures[]" },
  "keys": [
    { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  ]
}
```

No `Idempotency-Key` header is required. `agentId` is client-derived and the
operation is idempotent by construction: submitting bytes identical to the
current version succeeds with `200` and changes nothing, including the
sequence. A client retrying after a network timeout does exactly this, and the
write it is retrying may well have succeeded — answering it with a conflict
would report failure for an operation that worked.

The test is on the digest, not on the content. Different bytes at the same
version are still refused by §6.4, whatever they contain.

### 6.2 Creation

Accepted when the agent does not exist and:

1. §5.1 to §5.6 pass;
2. the card validates against the pinned A2A `AgentCard` schema;
3. `signatures[]` is non-empty and every signature verifies;
4. `{agentId}` in the request path equals the `kid` of at least one signing key.

The authorized set becomes the set of signing `kid` values. `seq` is 1.

Response `201 Created`.

### 6.3 Update

Accepted when the agent exists, is `ACTIVE`, and:

1. all creation checks except (4) pass;
2. **at least one signing `kid` belongs to the current authorized set**;
3. the version ordering rule of §6.4 holds.

The authorized set is replaced by the set of signing `kid` values. `seq` is
incremented.

Response `200 OK`.

### 6.4 Version ordering and replay

The A2A `AgentCard.version` field MUST be a valid Semantic Versioning 2.0.0
string, and each new version MUST be **strictly greater** than the current one.

This is the registry's replay defence and it is the reason the rule exists.
Every published version stays validly signed forever, so without a monotonic
element anyone who has merely *observed* an old card could re-submit it and roll
the entry back. Requiring a strictly greater `version` means a rollback needs a
fresh signature, which needs a key.

A client MAY additionally send `If-Match` with the current `cardDigest` to get
optimistic concurrency between two legitimate publishers. A mismatch returns
`412`.

### 6.5 Withdrawal

Included in V1 for a simple reason: the registry never holds the publisher's
key, so the publisher must be able to remove their own entry without asking an
operator.

```http
DELETE /v1/agents/{agentId}
```

```json
{
  "withdrawal": {
    "protected": "<base64url>",
    "payload": "<base64url>",
    "signature": "<base64url>"
  },
  "keys": [ { "...": "the JWK matching protected.kid" } ]
}
```

The decoded payload is exactly:

```json
{
  "action": "withdraw",
  "agentId": "<agentId>",
  "cardDigest": "sha256:<hex>",
  "issuedAt": "2026-08-25T12:00:00.000Z",
  "registryOrigin": "https://registry.aithos.world"
}
```

`payload` MUST equal `BASE64URL(UTF8(JCS(that object)))` verbatim. `cardDigest`
MUST equal the current version's digest, which prevents replay of an older
withdrawal. `registryOrigin` MUST equal this registry's canonical origin. The
signature MUST be by a key in the current authorized set, and the protected
header follows §5.5.

The agent becomes `WITHDRAWN`, and the registry MUST stop serving its current
card and its JWKS. This is not implied by the status change: the public read
path may be answered by a cache or an object store that never sees the API, and
because withdrawal is terminal no later publication would ever overwrite what
those hold. A registry that only flips a flag leaves the card published, which
defeats the one purpose of withdrawal.

Published versions remain readable at their digest. What was published is not
erased; only its current status changes.

Withdrawal is terminal in V1: the `agentId` is never reusable, so the
identifier cannot be recycled to point at different content.

## 7. Public endpoints

All endpoints in this section are anonymous and read-only.

### 7.1 Current card

```http
GET /v1/agents/{agentId}/agent-card.json
```

```http
HTTP/1.1 200 OK
Content-Type: application/a2a+json
ETag: "<opaque>"
Cache-Control: public, max-age=60
```

The response body is `cardBytes`, verbatim. A `WITHDRAWN` agent returns
`410 Gone`, and a missing one `404`.

`ETag` is an opaque validator in the sense of RFC 9110, good for
`If-None-Match` and nothing else. It is **not** the card digest and MUST NOT be
parsed as one: this endpoint may be answered by a cache or an object store that
computes its own validator.

A client that needs the digest computes it from the bytes it received. That is
not a workaround, it is the only correct behaviour — a digest handed over by
the same server whose answer it is meant to check establishes nothing.

### 7.2 JWKS

```http
GET /v1/agents/{agentId}/jwks.json
Content-Type: application/jwk-set+json
```

The currently authorized public keys, each with its `kid`.

### 7.3 Record and history

```http
GET /v1/agents/{agentId}
GET /v1/agents/{agentId}/versions
GET /v1/agents/{agentId}/versions/{cardDigest}/agent-card.json
```

The record is a projection: `agentId`, `status`, `currentVersionDigest`,
`authorizedKids`, timestamps and same-origin links. It is a convenience, never
a substitute for verifying the card.

Historical versions are immutable exact bytes and use
`Cache-Control: public, max-age=31536000, immutable`. Their digest is in the
request path, so it never needs carrying in a header.

### 7.4 Listing

```http
GET /v1/agents?limit=&cursor=
```

Newest-updated first, cursor-paginated. V1 has no search, no ranking and no
scoring. Entries carry no badge of any kind.

### 7.5 Registry manifest

```http
GET /v1/registry
```

Canonical origin, pinned A2A commit, presence-table digest, accepted `alg`
values, limits, and a link to the published test vectors.

## 8. Limits

| Limit | Value |
| --- | --- |
| Card size | 256 KiB |
| Keys per request | 8 |
| Signatures per card | 8 |
| Versions retained | unbounded |

Write rate limits are per source address and per `agentId`.

## 9. Problems

RFC 9457 `application/problem+json`.

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `JSON_INVALID` | Invalid, duplicate-member or non-I-JSON body |
| 400 | `PRIVATE_KEY_SUBMITTED` | A submitted JWK contained private material |
| 403 | `NOT_AUTHORIZED_KEY` | No signature by a currently authorized key |
| 404 | `NOT_FOUND` | Unknown `agentId` |
| 409 | `AGENT_ID_MISMATCH` | Path does not equal any signing `kid` |
| 409 | `VERSION_NOT_INCREASING` | `version` is not strictly greater |
| 410 | `WITHDRAWN` | Entry was withdrawn by its key holder |
| 412 | `PRECONDITION_FAILED` | `If-Match` did not match the current digest |
| 413 | `CARD_TOO_LARGE` | Card exceeds the size limit |
| 422 | `CARD_INVALID` | Card violates the pinned A2A schema |
| 422 | `PRESENCE_INVALID` | Field-presence rules of §5.2 not applied |
| 422 | `SIGNATURE_INVALID` | A JWS failed verification |
| 422 | `KID_NOT_THUMBPRINT` | `kid` is not the RFC 7638 thumbprint of its JWK |
| 422 | `ALG_NOT_ALLOWED` | Algorithm outside the allowlist |
| 422 | `UNUSED_KEY` | A submitted JWK is referenced by no signature |

## 10. Deliberately out of scope

V1 does **not** provide: domain verification, organizational identity, endpoint
liveness or conformance checks, a transparency log, accounts, search, ranking,
reputation, or any notion of a verified badge.

Three things are reserved so that later work is additive rather than a
migration:

- **URL and identifier shape.** `agentId` derivation, the `/v1/agents/{id}/…`
  paths and the digest-based ETags are stable. A future domain-verification
  layer attaches as an attribute of the agent record. It changes neither the
  identifier nor the card.
- **Signed statements.** V1 publishes no registry-signed statement. When one is
  introduced, it will be a separate envelope alongside the card, never a field
  inside it, so that stored cards stay byte-identical.
- **Transparency.** V1 has no append-only log, so mis-issuance by a compromised
  registry operator is undetectable by publishers. This is acceptable only
  because V1 makes no identity claim. It stops being acceptable the day a
  verified badge exists.

## 11. Conformance

The registry publishes test vectors covering: canonical bytes for a reference
card, each presence rule, `kid`/thumbprint agreement, multi-signature rotation,
rollback rejection, duplicate-member rejection, I-JSON number rejection,
`alg` confusion rejection, private-key rejection, and withdrawal replay
rejection.

A second, independent implementation of the verifier is expected to pass the
same vectors. Until it does, no interoperability claim is made.
