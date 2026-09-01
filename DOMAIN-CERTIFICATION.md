# Aithos Domain Certification Profile

**Status:** specification draft
**Version:** 0.1.0
**Date:** 2026-09-01
**Applies to:** Aithos Agent Card Registry V1, `SPEC.md` 0.1.0

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**
and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

This document is **additive**. It defines no new card field, changes no
canonicalization rule, and alters no byte of any stored `cardBytes`. An
implementation of `SPEC.md` 0.1.0 that does not implement this profile remains
conformant to `SPEC.md` 0.1.0, and every card published before this profile
existed keeps its digest.

## 1. What this is

`SPEC.md` §1 states what a V1 entry claims and, just as plainly, what it does
not: no domain, no organization, no endpoint. §10 reserves domain verification
as an attribute of the agent record, attaching later without touching the
identifier or the card. This is that attachment.

The claim a certified domain adds is exactly:

> At the time stated, the DNS zone for `example.com` published a record naming
> agent `<agentId>`, and the holder of a key authorized for `<agentId>` asked
> for that domain to be listed here.

Both halves are load-bearing and neither implies the other. What it still does
not claim is set out in §9.

### 1.1 Why both halves

A DNS record alone proves one direction: what the domain says about the agent.
It cannot prove what the agent says about the domain, because the agent's key
has no authority over someone else's zone — which is the whole reason a TXT
record proves anything at all.

Accepting that one direction on its own reproduces the defect `SPEC.md` §6.1
already refuses under `UNPROVEN_KEY`. Anyone who can publish a TXT record can
publish one naming a well-known agent, and that agent's entry then lists a
domain its key holder never asked for and cannot remove. The entry would be
making a statement on behalf of a key holder who was never consulted.

The converse is refused for the same reason: a signed request naming
`example.com` establishes nothing about `example.com`, only that somebody asked.

So a certification requires an assertion from each side, each made where that
side actually has authority: the domain speaks in its own zone, the key speaks
by signing.

### 1.2 Why the agent's half is not carried in DNS

A signed statement could be placed in the TXT record itself, as DKIM places key
material there, and the certification would then be a single self-contained
object needing no registry state at all.

It is not, because consent that cannot be withdrawn is not consent. The agent's
half would live in a zone the agent does not control: the key holder could never
retract it, and the domain owner could keep serving it indefinitely. The signed
half therefore goes where its author can also revoke it.

## 2. Normative baseline additions

In addition to the baseline of `SPEC.md` §2:

- RFC 1035 and RFC 9499, for `TXT` records and DNS terminology;
- RFC 8552 and RFC 8553, for underscored, globally scoped DNS node names;
- RFC 5890 and RFC 5891 (IDNA2008), for internationalized domain names;
- RFC 7208 §3.3, for the treatment of a multi-string `TXT` record;
- RFC 6376 §3.2, whose tag-value syntax this profile follows in shape.

## 3. The DNS record

### 3.1 Name

For a certified domain `D`, the record name is:

```text
_a2a.<D>
```

`D` is in A-label form (§5.4). One name serves every agent certified for that
domain; the record set MAY hold many records.

`_a2a` is not yet in the IANA *Underscored and Globally Scoped DNS Node Names*
registry (RFC 8553). Registration is intended. Until then, coexistence is safe
by construction: §3.3 requires every record this profile reads to begin with
`v=A2A1`, and requires any other record at the name to be ignored rather than
treated as an error. A future unrelated use of `_a2a` does not break a zone
that also carries these records, and does not break this profile.

### 3.2 Record data

```text
_a2a.acme.com.   IN   TXT   "v=A2A1; k=<agentId>"
```

The record data is a sequence of `;`-separated `tag=value` pairs. Two tags are
REQUIRED and no other tag is defined by this version:

| Tag | Value |
| --- | --- |
| `v` | Exactly `A2A1`. MUST be the first tag. |
| `k` | The `agentId` (`SPEC.md` §3.3): 43 unpadded base64url characters. |

Where a `TXT` record consists of several character-strings, the record data is
their concatenation with no separator, as RFC 7208 §3.3 specifies for the same
situation. ASCII space and horizontal tab surrounding a tag, an `=` or a `;`
are ignored. Tag names are lowercase and case-sensitive; the value of `v` is
case-sensitive; `k` is base64url and therefore case-sensitive.

An unrecognized tag MUST be ignored, so that a later version of this profile can
add one without invalidating deployed zones.

The `agentId` appears in the record *data* and never in the record *name*. DNS
names are case-insensitive and resolvers may vary the case of a query name;
base64url is case-sensitive. A name carrying an `agentId` would therefore be
neither reliably comparable nor safely delegable.

### 3.3 Matching

Domain `D` carries a valid declaration for `agentId` `A` when the record set at
`_a2a.<D>` contains at least one `TXT` record whose data, after §3.2 parsing,
has `v=A2A1` as its first tag and `k=A`.

Every other record at that name MUST be ignored, including records with a
different `k`, records with an unrecognized `v`, and records that do not parse.
A malformed record at the name MUST NOT cause the resolution to fail: a domain
that hosts several agents would otherwise let one bad record deny all the
others.

### 3.4 Delegation

No delegation mechanism is defined, because DNS already has one. A resolver
follows `CNAME` transparently, so

```text
_a2a.acme.com.   IN   CNAME   _a2a.acme.agents.example.net.
```

lets a hosting provider maintain the declarations for a customer's domain
without the customer editing their zone again. The certification is attributed
to the queried name `_a2a.acme.com`, never to the target.

### 3.5 The record is permanent

The record MUST remain published for as long as the certification is meant to
hold. It is not a challenge to be removed once observed.

This is what keeps the registry out of the trust path. The record is the
evidence, it is public, and any party — a client, a competitor, an auditor —
can resolve it and reach the same conclusion the registry reached. The registry
publishes an observation, not an attestation, and `SPEC.md` §10's third reserved
point is therefore not triggered: there is no registry-signed statement whose
mis-issuance would be undetectable, because there is no registry-signed
statement.

A profile that removed the record after checking it would be making the opposite
trade. The proof would exist only in the registry's memory, every reader would
be trusting the operator's word, and the transparency log §10 requires before a
verified badge exists would become a prerequisite. ACME can discard a challenge
because it issues a certificate that is itself published and logged; this
profile issues nothing.

Permanence also makes revalidation (§7) possible at no cost to the publisher.

## 4. Resources

### 4.1 Agent, extended

The agent record of `SPEC.md` §4.1 gains three members:

```text
requestedDomains[]      // the set from the last accepted certification, verbatim
certifiedDomains[]      // the subset currently observed in DNS; published
certificationIssuedAt   // the issuedAt of the last accepted certification
```

### 4.2 CertifiedDomain

```text
domain                  // A-label, lowercase
certifiedAt             // first observation in the current continuous run
lastCheckedAt           // most recent successful observation
```

### 4.3 Why two sets

`requestedDomains` is what a key holder signed. `certifiedDomains` is what the
registry can currently observe. Only the second is published.

They are kept apart because they answer different questions and fail
differently. A domain whose zone stops answering for twenty minutes has not been
un-asked-for; requiring the publisher to re-run a signed command after every
transient resolution failure would make the operation hostile without making any
reader safer. Keeping the request lets the certification return by itself when
the record does, and keeping the observation separate means the registry never
publishes a domain it cannot see right now.

## 5. Certification

### 5.1 Request

```http
PUT /v1/agents/{agentId}/domains
Content-Type: application/json
```

```json
{
  "certification": {
    "protected": "<base64url>",
    "payload": "<base64url>",
    "signature": "<base64url>"
  },
  "keys": [ { "...": "the JWK matching protected.kid" } ]
}
```

The envelope is the one `SPEC.md` §6.5 already defines for withdrawal, and the
protected header follows §5.5 unchanged. No new signature construction is
introduced by this profile.

### 5.2 Payload

The decoded payload is exactly:

```json
{
  "action": "certify-domains",
  "agentId": "<agentId>",
  "domains": ["acme.com", "acme.fr"],
  "issuedAt": "2026-09-01T09:14:22.000Z",
  "registryOrigin": "https://registry.aithos.world"
}
```

`payload` MUST equal `BASE64URL(UTF8(JCS(that object)))` verbatim. Extra members
are refused. `registryOrigin` MUST equal this registry's canonical origin, so a
certification cannot be lifted into another registry.

`domains` MUST be an array of A-labels (§5.4), sorted in ascending code-point
order, with no duplicate. JCS orders object members but not array elements, so
array order is signed as submitted; requiring one order makes the payload a
deterministic function of the set, and removes any question of whether
`["a","b"]` and `["b","a"]` are the same request. An unsorted or duplicated
array is `DOMAINS_NOT_CANONICAL`.

An empty `domains` array is valid and removes every certification. There is no
separate deletion operation, for the same reason `SPEC.md` §3.4 has no rotation
operation: the request states the complete set, and stating a smaller one is how
you shrink it.

`cardDigest` is deliberately **absent**, unlike the withdrawal payload of §6.5.
A certification is a statement about domains, not about a card, and it survives
publication of a new version. Binding it to a digest would expire every
certification at the next `publish` for no gain.

### 5.3 Authorization and replay

The certification is accepted when:

1. the agent exists and is `ACTIVE`;
2. the protected header satisfies `SPEC.md` §5.5 and the key is supplied in
   `keys` under §5.6;
3. the signature verifies and `protected.kid` is in the agent's **current**
   authorized set (`SPEC.md` §3.4);
4. `issuedAt` is a valid RFC 3339 UTC timestamp and is **strictly greater** than
   the stored `certificationIssuedAt`;
5. every domain passes §5.4 and §5.5.

Rule (4) is the replay defence, and it is `SPEC.md` §6.4's rule applied to a
different field. Every accepted payload stays validly signed forever, and the
set replaces rather than accumulates, so without a monotonic element anyone who
observed an earlier certification could resubmit it and silently restore a
domain the publisher had removed. Requiring a strictly greater `issuedAt` means
a rollback needs a fresh signature, which needs a key. The registry compares the
value only against the one it stored; it does not need the client's clock to be
correct, only monotonic.

A signature by a key that is not currently authorized is `NOT_AUTHORIZED_KEY`,
whatever that key's history: like §6.3, a certification authorizes a statement
*here and now*.

### 5.4 Domain syntax

Each element of `domains`:

- MUST be a fully-qualified domain name in A-label form (RFC 5890), with no
  trailing dot and no scheme, port, path or userinfo;
- MUST be lowercase, and MUST consist only of the characters permitted in an
  LDH label, with each label 1–63 octets and the name at most 253 octets;
- MUST NOT be an IP address literal;
- MUST NOT be a public suffix, evaluated against the Public Suffix List.

A U-label — `acmé.com` rather than `xn--acm-dla.com` — is refused rather than
converted. Conversion is where homograph confusion is introduced: the registry
would be choosing, on the publisher's behalf, which Unicode string a stored name
came from, and §9 then has to display something. The publisher performs IDNA
conversion once, at authoring time, and states the result. This is the same
division of labour `SPEC.md` §5.2 applies to field presence.

Refusing a public suffix keeps the operation from producing a statement about a
name no single party controls.

### 5.5 Resolution

Before storing anything, the registry MUST resolve every domain in the payload
itself. A client's claim that a record exists is not evidence that it does.

The registry:

1. queries `TXT` at `_a2a.<D>` — `QTYPE=TXT` only, never `ANY`;
2. uses its own recursive resolvers, and MUST NOT use any resolver, nameserver
   or address named in the request;
3. retries over TCP when the answer is truncated;
4. follows at most 8 `CNAME`/`DNAME` redirections;
5. examines at most the limits of §8;
6. applies §3.3.

Per domain, the outcome is one of: **observed** (§3.3 matched); **absent** (the
name resolved but no record matched); or **unresolved** (`SERVFAIL`, timeout,
truncation that TCP did not repair, or a redirection limit reached). `NXDOMAIN`
and `NODATA` are *absent*, not *unresolved*: they are answers.

**The operation is atomic.** If any domain is not *observed*, nothing is stored
and the request is refused, with a per-domain outcome in the problem document.
Storing the subset that resolved would leave `requestedDomains` different from
any set a key ever signed, and §4.3's distinction between what was asked for and
what is observable only holds if the first is always exactly what was signed.

Resolution happens in the request path, which `SPEC.md` otherwise avoids: this
endpoint exists in order to perform it, its cost is bounded by §8, its result is
what the caller is waiting for, and the alternative — accepting a request and
resolving later — would publish a pending state that says a domain was claimed
but not checked, which is the one thing this profile must never publish.

### 5.6 Effect

On acceptance, `requestedDomains` becomes the payload's `domains`,
`certifiedDomains` becomes the same set with `certifiedAt` and `lastCheckedAt`
set to the observation time, and `certificationIssuedAt` becomes the payload's
`issuedAt`.

Response `200 OK`, carrying the resulting record projection.

### 5.7 Withdrawal

A `WITHDRAWN` agent (`SPEC.md` §6.5) certifies nothing: this endpoint answers
`410`, and the read path serves no domains for it, with the same shape as the
card and the JWKS.

## 6. Read surface

The record projection of `SPEC.md` §7.3 gains:

```json
{
  "domains": [
    { "domain": "acme.com", "certifiedAt": "…", "lastCheckedAt": "…" }
  ]
}
```

`domains` is `certifiedDomains`, sorted, and never `requestedDomains`. A reader
is told what the registry can currently see, not what somebody once asked for.

No other endpoint is added. The certified set is small, it changes rarely, and
it belongs beside the status and the authorized key set rather than at a path of
its own.

## 7. Freshness and revalidation

A certification is an observation with a timestamp, and this profile states its
bound rather than implying one, as `SPEC.md` §6.6 does for the read path.

The periodic pass of §6.6 re-resolves every domain in `requestedDomains` for
every `ACTIVE` agent, under §5.5. For each:

- *observed* — `lastCheckedAt` is updated; if the domain was not in
  `certifiedDomains`, it is added, with `certifiedAt` set to now;
- *absent* or *unresolved* — the domain is removed from `certifiedDomains` once
  it has failed **three consecutive passes**, and is left alone before that.

**The bound, stated plainly.** A domain whose record is removed stops being
published within three passes plus the read path's cache lifetime; with the
hourly pass of §6.6 that is under four hours. A domain whose record returns is
republished at the next pass. A deployment MUST publish its interval.

Three passes rather than one, because a single failing pass is far more likely
to be a resolver hiccup than a revoked declaration, and because the cost of the
delay is bounded and public while the cost of flapping is a certification that
appears and disappears for reasons no reader can see.

Removal is not a signed operation and does not touch `requestedDomains`. The
registry is not deciding anything; it is reporting that it can no longer observe
what it once observed. This is what makes a certification self-correcting when a
domain expires, changes hands, or has its declaration deleted — the case that
matters most, and the one a single check at certification time never covers.

A change to `certifiedDomains` is committed state and therefore converges to the
read path exactly like a publication, under §6.6 and its sequence-stamping rule.

## 8. Limits

| Limit | Value |
| --- | --- |
| Domains per agent | 8 |
| `TXT` records examined per name | 32 |
| Record data examined per name | 4096 octets |
| Resolution timeout, per domain | 5 s |
| `CNAME`/`DNAME` redirections | 8 |
| Certification requests | rate limited per source address and per `agentId` |

The per-name limits exist because an anonymous caller chooses the name being
queried and therefore chooses how much work the answer costs. The per-domain
timeout bounds a request at 8 × 5 s in the worst case; a deployment SHOULD
resolve the domains of one request concurrently.

## 9. What a certified domain does not claim

Interfaces displaying a certified domain MUST NOT present it as more than §1
states. Specifically, a certified domain says nothing about:

- the truth of `provider.organization`, or of any other card field. Those remain
  unverified, and `SPEC.md` §1's rule that the key thumbprint, not `name`, is
  the identity of an entry is unchanged;
- who operates the endpoints in `supported_interfaces[]`. A certified domain
  need not be the host of any of them, and this profile does not require it to
  be. An interface SHOULD show the endpoint hosts alongside the certified
  domains rather than merging the two lists, since a reader who assumes they are
  the same thing is the reader this registry exists to protect;
- the conduct, quality or safety of the agent.

Domains MUST be displayed in the A-label form in which they are stored, and MUST
NOT be rendered as U-labels. `xn--80ak6aa92e.com` displays as `аpple.com` in
Cyrillic; a registry that renders it has built the phishing instrument its own
`README` refuses to build.

No badge, tick, score or ranking is defined by this profile, and none may be
inferred from it. The honest rendering is a domain and a date.

## 10. Deliberately out of scope

Reserved, additive, and not part of this version:

- **DNSSEC.** Not required, and not reported. A declaration in a signed zone is
  materially stronger than one in an unsigned zone, and recording the validation
  state is the obvious first extension — it adds a member to §4.2 and nothing
  else.
- **Multi-perspective resolution.** A single vantage point is trusted here. An
  off-path attacker who can influence one resolution path can produce one false
  observation; §7 will remove it again unless the influence persists. Resolving
  from several vantage points and requiring quorum is the second obvious
  extension, and is the direction the CA/Browser Forum has taken for the same
  threat.
- **`.well-known` coherence.** Whether `https://<D>/.well-known/agent-card.json`
  serves the same bytes as the entry is the question an A2A client most wants
  answered, and it is a *live* check, never stored evidence: a card republished
  without updating the well-known copy would otherwise revoke a domain
  certification for no security reason.
- **Subtree and wildcard scope.** A certification covers exactly the name given.
  `acme.com` says nothing about `agents.acme.com`.
- **Organizational identity, endpoint liveness, reputation.** Out of scope in
  `SPEC.md` §10 and still out of scope here.
- **Registry-signed certification statements, and the transparency log they
  would require.** This profile publishes only what any party can re-resolve, so
  a compromised operator publishing a domain nobody declared is detectable by
  anyone who looks. The day the registry signs a statement that a reader is
  expected to trust without re-resolving, `SPEC.md` §10's third reserved point
  applies in full and an append-only log becomes a prerequisite, not an
  improvement.

## 11. Problems

RFC 9457, as `SPEC.md` §9. New codes:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 422 | `DOMAIN_SYNTAX_INVALID` | A domain violates §5.4 |
| 422 | `DOMAIN_IS_PUBLIC_SUFFIX` | A domain is a public suffix |
| 422 | `DOMAINS_NOT_CANONICAL` | `domains` is unsorted or holds a duplicate |
| 422 | `TOO_MANY_DOMAINS` | More domains than §8 allows |
| 422 | `DNS_RECORD_ABSENT` | The name resolved; no record matched §3.3 |
| 422 | `DNS_UNRESOLVED` | `SERVFAIL`, timeout, or a limit of §5.5 reached |
| 409 | `CERTIFICATION_NOT_INCREASING` | `issuedAt` is not strictly greater |

Existing codes apply unchanged: `NOT_AUTHORIZED_KEY`, `SIGNATURE_INVALID`,
`KID_NOT_THUMBPRINT`, `ALG_NOT_ALLOWED`, `PRIVATE_KEY_SUBMITTED`, `NOT_FOUND`,
`WITHDRAWN`, `JSON_INVALID`, `RATE_LIMITED`.

`DNS_RECORD_ABSENT` and `DNS_UNRESOLVED` are separate because the two lead to
different actions: the first means the record is missing and the publisher must
add it, the second means nothing can be concluded and the request should be
retried. A single code would make the command line guess.

A problem document for either MUST carry a `domains` member giving the outcome
per domain, so that a request naming four domains does not have to be bisected
to find which one failed.

## 12. Conformance

Test vectors are published for: record-data parsing, including a multi-string
`TXT` record, an unknown tag, a wrong `v`, a wrong `k`, and a malformed record
sharing a name with a valid one; the canonical payload bytes of §5.2; rejection
of an unsorted or duplicated `domains` array; rejection of a replayed
certification under §5.3(4); the atomicity of §5.5; and the three-pass removal
of §7.

A second implementation is expected to pass them. Until it does, no
interoperability claim is made.

---

## Appendix A — The command line (non-normative)

```sh
aithos certify --key <kid> --domains acme.com,acme.fr
```

First run, before the records exist:

```text
Add these records, then run the same command again:

  _a2a.acme.com.   IN   TXT   "v=A2A1; k=<agentId>"
  _a2a.acme.fr.    IN   TXT   "v=A2A1; k=<agentId>"

Leave them published. They are the evidence, not a one-time challenge:
removing one withdraws the certification.
```

The command resolves locally first and reports what it sees, so a publisher
waiting on propagation learns it from their own resolver rather than from a
rejected request. It sends the signed payload only once every domain is visible.

Because the set replaces (§5.2), the same command is how a domain is removed —
name the ones to keep — and `--domains ""` removes all of them.

`aithos verify` gains a line per certified domain, resolved live by the client
and not read from the registry, since a certification the reader cannot
reproduce is one the reader has to take on faith.

## Appendix B — Relationship to A2A (non-normative)

A2A v1.0.1 defines no domain verification. §8.2 gives one domain-anchored
mechanism — an Agent Card served at `https://<domain>/.well-known/agent-card.json`
— and §8.4 gives signing, whose protected header may carry `jku` but whose trust
in the resulting key is left to the client. Nothing in the card carries a
verified domain, and this profile adds nothing to it: `AgentCard` is untouched,
so a generic A2A client sees exactly what it saw before, byte for byte.

What is offered outside the registry is the record itself. `k` is an RFC 7638
JWK thumbprint, not a registry-scoped identifier, so

```text
_a2a.acme.com.   IN   TXT   "v=A2A1; k=<thumbprint>"
```

reads as *this domain declares that this key speaks for it* — a statement any
A2A verifier can use against any signed card from any source, with a resolver
and no registry at all. That, rather than anything in this registry's API, is
the part of this profile worth standardizing.
