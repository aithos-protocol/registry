# Design handoff: interaction ranks

> **Historical handoff, superseded by [`../RANKS.md`](../RANKS.md) 0.0.5.**
> The current V0 rates existing complete artifacts including business metadata.
> Each author signs an independent score, unique artifact reference and local
> version commitment. There is no production agreement, acceptance callback or
> failure rating. Integration targets `init(sdkInstance, { privateKey })` and
> `rank(artifact, score)`. Identity exchange and artifact context are library
> responsibilities; an unknown receiver may remain unassigned, without affecting
> any agent's reputation. Retrospective attribution is only a deferred feasibility
> note. Divergences remain valid declarations, and confirmations come from a
> separate chained public journal. The text below preserves the original design
> exploration and is not the current implementation contract.

**Date:** 2026-09-17
**For:** a session with no prior context, in `agents-card-registery-2`
**Goal:** write the **design** (a draft profile, not code) for signed, two-sided,
optional ranks attached to A2A artifacts, recorded by a third-party rank service
(Aithos by default), plus a client library an existing A2A user adopts in two lines
**Branch:** `agent-ranks`, created from `main` (this file is its first commit)
**Output of the session:** `RANKS.md` at the repository root, plus the review
checkpoint in §9. **No code, no `openapi.json` change, no infra.**

---

## 0. Read before writing a line

1. **`SPEC.md`**: §3 (identity: the key is the account, `kid` = RFC 7638 thumbprint,
   `agentId` = genesis key, authorized key set and lineage), §4.1 (`createdAt`),
   §5.3–§5.5 (canonical bytes, signing payload, verification), §6.1 (publication
   proofs, and the pre-emption attack), §6.4 (ordering and replay), §8 (limits),
   §9 (problems), and **§10**, which today lists *"a transparency log, ranking,
   reputation"* as out of scope and reserves *signed statements* as separate
   envelopes. This work changes §10 (see §7).
2. **`DOMAIN-CERTIFICATION.md`**: for its **form**. `RANKS.md` copies it: status
   header, "this document is additive", a §1 that states the exact claim, a final
   section that bounds it.
3. **`CONTRIBUTING.md`**, section "The shape of a change", and **`audits/LEDGER.md`**:
   ranking is a ledgered exclusion, so reopening it needs the new evidence written
   down (§7).
4. **`a2a.proto`** (A2A v1.0.1, pinned by `SPEC.md` §2): `Message` (`message_id`,
   `context_id`, `task_id`, `metadata: Struct`, `extensions`), `Artifact`
   (`artifact_id` *"must be unique within a task"*, `parts`, `metadata: Struct`,
   `extensions`), `TaskState` (`FAILED`, `CANCELED`, `REJECTED` are terminal),
   `AgentExtension` (`uri`, `required`, `params`).
5. **`docs/trust-standards-review-2026-09.md`**: AI Catalog PR #117 (`signatures[]`
   with `paths`, contributor `trustManifests` keyed by identity), ARD's delegation of
   trust, and the doctrine "sign observations, never ratings" that this work amends.
6. **`docs/sdk-replacement-review-2026-09.md`**: the Python and JS SDKs canonicalize
   differently from A2A §8.4.1 and Python mutates the card before parsing. The same
   class of bug is the main technical risk here (§5, P4).

---

## 1. The claim, in one sentence

> The holder of a key authorized for agent `R` states, at a time bounded by the
> log, this outcome about a specific exchange with agent `P`, and that exchange is
> proven by `P`'s own signature (or, if not, is marked unattested).

A rank is **a signed statement by a party to an exchange about that exchange**. It is
not a verdict of the rank service. The service records, orders and proves inclusion;
scores are computed from the evidence by published, versioned formulas.

---

## 2. What Mathieu stated (requirements, not suggestions)

- Agents sign each artifact they provide, **including its metadata**.
- A rank is **always attached to an artifact** and carries the ids of the **rater**
  and the **rated**.
- Ranks are **two-sided** and **optional**: the receiver can rank what it received;
  the sender can rank after producing an artifact **or after failing to produce one**.
- **Only one rank per agent and artifact** is recorded.
- Hashing and chaining make ranks **impossible to falsify** after the fact.
- A **third party** records ranks; **Aithos by default**, replaceable. Align with AI
  Catalog where it fits.
- Ranks can later be analyzed by use case (from metadata) and weighted by **the
  raters' own ranks**.
- Signals against newly minted identities: **the agent's domain, its IP, and its
  age**.
- Fake-rater resistance is **not** in scope for this design beyond recording the
  signals above.
- A **library** that is trivial for current A2A users: install, then one line to
  rank.
- The goal is to **make the specs evolve** (A2A extension, AI Catalog, ARD).

---

## 3. Invariants (each deserves a test in the eventual implementation)

1. **No rank without the rater's authorized key.** The signature verifies against a
   `kid` in the rater's authorized set **at the log time of submission** (SPEC §3.4
   lineage gives the historical check that AI Catalog lacks).
2. **The rated party cannot suppress, edit or reorder a rank about itself.** The
   rater submits directly to the log; the rated party is never in the path.
3. **The service cannot silently rewrite history.** Append-only Merkle log, signed
   tree heads, inclusion and consistency proofs.
4. **At most one rank per `(subject, rater)`** (definition of subject in §4.3).
   Enforced by the service and checkable by anyone from the log.
5. **No content leaves the agents.** Only digests of parts and a constrained set of
   metadata reach the service. No artifact body, no message body.
6. **The registry core does not change.** No card byte, no canonicalization rule, no
   existing endpoint. `SPEC.md` test vectors (§11) stay green untouched.
7. **The rank service never emits a score as its own assertion.** Aggregates are
   labeled by formula id and version, and are recomputable from the public log.
8. **Portable statements.** A rank verifies offline, without calling Aithos, given
   the rater's key history and the log proof.

---

## 4. Proposed model (to be settled, then written normatively)

### 4.1 The in-band handshake (A2A extension)

A rank needs **proof that the exchange happened**; otherwise anyone who has seen an
artifact can rank it. Proposed: one A2A extension, URI to be decided
(e.g. `https://aithos.world/ext/ranks/v1`), declared in the Agent Card's
`capabilities.extensions`, with `params` naming the accepted rank services.

1. **Requester → provider.** The library adds to `Message.metadata[<ext-uri>]` a
   **message seal**: requester `agentId`, `kid`, digest of the message (excluding the
   seal itself), `issuedAt`, nonce, detached JWS.
2. **Provider → requester.** For every artifact, the library adds to
   `Artifact.metadata[<ext-uri>]` an **artifact receipt**: provider `agentId`, `kid`,
   `taskId`, `contextId`, `artifactId`, digest of `parts` and of the rest of
   `metadata` (excluding the receipt), **the requester's `agentId` and message
   digest** (if the message was sealed), `issuedAt`, detached JWS.
3. **Terminal failure.** When the task ends `FAILED` / `REJECTED` / `CANCELED` with no
   artifact, the provider adds a **status receipt** to `TaskStatus` update metadata,
   same fields minus `artifactId`, plus the terminal state.

The seal and the receipt bind both identities to one exchange. Each side then holds
the other's signature: that is the proof of interaction for a two-sided rank.

### 4.2 The rank statement

`{ subject, rater, rated, role: "requester"|"provider", outcome, score?, facets,
issuedAt }`, signed by the rater (detached JWS over JCS, the payload construction of
AI Catalog #117 if it fits: `context`, `signer`, sorted `[path, value]` pairs).

- `subject`: digest of the counterpart's receipt (artifact or status) or, for the
  provider, of the requester's seal + its own receipt.
- `outcome`: small closed enum (e.g. `accepted`, `rejected`, `disputed`, `failed`,
  `abandoned`). `score`: optional bounded integer. Scale is a decision (§6).
- `facets`: the **constrained** use-case metadata (skill id, input/output media types,
  sizes, latency, terminal state). Free-form extras only as salted digests.

### 4.3 Uniqueness

Subject key = `(provider agentId, taskId, artifactId | "#status")`, because
`artifactId` is only unique within a task. Uniqueness = `(subject key, rater agentId)`.
First statement included in the log wins; a duplicate is a problem response (409-like,
new `/problems/` code). Whether one superseding revision is allowed is a decision (§6).

### 4.4 The rank service (Aithos by default)

- `POST` a rank statement → verification (signature, key authorized at log time,
  counterpart receipt valid, uniqueness) → inclusion → returns a **log receipt**
  (inclusion proof + signed tree head).
- Public reads: evidence per agent (paginated), log checkpoints and proofs, and
  aggregates **per formula id/version**, filterable by facet.
- Records, **privately and outside the signed statement**, the submission network
  signals (§5, P5).
- Shape the statement / log / receipt after **IETF SCITT** (signed statement,
  transparency service, receipt) where it fits: verify the current state of the SCITT
  architecture and COSE receipt drafts before choosing JOSE vs COSE (JOSE matches
  everything else in this repo).

### 4.5 The library

Target developer experience (illustrative, to be checked against real SDK hooks):

```python
ranks = aithos_ranks.Ranks.from_env()          # key, agentId, rank service
handler = ranks.wrap_server(handler)            # seals every artifact / failure
client  = ranks.wrap_client(client)             # seals messages, keeps receipts

await ranks.rank(artifact, outcome="accepted", score=4)   # the one line, either side
```

Setup is **one wrap per side**; ranking is **one line**. Signing is synchronous and
local; submission is queued and retried in the background, never in the request path.
Hook points to confirm in code (branch `main` of each SDK):
Python server request handler / event queue and `TaskUpdater.add_artifact`, Python
client call interceptors; JS `ExecutionEventBus` and client factory options; Go
`CardParser` / client options; Rust `a2a-rs`.

---

## 5. Problems the design must answer explicitly

- **P1. Adoption asymmetry.** If the counterpart does not run the library, there is no
  receipt and no proof of interaction. Choose: refuse, or accept as `unattested` (kept
  separate in every aggregate).
- **P2. Failure has no artifact.** Covered by the status receipt (§4.1.3); the design
  must make "a rank is attached to an artifact" read as "to an artifact or to a
  terminal task outcome".
- **P3. Requesters are often not agents.** Many A2A clients have no Agent Card. They
  still need a registry identity (SPEC §3: a genesis key, no domain required). Define
  what a rank from an unregistered or never-published key is worth (proposal: recorded,
  flagged).
- **P4. Canonicalization across SDKs (main technical risk).** `metadata` is a protobuf
  `Struct`: every number becomes a double (integers above 2^53 lose precision), and
  empty values may be dropped. The Python SDK mutates objects on parse. Both sides must
  compute **the same digest** from their own SDK objects. Define the digest input
  precisely (what is hashed: wire JSON, or a normalized form; how file parts by URI are
  covered), and plan **cross-language test vectors** that include the failure cases.
  Strong recommendation: one Rust core reusing `a2a-card` `canonical` + `jws`, bound to
  Python and TypeScript, rather than three re-implementations.
- **P5. IP as a signal.** The service only sees the **submitter's** address; the
  provider's serving address is derivable from its card URL. IPv6 /64s are nearly free,
  residential proxies are cheap, and many legitimate agents share cloud egress. Record
  prefix (/24, /48) and ASN, never raw addresses in the signed statement or the public
  log. **IP addresses are personal data under GDPR**: private storage, truncation,
  retention period, stated purpose.
- **P6. Agent age.** The Agent Card has **no creation date**, and a self-declared one is
  worthless. Use what cannot be backdated: registry `createdAt` (§4.1), first
  appearance in the rank log, and domain certification date.
- **P7. Retaliation between the two sides.** If one side sees the other's rank first, it
  can retaliate. Options: sealed until both ranked or a window closes (service holds
  content, log holds the hash immediately), or commit/reveal (costs a second call and
  breaks the one-line promise). State the trust assumption either way.
- **P8. "One rank" in an append-only log is forever.** No correction, and a rank signed
  just before a key compromise stays valid unless revocation time is honored. Decide
  immutable vs one revision; define validity against key lineage and log time.
- **P9. Metadata leaks.** Use-case metadata in a public log can expose business
  relationships, confidential labels or personal data. Closed facet schema; who-ranked-
  whom visibility is itself a decision (public, pseudonymous, aggregates only).
- **P10. Doctrine.** `SPEC.md` §10 and the ledger exclude ranking and reputation, and
  the neutrality argument depended on it. Keep ranks in a **separate profile and
  service**, never in the registry record, and write down why it is compatible (§7).

---

## 6. Decisions for Mathieu (put a recommendation next to each in `RANKS.md`)

1. Unattested ranks (P1): refuse, or accept flagged.
2. Rank value: `outcome` enum only, or enum + optional score; scale of the score.
3. Visibility (P7, P9): sealed until both sides or deadline; public rater ids or
   pseudonymous.
4. Revision (P8): immutable, or one superseding revision per `(subject, rater)`.
5. Library strategy (P4): Rust core with bindings, or native per language; which
   languages ship first (Python and TypeScript cover most A2A users).
6. Envelope: JOSE (consistent with the repo) or COSE (SCITT native).
7. Extension URI and name (`ranks`, `interaction-ranks`, …), and whether it is proposed
   upstream to A2A as an extension from day one.

---

## 7. Changes in this repository that come with the design

- `RANKS.md`: new additive profile (objects, digests, signatures, verification,
  uniqueness, log, service API sketch, library contract, problems, limits).
- `SPEC.md` §10: amend the out-of-scope list (ranking, reputation, transparency log)
  to point at the profile, the same way domain verification was moved. The last bullet
  ("stops being acceptable the day a verified badge exists") argues **for** the log
  this profile introduces: say so.
- `audits/LEDGER.md`: a row recording the reopened decision and the new evidence
  (Mathieu's decision of 2026-09-17; ranks are statements by parties, not by the
  registry; scores are formulas over public evidence).
- `vectors/ranks/`: **list** the vectors to produce (valid pair, SDK round-trip that
  changes a number, missing counterpart receipt, duplicate, revoked key, failure
  receipt). Do not produce them yet.

---

## 8. Upstream targets to name in the design

- **A2A**: the extension itself (the extension mechanism is the sanctioned path; check
  how activation is negotiated in v1.0.1, header name included).
- **AI Catalog #117**: rank aggregates as a contributor `trustManifests` entry keyed by
  the rank service identity, or a `trustSchema` pointing at its endpoint. Check the PR
  state on the day: it was draft with no reviews on 2026-09-16.
- **ARD**: ARD says relevance scores must not be read as trust judgments; ranks are a
  separate, declared signal, which fits.
- **AAIF Identity & Trust WG**: "Reputation" and "Evidence" components of its
  reference architecture; open call for presentations.
- **IETF SCITT**: statement / transparency service / receipt vocabulary.

---

## 9. How the session ends

1. Verify online, with dates, anything in §4.4, §4.5 and §8 marked "check".
2. Write `RANKS.md` with every §6 decision **left open and recommended**, not decided.
3. Stop and hand Mathieu: the draft, the list of §6 decisions, and anything found in
   step 1 that contradicts this handoff. Do not amend `SPEC.md` §10 or the ledger until
   the decisions are taken.
