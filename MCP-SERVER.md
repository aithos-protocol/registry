# Aithos Registry MCP Server

**Status:** design, not implemented. This document is normative for the
implementation that follows it, in the same sense as
[`DOMAIN-CERTIFICATION.md`](DOMAIN-CERTIFICATION.md): it fixes the decisions
before the code, so that the code has nothing left to invent.

**Depends on:** [`SPEC.md`](SPEC.md) V1 and
[`DOMAIN-CERTIFICATION.md`](DOMAIN-CERTIFICATION.md). It changes neither. Every
operation named here already exists as an HTTP request the registry answers
today.

## 1. What this is

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives an
agent the operations `aithos` gives a person: read an entry, check a card,
publish a card, certify domains.

It ships in two deployments, in this order:

1. **Local, stdio.** Runs on the operator's machine, reads the local keystore,
   signs and writes. This is the one that makes card editing possible.
2. **Hosted, HTTP, read-only.** Runs beside the registry at `aithos.world`,
   holds no key material and performs no write. This is the one that lets any
   agent anywhere ask whether another agent is what it claims.

### 1.1 Why an MCP server at all

The question this registry exists to answer — *is the agent I am about to talk
to published by the key it claims, and does the domain it names agree?* — is a
question one agent asks about another, mid-conversation, without a human
present. A command line cannot be asked that question. Until an agent can reach
the registry the way it reaches everything else, the registry answers only to
people, and the answer arrives too late to be acted on.

The write half follows for a smaller and more practical reason: an agent that
maintains its own card is an agent whose card is current. Cards go stale
because editing them is a chore performed by whoever remembers.

### 1.2 Why it needs no authentication

MCP's authorization model, at revision `2026-07-28`, is OAuth 2.1 over HTTP
transports and "credentials from the environment" over stdio. There is no
mode in which a request is authenticated by being signed with the caller's own
key, and the nearest thing — the `oauth-client-credentials` extension's
`private_key_jwt` — still means pre-registration with an authorization server
in exchange for a bearer token.

None of which this server needs, because **the authorization already travels
inside the payload.** A publication carries proofs signed by every key entering
the authorized set (`SPEC.md` §6.1); a certification carries a JWS envelope
whose `kid` is the RFC 7638 thumbprint of the signing key
(`DOMAIN-CERTIFICATION.md` §5.1). `registry-api` has no transport
authentication and needs none. An MCP server in front of it inherits that
property: it relays operations that authorize themselves.

**Why this is a decision and not a convenience.** A hosted MCP server that held
users' keys in order to sign on their behalf would be an operator with the power
to publish as any of them, and `README.md` is explicit that no such operator
exists — "there is no operator to restore access to a lost key". Any design in
which a private key reaches a server the key holder does not run is rejected by
this document without further argument.

**An Agent Card cannot serve as a credential.** A card is public; presenting one
proves nothing about who is presenting it. What proves something is a signature
by the key whose thumbprint is the `agentId`. "Authenticate with your agent
card" is, correctly stated, "sign with your key" — which is the envelope
`SPEC.md` §6.5 already defines. This is recorded because it is the mistake this
design is most likely to be asked to make.

## 2. Normative baseline

An implementation MUST conform to:

- MCP protocol revision **`2026-07-28`** or later.
- `SPEC.md` V1, unchanged.
- `DOMAIN-CERTIFICATION.md`, unchanged.

The `2026-07-28` revision is load-bearing here, in three ways:

- **The core is stateless.** `initialize`/`initialized` and `Mcp-Session-Id` are
  gone; each request carries its protocol version, client identity and
  capabilities in `_meta`. The hosted server is therefore a request/response
  handler with no session store — deployable as one more route on the Lambda
  that already serves `/v1`, behind the CloudFront distribution that already
  fronts it.
- **List results carry `ttlMs` and `cacheScope`.** The registry's read path
  already states its cache lifetimes (`SPEC.md` §7.1, §7.3); the tool surface
  restates them rather than inventing its own.
- **Multi round-trip requests (MRTR)** replace server-initiated requests. Where
  this document requires a confirmation, MRTR is the mechanism: the server
  returns `resultType: "input_required"` and the client retries the original
  call with `inputResponses`. Because the client retries the *original* call,
  the server re-derives its state from the original arguments and stays
  stateless.

Roots, Sampling and Logging are deprecated as of this revision. An
implementation MUST NOT depend on them.

## 3. Two deployments

### 3.1 Local, stdio — the signer

Shipped as a subcommand of the existing binary:

```sh
aithos mcp
```

It speaks MCP over stdio and reads the same keystore `aithos` reads — 
`$AITHOS_HOME`, else `$XDG_CONFIG_HOME/aithos`, else `$HOME/.config/aithos`,
files at mode 0600. It honours `--registry` and `AITHOS_REGISTRY` exactly as the
rest of the tool does.

Authentication is the filesystem. This is what the MCP specification means for
stdio transports, and it is also the truthful description: whoever can read the
key file can already publish, with or without this server.

### 3.2 Hosted, HTTP — read-only

Served from the `aithos.world` deployment, anonymous, no authorization, no
`WWW-Authenticate` challenge, no OAuth metadata. It exposes the read tools of
§4.1 and nothing else.

It MUST NOT accept key material in any tool argument, and MUST NOT expose any
tool that writes.

### 3.3 Why the hosted deployment never signs, and never relays a signature

An earlier sketch had the hosted server accept an unsigned card, return the
bytes to be signed, take the signature back, and submit. It is rejected.

Signing a publication requires two signatures per key — one over the card
(`SPEC.md` §5.4), one over the proof (§6.1) — and the proof payload contains
`cardDigest`, which is a digest of the card *including* its signatures. The
second signature therefore cannot be prepared until the first exists. Splitting
signer from assembler across a network turns one local operation into three
round trips and a protocol of its own.

There is no reason to split them. JCS is deterministic, which is the entire
point of it: whoever holds the key can canonicalize, digest and sign without
asking anyone. `aithos publish --offline` already does exactly this, producing
the complete signed artifact with no network at all. `a2a-card` compiles to
`wasm32-unknown-unknown` as it stands, so even an agent with no Rust host can
canonicalize in-process and sign with WebCrypto.

**A design in which the MCP server canonicalizes bytes and hands them back to be
signed is a design to throw away.** Signing is local and atomic. Publishing is
one request.

## 4. Tool surface

Tool names deliberately match the command-line verbs. A person reading a
transcript of what an agent did should recognize the operation as the one they
would have typed. A host MAY namespace them.

Every tool result is JSON. Every tool that reports on an entry carries evidence,
under §7.

### 4.1 Read tools

Available in both deployments. No key, no side effect.

| Tool | Backing request | Returns |
| --- | --- | --- |
| `whatis` | `GET /v1/agents/{agentId}` | The record projection of `SPEC.md` §7.3, extended by `DOMAIN-CERTIFICATION.md` §6 |
| `card_get` | `GET /v1/agents/{agentId}/agent-card.json` | `cardBytes` verbatim, plus the digest the client computed from them |
| `card_history` | `GET /v1/agents/{agentId}/versions` | Version list; a specific version via `versions/{cardDigest}/agent-card.json` |
| `keys` | `GET /v1/agents/{agentId}/jwks.json` | The published JWKS |
| `verify` | none (local computation) | Whether the bytes and the signatures agree, and which `kid` signed |
| `list` | `GET /v1/agents?limit=&cursor=` | A page of entries, newest-updated first |
| `manifest` | `GET /v1/registry` | Origin, pinned A2A commit, `alg` allowlist, limits, presence-table digest |

`whatis` returns, verbatim from the registry:

```json
{
  "agentId": "…", "status": "ACTIVE", "seq": 7,
  "cardDigest": "sha256:…", "cardVersion": "1.2.0",
  "authorizedKids": ["…"],
  "createdAt": "…", "updatedAt": "…",
  "agentCardUrl": "…", "jwksUrl": "…",
  "domains": [
    { "domain": "acme.com", "certifiedAt": "…", "lastCheckedAt": "…" }
  ]
}
```

An absent `domains` member means the registry did not state one, not that there
are none — the distinction `agent_json` already preserves.

`verify` MUST compute the digest from the bytes it received and MUST NOT report
a digest handed to it by the same server whose answer it is checking
(`SPEC.md` §7.1). It MUST NOT treat `jku` as a trust anchor (§5.7).

### 4.2 Write tools

**Local deployment only.**

| Tool | Backing request |
| --- | --- |
| `card_check` | none — strict parse and field presence, local, no key, no network |
| `card_publish` | `PUT /v1/agents/{agentId}` |
| `certify` | `PUT /v1/agents/{agentId}/domains` |

`card_check` is separate from `card_publish` on purpose, and is the tool a model
should call most. It runs `a2a_card::strict::parse` and the field-presence rules
of `SPEC.md` §5.2 with no key and no network, so a model can iterate on a card
until it is valid without touching the keystore or the registry. It also catches
the failure the CLI's own `publish` documents: a duplicate member is resolved
silently by keeping the last one, so `"name": "Mine"` followed by
`"name": "Impostor"` signs as `Impostor`. A model generating JSON will produce a
duplicate member sooner than a person will.

`card_publish` performs, in one call and in this order: strict parse, optional
version bump, sign the card, canonicalize, digest, sign the proof, `PUT`. It is
one signing operation and one HTTP request, exactly as `publish()` performs them
today. It MUST enforce §6.

`certify` takes the complete domain set. The set replaces the set, sorted
ascending by code point, A-labels only, at most 8
(`DOMAIN-CERTIFICATION.md` §5.2, §5.4, §8). An empty set removes every
certification. On refusal the tool MUST surface the per-domain `outcomes` array
— `observed`, `absent`, `unresolved` — because the code alone
(`DNS_RECORD_ABSENT`, `DNS_UNRESOLVED`) does not say which domain failed.

`certify` is exposed, and `withdraw` is not, for a reason that is about
reversibility and nothing else: a certification stated in error is undone by
another signed certification, and in the meantime the hourly revalidation of
`DOMAIN-CERTIFICATION.md` §7 corrects the registry's view without anyone
signing anything.

### 4.3 Tools deliberately absent

**`withdraw` has no tool.** Withdrawal is permanent and the identifier is never
reusable (`SPEC.md` §6.5). There is no operator to appeal to. A confirmation
step does not fix this: the confirmation text is authored by the server and read
by a model that may itself be acting on injected instructions, so the reviewer
and the attacker can be the same process. Leaving the destructive verb on the
command line costs an agent nothing and removes the only unrecoverable outcome
in the system.

**`key new` has no tool.** Key generation is not an agent operation. A key
generated inside a model's tool call is a key whose provenance nobody can state.

**No tool accepts, returns, or logs private key material**, in either
deployment. `SPEC.md` §5.6 already refuses a private JWK submitted to the
registry with `PRIVATE_KEY_SUBMITTED` and forbids storing or logging it; this
document extends the same refusal to the tool boundary.

## 5. Key custody

### 5.1 Where the key lives

Where `aithos` already puts it. The MCP server introduces no new store, no new
format, and no copy.

### 5.2 The passphrase never crosses the protocol

Keys are PBKDF2-wrapped on disk unless created with `--no-passphrase`. Two
sources are forbidden outright:

- **Standard input.** On a stdio server, stdin is the JSON-RPC channel.
  `rpassword::prompt_password` on that stream would consume protocol frames.
- **A tool argument.** A passphrase passed as a tool argument enters the model's
  context window and every transcript, log and cache that context reaches. This
  is worse than a plaintext key on disk, because it is copied to places nobody
  chose.

MRTR does not rescue this. An `input_required` round trip returns through the
client, which is the model.

### 5.3 Unlocking

An implementation MUST determine, without reading the key, whether the file is
encrypted — `KeyFile::is_encrypted` exists for this — and:

- if the key is unencrypted, use it;
- if the key is encrypted and a controlling terminal exists, it MAY prompt on
  `/dev/tty` directly, never on stdin;
- otherwise it MUST refuse the operation with an error naming the three ways
  out: run the operation from the command line, unlock the key out of band, or
  use a key created for this agent.

A GUI MCP host launches its servers with no controlling terminal, so the third
branch is the common case and its error message is a user-facing surface, not an
edge case. It MUST say which key it could not unlock.

## 6. The authorized key set is frozen

`card_publish` MUST read the current record, and MUST refuse any publication
whose set of signing keys differs from `authorizedKids`. The refusal names both
sets. There is no flag, no confirmation and no escape hatch on this tool;
changing the set is done with `aithos publish --key … --key …` from a terminal.

**Why this and not a confirmation.** The authorized set is the whole
authorization model: a write is authorized when a signature comes from a key in
the previous version's set, and the new set is the set of keys that signed the
new version (`SPEC.md` §3.4, §6.3). A publication that adds a key adds a
permanent co-owner of the entry. A publication that drops one removes an owner,
permanently.

An agent editing a card reads text it did not write — the card it is updating,
a page it fetched, another agent's card it was asked to compare against. Any of
that text can contain instructions. If the key set were a parameter the model
could set, then one injected instruction, executed once, hands an entry to
somebody else forever, and `README.md` is correct that nobody can undo it. The
tool that edits your description must not be the tool that can give your
identity away.

Genesis is excluded for the same reason: `card_publish` MUST refuse to create an
entry that does not exist. The genesis key names the entry (`SPEC.md` §6.1), so
creation is the one publication whose key set is decided rather than inherited.

## 7. Evidence, not verdicts

A tool result is read by a model that will not repeat the work. If `whatis`
answered `{"certified": true}`, the registry's word would become the finding,
and no client would ever re-resolve the record — which is precisely the
attestation `DOMAIN-CERTIFICATION.md` refuses to issue: the registry publishes
"an observation that anyone can redo, never an attestation".

Therefore, normatively:

- A tool MUST NOT return a bare boolean verdict about an agent's identity,
  ownership or trustworthiness.
- A result concerning a domain MUST carry `certifiedAt`, `lastCheckedAt`, and
  the DNS name that was observed (`_a2a.<domain>`), so the caller can repeat the
  lookup.
- A result concerning a card MUST carry the `kid` that signed it and the digest
  computed from the received bytes.
- A domain MUST appear in the A-label form in which it is stored, and a tool
  MUST NOT render it as a U-label (`DOMAIN-CERTIFICATION.md` §9).
  `xn--80ak6aa92e.com` rendered as `аpple.com` is the phishing instrument
  this registry refuses to build, and a tool result is a display surface like
  any other — the worst one to get this wrong on, since its reader is a model
  that will quote it onward without a second look.
- Tool descriptions MUST state what a certification does not claim
  (`DOMAIN-CERTIFICATION.md` §9) and that V1 verifies no organization
  (`SPEC.md` §1). The tool description is where a model reads this; a paragraph
  in a specification is not.

The freshness bound is stated, not implied: with the hourly pass, a domain whose
record is removed stops being published within three passes plus the read path's
cache lifetime — under four hours. A result MUST make `lastCheckedAt` available
so a caller can decide whether that is recent enough for what it is about to do.

## 8. Errors

Every refusal the registry makes is an RFC 9457 problem document carrying a
`code` (`SPEC.md` §9). A tool MUST surface that `code` verbatim alongside the
human sentence, and MUST NOT flatten it into a generic failure string: the codes
are the difference between "retry this" and "this will never work".

Three refusals carry no `code` and MUST be handled by status alone: `429` from
the gateway, `403` from the edge for a method a cached path does not serve, and
the edge's `RATE_LIMITED` body served as `application/json` rather than
`application/problem+json`.

`VERSION_NOT_INCREASING` deserves a named behaviour: the tool MUST report that
the card must move forward and that `bump` is how, rather than reporting a
conflict. It is the refusal an agent will hit most.

## 9. Limits

The tools add none. They restate the registry's: request body 512 KiB, card
256 KiB, 8 keys per request, 8 signatures per card, 8 domains per agent, 50
validation issues reported. A tool MUST refuse locally what the registry would
refuse remotely, and MUST say the limit it hit.

Write rate limits are per source address and per `agentId`, applied by the
registry. The local server adds no limiter of its own; it is one process on one
machine and the registry is the authority.

## 10. Deliberately out of scope

- **Authentication of MCP callers**, in either deployment. §1.2.
- **Any new registry capability.** This server exposes what `SPEC.md` and
  `DOMAIN-CERTIFICATION.md` already define, and nothing more. In particular the
  reverse question — *which agents does `acme.com` certify?* — has no endpoint
  today and does not acquire one here. It is the most natural question an agent
  asks, and it is Appendix B.
- **Writes from the hosted deployment.** §3.3.
- **`withdraw`, key generation, key-set changes.** §4.3, §6.
- **Card authoring assistance.** The server validates cards; it does not
  suggest content. A tool that wrote descriptions would be a tool that writes
  identity claims.
- **Caching or mirroring registry state.** The hosted server is a request/
  response handler over the live registry. A cache would be a second registry
  with a different answer.

## 11. Conformance

An implementation conforms when:

1. Every tool in §4 is present in the deployment §3 assigns it to, and no tool
   outside §4 is present.
2. No private key material crosses any tool boundary, in argument, result or
   log.
3. `card_publish` refuses a key-set change and refuses creation (§6), proven by
   test.
4. No tool returns a bare verdict, and every domain result carries its
   observation timestamps and the observed DNS name (§7).
5. Registry `code` values survive to the tool result verbatim (§8).
6. The local server refuses cleanly, with a message naming the three ways out,
   when an encrypted key cannot be unlocked without stdin (§5.3).

## Appendix A — A worked edit (non-normative)

An agent updating its own description:

```text
whatis(agentId)                     → status ACTIVE, cardVersion 1.2.0,
                                      authorizedKids [k1], domains [acme.com]
card_get(agentId)                   → the current card bytes + digest
  … the model edits `description` …
card_check(card)                    → valid
card_publish(card, key=k1,          → signs the card, digests, signs the proof,
             bump="patch")            PUT → 1.2.1
```

Two calls do the work; `card_check` is free and runs as often as the model
needs. The gap between `card_get` and `card_publish` is where a person looking
at the host's tool-call display sees the diff — which is the reason the two are
not collapsed into a single `card_edit(agentId, changes)` tool. Such a tool
would sign a card that neither the person nor the model ever saw assembled, and
would require choosing a patch language for no protocol gain.

The reviewer of that diff is the **person**, not the model. An implementation
MUST NOT describe the model's own inspection of the card as a review step.

## Appendix B — Open questions (non-normative)

- **The reverse index.** `domain → agents` has no endpoint. Answering it means
  a new route, a secondary index, and an amendment to `DOMAIN-CERTIFICATION.md`
  §6, which currently says "no other endpoint is added" and argues for it. Worth
  reopening only with the MCP use case in hand, which is exactly the case that
  makes it worth reopening.
- **Does the hosted server publish its own card?** A registry whose own MCP
  server is an entry in it, with `aithos.world` certified, is the shortest
  possible demonstration of the whole mechanism. It is also the registry
  vouching for itself, which proves nothing to anyone who does not already
  resolve the TXT record. Presentation question, not a protocol one.
- **Tool-name namespacing.** `verify` and `list` are generic enough to collide
  in a host holding forty tools. The `2026-07-28` revision carries the tool name
  in the `Mcp-Name` header per server, so collision is the host's problem — but
  a model choosing between tools reads names, not headers.
- **Crate shape.** `aithos mcp` as a subcommand keeps one binary and one
  install; a separate `aithos-mcp` crate keeps the CLI's dependency tree free of
  an MCP runtime. The publication order of `release_0.1.0` gains a crate either
  way if the split is taken.
