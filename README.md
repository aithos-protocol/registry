# Aithos Agent Card Registry

A public registry that hosts [A2A](https://a2a-protocol.org) Agent Cards.
Anyone can publish a card; the card is signed by its owner's key; only a holder
of an authorized key can change it.

There are no accounts, no passwords and no sessions. **The key is the account.**

See [`SPEC.md`](SPEC.md) for the normative rules.

## What a V1 entry claims

> This Agent Card was published by the holder of key `<thumbprint>`, and every
> subsequent version has been signed by a key authorized by that lineage.

That is not an identity claim. V1 verifies no domain and no organization, so a
card named `Acme Support` proves nothing about Acme. Interfaces MUST show the
key thumbprint, not the `name` field, as the identity of an entry.

## Layout

```text
SPEC.md                  normative protocol rules
crates/a2a-card/         strict parsing, field presence, RFC 8785
                         canonicalization, digests
crates/registry-core/    RFC 7638 thumbprints, JWS verification, and the
                         write-authorization rules
crates/registry-api/     HTTP surface, storage contract, in-memory store
crates/registry-lambda/  DynamoDB and S3 backend, Lambda entry point
crates/registry-e2e/     tests against a deployed environment
crates/aithos-cli/       the `aithos` command line: publish and verify
vectors/                 published conformance vectors
  rfc8785/               the official RFC 8785 test vectors
  a2a-sample-agent-card.json   the sample card from A2A §8.5
infra/                   Terraform (AWS: Lambda + DynamoDB + S3 + CloudFront)
```

Both crates are pure: no I/O, no storage opinion, no key material. `a2a-card`
compiles to `wasm32-unknown-unknown` as it stands, so the browser that authors
and signs a card and the server that verifies it can run the same
canonicalization code, and their bytes cannot diverge.

`registry-core` is server-side. It does not currently build for
`wasm32-unknown-unknown`, because the crypto crates pull `getrandom`, which
needs its `js` feature on that target. Browser-side *verification* would need
that; browser-side *signing* does not, and should not: key custody stays with
WebCrypto, where a key generated with `extractable: false` never enters
WebAssembly linear memory.

## How authorization works

There are no accounts, and no signed envelope wrapping the request. One rule
carries the whole design: a signature's `kid` is the RFC 7638 thumbprint of the
key that verifies it. `kid` sits inside the signed protected header, and the
thumbprint is a digest of the key material, so a public key submitted in a
plain request body cannot be swapped for another.

From there:

- an agent's identifier is the thumbprint of its genesis key, which a client
  can compute offline, before it ever contacts the registry;
- a write is authorized when at least one signature comes from a key in the
  previous version's authorized set;
- the new authorized set is the set of keys that signed the new version.

Key rotation and backup keys fall out of that last line with no extra
machinery: co-sign one version with the old key and the new one to widen the
set, then sign with the survivors alone to narrow it. A2A already allows
multiple signatures for exactly this purpose.

## Pinned baseline

| Dependency | Pin |
| --- | --- |
| A2A | `v1.0.1`, commit `3303592588e388e62e0f69f701af531d2f4e3991` |
| Canonicalization | RFC 8785 (JCS) |
| Signatures | RFC 7515 (JWS), `ES256` / `EdDSA` / `RS256` |
| Key identifiers | RFC 7638 JWK thumbprints |

The field-presence table in `crates/a2a-card/src/schema.rs` is derived by hand
from the pinned `specification/a2a.proto`. It is the only part of the system
with no off-the-shelf equivalent, and it must be re-derived whenever the pin
moves.

## Development

```sh
cargo test           # 100 tests, none of which touch a network
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo build -p a2a-card --target wasm32-unknown-unknown
```

The suite verifies against published vectors wherever one exists: the official
RFC 8785 canonicalization vectors, the worked example of A2A §8.4.1 byte for
byte, the specification's own sample card, and the RFC 7638 thumbprint example.
Signatures in the tests are real, produced by generated keys.

## Planned deployment

The read path and the write path are deliberately asymmetric, because their
traffic is.

Published card bytes are immutable and addressed by their own digest, which
makes them static objects. The public read surface is therefore served from
**S3 behind CloudFront** and never reaches compute at all. Writes are rare, and
go to a **Rust Lambda** behind an **HTTP API**, with **DynamoDB** holding agent
state.

The two invariants of §6 — a strictly increasing card version, and a signature
from a currently authorized key — are evaluated against a snapshot of the
agent's state, so committing them has to be conditional on that snapshot still
being current. DynamoDB's conditional writes express exactly that, which is why
the `Store` contract in `registry-api` is written around a `Conflict` error
rather than around locks.

## The command line

```sh
cargo install --path crates/aithos-cli     # installs `aithos`

aithos key new                             # its thumbprint is your entry's address
aithos card init                           # a card that already passes the strict profile
aithos publish agent-card.json --key <kid> --bump patch
aithos verify <agent-id>                   # is this document intact, and who signed it?
aithos whatis <agent-id>                   # what does the registry hold at this address?
aithos withdraw <agent-id> --key <kid>     # permanent; the address is never reusable
```

`whatis` is `whois` for an agent address, and the analogy holds in both
directions. It reports registration facts — when the address was first
published, who may change it now, how many versions it has, whether the current
card verifies — and it reports nothing about whether the thing at that address
is honest. Its output keeps those apart on purpose: the card's `name`,
`description` and declared endpoints sit under a heading that says nobody
checked them, because a lookup tool that printed a self-declared organisation
beside a green tick would be a phishing instrument with this registry's name on
it.

`verify` is the reason the rest exists. Publishing is rare — a few people, a few
times a year. Verifying is what every consumer of an agent does, and until now
it meant reimplementing RFC 8785 canonicalization, A2A's field-presence rules
and detached JWS. It works on any signed A2A card, not only cards from this
registry: a verifier that only trusts its own issuer is not a verifier.

It also reports what it did **not** establish — no domain, no organisation, and
nothing about whether the key holder operates the endpoints the card declares.
Output that lets a reader believe otherwise would be a phishing tool with a tick
next to it.

There is no `rotate` command. Rotation is the choice of which keys sign:
`--key` repeats. Co-sign one version with the old key and the new one to widen
the authorized set, then sign with the survivors alone to narrow it. The tool
exposes the protocol rather than inventing a second mechanism on top of it.

Keys live in `~/.config/aithos/keys`, mode `0600`, encrypted at rest as a JWE
(`PBES2-HS256+A128KW` with `A256GCM`) unless `--no-passphrase` says otherwise.
No daemon, no agent — the model is the one already in everyone's fingers.

`--offline` signs and writes without contacting anything, so the machine holding
the key never needs to reach the network.

## Testing against a deployed environment

```sh
REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
  cargo test -p registry-e2e -- --ignored --test-threads=1
```

These need no AWS credentials — every endpoint is public and each run generates
its own keys — and they are `#[ignore]`d so they never run by accident. Run them
after a deployment, before promoting a change, or while debugging.

They exist because the offline suite proves the protocol and nothing else: the
DynamoDB conditional expression, the transaction cancellation reason this code
parses, API Gateway's body handling and CloudFront's routing were all written
by reasoning and had never been executed. The first run found three defects,
including a routing rule that sent every historical version to an object store
with no such key.

**They write to a real append-only registry**, so nothing they publish can be
deleted. Each run creates as few entries as it can and ends by withdrawing them
— which is also the only real-world coverage the withdrawal path gets.

## Status

Deployed to development and exercised end to end, and put through ten rounds of
independent adversarial review. Each round's report is in `audits/`, with every
decision — including the ones not taken, and why — in `audits/LEDGER.md`.

### How the read path stays true

The `v1/agents/…` pointers are what the edge serves, and the request path does
not write them: the API role holds no write permission under `v1/` at all. They
are converged from the register instead, by one function with two triggers — a
DynamoDB stream that says *which* agent changed, and an hourly pass over every
agent that makes the guarantee survive the stream losing a record. Neither is a
source of truth; the register is. `SPEC.md` §6.6 states the design and the
bound it offers, which is eventual rather than immediate and is written down
rather than implied.

This replaced an earlier design where the request path refreshed the pointers
after each commit. Two publications close together could have those writes
reordered, leaving the edge on the older card until someone published again —
and nothing would ever notice, because the API answered correctly from the table
either way.
