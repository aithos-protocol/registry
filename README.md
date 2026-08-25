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
cargo test           # 50 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo build -p a2a-card --target wasm32-unknown-unknown
```

The suite verifies against published vectors wherever one exists: the official
RFC 8785 canonicalization vectors, the worked example of A2A §8.4.1 byte for
byte, the specification's own sample card, and the RFC 7638 thumbprint example.
Signatures in the tests are real, produced by generated keys.

## Status

The protocol core is implemented and tested. Still to come: the HTTP surface,
storage, the Terraform stack, and the browser signing client.
