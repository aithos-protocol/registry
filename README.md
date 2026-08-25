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
crates/a2a-card/         the deterministic core: strict parsing, field
                         presence, RFC 8785 canonicalization, digests
vectors/                 published conformance vectors
  rfc8785/               the official RFC 8785 test vectors
  a2a-sample-agent-card.json   the sample card from A2A §8.5
infra/                   Terraform (AWS: Lambda + DynamoDB + S3 + CloudFront)
```

`a2a-card` is pure: no I/O, no key material, no storage opinion. It is meant to
compile to WebAssembly and run unchanged in the browser that authors and signs
a card, so that the bytes the publisher signs and the bytes the registry
verifies cannot diverge.

Key custody stays with the browser: keys are generated through WebCrypto with
`extractable: false` and never enter WebAssembly linear memory.

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
cargo test           # 22 tests, including the official RFC 8785 vectors
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Status

The deterministic core is implemented and tested. The HTTP surface, storage and
infrastructure are not yet written.
