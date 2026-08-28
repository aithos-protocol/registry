# aithos-registry-core

Key identity, detached JWS verification, and the write-authorization rules of
the Aithos Agent Card Registry.

- **Keys are accounts.** An entry is named by the RFC 7638 thumbprint of the key
  that created it, and `kid` must equal that thumbprint — which is what makes
  key substitution impossible without a second signed envelope.
- **Verification before trust.** The algorithm allowlist is applied before any
  key is resolved; Ed25519 is verified strictly and small-order keys refused;
  RSA moduli must be minimally encoded.
- **Publication proofs.** A card signature says who signed a document, never
  where its signer wanted it published. Admission requires a separate signature,
  from every key entering the authorized set, over this registry, this
  identifier and this exact card.

Pure logic: no I/O, no clock, no network. Canonicalization comes from
[`aithos-a2a-card`](https://crates.io/crates/aithos-a2a-card).

Licensed under Apache-2.0. Source, specification and audit history:
<https://github.com/aithos-protocol/registry>
