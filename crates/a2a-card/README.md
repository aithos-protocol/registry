# aithos-a2a-card

Strict parsing, field-presence validation and RFC 8785 canonicalization for
[A2A](https://github.com/a2aproject/A2A) Agent Cards.

Two implementations that disagree about one field's presence rule produce two
different canonical documents, and therefore two different signatures over what
looks like the same card. This crate exists to make that disagreement
impossible to have by accident:

- **Strict JSON** — duplicate members, lone surrogates, non-I-JSON integers and
  subnormals are refused rather than silently normalised.
- **The field-presence table** of A2A §8.4.1, hand-derived from `a2a.proto` at a
  pinned commit and published as a digest, so a second implementation can check
  it pinned the same one.
- **RFC 8785 (JCS)** canonical bytes, with a differential test against an
  independent implementation.

It has no opinion about registries, keys or transport. Verification lives in
[`aithos-registry-core`](https://crates.io/crates/aithos-registry-core); the
command line is [`aithos`](https://crates.io/crates/aithos).

Licensed under Apache-2.0. Source, specification and audit history:
<https://github.com/aithos-protocol/registry>
