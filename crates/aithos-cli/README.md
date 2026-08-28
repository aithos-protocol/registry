# aithos

Publish and verify signed A2A Agent Cards from the command line.

```sh
cargo install aithos
```

`verify` is the reason the rest exists. Publishing is rare — a few people, a few
times a year. Verifying is what every consumer of an agent does, and doing it by
hand means reimplementing RFC 8785 canonicalization, A2A's field-presence rules
and detached JWS. It works on any signed A2A card, not only cards from one
registry: a verifier that only trusts its own issuer is not a verifier.

```sh
aithos key new                          # its thumbprint is your entry's address
aithos card init                        # a card that already passes the strict profile
aithos publish agent-card.json --key <kid>
aithos verify <agent-id>                # is this document intact, and who signed it?
aithos whatis <agent-id>                # what does the registry hold at this address?
```

An entry states that a card was published by the holder of a key, and that every
version since was signed by a key that lineage authorized. It says nothing about
any domain or organisation, and the output says so every time.

Licensed under Apache-2.0. Source, specification and audit history:
<https://github.com/aithos-protocol/registry>
