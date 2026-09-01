# aithos-registry-dns

TXT resolution for [Agent Card Registry](https://github.com/aithos-protocol/registry)
domain certification (`DOMAIN-CERTIFICATION.md` §5.5).

One trait — `Resolver` — and two implementations: `HickoryResolver`, the real
one, configured once at boot and never from a request; and `StaticResolver`,
which answers from a map so the registry's HTTP surface and the CLI can be
tested with no network.

The contract keeps §5.5's load-bearing distinction: `NoRecords` means the name
**answered** and nothing is there (NXDOMAIN and NODATA are answers — the
publisher's next step is to add the record), `Failed` means nothing can be
concluded (the caller's next step is to retry). Two problem codes depend on
the difference.

This crate exists so the CLI and the server share one resolution behaviour
without the CLI depending on the server crate, which would pull the AWS SDK
into every `cargo install aithos`.
