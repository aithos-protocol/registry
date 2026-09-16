# Aithos Agent Card Registry

![An A2A Agent Card, its certified domains and its key-derived address](docs/images/aithos-agent-identity-card.jpg)

A public, verifiable registry that hosts [A2A](https://a2a-protocol.org) Agent
Cards and lets their owners edit them. Anyone can publish a card; the card is
signed by its owner's key; only a holder of an authorized key can change it.

There are no accounts, no passwords and no sessions. **The key is the account.**

Aithos can also **certify ownership of domains** on an Agent Card, proved by a
record in each domain's own DNS zone.

📖 **[Documentation](https://aithos-protocol.github.io/registry/)** —
[`SPEC.md`](SPEC.md) holds the normative rules.

## Why this does not use the official A2A SDK yet

Cards are handled here by [`crates/a2a-card`](crates/a2a-card): strict parsing,
the A2A §8.4.1 field-presence table, RFC 8785 canonicalization and JWS
verification. `aithos card init` writes its template directly, not through
[`a2a-rs`](https://github.com/a2aproject/a2a-rs), the official Rust SDK.

That is a matter of timing. What sits around a card — how its signer is
identified and how that is verified — is being standardized right now, and none
of it is released:

- **AI Catalog** is rewriting its Trust Manifest. Signatures are being bound to
  the artifact release and the verification profile is narrowing to `did:web`
  ([#108](https://github.com/Agent-Card/ai-catalog/pull/108)–[#110](https://github.com/Agent-Card/ai-catalog/pull/110),
  targeted at 0.9 RC). A draft also reshapes manifests and signatures again
  ([#117](https://github.com/Agent-Card/ai-catalog/pull/117)).
- **A2A** is moving agent discovery onto AI Catalog
  ([A2A #2230](https://github.com/a2aproject/A2A/pull/2230)).

No SDK implements card signing or trust today. Adopting one now would only move
card authoring, and would mean a second migration once those releases land.

The migration is ready on the
[`sdk-card-authoring`](https://github.com/aithos-protocol/registry/tree/sdk-card-authoring)
branch. There, cards are built with the SDK's types and encoded by its
proto-generated JSON layer; `a2a-card` restores the §8.4.1 required fields
that encoder omits, and still owns canonicalization and signatures. The plan,
the measurements and the SDK gaps found on the way are in
[`docs/tasks/author-cards-with-a2a-sdk.md`](https://github.com/aithos-protocol/registry/blob/sdk-card-authoring/docs/tasks/author-cards-with-a2a-sdk.md)
on that branch.

## Quickstart with the CLI

```sh
brew install aithos-protocol/tap/aithos
```

```sh
aithos key new              # generates your key. Its thumbprint — a 43-character
                            # string, call it <kid> below — is your entry's
                            # permanent address, known before anything is published.

aithos card init            # writes agent-card.json, already valid
$EDITOR agent-card.json     # name, description, endpoints — say what your agent is
aithos publish agent-card.json --key <kid>

aithos whatis <kid>         # read the entry back: status, lineage, who may change it
aithos verify <kid>         # is the served card intact, and which key signed it?

$EDITOR agent-card.json     # edit the card…
aithos publish agent-card.json --key <kid> --bump patch    # …and publish the new version
```

Then, to certify the domains that entry owns:

```sh
aithos certify <kid> --key <kid> --domains acme.com,acme.fr
```

`--domains` names the complete set. When a zone has no record yet, the command
prints the line to paste into it and sends nothing.
[`DOMAIN-CERTIFICATION.md`](DOMAIN-CERTIFICATION.md) has the rules.

### Commands

| Command | What it does |
| --- | --- |
| `aithos key new` | Generate a key. Its thumbprint is the address of any entry it creates, so you know the address before publishing anything. |
| `aithos key ls` | List the keys on this machine. |
| `aithos card init` | Write a minimal card that already satisfies the strict A2A profile. |
| `aithos card check <file>` | Validate a card locally, without publishing it. |
| `aithos publish <file> --key <kid>` | Sign a card and publish it. `--bump major\|minor\|patch` raises the version; `--offline` signs without contacting anything; `--key` repeats to authorize several keys. |
| `aithos certify <kid> --key <kid> --domains <list>` | Certify domains: each zone declares the agent, and a key holder signs the request. |
| `aithos whatis <kid>` | Look up what the registry holds at an address, the way `whois` does. |
| `aithos verify <kid\|url\|file>` | Check a published card, or any signed A2A card, against its signatures. |
| `aithos withdraw <kid> --key <kid>` | Withdraw an entry. Permanent, and the identifier is never reusable. |

There is no `rotate` command: rotation is the choice of which keys sign. Co-sign
one version with the old key and the new one to widen the authorized set, then
sign with the survivors alone to narrow it.

Keys live in `~/.config/aithos/keys`, mode `0600`, encrypted at rest as a JWE
(`PBES2-HS256+A128KW` with `A256GCM`) unless `--no-passphrase` says otherwise.

### Other ways to install

```sh
cargo install aithos                      # from crates.io

# prebuilt, with a provenance attestation — the checkable way in:
gh release download --repo aithos-protocol/registry --pattern '*apple-darwin*'
gh attestation verify aithos-*.tar.gz --repo aithos-protocol/registry
```

Homebrew is the convenient way in, not the checkable one: the formula is four
URLs and four checksums. What proves a binary that will hold your signing keys
is `gh attestation verify`.

The tool talks to `https://registry.aithos.world` by default; `--registry` (or
`AITHOS_REGISTRY`) points it anywhere else, `registry-dev.aithos.world`
included. Register a second key before you need it — publish one version signed
by both (`--key` repeats) and either can act alone from then on; there is no
operator to restore access to a lost key.
