# Contributing

This registry's product is a security property: that an entry can only be
changed by a holder of its authorized keys, and that anyone can recompute that
for themselves. The most useful thing an outside contributor can do is
therefore not to add to it. It is to check it — independently, with fresh eyes,
and against the written rules rather than against the code's intentions.

That shapes what follows. There are four ways in, all narrow on purpose, and a
list of things that will be declined however well they are written.

## Four ways in

### 1. A bug, as a failing test

[`SPEC.md`](SPEC.md) is normative. Where the code and the spec disagree, that is
a defect regardless of which side you find more reasonable, and the best report
of it is a test that fails.

Write it in the crate that owns the behaviour, name it after the rule it pins
(`a_withdrawn_entry_serves_neither_its_card_nor_its_keys`, not `test_404`), and
open a pull request. **A red test on its own is a complete contribution** — you
do not have to bring the fix. That is already the form findings take here: every
row of the ledger names the test that would fail if the fix regressed.

Where a test cannot reach — a deployment behaviour, a race, an edge
configuration — a written failure scenario with the exact request and the exact
response is the fallback. "A concrete failure scenario, confirmed by execution
where possible" is the standard twelve audit rounds were held to, and it is the
standard a report is read against.

### 2. An ambiguity in `SPEC.md`

A normative sentence that two implementers read differently is a defect in the
spec, and the cheapest kind to fix. Open an issue quoting the section, give both
readings, and say which one you implemented and what it cost you. The fix lands
in `SPEC.md`; the code may not move at all.

The same holds for [`DOMAIN-CERTIFICATION.md`](DOMAIN-CERTIFICATION.md), which is
an additive profile over the same spec and is held to the same bar.

### 3. Test vectors, and a second implementation

`SPEC.md` §11 ends: *a second, independent implementation of the verifier is
expected to pass the same vectors; until it does, no interoperability claim is
made.* That sentence is a standing invitation, and it is the one contribution
this project cannot make for itself.

Two things are wanted:

- **A verifier in another language, run against [`vectors/`](vectors/).** It does
  not have to live in this repository. What matters is the report: what
  diverged, on which vector, and what your implementation produced instead.
  Every divergence is either a bug here or a vector that was never precise
  enough, and both are worth having.
- **New vectors for a rule that has none.** A vector is an input, an expected
  output, and the section number it pins — never a snapshot of what the current
  code happens to produce. `vectors/rfc8785/` covers canonicalization,
  `vectors/domain-certification/` covers the profile, and each directory's
  `README.md` states what its files pin. Extend that shape; do not invent a new
  one.

### 4. An adversarial review round

Twelve rounds sit in [`audits/`](audits/), one file each, with every acted-on
finding recorded in [`audits/LEDGER.md`](audits/LEDGER.md). The method is the
contribution: attack a named surface, verify by execution wherever possible,
weight your own findings, and report what you tried and failed to break as
plainly as what you broke. A round that finds nothing and states precisely what
it attacked is worth publishing.

Read the ledger before you start. Auditors under contract here work blind, on
purpose, so their findings stay independent — but a volunteer is not under
contract, and rows marked **Declined** or **Accepted, documented** carry the
reasoning that made them so. Disagreeing with one is welcome; restating the
finding it already answers is not. Say why the recorded reasoning fails.

Never demonstrate a finding against entries you do not own.
`registry-dev.aithos.world` is a real, append-only register: what is published
there cannot be unpublished. See [`SECURITY.md`](SECURITY.md).

## What will not be merged

`SPEC.md` §10 lists what V1 deliberately does not do: organizational identity,
endpoint liveness or conformance checks, a transparency log, accounts, search,
ranking, reputation, verified badges. Those are not gaps awaiting a patch. They
are the reason the claim an entry makes is small enough to be true, and a pull
request that adds one will be declined without any judgement on its code.

Concretely, in roughly the order these come up:

- **A new CLI command.** The nine in the README are the surface. `rotate` is
  absent for a reason the README states; the same kind of reason governs the
  rest.
- **A new field in the card.** Anything the registry asserts sits *beside* the
  card, never inside it, so that stored cards stay byte-identical. Certified
  domains are the worked example.
- **A dependency that replaces something short.** Every crate in the tree is
  answerable to `cargo deny`, and the deterministic core has to keep building
  for `wasm32-unknown-unknown`.
- **Formatting, style, or modernization sweeps.** `cargo fmt` and
  `clippy -D warnings` already run in CI. A diff that touches many files and
  changes no behaviour is expensive to review and pins nothing.
- **A fix without a test that fails before it.** Prose is the exception.
- **Reopening a ledgered decision with no new evidence.**

None of that is permanent. It is a no for V1, whose limits are written down
precisely so they can be argued with as text.

## Building, and what CI checks

The toolchain is pinned in `rust-toolchain.toml`; `rustup show` installs it.
Then, in the order CI runs them:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
rustup target add wasm32-unknown-unknown
cargo build -p aithos-a2a-card --target wasm32-unknown-unknown
cargo deny check bans licenses sources advisories
(cd infra && terraform fmt -check -recursive && terraform init -backend=false && terraform validate)
```

The wasm build is not decoration: the deterministic core is meant to run in the
browser that signs a card, and if that stops being true the two sides can drift
byte for byte.

The end-to-end suite is missing from that list by construction. Every test in
`registry-e2e` is `#[ignore]`d and needs a deployed environment:

```sh
REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
  cargo test -p registry-e2e -- --ignored --test-threads=1
```

It needs no credentials — every endpoint is public and each run generates its
own keys — but it writes to a real append-only register and withdraws what it
created at the end. **You are not expected to run it to contribute.**

### Where things live

| Crate | What it owns |
| --- | --- |
| `crates/a2a-card` | Strict A2A parsing, the presence table, RFC 8785 canonical bytes. Pure, and must keep building for wasm. |
| `crates/registry-core` | The write rules: JWS/JWK, publication proofs, version ordering, the `Code` enum. Pure, no I/O. |
| `crates/registry-dns` | The one resolver contract the server, the sweeper and the CLI share — which is why `cargo install aithos` pulls no AWS SDK. |
| `crates/registry-api` | The HTTP surface, storage-agnostic, with an in-memory store for tests. |
| `crates/registry-lambda` | The deployed binary: AWS store, reconciler, sweeper. |
| `crates/aithos-cli` | The `aithos` command and key custody. |
| `crates/registry-e2e` | Ignored tests against a deployed registry. No library code. |

A rule the audit rounds keep confirming: if a check can live in `registry-core`
or `a2a-card`, that is where it belongs. Those two crates are the whole of what
a second implementation has to reproduce.

`openapi.json` sits at the root and is written by hand rather than derived from
the code, for the same reason the field-presence table of `SPEC.md` §5.2 is: a
description generated from an implementation documents that implementation,
mistakes included, and stops being a second opinion about what the protocol
says. The cost of writing it by hand is drift, so drift is what the test guards
— `crates/registry-api/tests/openapi.rs` fails when the operations there stop
matching the router, or when the problem codes stop matching the catalogue,
`SPEC.md` §9 or the published problem pages. It is JSON rather than YAML
because the file is served verbatim at `/v1/openapi.json`: there is no build
step between what is reviewed here and what a client fetches, and the test reads
it with the JSON parser the service already depends on. Editing it republishes
[the rendered reference](https://aithos-protocol.github.io/registry/) through
`.github/workflows/pages.yml`.

## The shape of a change

One change per pull request. A subject line says what changed and, where there
is one, the reason — `release: 0.2.0, because a library enum grew`. The body is
prose, and it explains *why*, including what was considered and rejected. Ten
minutes of `git log` will tell you more about the expected register than any
rule here could.

If the change is normative, `SPEC.md` moves in the same commit. If it touches a
decision recorded in `audits/LEDGER.md`, the row moves in the same commit too:
the ledger exists so that a later round cannot quietly undo an earlier decision,
and this is included in "a later round".

## Provenance

Contributions are made under Apache-2.0, the project's license. Sign off each
commit under the [Developer Certificate of Origin](https://developercertificate.org):

```sh
git commit -s
```

That adds a `Signed-off-by` line and means what the DCO says: you wrote the
patch, or you have the right to submit it under this license. There is no CLA
and no account to create.

## Assisted work

Model-assisted contributions are welcome. Much of this repository is one, and
its commit trailers say so.

The rule is not about the tool; it is that you answer for the result. You can
explain why each line is there, you have run the checks above, and you can
handle a review question without going back to the model. A patch its author
cannot defend has to be re-derived by the reviewer from scratch, which is more
work than writing it was.

The same standard governs a finding. A plausible-sounding vulnerability with no
reproduction is noise, and noise is what a single-maintainer project can least
afford to read carefully.

## Security

Do not open a public issue for anything you believe is exploitable.
[`SECURITY.md`](SECURITY.md) has the private reporting path, the scope, and what
to expect.

## Asking first

For anything larger than a test or a vector, an issue before a pull request will
save you the work. The most frequent reason for a decline here is not
quality — it is scope, and scope is cheaper to settle in a paragraph than in a
branch.
