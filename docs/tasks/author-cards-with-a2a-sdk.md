# Author Agent Cards with the official A2A SDK

**Date:** 2026-09-16
**Status:** implemented on the `sdk-card-authoring` branch, not merged into `main`.
`main` waits for the trust releases described in the README (AI Catalog Trust
Manifest rework, A2A discovery on AI Catalog) before it moves.
**Decision it implements:** cards are *created and edited* with the official A2A SDK
(`a2aproject/a2a-rs`), not written as JSON by hand.

---

## 1. The boundary: what the SDK can and cannot own

| Step | Owner after the refactor | Why |
| --- | --- | --- |
| Card model: building, editing (`card init`, `--bump`) | **A2A SDK** — `a2a-lf` types | the point of the decision |
| Encoding to JSON | **A2A SDK** — `a2a-pb` generated proto3 JSON (`protojson_conv::to_value`) | generated from the proto, so the `securityRequirements` shape comes out right |
| §8.4.1 rule 1 (`REQUIRED` kept at default) | `a2a-card::presence::complete_required` (new, table-driven, ~40 lines) | no SDK layer applies it (§2) |
| Strict gate, JCS, digest, JWS, JWK, report | `a2a-card`, unchanged | no SDK has any of it |
| Registry (core, api, lambda) | unchanged, **no SDK dependency** | it stores and serves bytes; it never re-encodes a card |
| `verify` | unchanged | byte-exact; the SDK resolver returns a struct, not bytes |
| Browser / wasm | unchanged | `a2a-pb` (tonic, hyper) and `a2a-lf` (uuid) do not build for `wasm32` |

The SDK replaces the hand-written *authoring*. It cannot replace the hand-written
*verification*: nothing to replace it with exists in any language.

---

## 2. Measured: neither SDK encoder is signable on its own

Same `a2a::AgentCard` value, two SDK encoders, checked by `a2a-card`:

| Card | `a2a-lf` serde (`serde_json::to_value`) | `a2a-pb` protojson |
| --- | --- | --- |
| spec sample (§8.5, with `securityRequirements`) | **refused** — writes `{"google":[…]}` | accepted |
| `description: ""`, skill `description: ""`, `tags: []` | accepted | **refused** — omits all three |
| `skills: []` | accepted | **refused** — omits `skills` |
| `streaming: false`, `iconUrl: ""` | accepted | accepted |

`a2a-lf` gets presence right and shape wrong; `a2a-pb` gets shape right and presence
wrong. The pipeline takes the SDK's shape and restores presence from our table:

```text
a2a::AgentCard ──a2a_pb::protojson_conv::to_value──▶ proto3 JSON
   ──a2a_card::presence::complete_required──▶ ──a2a_card::validate_value──▶ CanonicalCard ──sign──▶
```

**Round-trip invariant, measured:** for every strictly valid card the SDK can read,
`encode(decode(card))` gives **byte-identical** canonical bytes. Covered: the spec
sample, `REQUIRED` defaults everywhere, `skills: []`, optional-at-default members,
extensions with nested `params`, OAuth2 flows, `tenant`, provider, and skill-level
security.

**One case the SDK cannot read:** an API-key requirement with no scopes,
`{"schemes":{"k":{}}}`. This is correct proto3 JSON (an empty `list` is omitted), but
`a2a-lf` fails with `invalid wrapped security scopes`. The SDK can still *build* such a
card, and the pipeline emits it correctly; only reading an existing file fails.
`decode` reports it, and nothing is silently rewritten.

---

## 3. What this branch changes

| File | Change |
| --- | --- |
| `crates/a2a-card/src/presence.rs` | `complete_required(&mut Value)`: adds missing `REQUIRED` members at default, never removes or reshapes; walks the same table as `validate_card`; 2 tests. Pure, still builds for `wasm32`. The table digest is unchanged |
| `crates/a2a-card-sdk/` (new, `aithos-a2a-card-sdk`) | re-exports the SDK types; `encode(&AgentCard) -> CanonicalCard`; `decode(&CanonicalCard) -> AgentCard` with a byte-exact round-trip guard (`Unreadable` / `NotRepresentable`); 3 tests |
| `crates/aithos-cli/src/card.rs` | `scaffold` builds an `AgentCard` struct (no `json!` literal); `bump` goes SDK → edit `version` → SDK, and refuses with the reason when the SDK cannot carry the card |
| `crates/aithos-cli/src/main.rs` | `card check` adds a line: `a2a sdk  readable by the official A2A SDK, round trip exact`, or the warning |
| `crates/aithos-cli/src/{error,verify}.rs` | error conversion, test call sites |

Results (build container, 2026-09-16, rebased on `main` `2e7e9a9`): `cargo test --all` 232 passed (7 ignored), `a2a-card-sdk` 3/3 and all
green; `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt` clean; `a2a-card` builds for
`wasm32-unknown-unknown`; `cargo deny` licenses and bans OK. `cargo deny advisories`
fails, but on RUSTSEC-2026-0285 (rustls), which **already fails on `main`**. It is
unrelated to this change and worth its own fix.

```text
$ aithos card init --name Demo --url https://demo.example/a2a && aithos card check agent-card.json
valid    agent-card.json
…
a2a sdk  readable by the official A2A SDK, round trip exact
$ aithos card check apikey.json
a2a sdk  warning: the A2A SDK cannot read this card: invalid wrapped security scopes for k
```

### Cost, measured (2 CPUs, clean release build of `aithos`)

| | `main` | with SDK |
| --- | --- | --- |
| Crates in `Cargo.lock` | 374 | 419 (+45) |
| Crates in the CLI's normal tree | 276 | 316 (+40: tonic, prost, pbjson…) |
| Clean release build | 2 min 17 s | 3 min 05 s (+35 %) |
| Binary | 9.35 MB | 10.99 MB (+1.6 MB) |
| Build requirement | — | `a2a-pb` runs `protoc` (vendored binary) in its build script |

---

## 4. Remaining phases

1. **Merge this branch** (`a2a-card` gains `complete_required`, new crate, CLI)
   once the trust releases land. Ledger entry: the SDK owns authoring, `a2a-card` owns verification, and why
   both encoders needed help.
2. **Test fixtures on the SDK.** The `card_body()` helpers in
   `registry-core/tests/common`, `registry-api/tests/common` and
   `registry-e2e/tests/common` build an `AgentCard` and `encode` it (dev-dependency
   only). Then the whole suite runs on SDK-authored cards. `a2a-card`'s own tests keep
   raw JSON on purpose: they test what an SDK cannot even express (duplicates, unknown
   members, oneof violations).
3. **Replace hand-editing with commands (optional, product call).** For example
   `aithos card skill add`, `card interface add`, `card provider set`,
   `card security add`: each loads through `decode`, edits the SDK struct, and writes
   through `encode`.
4. **Upstream to `a2a-rs`** (issues, then PRs):
   - `a2a-lf` serializes `SecurityRequirement` as a bare map, not proto3 JSON;
   - `a2a-lf` cannot read `{"schemes":{"k":{}}}`;
   - `a2a-pb` protojson drops `REQUIRED` members at default: offer `complete_required`
     as `to_signable_value`, since A2A §8.4.1 applies to every SDK that signs;
   - `AgentInterface` silently strips `http://` from gRPC URLs;
   - `a2a-pb` pulls `tonic` with default features into a types-only use.
   
   When the first two are fixed, `decode` stops refusing; the guard stays.

---

## 5. Decisions for Mathieu

1. **`--bump` on a card the SDK cannot read.** Prototype: refuse, with the reason
   (strict reading of "use the SDK"). Alternative: fall back to editing `version`
   directly, with a warning.
2. **`card check` when the SDK cannot read a card:** warning (prototype) or error.
   An error would refuse cards that are valid A2A, which the registry accepts.
3. **Packaging.** `cargo install aithos` from crates.io needs every dependency
   published, so either publish `aithos-a2a-card-sdk` (one more crate in the release
   bump), or make it a module inside `aithos-cli` (and tests import it through a path
   dev-dependency). Recommended: publish it, because it is the part other Rust authors
   would reuse.
4. **Accept the cost** in §3 (+40 crates, +35 % clean build, +1.6 MB).
