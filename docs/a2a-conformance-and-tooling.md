# A2A conformance, the SDK landscape, and where the presence table should come from

**Date:** 2026-08-29
**Scope:** `crates/a2a-card` against the pinned A2A commit, the official A2A SDKs,
and one proposed refactor.
**Status:** report. Nothing here has been applied.

---

## 1. The presence table is correct

`crates/a2a-card/src/schema.rs` was compared field by field against the vendored
`a2a.proto` and against the same file as published upstream at the pinned commit
`3303592588e388e62e0f69f701af531d2f4e3991`.

**Exact match, all 20 messages.** JSON member names (the proto3 lowerCamelCase
mapping), `(google.api.field_behavior) = REQUIRED`, the proto3 `optional`
keyword, both `oneof` wrappers (`SecurityScheme.scheme`, `OAuthFlows.flow`), and
`google.protobuf.Struct` for `AgentExtension.params` and
`AgentCardSignature.header`. No field missing, none extra, no behaviour inverted.

The reading of A2A §8.4.1 is right too, including the part that is easy to get
wrong: a singular message field carries explicit presence in proto3, so an empty
object is a legal *present* value and not a default to be omitted. That is what
`Ty::default_is_omittable` encodes, and `empty_message_field_is_legal` pins it.

This agrees with every audit round that re-derived the table by hand. **Section 6
is about the cost of that "by hand", not about a defect.**

---

## 2. Where the A2A specification contradicts itself

At the pinned commit, `docs/specification.md` and `specification/a2a.proto`
disagree about one member of `AgentCard`:

| Source | Shape |
| --- | --- |
| `a2a.proto` | `repeated SecurityRequirement security_requirements = 9;` where `SecurityRequirement` is `map<string, StringList> schemes` |
| `docs/specification.md` §8.5 sample | `"security": [{ "google": ["openid", "profile", "email"] }]` |

The strings `securityRequirements` and `security_requirements` occur **zero**
times in the prose specification; `"security":` occurs three times. The prose
kept the v0.3 OpenAPI-style shorthand; the proto did not.

**This registry follows the proto, which is the right call** — the proto is what
defines field presence, and field presence is what the signature is computed
over. But the consequence is worth stating out loud: a publisher who builds a
card from the prose gets `CARD_INVALID` at `/security` ("member is unknown to
AgentCard"), with no hint that the specification they were reading is the reason.

**Recommended:**

- one sentence in `SPEC.md` §2 recording that the proto wins where the two
  disagree, naming this member as the known instance;
- consider a targeted hint in the error detail for a top-level `security` member,
  pointing at `securityRequirements`. It is the single most likely first-contact
  failure for an honest publisher.

### 2.1 The sample-card vector is adapted, and does not say so

`vectors/a2a-sample-agent-card.json` is described as "the sample card from A2A
§8.5" in `README.md`, "the specification's own sample card" in `README.md`'s test
paragraph, and "the specification's own sample card must validate" in
`tests/validation.rs`. It is not that card verbatim: `security` was rewritten
into the `securityRequirements` / `schemes` / `list` shape, and a `signatures[]`
block was added.

The adaptation is *necessary* — the §8.5 card cannot validate against the proto.
The claim around it is what needs fixing: rename the vector (for example
`a2a-sample-agent-card.adapted.json`), and say in one line what was changed and
why. In a repository that keeps an audit ledger so a later round cannot quietly
undo an earlier decision, an over-claiming test comment is the wrong kind of
artefact.

---

## 3. Two strictnesses beyond the specification

Both are correct for a byte-exact registry. Neither is written down.

1. **Unknown members are rejected.** Canonical proto3 JSON parsers *may* ignore
   unknown fields; this one refuses them. For a store whose whole product is
   "these exact bytes were signed", refusing is right — silently dropping a
   member the publisher believed was carried would be much worse.
2. **`snake_case` member names are rejected.** Proto3 JSON accepts the original
   proto field name as an alternate spelling of the lowerCamelCase name. Here,
   `default_input_modes` is an unknown member. Also right: two spellings of one
   field means two canonical forms and two digests for one card.

**Recommended:** two sentences in `SPEC.md` §5.2. They are conformance-visible
choices, and `/v1/registry` already publishes the table digest precisely so that
another implementation can check it agrees.

---

## 4. Is there an official library that generates an Agent Card?

Yes for the *types*, no for anything this registry needs.

| SDK | Package | AgentCard type | Canonicalization | Presence validation | Card signing |
| --- | --- | --- | --- | --- | --- |
| Python | `a2a-sdk` | yes | no | no | no |
| JavaScript | `@a2a-js/sdk` | yes | no | no | no |
| Java | `a2a-java` | yes | no | no | no |
| Go | `a2a-go` | yes | no | no | no |
| .NET | `A2A` | yes | no | no | no |
| Rust | `a2a-lf` (`a2aproject/a2a-rs`) | yes | no | no | no |

Every one of them generates the card type from `a2a.proto` or the JSON Schema and
stops there. A2A says cards **MAY** be signed and leaves canonicalization,
presence and JWS to the implementer; the community has been asking for the
missing half since [Discussion #199][d199], "Sign agent cards for the love of
god!".

**There is no official Agent Card signing library in any language.** The nearest
non-official work is [`sigstore/sigstore-a2a`][sigstore], which is a different
trust model (keyless / OIDC) rather than a substitute for `kid` = RFC 7638
thumbprint.

`crates/a2a-card` is therefore not duplicating anything. It is the part nobody
ships.

---

## 5. Evaluation: should we depend on `a2aproject/a2a-rs`?

**No — not on the verification path. Keep the vendored `a2a.proto`.**

`a2a-rs` is the official Rust workspace. Its `a2a-pb` crate generates types from
a vendored `a2a.proto` with `tonic-prost-build`, and proto3 JSON serde with
`pbjson-build`. Four reasons it is the wrong dependency here:

1. **Their JSON is deliberately lenient.** `a2a-pb/build.rs` post-patches the
   generated deserializer so that `null` is accepted in place of every repeated
   field — `supportedInterfaces`, `securityRequirements`, `skills`, `signatures`,
   `tags`, and a dozen more — plus `null` for maps. That is the correct choice for
   an interop client and the exact opposite of what a signed-bytes registry needs.
2. **No duplicate-member detection, no canonical output.** pbjson is a
   serde-based proto3 JSON codec, not an I-JSON gate and not a JCS writer. It
   would have to be wrapped in the strict layer that already exists.
3. **Weight and target.** It pulls `prost`, `tonic`, `pbjson` and a vendored
   `protoc` into a crate whose stated property is that it is pure and compiles to
   `wasm32-unknown-unknown` so the browser that signs and the server that verifies
   run identical code. That property is worth more than the dependency.
4. **Churn.** The workspace publishes under `a2a-lf` / `a2a-client-lf` /
   `a2a-server-lf` at independent versions (0.3.0 / 0.2.2 / 0.4.1 at the time of
   writing); the plain `a2a` crate name on crates.io is someone else.

The one thing worth taking from it is the confirmation that the pinned proto's
package is `lf.a2a.v1` and that generating from the proto is the ecosystem's
normal practice — which is the subject of the next section.

---

## 6. The real gap: nothing ties the table to the proto

Two facts, both true today:

- `schema.rs::table_digest()` is pinned by a literal in
  `the_table_digest_is_pinned`. That stops an *accidental* edit to the table.
  It pins the table **to itself**.
- The table is checked **against `a2a.proto` by a human**, in every audit round.
  Ten rounds so far have re-derived it by hand.

Nothing in CI compares the two. So two failure modes are silent:

- **(a)** the vendored `a2a.proto` is not byte-identical to the file at the pinned
  commit — nothing verifies it;
- **(b)** the table and the proto disagree, and the auditor of that round missed
  the one field.

Both produce the same symptom: a canonical form that differs from every other
correct implementation's, and therefore signatures that verify nowhere else. The
table digest would be stably, confidently wrong.

`SPEC.md` §5.2 says "Implementations derive a static presence table from the
pinned `a2a.proto`." Right now that derivation is a claim about a past human
action, not something the suite can demonstrate.

### 6.1 Proposal

**Derive the table from `a2a.proto` at test time and assert it equals the
hand-written one.** The hand-written table stays the runtime source of truth.

```text
tests/schema_matches_proto.rs
  include_str!("../../../a2a.proto")
    -> minimal proto parser (messages, fields, optional/repeated/map/oneof,
       (google.api.field_behavior) = REQUIRED)
    -> derived table, rooted at lf.a2a.v1.AgentCard
    -> rendered with schema.rs's own render grammar
  assert_eq!(rendered_derived, rendered_actual)   // diff names the field
```

Plus a second test pinning `sha256(a2a.proto)` to the upstream file at the pinned
commit, so (a) is closed as well.

**Why a text parser rather than prost.** `field_behavior` is extension 1052 on
`FieldOptions`. prost discards unknown fields on decode and `prost-types`
exposes no accessor for it, so a `FileDescriptorSet` round-trip loses exactly the
annotation the table is built from. Recovering it means either patching protoc
output or hand-decoding the options bytes. Against that, `a2a.proto` is a
single, regular, machine-generated file: a parser for the subset that matters is
roughly 150 lines and is itself auditable — which fits this repository better
than a dependency that has to be argued about.

**Why not `build.rs`.** A build script would put codegen, and possibly `protoc`,
on the runtime crate's build — the one that must stay pure and wasm-clean. A
dev-only integration test costs nothing at runtime and fails just as loudly.

### 6.2 What this changes

| | Before | After |
| --- | --- | --- |
| Table drift vs proto | caught by a human, per audit round | caught by `cargo test` |
| Vendored proto authenticity | unverified | pinned by digest |
| Runtime dependencies | unchanged | unchanged |
| `wasm32-unknown-unknown` | builds | builds |
| Published table digest | `cc3191a6…` | identical (the table is not edited) |
| Audit effort per round | re-derive 20 messages by hand | read the parser once |

If the derived table and the written table disagree on the first run, that is the
finding — and it is one no round has been able to rule out cheaply.

The executable brief is in [`docs/tasks/derive-presence-table-from-proto.md`](tasks/derive-presence-table-from-proto.md).

---

## 7. Summary of recommendations

| # | Item | Effort | Priority |
| --- | --- | --- | --- |
| 1 | Derive the presence table from `a2a.proto` in a test; pin `sha256(a2a.proto)` | ~1 day | high |
| 2 | Rename the adapted sample-card vector and correct the three claims about it | 15 min | high |
| 3 | `SPEC.md` §2: the proto wins over the prose; name the `security` instance | 15 min | medium |
| 4 | `SPEC.md` §5.2: document the unknown-member and `snake_case` refusals | 15 min | medium |
| 5 | Error hint for a top-level `security` member | 30 min | low |
| 6 | Do not depend on `a2a-rs`; record the decision in the ledger | 10 min | low |

[d199]: https://github.com/a2aproject/A2A/discussions/199
[sigstore]: https://github.com/sigstore/sigstore-a2a
