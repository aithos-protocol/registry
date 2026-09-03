# Task brief: derive the A2A presence table from `a2a.proto`

Self-contained brief. An agent should be able to run this with no context beyond
the repository. Read all of it before editing anything.

Background and justification: [`docs/a2a-conformance-and-tooling.md`](../a2a-conformance-and-tooling.md).

---

## Problem

`crates/a2a-card/src/schema.rs` holds a hand-written table of the A2A
`AgentCard` shape and its protobuf field-presence behaviour. Everything the
registry does — canonical bytes, digests, signature payloads — depends on that
table being an exact transcription of `a2a.proto` at the pinned commit
`3303592588e388e62e0f69f701af531d2f4e3991`.

Today nothing checks that. `table_digest()` is pinned to a literal, which catches
an accidental edit but pins the table only to itself. The table-versus-proto
comparison is done by a human in each audit round. And the vendored `a2a.proto`
at the repository root is not itself verified against upstream.

A single wrong field would give this registry a canonical form that no other
correct implementation produces — stably, with a green suite.

## Goal

Make `cargo test` prove what `SPEC.md` §5.2 asserts: that the table is derived
from the pinned proto.

**The hand-written table remains the runtime source of truth.** This task adds a
check, it does not replace `schema.rs` with generated code.

---

## Hard constraints

Violating any of these means the task failed, even if the tests pass.

1. **No change to `crates/a2a-card`'s runtime dependencies.** No `prost`, no
   `tonic`, no `protoc`, no `build.rs`. New code is a dev-dependency-free
   integration test, or at most uses crates already in `[workspace.dependencies]`.
2. **`cargo build -p aithos-a2a-card --target wasm32-unknown-unknown` must still
   succeed.**
3. **`table_digest()` must not change.** It is
   `sha256:cc3191a655d53847bed8f0afcb8138932daea9184a20ee2420e49287b39c9b84`,
   published by `/v1/registry` as an interoperability fact. If your work changes
   it, you have edited the table — stop and report instead (see "If they
   disagree").
4. **No behavioural change to parsing, validation or canonicalization.** No edits
   to `strict.rs`, `presence.rs`, `canonical.rs`, `error.rs`, `lib.rs`.
5. `cargo clippy --all-targets -- -D warnings` and `cargo fmt --all --check` stay
   clean.

---

## Deliverable 1 — pin the vendored proto

The repository root holds `a2a.proto`. Verify it is byte-identical to the
upstream file at the pinned commit:

```
https://raw.githubusercontent.com/a2aproject/A2A/3303592588e388e62e0f69f701af531d2f4e3991/specification/a2a.proto
```

- **Identical:** add a test in `crates/a2a-card` that asserts
  `sha256(include_bytes!("../../../a2a.proto"))` equals a pinned literal, with a
  doc comment naming the upstream URL and commit. Same shape and same reasoning
  as `the_table_digest_is_pinned`.
- **Not identical:** **stop.** Do not "fix" either file. Report exactly what
  differs (a unified diff of the two) and wait. A vendored proto that drifted
  from the commit `SPEC.md` pins is a finding in its own right.
- **No network access:** say so, pin the digest of the vendored file anyway, and
  flag the upstream comparison as not performed.

## Deliverable 2 — derive the table from the proto and compare

Add `crates/a2a-card/tests/schema_matches_proto.rs`:

1. Read the proto with `include_str!("../../../a2a.proto")`.
2. Parse the subset that the presence table depends on. Nothing more:
   - `message <Name> { ... }` blocks, including nested `oneof <name> { ... }`;
   - field lines: `[optional|repeated] <type> <snake_name> = <n> [ ... ];` and
     `map<string, <type>> <snake_name> = <n>;`;
   - the `(google.api.field_behavior) = REQUIRED` annotation in the option
     brackets;
   - `//` comments and blank lines, discarded.
   The file is machine-generated and regular; do not build a general proto
   parser. Reject anything you did not expect with a panic that quotes the line —
   a silently skipped field is the one failure mode that matters here.
3. Map to the table's vocabulary, rooted at `AgentCard`:
   - JSON name = proto3 lowerCamelCase of the field name (`security_requirements`
     → `securityRequirements`, `oauth2_metadata_url` → `oauth2MetadataUrl`,
     `pkce_required` → `pkceRequired`). Write this as its own function and unit
     test it on those three plus `mtls_security_scheme` and
     `open_id_connect_security_scheme`.
   - `REQUIRED` annotation → `Behavior::Required`; `optional` keyword →
     `Behavior::Optional`; anything else → `Behavior::Implicit`. A `oneof` member
     is `Implicit`.
   - `string` → `Ty::Str`, `bool` → `Ty::Bool`,
     `google.protobuf.Struct` → `Ty::Struct`, `map<string, T>` → `Ty::Map`,
     `repeated T` → `Ty::Repeated`, a message name → `Ty::Msg`.
   - a message containing exactly one `oneof` and nothing else → `is_oneof: true`,
     with the `oneof`'s members as its fields.
4. Walk only what `AgentCard` reaches. The proto describes the whole A2A service;
   `Task`, `Message`, `Part` and friends are out of scope and must not appear in
   the derived table.
5. Render the derived table with the **same grammar `schema.rs` already uses**
   (`render_msg` / `render_ty`, behind the digest). Expose it to the test —
   `#[doc(hidden)] pub fn render_table_for_tests() -> String`, or make the
   renderer generic over a small trait. Do not duplicate the grammar: the point
   is that both sides are rendered by one function.
6. Assert the two rendered strings are equal. On failure print a line-by-line
   diff, so the message names the offending field rather than dumping two blobs.

### If they disagree

**Do not edit `schema.rs` to make the test pass.** A disagreement is either a
parser bug or a real conformance defect, and the second one is the reason this
task exists. Report:

- the exact fields that differ, with the proto line number and the `schema.rs`
  line number;
- which side you believe is wrong, and why;
- the canonical-form consequence (which cards would be accepted or refused
  differently).

Then stop. Changing the table changes `table_digest()`, which is a published
interoperability fact and a protocol-visible decision — not an agent's call.

## Deliverable 3 — documentation and CI

- `SPEC.md` §5.2: one sentence saying the derivation is now checked by the suite,
  and that an A2A upgrade means updating `a2a.proto`, both pinned digests and the
  table together, in one commit.
- Confirm the new tests run under the existing `.github/workflows/ci.yml`
  (`cargo test` at the workspace root). Add nothing if they already do.
- Add a row to `audits/LEDGER.md` recording what was done and why, in the voice
  of the existing rows.

---

## Out of scope

Do not do these here, even though the report recommends them. They are separate
commits and some need a human decision:

- renaming `vectors/a2a-sample-agent-card.json` and correcting the claims about it;
- the `SPEC.md` §2 note about the prose-versus-proto disagreement;
- documenting the unknown-member and `snake_case` refusals;
- any error-message hint for a top-level `security` member;
- taking or refusing a dependency on `a2a-rs`.

## Acceptance

```bash
cargo test                                                   # all green, new tests included
cargo clippy --all-targets -- -D warnings                    # clean
cargo fmt --all --check                                      # clean
cargo build -p aithos-a2a-card --target wasm32-unknown-unknown   # builds
```

and:

- `a2a_card::schema::table_digest()` is unchanged;
- `crates/a2a-card/Cargo.toml`'s `[dependencies]` is unchanged;
- deliberately breaking one field in `schema.rs` (for example `imp("tenant", …)`
  → `req("tenant", …)`) makes the new test fail with a message naming `tenant`.
  Demonstrate this, then revert it.

## Report back

- whether the vendored proto matched upstream;
- whether the derived table matched the written one, and any difference in full;
- the parser's line count and what it refuses;
- anything in the proto you had to special-case, since that is where the next
  A2A upgrade will hurt.
