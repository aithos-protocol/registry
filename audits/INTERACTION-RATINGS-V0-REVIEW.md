# Independent review — Aithos Interaction Ratings V0

**Review date:** 2026-09-17. **Reviewed draft:** 0.0.4, commit `4335e6a42ef2dd07abe9734fb6111440a77b50ef`, branch `agent-ranks`.

**Verdict: proceed with a narrowly scoped design-partner implementation, after resolving three integration-contract gaps below. Do not freeze 0.0.4 as an implementation-complete specification or promise a two-line integration yet.** The independent observations, reciprocal scores and signed public recording are relevant and implementable. The main difficulty is collecting the right evidence during a real A2A exchange, not creating another cryptographic signature at the end.

No critical break in the proposed signature/reference construction was identified. This is a design and integration audit, with targeted SDK experiments, not a cryptographic proof or an audit of a ratings implementation: no such implementation exists in the reviewed tree. The current draft correctly distinguishes authentic declarations from truthful ones, disagreement from fraud, and journal consistency from completeness. Those boundaries should be preserved.

## 1. Scope, independence and evidence

I first inspected current primary sources for the A2A organization, protocol, official JS and Python SDKs, discovery and trust work, AI Catalog, and the registry implementation. I then evaluated the draft against that investigation. Previous draft-review conclusions and the audit ledger were treated as history and scope constraints, not evidence that the design works. No additional reviewing agents were used.

The review covered all of `RANKS.md`, the feature overview, the planned vector checklist, relevant registry specification/contribution rules and ledger entries, and the concrete code paths named below. Only this report was added to the specification worktree. No specification, runtime, ledger or user-checkout file was changed; no commit, push, production call, public registration or message to an upstream project was made.

The registry branch's pre-design base is `2e7e9a9`; current upstream main was independently cloned at `3daf6cfca50d91ea06d5f8de21d7f4d889fad41a`. A file-hash comparison of the two trees found identical `infra/` contents and identical `crates/` contents except the OpenAPI test. Thus the implementation observations below apply to both runtime baselines; their documentation and OpenAPI work are not conflated.

### Examined sources and adoption status

| Source | Observed revision / date | Status and use in this review |
| --- | --- | --- |
| Aithos specification branch | `4335e6a42ef2dd07abe9734fb6111440a77b50ef`; draft dated 2026-09-17 | Local review baseline, not implemented ratings. |
| [Aithos registry main](https://github.com/aithos-protocol/registry/tree/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a) | `3daf6cfca50d91ea06d5f8de21d7f4d889fad41a`; 2026-09-17 | Current implementation and deployment architecture. |
| [A2A v1.0.1](https://github.com/a2aproject/A2A/tree/3303592588e388e62e0f69f701af531d2f4e3991) | `3303592588e388e62e0f69f701af531d2f4e3991`; released 2026-05-28 | Latest protocol release observed; the draft's actual normative pin. |
| [A2A main](https://github.com/a2aproject/A2A/tree/afda8316c64951a2ecb2a0d3d10867405d2b4095) | `afda8316c64951a2ecb2a0d3d10867405d2b4095`; 2026-09-16 | Current documentation, governance and model comparison. |
| [JS SDK v1.1.0](https://github.com/a2aproject/a2a-js/tree/eeffd69c983b6501cac912c693b69c034977455c) | `eeffd69c983b6501cac912c693b69c034977455c`; released 2026-08-26 | Source examined; npm `@a2a-js/sdk@1.1.0` installed and exercised locally. |
| [JS SDK main](https://github.com/a2aproject/a2a-js/tree/55b601c9e2aa0cccdfec859ec7b83b8044b8af7e) | `55b601c9e2aa0cccdfec859ec7b83b8044b8af7e`; 2026-09-16 | Compared with release; not assumed to be npm-delivered. |
| [Python SDK v1.1.4](https://github.com/a2aproject/a2a-python/tree/2d4d3048b245d2af854bad804f0e722ea9febc08) | `2d4d3048b245d2af854bad804f0e722ea9febc08`; GitHub release 2026-09-08 | Source examined and built locally from this tag. |
| [Python SDK v1.1.2](https://github.com/a2aproject/a2a-python/tree/3e6fa6a41d64f0581202df214a0515a0b0194832) | `3e6fa6a41d64f0581202df214a0515a0b0194832`; GitHub release 2026-07-22 | Actual latest version reported by public PyPI during the audit; installed from PyPI and exercised separately. |
| [Python SDK main](https://github.com/a2aproject/a2a-python/tree/4554e2d6279b560bfcf61050799c6ea66da17583) | `4554e2d6279b560bfcf61050799c6ea66da17583`; 2026-09-15 | Current implementation, distinguished from both release/package pins. |
| [AI Catalog](https://github.com/Agent-Card/ai-catalog/tree/04a99cd1ac9a20dd6586c6196e87f5e4570303b1) | `04a99cd1ac9a20dd6586c6196e87f5e4570303b1`; 2026-09-05 | Repository discovered through the official `ai-catalog.io` site; outside `a2aproject`. No GitHub releases returned at inspection. |
| [A2A discovery PR #2240](https://github.com/a2aproject/A2A/pull/2240) | head `50c5bd2a8e70df7d3c29930e02100042394ce6b9`; checked 2026-09-17 | Open, not merged; prefers AI Catalog while retaining Agent Card discovery. |
| [AI Catalog PR #117](https://github.com/Agent-Card/ai-catalog/pull/117) | head `c708f0ce776236b6d07d885fed510941a7fc9209`; checked 2026-09-17 | Open draft; contributor-specific trust manifests and selected-field signatures. Not a shipped dependency. |
| [OID4VP experimental extension](https://github.com/a2aproject/experimental-ext-oid4vp-auth/tree/e86356d4a330ede795eb5b458fd2a838ffea0064) | `e86356d4a330ede795eb5b458fd2a838ffea0064`; 2026-08-04 | Experimental in-task credential authorization, not artifact receipts or scoring. |
| [Official A2A TCK](https://github.com/a2aproject/a2a-tck/tree/263b9cfaf16a554bdfb166a7ba5b67716e946349) | `263b9cfaf16a554bdfb166a7ba5b67716e946349`; 2026-09-01 | Scope inspected; no TCK execution or ratings-extension coverage claimed. |

The vendored `a2a.proto` exactly matches v1.0.1: SHA-256 `e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016`. Comparing the released proto to examined main found only an AgentInterface address-comment change; the task/artifact models relevant here are unchanged. Protocol pinning is therefore reasonable. It does **not** select a language SDK version or guarantee its codecs implement that model correctly.

The Python release/package distinction is material: `uv pip install a2a-sdk==1.1.4` failed to resolve, and [public PyPI JSON metadata](https://pypi.org/pypi/a2a-sdk/json) reported latest `1.1.2` with no `1.1.4` release. The source tag installed successfully. This is an observation at review time, not a claim that future publication cannot fix it. A pilot lockfile must identify the package or source commit actually installed.

## 2. What A2A and AI Catalog really provide

### A2A semantics support the approach, with application decisions

The [pinned task and artifact definitions](https://github.com/a2aproject/A2A/blob/3303592588e388e62e0f69f701af531d2f4e3991/specification/a2a.proto#L163-L321) establish the following:

- A response can be a direct `Message`, without a task or artifact. Creating a task or entering `WORKING` does not prove a commercial commitment to produce an artifact.
- The server creates a task ID. Artifact IDs are unique within a task; an artifact has no enclosing task ID, participant identity or terminal-state field of its own.
- A task may have several artifacts. A2A has no universal designation of the one commercially final result.
- Artifacts and parts have metadata; a part has one content alternative: `text`, raw bytes, `url`, or an arbitrary JSON `data` value. `data: null` and empty text are meaningful valid content alternatives.
- `TaskStatusUpdateEvent` has metadata; `TaskStatus` does not. The draft correctly uses the event/task carriers.
- `lastChunk` completes an artifact stream, not necessarily the entire task. A task can later fail or be canceled. `INPUT_REQUIRED` and `AUTH_REQUIRED` are not terminal failures.

The [task lifecycle guidance](https://github.com/a2aproject/A2A/blob/afda8316c64951a2ecb2a0d3d10867405d2b4095/docs/topics/life-of-a-task.md#L1-L71) makes multi-turn work and refinement explicit. A finished task is not a generic container to keep reopening for further productions. The draft's one-production/one-final-result restriction is a valid profile restriction, provided partners can map their quotation workflow to it.

Transport authentication and rating identity are separate. A2A task retrieval remains subject to the server's authorization scope. A keyless ratings API does not make a private A2A task public or supply the credentials needed for `GetTask`. The [JS owner resolver](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/owner_resolver.ts#L3-L17) and [Python request context](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/server/agent_execution/context.py#L21-L80) expose application/user context, not Aithos Ed25519 identities.

The [extension mechanism](https://github.com/a2aproject/A2A/blob/afda8316c64951a2ecb2a0d3d10867405d2b4095/docs/topics/extensions.md#L18-L40) is a legitimate place for the proposed agreement and bookkeeping. Extension support is not automatically implemented by the SDK merely because the Agent Card declares a URI. Upstream governance explicitly allows experimental/community work and does not require every SDK to implement each extension.

### No upstream dependency closes the integration gap

Agent Card signatures authenticate an Agent Card. The SDK signing helpers are explicitly card-specific: [JS signer/verifier](https://github.com/a2aproject/a2a-js/blob/55b601c9e2aa0cccdfec859ec7b83b8044b8af7e/src/signature.ts#L1-L117), [Python helpers](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/utils/signing.py#L55-L164). They do not sign the caller's task artifact or future rating.

[A2A #1140](https://github.com/a2aproject/A2A/issues/1140), proposing artifact integrity/signatures, remained open. [#1718](https://github.com/a2aproject/A2A/issues/1718), proposing bilateral interaction records, remained an open community proposal; its broad trust claims are not protocol guarantees. [#2236](https://github.com/a2aproject/A2A/issues/2236), optional artifact receipts, was closed `not_planned`; the closing comment says the proposer is exploring alignment, not that the feature was adopted. [Trust-root PR #2099](https://github.com/a2aproject/A2A/pull/2099), head `20d38d0096590c0f3fa491a2574fb429409590ce`, was also open. The draft is right to pin a service key independently instead of treating a fetched key as proof of operator identity.

AI Catalog is a typed discovery container for resources such as Agent Cards, plugins and datasets. Its current [Trust Manifest rules](https://github.com/Agent-Card/ai-catalog/blob/04a99cd1ac9a20dd6586c6196e87f5e4570303b1/specification/ai-catalog.md#L850-L1000) cover signed trust metadata, subject/content binding, and independently anchored identities. These are useful design precedents; they do not supply task observation capture, production acceptance, exchange pairing or a rating journal. PR #117 adds independently signed contributor metadata about catalog entries, not automatic independent signatures on A2A task outputs. Reusing a catalog trust manifest as the pilot's production receipt would add dependencies while leaving the hard work unsolved.

The experimental [OID4VP flow](https://github.com/a2aproject/experimental-ext-oid4vp-auth/blob/e86356d4a330ede795eb5b458fd2a838ffea0064/v1/spec.md#L17-L109) requests credentials around `AUTH_REQUIRED`; it neither establishes the proposed production agreement nor makes an interrupted task a failed production. It is unnecessary for this V0.

## 3. Findings ranked by pilot impact

Here **P1** means resolve before freezing the first adapter contract or promising partner integration; **P2** means specify the pilot constraint or implementation decision before launch. None of these labels alleges a deployed ratings vulnerability. Deliberately accepted anti-abuse limitations are separated in §6.

| ID | Priority | Finding | Minimal disposition |
| --- | --- | --- | --- |
| IR-01 | P1 | Agreement setup, private terms/salt transport and final-result designation are not an implementable adapter contract yet. | Define one concrete partner flow and its hooks; simplify the private terms commitment if unnecessary. |
| IR-02 | P1 | Current SDK codecs and aggregation differ in ways that defeat a generic final-artifact adapter. | Pin one actual package/transport; define snapshot timing/assembly; exercise the valid edge cases. |
| IR-03 | P1 | Rating POST retries are precise, but production-request/acceptance retries are not. | Reuse the original acceptance and task binding for a retried production; define the application state needed. |
| IR-04 | P2 | `(provider, taskId)` assumes a provider-wide task namespace absent from the setup contract. | Require unique opaque task IDs across every endpoint/tenant using that ratings key, or narrow the key's scope. |
| IR-05 | P2 | The declared Ed25519 identity and strict verifier are not drop-in replacements for the registry CLI or ordinary runtime verification. | Ship a defined local key import/generation path and strict verification vectors. Keep identity namespaces distinct. |
| IR-06 | P2 | The journal requires a new authoritative transactional service; the registry's storage/read infrastructure is not directly reusable as the ratings log. | Implement an isolated store/append contract and service signing custody; use the existing architecture as a pattern only. |

### IR-01 — The two-line rating API still lacks the earlier integration contract

**Locations:** [RANKS.md:235–254](/private/tmp/aithos-agent-ranks-spec/RANKS.md:235), [256–284](/private/tmp/aithos-agent-ranks-spec/RANKS.md:256), [397–438](/private/tmp/aithos-agent-ranks-spec/RANKS.md:397), [975–992](/private/tmp/aithos-agent-ranks-spec/RANKS.md:975); [overview:167–179](/private/tmp/aithos-agent-ranks-spec/docs/interaction-ratings.md:167).

The draft correctly admits that the two lines are a target API, not the complete integration. However, it leaves the actual setup to an adapter whose required application interface is undefined:

1. The requester must sign **before** the provider accepts. Passing a private key only to `rank` at the end cannot make it available earlier. Setup needs a signer/key reference or an explicit signing callback in both applications.
2. The provider must receive the exact `termsBytes` and salt and verify their digest before acceptance. The metadata table carries the signed request but defines no carrier/encoding for those private values in the request. The final artifact's salt arrives too late to validate acceptance. Leaving the terms format to an application is reasonable; leaving its one selected pilot mapping undocumented is not an integration plan.
3. Acceptance is a business decision. Neither SDK has an Aithos production-accepted hook. An application callback, wrapper around the quotation handler, or explicit method call must state that decision. Inferring it from `WORKING` would violate the draft.
4. The application designates one final artifact, but there is no explicit selection contract for a task with multiple artifacts, two artifacts carrying copied extension metadata, or final designation occurring before task completion. The adapter must know which candidate is final and when it becomes eligible. A successful native artifact alone cannot establish this.

**Failure scenario:** a partner installs a client interceptor and a server executor wrapper. Its buyer sends the signed request metadata; its seller sees only a digest, because the application message has already been parsed and no exact private-byte envelope was specified. The wrapper either refuses to sign acceptance or invents a serialization. The former makes the quotation unrateable; the latter violates the agreed-byte requirement. Later, the quote and a supporting catalog artifact both carry the extension bundle. `rank(key, artifact, score)` cannot verify which one was designated merely from that bundle.

**Minimal fix:** document and demonstrate one complete request → accept → final-result flow. Choose a private request carrier with an exact encoding, one signer configuration per role, a callback for explicit acceptance, and one unambiguous final-artifact selection rule. Freeze a local observation handle after terminal outcome, before exposing mutable application objects. The developer can still call `rank(privateKey, artifact, score)` without assembling receipt objects.

**Complexity judgment:** a shared exchange identifier, participant identities, an explicit production-acceptance decision and a common private salt are useful. The **full arbitrary private terms-byte commitment is not necessary merely to compare two artifact observations or record subjective contributions**. Its extra benefit is committing to precisely agreed request terms, which this public service cannot evaluate. For an extremely small pilot, either use a single fixed quotation-request representation already available to both apps, or remove/defer the terms commitment and keep the narrow signed participation/production commitment. Do not build a generalized terms-negotiation layer solely because §3 currently implies one. Removing both agreement signatures entirely would change the claim and permit unsupported ratings about nonparticipating keys; that tradeoff must be explicit, not hidden in an adapter shortcut.

### IR-02 — The required snapshot is feasible, but not a generic SDK-object hash

**Locations:** [RANKS.md:415–470](/private/tmp/aithos-agent-ranks-spec/RANKS.md:415), [930–948](/private/tmp/aithos-agent-ranks-spec/RANKS.md:930), [1009–1014](/private/tmp/aithos-agent-ranks-spec/RANKS.md:1009); [vector checklist:12–16](/private/tmp/aithos-agent-ranks-spec/vectors/ranks/README.md:12).

There are three independently established obstacles.

**A. Loss before the interceptor.** The released [JS Part decoder](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/types/pb/a2a.ts#L1071-L1115) uses `isSet`, which excludes null. A valid A2A `{data:null}` becomes a typed Part with no content and re-encodes to `{}`. The decoder also accepts invalid `text:42` by string coercion, chooses the first alternative of an invalid multi-content Part, and discards unknown core fields. [Artifact decoding](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/types/pb/a2a.ts#L1181-L1198) normalizes explicit `name:null` to an empty default. These cases were executed, not inferred from a README. Current JS main retains the relevant `isSet(object.data)` behavior in its hand-maintained codec.

The [JS JSON-RPC transport](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/client/transports/json_rpc_transport.ts#L72-L86) decodes before the [client after-hook](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/client/multitransport-client.ts#L169-L183) receives the result. A post-decode hook cannot recover fields or presence that have been erased. Python's protobuf decoder preserved valid `data:null` and rejected the invalid/ambiguous cases in the equivalent local tests. The invalid cases do not prove valid A2A is incompatible; the null-data case does expose a valid-input interoperability problem.

**B. No normative reduction from chunks to the snapshot.** Both SDKs append part arrays rather than concatenate adjacent text parts. JS changes an existing artifact's nonempty `name` and `description` on append; Python leaves the original values. Both merge artifact metadata, while neither tested reducer updates `extensions` on an append. These behaviors were executed through the actual [JS ResultManager](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/result_manager.ts#L256-L297) and [Python TaskManager](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/server/tasks/task_manager.py#L23-L86).

The same sequence produced `name:"second"` in JS and `name:"first"` in Python. The sequence is schema-valid; upstream does not give the ratings profile a sufficiently detailed cross-SDK merge contract for these fields. This experiment demonstrates implementation divergence, not that either SDK is definitively violating a normative A2A merge rule. The draft cannot promise matching commitments by saying only that chunks are assembled.

**C. Recovery and activation need more than an executor event.** JS's status-event reducer does not persist `TaskStatusUpdateEvent.metadata` into the stored Task; Python's does. An agreement sent only in a status event can therefore be visible live but absent from a later JS task lookup. A conforming adapter must also preserve it in the Task itself as the draft requires. In an additional experiment using the actual JS Express route, activating the extension inside the streaming iterator produced an SSE result but no `A2A-Extensions` response header: the [middleware reads activated extensions before starting that iterator](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/express/json_rpc_handler.ts#L115-L183). Earlier middleware/context setup or a transport adaptation is required. The experiment used mocked request/response objects, not a deployed HTTP service.

**Failure scenario:** the provider signs its final business object with one text part and a final name; the requester assembles streamed parts using a different reducer. Both behaved honestly, yet the snapshots differ. Or the requester receives valid null structured data but the JS decoder removes its content, making the rating ineligible. These are integration failures before they are useful business disagreements.

**Minimal fix:** pin a package, runtime and binding, not just A2A v1.0.1. Specify the typed-to-snapshot adapter and the point at which it captures each role's own result. For the first pilot, the smallest restriction is a single complete final Artifact in a terminal Task, with a fixed business schema and no chunked artifact updates. Ordinary progress events may still exist. If streaming is needed, define replacement/append behavior, field merging, duplicate/reconnect handling and the exact relation between the provider's outgoing snapshot and the requester's assembled snapshot. Do not refetch an already observed artifact merely to force matching. A restricted pilot profile must be named as such; it is not full conformance to every input contemplated by 0.0.4.

For JS, handle the valid null-data defect at a supported decoding boundary or explicitly exclude that input from the first partner's documented supported subset. Rejecting unknown/ambiguous **wire** fields requires access before the SDK normalizes them; a typed-only adapter can validate the object it receives but cannot honestly claim to reject every malformed original JSON input. Narrow the claim accordingly or add the boundary. No cross-language claim is necessary for a single-language pilot, but the selected path must run its own round-trip vectors.

### IR-03 — A retried production can generate incompatible signed acceptances

**Locations:** [RANKS.md:232–254](/private/tmp/aithos-agent-ranks-spec/RANKS.md:232), [258–284](/private/tmp/aithos-agent-ranks-spec/RANKS.md:258), [616–651](/private/tmp/aithos-agent-ranks-spec/RANKS.md:616), [958–963](/private/tmp/aithos-agent-ranks-spec/RANKS.md:958).

The requester must reuse an `exchangeId` for the same production. The service later binds it to one request and acceptance, including the acceptance's `issuedAt` and server task ID. However, the draft does not tell the provider how to recognize a duplicate incoming production, return the original acceptance, or prevent concurrent callbacks from signing different acceptances.

A2A request/message IDs do not give this profile automatic exactly-once business execution. The [JS request context creation](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/request_handler/default_request_handler.ts#L188-L206) generates a fresh task ID when none is present; [Python's context](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/server/agent_execution/context.py#L168-L191) also generates missing IDs. Neither path deduplicates an Aithos `exchangeId` on its own.

**Failure scenario:** the seller accepts request `R` as task `T1`; its response is lost. The buyer retries `R`. A new native task `T2` is created and the seller signs acceptance `A2`. The seller rates `T1` while the buyer rates the result of `T2`. Both bundles are individually valid, but whichever reaches Aithos second gets `EXCHANGE_CONFLICT`; their differing observations are not retained as a pair. Even re-signing the same task with a new acceptance timestamp can change `acceptanceDigest` and produce the conflict. This is distinct from the well-specified retry of an already signed ratings POST.

**Minimal fix:** require the provider's adapter/application to bind `(requester, exchangeId)` to the original request digest, accepted task ID and acceptance payload once; repeated identical requests retrieve that binding, and inconsistent reuses fail locally without creating a second production. Serialize concurrent acceptance creation. Use the partner's existing task/order state; do not introduce a generalized message broker. For recovery across restarts, either persist this small agreement record with the task or explicitly limit the pilot's restart behavior. Durable background rating queues remain optional.

Also define same-process repeated `rank` behavior: a transport retry must reuse its first frozen signed submission, including timestamp and observation. A later invocation that recomputes `issuedAt` is a new attempted rating, not a retry. Returning the original promise/package or a clear already-rated result is enough. The lack of guaranteed recovery after a client loses all retry state is already disclosed and is not, by itself, a request for a V0 receipt-archival subsystem.

### IR-04 — Task uniqueness must cover the ratings identity's entire scope

**Locations:** [RANKS.md:352–356](/private/tmp/aithos-agent-ranks-spec/RANKS.md:352), [616–620](/private/tmp/aithos-agent-ranks-spec/RANKS.md:616), [930–939](/private/tmp/aithos-agent-ranks-spec/RANKS.md:930).

The journal's `(provider, taskId)` key is safe if task IDs are never reused anywhere under that provider ratings key. Native stores may also scope access by tenant and owner; the [JS write-lock scope](https://github.com/a2aproject/a2a-js/blob/55b601c9e2aa0cccdfec859ec7b83b8044b8af7e/src/server/result_manager.ts#L13-L37) explicitly includes both. A company may use one ratings key across multiple endpoints, environments or tenant stores. The draft does not state that this requires a shared task-ID namespace.

**Failure scenario:** two tenants each use task `quote-1001` under the same seller ratings key. Different buyers and exchange IDs do not help: the second production conflicts with the first global `(provider, taskId)` binding. Random UUID defaults make this unlikely, but customizable ID generators and reused business IDs exist.

**Minimal fix:** for V0 require fresh UUID task IDs across every application using one ratings key, separate development and production keys, and preserve original endpoint/tenant/auth context in the local lookup handle. If partners cannot satisfy that restriction, sign a stable task namespace and include it consistently in uniqueness/pairing. Do not pretend that adding `contextId` alone establishes provider-wide uniqueness. This is a setup constraint, not a reason to build global agent identity now.

### IR-05 — Ed25519 is viable, but key reuse and strict verification need explicit implementation

**Locations:** [RANKS.md:109–124](/private/tmp/aithos-agent-ranks-spec/RANKS.md:109), [177–202](/private/tmp/aithos-agent-ranks-spec/RANKS.md:177), [923–945](/private/tmp/aithos-agent-ranks-spec/RANKS.md:923).

The public key and signature encodings are sufficiently precise to implement. The private-key argument is not yet an import contract: seed bytes, a 64-byte expanded private key, PKCS#8, a private JWK, Node `KeyObject` and WebCrypto `CryptoKey` are different inputs. This is easy to resolve by selecting one initial representation and explicit conversion helpers.

The existing registry CLI generates and loads **P-256**, not Ed25519 ([keyfile.rs:87–113](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/aithos-cli/src/keyfile.rs#L87-L113)). Its existing private key cannot satisfy `rank` as currently specified. A new Ed25519 key creates a new ratings identity. This is consistent with the draft's explicit separation from registry lineage, but must be part of onboarding; UI code must not join identities merely because both fields are called `agentId`.

Strict verification is also substantive. In local tests, Node 23.9.0 `crypto.verify` and Python `cryptography` 50.0.1 accepted the Ed25519 identity-point public key (`x = AQAAAA…`) with a signature having identity-point `R` and zero `S` over arbitrary bytes. No private key is needed for that case. Therefore these ordinary verification calls **alone** do not meet the draft's weak-key rejection rule. This is not a flaw in §2.3: §2.3 correctly prohibits it. The registry already performs the additional rejection and `verify_strict` ([jws.rs:238–274](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/registry-core/src/jws.rs#L238-L274)).

**Minimal fix:** choose the client verifier and make the weak/noncanonical-key/signature vectors run on every supported runtime. Reuse the registry's verified rules where appropriate, with the ratings profile's stricter closed header/JWK schemas. Do not wrap Agent Card signing helpers and assume they implement the ratings envelope, domain labels or projection. Provision and pin a separate service key; no automatic replacement when a key is missing. Key rotation/delegation can remain deferred.

### IR-06 — The public log is a separate service with a new transaction boundary

**Locations:** [RANKS.md:14–18](/private/tmp/aithos-agent-ranks-spec/RANKS.md:14), [633–636](/private/tmp/aithos-agent-ranks-spec/RANKS.md:633), [703–768](/private/tmp/aithos-agent-ranks-spec/RANKS.md:703), [833–875](/private/tmp/aithos-agent-ranks-spec/RANKS.md:833); [CONTRIBUTING.md:84–105](/private/tmp/aithos-agent-ranks-spec/CONTRIBUTING.md:84).

The repository is a sound starting point for parsing, verification and service structure. It is not an existing transparency-log implementation. Its [Store](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/registry-api/src/store.rs#L125-L177) commits per-agent card state, and its [AWS write path](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/registry-lambda/src/aws_store.rs#L98-L201) uploads a card blob before a transaction, with per-agent sequence conditions and a separate convergent read projection. It has no global ratings head, stored signed receipt, ratings index or service signer.

**Failure scenario:** an adaptation acknowledges a rating as soon as its receipt blob is uploaded, or serves that blob without checking a committed journal reference, while agreement bindings and journal position are still pending. Alternatively, an eventually updated index omits a newly committed counterpart at `through=N` even though the returned signed checkpoint names N. Those adaptations violate the ratings contract. The existing registry's S3-first ordering is **not itself a defect**: historical card reads are gated by committed version metadata. Immutable blobs written in advance and made reachable only by an atomic metadata commit can likewise satisfy logical atomicity for ratings.

**Minimal fix:** define a separate ratings store operation that atomically makes the agreement indexes, author slot, exact bundle, journal entry, original signed receipt and global head authoritative. Keeping the small package in the same transactional store is the simplest pilot option, not the only valid design. Prewritten immutable blobs are also possible if all public access and acknowledgment are gated by the committed references and the required durability is met. A compare-and-swap head is enough at pilot volume. A losing concurrent append can recompute its unexposed candidate receipt against the new head; it must never return or publish a receipt for an uncommitted position. Lost transaction responses must be reconciled by reading the stored rating before returning a conflict.

For small volume, summaries and comparisons may scan the bounded authoritative journal prefix. This is simpler than introducing historical materialized aggregates immediately. If indexed views are used, they must be complete through the chosen checkpoint before being represented as that prefix. Ordinary eventually consistent convenience indexes are not sufficient for that guarantee.

Deployment also needs an Ed25519 signing/custody path absent from the current Lambda configuration, and a decision for backup and restoration of both the key and committed head. Copying the existing edge rules unchanged would miss the new write method: current [write-rate rules match PUT and DELETE](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/infra/guardrails.tf#L73-L115), whereas ratings use POST. Its uncached API behavior and signing-free registry configuration are useful context, not finished ratings deployment. These are modest operational requirements for a public endpoint, not justification for accounts, a blockchain, witnesses or a reputation platform.

## 4. A realistic minimal SDK integration

The following are actual extension points, not a claim that an Aithos adapter already exists.

| Need | JS/TS SDK reality | Python SDK reality | Application/library responsibility |
| --- | --- | --- | --- |
| Add signed request and activation | `CallInterceptor.before`, mutable request, service parameters / `withA2AExtensions` | `ClientCallInterceptor.before`, `ClientCallContext` service parameters | Choose the production request, supply signer and exact private request material; do not sign every chat. |
| Accept production | Executor receives `RequestContext` including task ID and request | `AgentExecutor.execute(context, event_queue)` and `RequestContext` | Explicit business decision, verify request, sign/reuse acceptance, persist it with task. |
| Carry agreement | Task/artifact/event metadata and artifact/message extensions | Same ProtoJSON fields, represented as protobuf messages/Struct | Preserve exact envelope strings; ensure task recovery contains agreement, not only live event metadata. |
| Capture result | Client after-hooks receive decoded Task or individual stream responses; server event bus exposes produced events | `BaseClient` yields `StreamResponse`; server `TaskUpdater` emits artifact/status events | Own assembly/selection/immutable snapshot. Neither client hook delivers an automatic Aithos final result. |
| Observe failure | JS handler may synthesize FAILED after an executor exception | Exceptions can propagate; application helpers can emit explicit failed/canceled/rejected states | Require prior accepted production and an actual terminal outcome; no rating from a transport exception alone. |
| Recover context | Existing `getTask` with original client configuration | Existing `get_task` with original context/auth | Preserve origin, tenant and credentials; never use bare artifact ID as lookup key or overwrite a captured result. |

Useful code: [JS RequestContext](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/agent_execution/request_context.ts), [JS executor](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/agent_execution/agent_executor.ts), [Python BaseClient](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/client/base_client.py#L50-L135), [Python TaskUpdater](https://github.com/a2aproject/a2a-python/blob/2d4d3048b245d2af854bad804f0e722ea9febc08/src/a2a/server/tasks/task_updater.py#L67-L209).

An honest minimal public example should show setup beside the attractive rating call. For example, **pseudocode for a future library**, with invented method names:

```javascript
const ratings = configureRatings({
  signer: localEd25519Signer,        // available before request/acceptance
  service: { origin, expectedLogId },
  codecProfile: pinnedPartnerProfile,
  production: quotationPolicy       // exact request format and final selector
});

const client = ratings.wrapClient(existingA2AClient);
const executor = ratings.wrapExecutor(existingQuotationExecutor);
// quotationPolicy has explicit accept/finalize callbacks in business code.
// The wrappers persist agreement with task state and capture a frozen local result.

const artifact = await applicationQuotationFlow(client);
const confirmation = await ratings.rank(privateKey, artifact, score);
```

This does not require the application to assemble JWS envelopes. It does require both applications to enroll their own local signer and map a few business decisions. If the design partner controls only the seller and cannot instrument requester/buyer applications, this profile cannot deliver its promised buyer-agent ratings for those callers. That is a pilot-selection issue to settle before implementation effort, not something the registry or AI Catalog can solve.

A local handle must be scoped to the agreement/task and preserve the snapshot, salt and observed terminal state. A JS WeakMap attached to a mutable object can work within one uninterrupted call chain, but JSON cloning/queueing loses object identity; a real adapter must either provide a supported serialization/recovery path or clearly restrict that behavior. Metadata supplied by a peer is not evidence that the local application observed `COMPLETED`. A final Task lookup can fill an unobserved gap; it cannot rewrite a previously captured local result.

For a first quotation pilot, I would support one deployed SDK version, one HTTPS binding, one application request schema, one complete designated final artifact, and explicit failed/canceled/rejected task results. Keep ratings asynchronous relative to artifact delivery. Broader transport support, chunk streaming and multiple artifact productions should be added only when a partner actually requires them.

## 5. What the draft already gets right

These conclusions follow from tracing the proposed signed objects and state keys, not from the previous ledger review.

- **Separate author statements.** The requester and provider each sign their own observation and their score of the counterpart. No peer artifact signature, peer rating, digest approval or new countersignature is needed at rating time. Either direction can be recorded first and remain unilateral.
- **Pairing survives disagreement.** Pairing on the fixed agreement/provider task, rather than artifact ID or digest, admits different IDs, different content/metadata digests and artifact-versus-failure declarations without splitting the exchange. Different scores are correctly excluded from observation comparison.
- **A meaningful production boundary.** Explicit acceptance prevents an ordinary chat or pre-acceptance refusal from automatically becoming a production failure. Signed observations of explicit terminal failure are legitimate subjective records; absence of a provider failure signature does not turn them into proof of provider admission.
- **No automatic blame.** Divergent observations remain valid declarations and remain in their respective aggregates. Neither hash comparison nor independent signatures identify the dishonest party. Treating a divergent observation as proof of fraud would create a new attack surface; the draft correctly avoids that.
- **Cryptographic reference binding.** Domain-separated hashes, `kid == thumbprint`, expected-signer checks, and the request → acceptance → rating chain bind each declaration to both participants and one service. Self-ratings/third-party raters are rejected by role binding. Embedded public keys suffice for these key-defined identities; remote key lookup and a service API key are unnecessary.
- **Content commitment boundaries.** The salted projection covers business metadata and ordered content while excluding only the reserved bookkeeping namespace. Common salt permits comparison; distinct hash labels separate production and artifact commitments. This protects against unsalted low-entropy guessing while the salt stays private. A URL commits to the reference, not downloaded bytes; the draft states this accurately. If quotation PDFs live at URLs, put an application-verified file digest in covered metadata or accept that bytes are outside the promise.
- **Immutable service retries.** Returning the original package for the same validated payload identity, rather than signing a new timestamp or appending another entry, is correct. Same-author changes are replacements to reject; peer disagreement is a second observation to accept. Payload identity is appropriately separate from the full-envelope `recordHash`.
- **Honest journal guarantees.** The receipt binds a position, record and predecessor chain under a separately pinned service key. Retained anchors can detect incompatible prefixes when compared; a fresh reader cannot prove global completeness, freshness or absence of forks. Signed checkpoints do not authenticate filtered-list completeness or arithmetic results. These limitations are explicitly disclosed.
- **Score arithmetic.** Six-decimal scores and integer micro-units avoid accumulated binary-float error. Missing rating differs from zero, roles remain separate, and the denominator/count must accompany the mean. The formula is a transparent summary, not a calibrated reliability probability.
- **Architectural boundary.** The profile does not modify stored Agent Card bytes, registry key lineage, publication authorization, or domain certification. This matches the repository's intended scope and avoids turning the card registry into an execution service.

## 6. Necessary complexity, simplifications and accepted limitations

| Element | Judgment for the design-partner V0 |
| --- | --- |
| Independent signature over observation and score, explicit opposite role, fixed exchange pairing | Essential to the requested product. |
| Common private salt and deterministic artifact projection | Necessary if commitments are both publicly visible and comparable without publishing business contents. |
| Bilateral prior participation/production agreement | Justified for the current claim and to prevent arbitrary claims about a nonparticipating key. Requires two-sided adoption; cannot be sold as retrospective rating of arbitrary A2A traffic. |
| Generic private terms byte negotiation | More than the minimum rating goal needs. Use one existing request representation or defer it, rather than developing a terms protocol. |
| Exact immutable retry and atomic append | Necessary even at low volume. A small transaction is enough. |
| Public signed confirmation and linear journal | Appropriate for the explicitly requested auditability. No need for Merkle proofs or a separate client auditor in V0. |
| Arbitrary historical summaries and comparisons at every `through` | Convenient, not essential to initial product learning. Keep correctness if retained; compute from bounded prefixes at pilot volume rather than adding complex indexing. |
| Every A2A transport, v0.3 compatibility, every Part shape, general streaming/reconnect handling | Defer beyond the partner's supported profile. Publicly identify the restriction. |
| Common numeric rubric | Necessary for interpreting one pilot's results, but it can be an agreed business document. No automatic evaluator or new rubric ontology is required. |
| Key rotation, identity linking, Sybil resistance, weighting, moderation, blind ratings, monitors and federation | Deliberately out of scope. Do not make them pilot prerequisites. |

Collusion, fabricated exchanges between keys controlled by one operator, retaliatory scores, selective participation and absence of universal delivery proof remain accepted limitations. The signatures prevent impersonating an existing honest key; they do not make a new identity scarce. The service cannot derive the number of all business interactions from optional submissions. These are reasons to avoid claims of verified commercial reliability, not reasons to block this limited pilot.

The outcome restrictions also create missing data: a provider can refuse acceptance, and a silent exchange may never yield an eligible final observation. This is already disclosed. If a seller wants to rate a buyer who stops cooperating after acceptance, its business application can explicitly close the production as canceled/failed under its policy. The adapter must not turn a network timeout alone into that decision or an automatic zero.

Private artifact contents and salts still require the existing A2A application to enforce appropriate task access. Unauthenticated SDK demonstration defaults are not a privacy guarantee. Preserve the partner's HTTPS/auth/tenant setup; this does not introduce a ratings-service account. Public task/artifact identifiers should be newly generated opaque values, not customer names or order descriptions. The profile's public relationship graph and timestamps remain intentional disclosures even with salted contents.

## 7. Concrete implementation fit with the registry

The existing separation of pure rules, HTTP handlers, storage interfaces and runtime is useful. Minimal new boundaries could be a ratings validation module/crate, a ratings API/store contract with an in-memory test backend, a separate runtime/deployment, and one partner adapter package. These are suggested boundaries, not a demand for four separately published products.

Reuse the tested [strict JSON parser](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/a2a-card/src/strict.rs#L1-L30), [generic JCS/hash primitives](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/crates/a2a-card/src/canonical.rs#L13-L28) and appropriately wrapped JWK/JWS verification. Do not reuse Agent Card schema validation, presence normalization or the registry's lineage evaluator as if a rating were a card. The ratings header/public JWK rules are narrower and their artifact projection is different.

Do not put ratings state on an agent's `CURRENT` item or advance the card's sequence for a rating. The existing ledger's separate-CERT-item lesson applies here as an architectural principle: unrelated state must not be overwritten by a card publication. More fundamentally, ratings accept identities with no registry entry at all. A separate table/service is the most direct way to retain that independence.

For the first journal, a single serialized logical head with transactional conditional append is adequate until measured throughput proves otherwise. The 64 KiB submission bound makes small records plausible, but the encoded bundle, receipt and indexing overhead must be measured against the selected store limits. No distributed high-throughput log is needed for an initial partner. Preserve original packages byte-for-byte/canonical-byte-for-byte according to the defined record format; do not regenerate receipts from projections on reads.

The repository's [CI](https://github.com/aithos-protocol/registry/blob/3daf6cfca50d91ea06d5f8de21d7f4d889fad41a/.github/workflows/ci.yml) already provides Rust checks, security/dependency checks, a reproducible Lambda artifact and infrastructure validation. None currently exercises an Aithos JS/Python ratings adapter, a service signer or journal races. Add the small number of feature-specific tests; passing the registry suite would not establish ratings conformance. Live registry E2E tests write to a real append-only service and were intentionally not run for this review.

## 8. Experiments and reproducibility

All experiments ran locally using test values, no production keys, no external writes and no ratings implementation. Temporary dependency downloads were the only package-network activity. Shell runtime: Node `v23.9.0` / OpenSSL `3.6.3`; Python `3.13.12`; protobuf `6.33.6`; cryptography `50.0.1`.

| Experiment | Executed code | Observed result / limit |
| --- | --- | --- |
| JS Part/Artifact codecs | Unmodified source file from JS v1.1.0 | Valid `data:null` loses its content; empty text survives; invalid types/ambiguous oneofs/unknown fields are normalized or dropped. |
| JS artifact/task reducer | npm JS v1.1.0 `ResultManager`, in-memory store | Append updates nonempty name/description, appends Parts, merges artifact metadata, retains initial extensions, drops status-event metadata from stored Task. |
| Python codecs/reducer | v1.1.4 source build, then separately PyPI v1.1.2 | Valid null-data survives; invalid Part samples rejected; reducer retains initial name/description, appends Parts, merges artifact metadata and task status-event metadata. Relevant reducer files were unchanged between inspected tags. |
| Streaming extension response header | Actual npm JS v1.1.0 Express route; mocked req/res and request handler | Activating inside the iterator did not set the response `A2A-Extensions` header. No socket or real server was started. |
| Ed25519 weak-key verification | Node crypto and Python cryptography | Both ordinary verifier calls accepted the identity-point construction. Explicit strict rejection is required by the already-correct draft. |
| Protocol/vendor check | SHA-256 and git diff | Vendored proto equals the v1.0.1 source exactly; relevant core models unchanged on examined main. |
| Registry provenance | Per-file hashes of `crates/` and `infra/` | Only the OpenAPI test differs within those paths between the specification worktree and current main. |

Harnesses and recorded output are retained outside the reviewed tree:

```sh
node --experimental-transform-types /private/tmp/aithos-review-sdk-codec-repro.mjs
node /private/tmp/aithos-review-js-assembly-repro.mjs
/private/tmp/aithos-review-python-env/bin/python /private/tmp/aithos-review-python-repro.py
/private/tmp/aithos-review-python-pypi-env/bin/python /private/tmp/aithos-review-python-repro.py
node /private/tmp/aithos-review-js-extension-repro.mjs
node /private/tmp/aithos-review-ed25519-repro.mjs
/private/tmp/aithos-review-python-env/bin/python /private/tmp/aithos-review-ed25519-repro.py
```

Corresponding `.out` files are adjacent; the PyPI rerun output is `aithos-review-python-pypi-repro.out`. Dependency directories are `/private/tmp/aithos-review-js-env`, `/private/tmp/aithos-review-python-env` and `/private/tmp/aithos-review-python-pypi-env`. The JS source-codec harness also uses `/private/tmp/aithos-review-a2a-js-release`. The package-index observation is saved in `/private/tmp/aithos-review-pypi-a2a-sdk.json`. These temporary files are reproduction aids, not proposed repository changes or a new ratings implementation.

Not executed: a complete partner request/acceptance/rating exchange, cross-language Aithos JCS/signature vectors, a ratings storage concurrency test, live network SSE/reconnect tests, an A2A TCK run, full SDK or registry test suites, service deployment, load testing, AWS restore/recovery, browser-specific crypto, or a production credential flow. Source inspection and the focused experiments do not substitute for those gates. Java, Go, .NET and Rust SDK implementations were not exhaustively audited; no portability claim to them is made.

## 9. Go/no-go gates and recommended first delivery

**Go now:** agree a quotation use case with a partner that can instrument both participant applications; retain independent observations and signatures, decimal scores, correct disagreement pairing, keyless public submission, a separate public journal and signed confirmations. The existing A2A model and registry code provide enough building blocks. No upstream proposal needs to merge first.

**Before committing to the first adapter implementation:** settle IR-01's exact request/acceptance/finalization mapping and IR-03's acceptance retry behavior. Choose the downloadable SDK/runtime/binding and either a restricted complete-artifact path or a precise streaming reducer. Decide whether the full private terms commitment earns its integration cost. Record task/key scope and local key format. These are small concrete decisions; leaving them implicit is what makes the supposedly small V0 expand unpredictably.

**Before a partner uses real interactions:** run one end-to-end example in each rating direction with unequal scores, then with unequal artifact digests and artifact-versus-failure observations. Confirm that each author receives its own signed package and both scores remain visible. Exercise a lost response and concurrent opposite-direction submissions against the actual store, plus duplicate acceptance/request delivery against the adapter. Verify a retained receipt against the log, service-key pinning, weak-key rejection, salt exclusion, body limits, and the partner's metadata-preserving snapshot. Keep the business flow working when ratings submission is unavailable.

The [planned vector checklist](/private/tmp/aithos-agent-ranks-spec/vectors/ranks/README.md:1) is a good starting inventory, but currently contains no executable fixtures. Add the reproduced SDK cases, production-acceptance replay/concurrency, scoped task-ID collision, final selector ambiguity, and restart/clone boundaries to the chosen pilot test plan. Do not require every conceivable extension or every language before launching the selected supported profile.

**Final assessment:** the core V0 is relevant and achievable. Most of its cryptographic bookkeeping serves a concrete requirement. The remaining risk is presenting application-level consent, private context transfer and final observation capture as automatic SDK integration. Resolve and demonstrate those boundaries, keep the initial supported path narrow, and this is a reasonable design-partner pilot. Implementing all 1,090 lines as a universal A2A reputation service would overshoot the user's goal.

## Appendix A. Standalone reproduction instructions

These instructions retain the essential experiments even after the temporary files disappear. They install third-party dependencies only in a new scratch directory. Use the runtime versions stated in §8 when reproducing the crypto results; an upstream/runtime fix can legitimately change an assertion. No service needs to be contacted by the test programs.

```sh
mkdir /private/tmp/aithos-ratings-review-reproduction
cd /private/tmp/aithos-ratings-review-reproduction
npm install --ignore-scripts --no-audit --no-fund @a2a-js/sdk@1.1.0 express@5.1.0
python3.13 -m venv .venv
.venv/bin/python -m pip install 'a2a-sdk==1.1.2' 'protobuf==6.33.6' 'cryptography==50.0.1'
```

Save the following as `reproduce.mjs`, then run `node reproduce.mjs`. It uses the published JS package's actual codec, reducer and Express route; only HTTP request/response objects and the tiny server implementation are mocked.

```javascript
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { Part, Task, TaskArtifactUpdateEvent, TaskStatusUpdateEvent } from '@a2a-js/sdk';
import { ResultManager, InMemoryTaskStore, ServerCallContext } from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';

// null data and empty text are valid A2A; the other three samples are invalid
// or unknown core fields. They must not be described as valid-input failures.
for (const input of [
  {data:null}, {text:''}, {text:42},
  {text:'ok',data:{lost:true}}, {text:'ok',unknown:'lost'}
]) console.log('codec', input, Part.toJSON(Part.fromJSON(input)));
assert.equal(Part.fromJSON({data:null}).content, undefined);
assert.deepEqual(Part.toJSON(Part.fromJSON({text:''})), {text:''});

const context = new ServerCallContext(), store = new InMemoryTaskStore();
const manager = new ResultManager(store, context);
await manager.processEvent({kind:'task',data:Task.fromJSON({
  id:'t',contextId:'c',status:{state:'TASK_STATE_WORKING'}
})});
for (const [name,text,append] of [['first','A',false],['second','B',true]]) {
  await manager.processEvent({kind:'artifactUpdate',data:TaskArtifactUpdateEvent.fromJSON({
    taskId:'t',contextId:'c',append,lastChunk:append,
    artifact:{artifactId:'a',name,description:name,parts:[{text}],
      metadata:{[name]:1},extensions:[`https://example.com/${name}`]}
  })});
}
await manager.processEvent({kind:'statusUpdate',data:TaskStatusUpdateEvent.fromJSON({
  taskId:'t',contextId:'c',status:{state:'TASK_STATE_COMPLETED'},
  metadata:{agreement:{request:'test',acceptance:'test'}}
})});
const task = Task.toJSON(await store.load('t',context));
console.log('JS assembled',JSON.stringify(task));
assert.equal(task.artifacts[0].name,'second');
assert.equal(task.metadata,undefined);
assert.deepEqual(task.artifacts[0].extensions,['https://example.com/first']);

const uri='https://aithos.world/ext/interaction-ratings/v0';
let activated=false;
const requestHandler={
  async getAgentCard(){return {
    capabilities:{streaming:true,extensions:[{uri,required:false}]},
    supportedInterfaces:[{protocolBinding:'JSONRPC',protocolVersion:'1.0',url:'https://example.com/a2a'}]
  };},
  async *sendMessageStream(_params,ctx){
    ctx.addActivatedExtension(uri); activated=true;
    yield {payload:{$case:'task',value:Task.fromJSON({
      id:'t',contextId:'c',status:{state:'TASK_STATE_COMPLETED'}
    })}};
  }
};
const router=jsonRpcHandler({requestHandler,userBuilder:async()=>undefined});
const route=router.stack.find(x=>x.route?.path==='/').route.stack[0].handle;
const headers={'a2a-version':'1.0','a2a-extensions':uri};
const req={headers,header(k){return headers[k.toLowerCase()];},body:{
  jsonrpc:'2.0',id:'r',method:'SendStreamingMessage',
  params:{message:{messageId:'m',role:'ROLE_USER',parts:[{text:'hi'}]}}
}};
const responseHeaders={}; let body='';
const res={headersSent:false,writableEnded:false,
  setHeader(k,v){responseHeaders[k.toLowerCase()]=v;},
  flushHeaders(){this.headersSent=true;},write(v){body+=v;},
  end(){this.writableEnded=true;},status(){return this;},json(v){body=JSON.stringify(v);}
};
await route(req,res);
assert.equal(activated,true);
assert.equal(responseHeaders['a2a-extensions'],undefined);
assert.match(body,/TASK_STATE_COMPLETED/);
console.log('stream header',responseHeaders);

const key=Buffer.alloc(32); key[0]=1;
const signature=Buffer.alloc(64); signature[0]=1;
const jwk={kty:'OKP',crv:'Ed25519',x:key.toString('base64url')};
assert.equal(verify(null,Buffer.from('arbitrary message'),
  createPublicKey({key:jwk,format:'jwk'}),signature),true);
console.log('ordinary Node verifier accepts weak identity key');
```

Save this as `reproduce.py`, then run `.venv/bin/python reproduce.py`. The same assertions also ran against a separate installation built from Python SDK GitHub tag v1.1.4.

```python
import asyncio, json
from google.protobuf.json_format import ParseDict, MessageToDict
from a2a.types.a2a_pb2 import Part, Task, TaskArtifactUpdateEvent, TaskStatusUpdateEvent
from a2a.server.tasks.task_manager import TaskManager
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.context import ServerCallContext
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

assert ParseDict({'data': None}, Part()).WhichOneof('content') == 'data'
for invalid in ({'text':42}, {'text':'ok','data':{}}, {'text':'ok','unknown':1}):
    try:
        ParseDict(invalid, Part())
    except Exception as error:
        print('rejected invalid input', type(error).__name__)
    else:
        raise AssertionError('unexpected acceptance')

async def run():
    manager=TaskManager(InMemoryTaskStore(),ServerCallContext(),'t','c',None)
    await manager.process(ParseDict({
        'id':'t','contextId':'c','status':{'state':'TASK_STATE_WORKING'}
    },Task()))
    for name,text,append in [('first','A',False),('second','B',True)]:
        await manager.process(ParseDict({
            'taskId':'t','contextId':'c','append':append,'lastChunk':append,
            'artifact':{'artifactId':'a','name':name,'description':name,
                'parts':[{'text':text}],'metadata':{name:1},
                'extensions':['https://example.com/'+name]}
        },TaskArtifactUpdateEvent()))
    await manager.process(ParseDict({
        'taskId':'t','contextId':'c','status':{'state':'TASK_STATE_COMPLETED'},
        'metadata':{'agreement':{'request':'test','acceptance':'test'}}
    },TaskStatusUpdateEvent()))
    result=MessageToDict(await manager.get_task())
    print('Python assembled',json.dumps(result))
    assert result['artifacts'][0]['name']=='first'
    assert 'agreement' in result['metadata']
asyncio.run(run())

Ed25519PublicKey.from_public_bytes(b'\x01'+b'\x00'*31).verify(
    b'\x01'+b'\x00'*63,b'arbitrary message')
print('ordinary cryptography verifier accepts weak identity key')
```

For the v1.1.4 source comparison, clone `https://github.com/a2aproject/a2a-python.git` into a new scratch directory, fetch and check out `2d4d3048b245d2af854bad804f0e722ea9febc08`, create a second Python 3.13 virtual environment, and install that local checkout plus the same protobuf/cryptography versions. Do not silently substitute current main.

The actual source-codec experiment additionally ran the unmodified `src/types/pb/a2a.ts` at JS commit `eeffd69c983b6501cac912c693b69c034977455c` via Node's `--experimental-transform-types`; the published-package reproduction above exercises the same observed conversion behavior without depending on that TypeScript runtime switch. These scripts intentionally assert the problematic behavior to make a later upstream change visible. They are not conformance tests that an Aithos implementation should pass unchanged.
