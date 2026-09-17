# Independent review — Aithos Interaction Ratings 0.0.5

**Date:** 2026-09-17. **Reviewed revision:** `b2662502793e1f56736a1088c3898e54766bab20`, branch `agent-ranks`. **Verdict: conditional GO for a deliberately narrow design-partner prototype.** This is not approval to claim that the adapter or public service already works: neither is implemented here.

The artifact-only design is feasible. A2A already carries the proposed extension data, and the official JavaScript SDK offers enough hooks for a bounded integration. An executed experiment captured a producer's original artifact through synchronous executor decoration, exchanged signed identities through actual SDK JSON-RPC codecs, kept concurrent request correlations separate, and recovered the same reference and business metadata through `getTask` copies. The public statement, immutable author slot, null attribution, reciprocal comparison and role-specific aggregation rules are substantially coherent.

The important remaining decision is the exact supported lifecycle. “Complete artifacts in non-streaming terminal task snapshots” describes a response shape, but does not identify a unique server publication hook, persistence boundary or recoverable original object. The SDK can create that response through several different event paths. Choose one small path and make its constraints explicit. Do not restore production agreements, acceptance callbacks, failure ratings or a mandatory identity gate to solve this implementation problem.

## 1. Independence, scope and source provenance

I studied the current official protocol and SDK code before reading this revision. Existing source clones were checked for clean status, origin and commit; public remote refs were independently queried. The cached JS `main` was stale by one day's new commit, so a separate fresh clone was made. A fresh npm installation supplied the executable SDK. The 0.0.4 audit was consulted only after the new investigation and reproductions, for historical distinctions and proposal references; it did not supply this review's conclusions. Proposal states were then independently rechecked through GitHub's public API.

The review read all of the current `RANKS.md`, `docs/interaction-ratings.md`, `vectors/ranks/README.md`, `CONTRIBUTING.md` and `SPEC.md`; it checked the README's current feature description, security reporting boundary and relevant registry verifier/API code. It did not re-audit unrelated domain-certification or MCP designs. Historical handoffs are not current ratings requirements.

| Primary source | Revision checked | What the revision means |
| --- | --- | --- |
| [A2A v1.0.1](https://github.com/a2aproject/A2A/tree/3303592588e388e62e0f69f701af531d2f4e3991) | `3303592588e388e62e0f69f701af531d2f4e3991`, committed 2026-05-28 | Normative baseline selected by Aithos; not interchangeable with every later SDK change. |
| [A2A current main](https://github.com/a2aproject/A2A/tree/afda8316c64951a2ecb2a0d3d10867405d2b4095) | `afda8316c64951a2ecb2a0d3d10867405d2b4095`, 2026-09-16 | Current protocol/docs source at the remote check. |
| [JavaScript SDK release](https://github.com/a2aproject/a2a-js/tree/eeffd69c983b6501cac912c693b69c034977455c) | `eeffd69c983b6501cac912c693b69c034977455c`, 2026-08-26; npm `@a2a-js/sdk@1.1.0` | Actual package used in every SDK execution below; npm `latest` was 1.1.0 and `gitHead` matched the tag. |
| [JavaScript SDK current main](https://github.com/a2aproject/a2a-js/tree/ce7e7c1445229220156d1af0dd9e0feeb8ffbcd4) | `ce7e7c1445229220156d1af0dd9e0feeb8ffbcd4`, 2026-09-17 10:19:33 +02:00 | Source-only comparison, freshly cloned. Its fixes are not silently credited to 1.1.0. |
| [Python SDK release](https://github.com/a2aproject/a2a-python/tree/3e6fa6a41d64f0581202df214a0515a0b0194832) | `3e6fa6a41d64f0581202df214a0515a0b0194832`, 2026-07-22; PyPI `a2a-sdk==1.1.2` | Current PyPI release at the check; source comparison, not a Python execution claim. |
| [Python SDK main](https://github.com/a2aproject/a2a-python/tree/4554e2d6279b560bfcf61050799c6ea66da17583) | `4554e2d6279b560bfcf61050799c6ea66da17583`, 2026-09-15 | Current Python source, including client and task-manager behavior. |
| [AI Catalog](https://github.com/Agent-Card/ai-catalog/tree/04a99cd1ac9a20dd6586c6196e87f5e4570303b1) | `04a99cd1ac9a20dd6586c6196e87f5e4570303b1`, 2026-09-05 | The source cited by the draft: discovery and optional trust metadata, not a runtime artifact-rating implementation. |

The npm tarball integrity observed was `sha512-/Mhzw9C6VW7pFbY2Rq0pnrjT0Fy9PV0c46A7Gx1ppRlYq2u/6OV/bNRIoVBKChb8UZ8bE0WzzCc0pIr2CdmG+w==`. Tests ran under Node `v23.9.0`. The package declares Node >=20; this review does not generalize runtime crypto behavior to every supported Node version.

Current proposal status, checked on 2026-09-17: [artifact integrity #1140](https://github.com/a2aproject/A2A/issues/1140) and [bilateral interaction records #1718](https://github.com/a2aproject/A2A/issues/1718) were open; [optional artifact receipts #2236](https://github.com/a2aproject/A2A/issues/2236) was closed `not_planned`; [Agent Card verifier trust-root PR #2099](https://github.com/a2aproject/A2A/pull/2099) was open and unmerged. [AI Catalog contributor signatures PR #117](https://github.com/Agent-Card/ai-catalog/pull/117) was also open and unmerged. None is a shipped Aithos identity/capture service, and none is needed for this V0.

## 2. What the upstream actually permits

The [pinned proto](https://github.com/a2aproject/A2A/blob/3303592588e388e62e0f69f701af531d2f4e3991/specification/a2a.proto#L143-L320) makes `artifactId` task-scoped, provides task and artifact metadata, supports four part alternatives including null structured data, distinguishes terminal from interrupted states, and allows complete artifact updates as well as chunks. A `TaskStatus` is not a metadata carrier. Native A2A has no mandatory caller Agent Card, global ratings identity or standard artifact-signature field. Card signatures do not sign task outputs.

The [pinned extension rules](https://github.com/a2aproject/A2A/blob/3303592588e388e62e0f69f701af531d2f4e3991/docs/specification.md#L996-L1145) support namespaced metadata and optional opt-in extensions. The draft's `required: false`, request/response identity metadata and artifact bookkeeping therefore do not require a protocol fork. Wire protocol version `1.0` in the JS SDK header is a major/minor negotiation value, not evidence that its npm release number is the A2A specification version.

The JS [client hooks](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/client/interceptors.ts#L1-L55) allow mutable request and result values. [Execution](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/client/multitransport-client.ts#L443-L514) passes the same per-call options from `before` to `after`; a fresh context object and symbol key can retain the request UUID safely across concurrent calls. There is no need for a global “last peer.” `getTask` also runs through interceptors. The actual JSON-RPC transport checks response RPC IDs, while the Aithos UUID supplies the separate signed identity correlation.

The JS [official extension sample](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/samples/extensions/extensions.ts#L12-L82) decorates an `AgentExecutor` and its event bus. The [request context](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/agent_execution/request_context.ts#L11-L47) exposes the complete request, task IDs, current task and call context. These are concrete ways to verify incoming identity and stamp outgoing metadata before encoding. Synchronous key import and Ed25519 signing are available in Node; `init(): void` does not inherently require a network call or an asynchronous public API.

Python should remain a separate adapter. Its [client `send_message`](https://github.com/a2aproject/a2a-python/blob/3e6fa6a41d64f0581202df214a0515a0b0194832/src/a2a/client/base_client.py#L36-L107) returns an async iterator even for non-streaming responses, and it exposes an [async interceptor-attachment method](https://github.com/a2aproject/a2a-python/blob/3e6fa6a41d64f0581202df214a0515a0b0194832/src/a2a/client/client.py#L222-L224). Its [artifact reducer](https://github.com/a2aproject/a2a-python/blob/3e6fa6a41d64f0581202df214a0515a0b0194832/src/a2a/server/tasks/task_manager.py#L23-L87) appends parts and metadata but does not apply all the JS reducer's name/description behavior, and rejects append without an existing artifact. A2A compatibility does not make SDK object shapes or reducers identical. Excluding chunks and accepting honest observation divergence are appropriate simplifications.

## 3. Findings and smallest corrective decisions

Priority measures impact on a pilot contract, not severity of a deployed Aithos vulnerability. P1 must be resolved before promising the integration; P2 needs a precise profile restriction or implementation rule before launch; P3 is an edge correction. “Gate” explicitly means an obligation the draft already acknowledges, now supported by concrete evidence.

| ID | Priority / classification | Conclusion |
| --- | --- | --- |
| AIR5-01 | P1, acknowledged implementation gate | Name the actual initialization surfaces and publication/persistence path. The two calls are feasible for a bounded path, but terminal response shape alone does not define it. |
| AIR5-02 | P2, contract ambiguity | Define which SDK operation creates a new artifact instance and which state survives retries, continuation and restart. Business intent is not an observable generation key. |
| AIR5-03 | P2, confirmed pinned-SDK constraints | Nonempty JSON-RPC tenants can lose extension activation; task-store scoping does not scope the default event bus. Constrain the pilot or prove the bridge. |
| AIR5-04 | P3, numeric specification edge | A safe integer `sumUnits` does not guarantee exact six-decimal JSON serialization of `sumUnits / 1000000` at the permitted maximum. |

### AIR5-01 — Make the two-call contract concrete without adding business calls

**Locations:** `RANKS.md` §3.3 lines 278–299, §3.4 lines 319–355, §9.2 lines 824–874, §9.3 lines 877–905; overview lines 69–93; vector checklist “SDK profile,” “Capture/eligibility,” and “Reference persistence.”

The draft correctly labels the exact integration a prototype gate at lines 891–897. This finding does not reclassify that honest qualification as a contradiction. It identifies the choices that a demonstration must resolve:

1. **Client installation is conditional on the surface.** `Client.config` is optional and readonly as a property; its existing interceptor array is mutable. Our experiment appended an interceptor to a retained mutable config on an existing client. A default client with no config has no public `addInterceptor` method. Wrapping its public send/get methods is possible in JavaScript, but is adapter behavior requiring preservation of method semantics, existing interceptors and bound references. Do not present every existing client as already hot-pluggable through one official SDK method. [Source](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/client/multitransport-client.ts#L34-L82).
2. **The producer has a workable synchronous boundary.** Replacing the application-owned executor's public `execute` method with a decorator works even after `DefaultRequestHandler` construction: the handler retains that object. A decorated `publish` can attach ref/salt and snapshot the same artifact object the application will pass to `rank`. The harness does this. It is not an official mutable “SDK singleton”; the handler's executor/store/card fields are private in its TypeScript API. Accessing those runtime fields would be a separately version-coupled integration, not a public extension promise. [Handler construction](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/request_handler/default_request_handler.ts#L87-L125).
3. **A terminal response need not arise from a terminal Task event.** The normal sequence `Task(WORKING)`, one complete `artifactUpdate(append:false,lastChunk:true)`, then `statusUpdate(COMPLETED)` produced a complete terminal `sendMessage` response in the experiment. No terminal `AgentEvent.task` was published. A decorator that only watches terminal Task events misses the producer's original artifact in this valid, non-fragmented flow. Supporting it requires retaining the original complete artifact and finalizing its eligibility on the matching terminal event/store state. Alternatively require a full terminal Task event in the initial partner executor. That restriction is smaller and testable, but must be stated; “no chunks” does not imply it. [Event processing](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/request_handler/default_request_handler.ts#L248-L345), [artifact reduction](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/result_manager.ts#L255-L301).
4. **Publishing is not awaiting persistence.** `ExecutionEventBus.publish` returns void; queue consumption and `ResultManager` storage happen asynchronously. Immediately after synchronous publication, the harness found no task in the store, although original-object capture had succeeded. Store and result-manager paths clone objects. A decorator must arrange durable ref/salt/context persistence before the SDK exposes the deliverable response, rather than assuming that return from `publish` is a durable transaction. A post-response decorator alone can make the initial reply look right while leaving `getTask`, restart recovery and the producer's original object uninstrumented. [Event bus](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/events/execution_event_bus.ts#L78-L137), [store copies](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/store.ts#L53-L80).
5. **Await placement is an application decision with a real consequence.** In the terminal-Task-only path, `publish(terminalTask); await rank(...)` inside `execute` can keep a blocking A2A response waiting for the ratings service. The harness substituted a held promise for `rank` and proved the delay. Lines 872–874 already give the application control over awaiting/handling `rank`; this is not an intrinsic service dependency. Supply a producer example that handles the rating promise outside the delivery-critical execution lifetime, or use a demonstrated terminal-event path that closes the A2A response independently. Do not silently leave a floating rejected promise. [Blocking path and executor lifecycle](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/request_handler/default_request_handler.ts#L575-L676).

**Minimal correction:** replace `sdkInstance` with a documented type in each role, and add one supported producer sequence and one receiver sequence. For the smallest experiment, the client has a mutable interceptor configuration and the producer is a controlled executor that publishes its entire terminal Task. An adapter-owned wrapper may supply access to the executor, task store and card at construction; §9.3 already permits documenting that form. Keep the application calls `init(surface,{privateKey})` and `rank(artifact,score)`. If the wrapper requires construction setup, show it, rather than concealing it behind the word “instance.”

The actual adapter must also own optional extension advertisement/activation. It must not mutate an already-signed Agent Card without arranging a valid new card signature through the application's existing card-authoring path. This does not require changing registry schemas or stored card bytes. The harness predeclares the optional extension; automatic advertisement is not proved by that test.

**Acceptance evidence required:** both roles using the documented calls; original-object producer ranking; persisted ref/salt and private context; receiver normal result and `getTask` clones; post-capture mutation rejection; frozen objects either supported or rejected clearly; same-score parallel `rank` calls sharing one frozen submission; business delivery independent of a held or failing rating-service request. The current repository contains no adapter on which to assert these conformance results.

### AIR5-02 — Freeze the instance and recovery rules at an observable boundary

**Locations:** `RANKS.md` §3.1 lines 217–256, §3.3 lines 293–306, §3.4 lines 339–355, §6 lines 552–557, §9.2 lines 865–870; overview lines 124–147 and 169–178; vector checklist reference persistence and automatic identity.

“Same artifact instance” is stable once a reference exists. The unresolved case is selecting that instance before one exists, or after only part of the private context survives. The stated lookup tuple is task-store scope + task ID + native artifact ID; the text also requires a fresh reference for an intentional revision or new delivery exchange. Those are not necessarily distinguishable using that tuple. A repeated publication of copied `artifactId: output` can mean recovery, retry, replacement, or intentional new delivery. Equal bytes do not distinguish them; different bytes cannot automatically mean a legitimate revision because mutation must be rejected and observations can diverge honestly.

There is also a concrete lifecycle issue, not an argument for stronger participation proofs:

- In the executed continuation case, call 1 persisted complete artifact `a` with an interrupted task and Task identity correlation `request-1`. Call 2 completed the same task with artifact `b` and Task metadata for `request-2`. The final response contained **both** `a` and `b`, but its one task-level identity record named `request-2`. That is ordinary SDK [merge behavior](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/result_manager.ts#L170-L201). A single current task metadata value does not recover each artifact's original request/receiver context.
- Receiver identity is carried in **SendMessageRequest metadata**, not Message metadata. The SDK's [ResultManager context](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/result_manager.ts#L87-L93) preserves the user Message for task history, not the entire top-level request. Saving only the outgoing Task identity and artifact `{ref,salt}` therefore does not preserve the verified receiver announcement for a producer restart. The draft's additional private-context obligation is necessary; native task persistence does not implement it automatically.
- `returnImmediately:true` first returned a working task with no artifact in the experiment. It stayed empty after processing finished; a later `getTask` obtained the terminal artifact. A client adapter can capture the later call, provided it retained the original verified task/request context. It must not pretend that initializing before the first call automatically means it observed every later artifact. No background polling is necessary if ordinary application `getTask` is the declared recovery path.

**Smallest pilot rule:** one relevant SendMessage exchange per task; one intended receiver fixed for that task; no interrupted-task continuation in the first adapter; each native artifact ID identifies one immutable output in that task. Repeated reads and supported serialization of that saved output preserve its ref/salt. A revision or a new delivery is a new task and receives new references, even when the business content is equal. This follows A2A's [terminal-task refinement model](https://github.com/a2aproject/A2A/blob/afda8316c64951a2ecb2a0d3d10867405d2b4095/docs/topics/life-of-a-task.md#L73-L103) and does not require a business callback. Decide explicitly whether `returnImmediately` plus later `getTask` is supported or rejected for this first profile.

Within the existing task/artifact storage, retain an adapter-private record keyed by service/local identity + server endpoint/store scope + task/artifact instance. It needs the original reference, salt, producer/receiver identity context or explicit unknown receiver, request correlation, and sufficient captured snapshot/provenance to validate supported recovery. It must not leak the salt through a public card. A namespace collision with another initialized endpoint must not retrieve the wrong context. Do not “recover” a target from a later public rating or a different caller's current declaration.

Distinguish three retries in the text:

1. A retry of a frozen **ratings POST** reuses the exact payload, timestamp and reference. The existing rule is good.
2. A reread/retransmission of the **same persisted artifact** reuses ref/salt/context.
3. A repeated initial **A2A SendMessage** without a task ID may create a new task and new output in the SDK. A reused identity `requestId` does not itself make production idempotent. Either the chosen application already routes that retry to the existing task, or the resulting new task is a new artifact instance. V0 need not add a production-acceptance store, but must not promise to collapse these two situations automatically.

The ratings retry cache must be keyed by author slot, not object identity, because SDK reads return clones. Concurrent equivalent calls should share one frozen `issuedAt`/payload. The service still arbitrates incompatible calls, but a careless library must not manufacture a conflict from two identical user actions. After a client restart without retry state, lines 868–870 correctly make no exact resubmission-recovery promise. Do not confuse that accepted limit with the separately promised persistence of the artifact reference and producer context.

### AIR5-03 — Restrict the pinned JS tenant and task-ID scope

**Locations:** `RANKS.md` §3.1 lines 239–243, §3.3 lines 295–298, §3.4 lines 321–324 and 339–342, §9.3 lines 877–905; vector checklist “same native artifact ID in different tasks/tenants” and concurrent context capture.

**A. Nonempty JSON-RPC tenant loses activation on the outer HTTP context in 1.1.0.** The [released JSON-RPC handler](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/transports/jsonrpc/jsonrpc_transport_handler.ts#L93-L106) constructs a replacement `ServerCallContext` when a body tenant arrives and the original context has none. The executor activates the extension on the replacement. The [Express handler](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/express/json_rpc_handler.ts#L105-L123) later checks its original context when setting response headers. The harness confirmed inner activation present and outer activation absent. It exercises the exact transport/context mechanism, rather than running an actual Express socket server.

Current main [mutates the same context with `setTenant`](https://github.com/a2aproject/a2a-js/blob/ce7e7c1445229220156d1af0dd9e0feeb8ffbcd4/src/server/transports/jsonrpc/jsonrpc_transport_handler.ts#L93-L100). That fixes this mechanism in source; it does not fix the pinned published package. Also, a standard client `after` interceptor receives the decoded result, not raw response headers. If the adapter must verify activation headers, its exact supported transport/fetch integration must expose them; writing a request header alone does not prove response activation was observed.

**B. Store isolation does not isolate the default event bus.** The [store](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/store.ts#L11-L80) scopes tasks by tenant/owner, but the [default event-bus manager](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/server/events/execution_event_bus_manager.ts#L3-L30) keys solely by task ID. The harness seeded the same permitted local task ID into two tenant buckets and ran simultaneous continuations. Both returned tasks contained both tenants' artifacts. Including tenant in only the Aithos mapping does not prevent the underlying SDK from mixing the inputs to that mapping. The same manager API remains task-ID-only in examined main.

**Minimal correction:** for JS 1.1.0, declare an empty-tenant/single-tenant pilot and require task IDs unique across every owner/context sharing a handler/bus manager. Default fresh UUID task creation ordinarily satisfies that uniqueness; imported/restored IDs must too. If tenant support is needed, demonstrate context propagation and scoped bus/handler isolation first. Do not claim that a namespaced random `artifactRef` repairs already mixed task events. This is a concrete SDK constraint, not an A2A prohibition on tenants or a reason to redesign the ratings service.

### AIR5-04 — Tighten the exact aggregate serialization bound

**Location:** `RANKS.md` §8 lines 757–769, especially the shared safe-integer limit for `sumUnits` and the instruction to expose `sum = sumUnits / 1000000` using JCS.

The integer accumulator and half-up mean formula are appropriate. The permitted maximum, however, is not sufficient for exact public decimal sums. Node reproduced:

```javascript
Number.isSafeInteger(9007199254740991) // true
JSON.stringify(9007199254740991 / 1000000) // "9007199254.740992"
// Exact mathematical decimal: 9007199254.740991
```

This is a real boundary mismatch, not a material low-volume pilot problem. A JSON/JCS number at that magnitude cannot represent every micro-unit total. Specify an operational ceiling that keeps every public sum exactly representable as the intended decimal (a conservative pilot ceiling such as `sumUnits <= 10^12` is ample), and return the existing defined failure response rather than silently rounding beyond it. An exact integer `sumUnits` public field is another future encoding choice, but is unnecessary scope for the initial pilot. Add this vector when implementing aggregation.

## 4. End-to-end feasible pilot, and what remains to prove

This is an implementation outline within the draft's permitted adapter setup, not a replacement protocol.

**Initialization.** Each application initializes once, with one Ed25519 identity and one pinned service. The adapter identifies its supported client or producer surface, validates seed/public-key consistency synchronously, attaches hooks before calls flow, and establishes card advertisement/activation. Network service discovery is unnecessary during initialization. Reinitialization cannot substitute a different key or origin unnoticed. The test harness uses separate producer/receiver state inside one test process for convenience; the proposed production singleton still has one identity per process.

**Receiver request.** A client `before` hook creates a per-call context and signed receiver announcement, requests the optional extension and freezes the announcement for any exact retransmission that the adapter owns. All peer identity verification checks signer/thumbprint, role, profile and log; the signed UUID is compared to that call's retained UUID. Existing transport authentication remains independent.

**Producer publication.** The executor decorator verifies usable receiver metadata or records an explicit unknown receiver. Missing/bad metadata leaves business handling available and never becomes a trusted target. For the selected full-terminal-Task path it creates/recovers ref and salt atomically, attaches bookkeeping, captures the original artifact and frozen peer context, and lets the SDK persist the stamped artifact. The implementation must retain any additional private context alongside the application's durable task data before response delivery. This last durable-state integration is not present in the mechanism harness. Complete artifacts on a failed/canceled/rejected terminal task remain eligible; absent or incomplete artifacts do not.

**Producer rating.** After the supported publication boundary the same original artifact can resolve to captured context. The adapter validates that its protected ref/salt/content were not changed, chooses the receiver key or null from that frozen context, and freezes one rating per author slot. An application awaiting this promise must do so at a point that does not delay required business delivery if service independence is desired. No counterpart signature over the artifact is required.

**Receiver capture and rating.** The client `after` hook verifies the correlated producer announcement, checks that `artifactRef.producer` equals that key, validates complete local parts, and captures each returned artifact before later application mutation. A later supported `getTask` call receives new object identities but the same saved ref/salt; persisted local task/correlation state permits safe reconnection. Unsupported bare copies or unobserved responses produce local errors. The receiver targets the producer; it never invents the missing producer namespace.

**POST and receipt.** `rank` signs only the rated statement, submits it, verifies the expected service key and exact submitted payload plus entry hashes/bindings, and returns both signed objects. A network timeout is unknown acceptance, not definitive rejection. Exact frozen retransmission recovers the original stored package. Local context errors, service rejection and unknown acceptance remain distinct. The client need not keep a permanent receipt archive or run a monitor.

**Suggested smallest initial constraints:** Node runtime pinned with its crypto implementation; JS SDK 1.1.0; HTTPS JSON-RPC; one handler scope with globally unique task IDs and no nonempty tenant; one relevant exchange per task; full complete artifacts in one terminal Task publication; no chunk assembly, continuation, push delivery or unobserved restart bootstrap; supported serialization and `getTask` recovery explicitly enumerated. Keep several artifacts per terminal task if useful: they naturally get separate references and slots. These restrictions keep both roles and the two application calls; they do not require choosing a quotation schema or imposing a global identity system.

This is narrower than all possibilities hinted at in the vector checklist. The decision should be explicit: implement the additional lifecycle cases or mark them unsupported for the first adapter. Do not describe an unsupported case as globally impossible.

## 5. Positive conclusions and accepted security/product limits

### The artifact-only simplification removes actual former burdens

Compared with the structures described by 0.0.4, the following difficulties disappear by construction:

- No signed production agreement means no library-owned business acceptance decision, no private terms-byte serialization, no agreement countersignature and no three-envelope agreement bundle to reconcile.
- No artifact-free rating means no need to establish whether refusal, timeout, silence or interruption constitutes a punishable production failure. Neither A2A state nor a missing reply must be upgraded into business evidence.
- Rating each artifact separately removes a requirement to designate one special final business result among multiple task outputs.
- A random producer-namespaced reference separates instance identity from the native task-scoped ID. Native IDs can repeat across different tasks without becoming one rating slot.
- A counterpart need not cooperate at rating time. Neither a missing note nor a divergent digest suppresses an independently targeted score.
- A null receiver remains null permanently. No retrospective first-claimant identity assignment, moderation resolution or public participation graph is needed.

The disappearance of agreement-retry conflicts does **not** automatically make A2A production idempotent or eliminate persistence of references. AIR5-02 is the smaller, remaining lifecycle obligation. Key verification, private snapshot capture, atomic service storage and receipt checking also remain; they serve the new declaration model itself.

### Identity and replay claims are appropriately limited

The signed identity announcement proves authorship of that announcement, not fresh possession bound to an authenticated endpoint, a specific business request body or an artifact. The payload does not sign endpoint, tenant, request content or recipient key. Replaying a receiver announcement may make a producer's local interpretation wrong if the application/transport accepts that replay. The draft explicitly disclaims fresh possession and participation proof at §3.1, and the public service never receives those announcements. This is an accepted trust boundary, not grounds to add a handshake gate to V0.

The actual implementation must still check the simple promised bindings. A valid signature from some key is insufficient when the expected signer differs. Invalid receiver identity becomes unknown, not a targeted note; a receiver without verified producer context cannot form the required reference. Task/request correlations must be scoped, and must not migrate to another endpoint or tenant because a native ID matches.

### The reference, private observation and attribution are coherent

The reference identifies an instance; the salted digest commits to the author's local projected version, including business metadata. Excluding only the exact reserved top-level namespace and this profile's extension URI avoids a circular bookkeeping dependency without discarding business data. Part-level metadata remains included. The salt is transported privately with the artifact and is not a public payload member. Hashing should consume the decoded 32 salt bytes as the definition's byte concatenation implies. A URL part commits to its URL/metadata, not content fetched later.

Fresh refs for distinct identical artifacts are legitimate. Ref reuse, fabricated output and additional receiver claimants are also possible; signatures cannot establish the real inventory. The draft says so. Salt secrecy reduces public guessing and does not encrypt publicly disclosed native IDs or erase linkability. Operators must use opaque native IDs as specified.

The null-target role rule is well formed. The producer can sign a complete observed artifact even if it cannot identify the requester. Its declaration remains public but contributes to no identity's received score. A later receiver statement may be listed under the same reference and affect the producer's aggregate, without converting the prior null statement into a rating of that receiver.

### Pairing, retries and public means are mostly precise

Counterpart selection uses the shared reference and reciprocal signed identities/roles. The producer has one author slot and names at most one receiver, so extra claimant notes do not create an ambiguous counterpart for that producer. Null-target notes are never paired. Native ID/digest are compared only after pairing; score and timestamps are excluded. Divergence changes no receipt and suppresses no targeted score. The independent rule model verified these cases, including fixed-prefix views.

`ratingId` is payload-derived, while `recordHash` covers the complete stored envelope. This cleanly distinguishes identical validated payload retries from a changed score, timestamp, target or observation. Returning the original envelope is correct even if another valid signature for the same payload is presented. Verification cannot be skipped because a slot already exists. Atomic same-slot resolution, including simultaneous identical local calls, still needs implementation tests.

Role-separated arithmetic means with counts and “Not yet rated” for no data suit the stated product. These are subjective ratings of available artifacts, not success rates or verified transaction scores. Invented references and Sybil keys can influence them: that is explicitly accepted, not a missing requirement for a reputation platform. AIR5-04 concerns only the numerical representation at the permitted extreme.

### Journal and receipt boundaries are sound, but not an existing service

The service signs recording acknowledgments, not artifact truth. Pinning `logId`, validating the complete package, domain-separated record/entry/genesis hashes, contiguous journal positions and extension from retained anchors provide the stated tamper-evidence. A service cannot forge a genuine participant signature or change an anchored prefix without breaking the relevant cryptographic assumption. It can fork, suppress, withhold or serve stale histories; comparing retained views is required for detection. The draft correctly refuses a global completeness/freshness claim.

A signed head alone does not authenticate an arbitrary summary or prove a filtered page complete. Recomputing a full prefix is sufficient at low volume. The unchanged-prefix pagination and comparison rules are consistent with later reciprocal notes. No Merkle tree, external timestamp authority, monitor or permanent client archive is necessary for this V0 claim.

The required atomic transaction includes slot reservation, frozen submission, entry, original signed confirmation and head. The registry's existing per-card authorization/storage is not this transaction. The separate signer/log identity, commit reconciliation after uncertain storage responses, committed-only reads and backup/restore consistency are launch gates. This review did not implement or load-test them. Scanning a small log is a reasonable first implementation; materialized views are not a prerequisite.

### Strict Ed25519 and codec handling remain explicit gates

The specification's strict Ed25519 requirement is correct and operationally significant. In the tested Node runtime, an identity-point public key and a trivial publicly constructible signature passed generic `crypto.verify` for an arbitrary message. A generated-key happy-path signature test therefore does not establish the required key-holder property. The existing registry [verifier](../crates/registry-core/src/jws.rs) checks weak keys and uses `verify_strict`; a JS implementation needs equivalent tested behavior for participant announcements, ratings and service signatures. This is not a newly discovered omission in §2.3: it is confirmation that the explicit requirement must be implemented, rather than delegated blindly to the runtime. Private JWK seed/public-key consistency must likewise be checked.

The shipped [JS Part decoder](https://github.com/a2aproject/a2a-js/blob/eeffd69c983b6501cac912c693b69c034977455c/src/types/pb/a2a.ts#L1071-L1115) loses `data:null` oneof presence. The same `isSet(object.data)` decision remains in current main's [codec](https://github.com/a2aproject/a2a-js/blob/ce7e7c1445229220156d1af0dd9e0feeb8ffbcd4/src/types/protojson.ts#L274-L317). The harness reconfirmed the loss and verified empty text and nested null preservation. Rejecting the resulting empty part is an acceptable initial constraint under §4.1; signing it as complete is not. The adapter need not implement cross-language normalization or force matching hashes. Validation of captured typed objects is not a claim that upstream JSON parsing preserved unknown wire fields or invalid duplicate members.

## 6. Evidence, limitations and decision criteria

All experiments used local synthetic artifacts, ephemeral test keys and in-memory storage. No live registry/rating-service write, real credential, issue, external comment or message was used. Only this report was added to the specifications worktree. Research clones and scripts live in temporary directories.

| Experiment | Observed result | What it does not establish |
| --- | --- | --- |
| `sdk-probes.mjs` | Existing executor decoration and client interceptor setup worked; signed correlations survived two concurrent calls; producer original objects and receiver decoded objects were captured; ref/salt and nested business metadata survived JSON-RPC and `getTask` copies. | A published Aithos library, generic existing-instance support, automatic card advertisement, strict hostile-input parsing, a durable mapping or service receipt validation. |
| Same script | Task absent immediately after publish; held post-publication executor promise delayed blocking delivery; tenant clone lost outer activation; `data:null` lost content; Node accepted weak-key forgery; extreme sum serialization rounded. | A live Express/TLS deployment test; universal Node-runtime crypto behavior; a production incident. |
| `lifecycle-probes.mjs` | Complete artifact update + terminal status produced terminal result without terminal Task event; polling required a later read; continuation merged artifacts under newest Task identity; concurrent tenant-local same task ID mixed event-bus artifacts. | Full adapter behavior for continuation, distributed concurrency, browser runtime or recovery after process termination. |
| `journal-model.mjs` | Independent slot/pairing/arithmetic/hash model satisfied reciprocal divergence, permanent null exclusion, immutable retries and fixed-prefix examples. | A service implementation, real wire-valid signatures, strict cryptographic verification, database atomicity or crash recovery. Its symbolic placeholders are intentionally not conformance fixtures. |

The coordinating reviewer independently read and reran all three scripts and obtained the same results and checksums. No SDK test was run against current main; its distinctions above are source-level observations. Python comparisons are source-level only. HTTPS certificates, actual Express sockets, remote push, frozen custom SDK objects, application-specific stores, process crashes, malicious parser inputs and production service concurrency were not tested.

**Decision:** proceed with an adapter feasibility slice and a tiny separate journal prototype after selecting the narrow lifecycle. Before partner claims, demonstrate the exact two-role initialization/capture path and durable instance context, document unsupported paths, implement strict verification and atomic append/retry behavior, and execute the relevant existing vector checklist. The draft's architecture does not need a larger identity or reputation system to pass those gates.

## Appendix A — Reproducing the upstream and package checks

These are public, read-only remote checks. SDK probes themselves require no network after installation.

```sh
git ls-remote https://github.com/a2aproject/A2A.git refs/heads/main refs/tags/v1.0.1
git ls-remote https://github.com/a2aproject/a2a-js.git refs/heads/main refs/tags/v1.1.0
git ls-remote https://github.com/a2aproject/a2a-python.git refs/heads/main refs/tags/v1.1.2
mkdir -p /tmp/aithos-v005-review
cd /tmp/aithos-v005-review
npm install --save-exact --ignore-scripts --no-audit --no-fund @a2a-js/sdk@1.1.0
# Save the three scripts below in this directory, then:
node sdk-probes.mjs
node lifecycle-probes.mjs
node journal-model.mjs
```

The local audited copies are `/private/tmp/aithos-v005-independent-harness/`. SHA-256 checksums:

```text
95bd1da2ec86cd9a4105c9e201953169aed5567fb46fca8f0ac78e363ef23627  sdk-probes.mjs
2c97e843046397f4e930e6e44527ab664293afbb52a929533b76ebace2501435  lifecycle-probes.mjs
9a8718c4d8c27215f0bf7b05ac7728cb3ed223f1d6ab0a5a3a95b7732137a8e1  journal-model.mjs
```

The following scripts are included in full so the report does not depend on the lifetime of those temporary files. They intentionally test SDK mechanisms and specification rules rather than masquerading as a complete ratings implementation.


## Appendix B — SDK integration, timing, codec and runtime probes

```javascript
import assert from 'node:assert/strict';
import {randomUUID, randomBytes, createHash, createPrivateKey, createPublicKey,
  generateKeyPairSync, sign, verify} from 'node:crypto';
import {Artifact, Part, Task, TaskState, SendMessageRequest, Extensions} from '@a2a-js/sdk';
import {Client, JsonRpcTransportFactory} from '@a2a-js/sdk/client';
import {AgentEvent, DefaultRequestHandler, InMemoryTaskStore, ServerCallContext,
  JsonRpcTransportHandler} from '@a2a-js/sdk/server';

// Bounded SDK-mechanism experiment, NOT a conformant ratings implementation.
// Canonicalizer handles the generated ASCII payloads; not a hostile JSON parser.
const URI = 'https://aithos.world/ext/interaction-ratings/v0';
const canon = x => JSON.stringify(x, function(k,v) {
  return v && typeof v==='object' && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])) : v;
});
const b64 = x=>Buffer.from(x).toString('base64url');
const hash = x=>createHash('sha256').update(x).digest('base64url');
function key() {
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const jwk=publicKey.export({format:'jwk'});
  return {privateKey,jwk,id:hash(canon(jwk))};
}
const P=key(), R=key(), logId=key().id;
function signed(k,role,requestId) {
  const p={profile:URI,type:'peer-identity',logId,requestId,agentId:k.id,role};
  const protectedHeader=b64(canon({alg:'EdDSA',typ:'JOSE',kid:k.id}));
  const payload=b64(canon(p));
  return {jws:{protected:protectedHeader,payload,
    signature:b64(sign(null,Buffer.from(protectedHeader+'.'+payload),k.privateKey))},key:k.jwk};
}
function unpack(e,role) {
  const p=JSON.parse(Buffer.from(e.jws.payload,'base64url'));
  assert.equal(p.agentId,hash(canon(e.key))); assert.equal(p.role,role);
  assert.equal(p.logId,logId);
  assert(verify(null,Buffer.from(e.jws.protected+'.'+e.jws.payload),
    createPublicKey({format:'jwk',key:e.key}),Buffer.from(e.jws.signature,'base64url')));
  return p;
}
const card={name:'probe',description:'local only',version:'1',
  supportedInterfaces:[{url:'https://offline.invalid/a2a',protocolBinding:'JSONRPC',protocolVersion:'1.0'}],
  capabilities:{extensions:[{uri:URI,required:false}]},
  defaultInputModes:['text/plain'],defaultOutputModes:['text/plain'],skills:[]};
const makeArtifact = id=>Artifact.fromJSON({artifactId:id,parts:[{text:'complete',metadata:{nested:{a:null}}}],
  metadata:{price:1.25,tags:['a','b']}});
const request=()=>SendMessageRequest.fromJSON({message:{messageId:randomUUID(),role:'ROLE_USER',parts:[{text:'request'}]}});
const context=()=>new ServerCallContext({requestedVersion:'1.0',requestedExtensions:Extensions.createFrom(undefined,URI)});
const capturedProducer = new WeakMap(), capturedReceiver=new WeakMap();
const taskCorrelations=new Map();
const store=new InMemoryTaskStore();
let storeEmptyImmediatelyAfterPublish, responseContexts=[], executorContexts=[];
const executor={async execute(c,bus) {
  const a=makeArtifact('output');
  const t=Task.fromJSON({id:c.taskId,contextId:c.contextId,status:{state:'TASK_STATE_COMPLETED'},artifacts:[]});
  t.artifacts=[a];
  bus.publish(AgentEvent.task(t));
  // rank(original, score) can now resolve the synchronous boundary capture.
  assert(capturedProducer.has(a));
  storeEmptyImmediatelyAfterPublish = !(await store.load(c.taskId,c.context));
},async cancelTask(){}};
const handler=new DefaultRequestHandler(card,store,executor);
const rpc=new JsonRpcTransportHandler(handler);

// A synchronous init on the application-owned AgentExecutor object works even
// after DefaultRequestHandler construction, because it retains that object.
const priorExecute=executor.execute.bind(executor);
executor.execute=async function(c,bus) {
  executorContexts.push(c.context);
  const receiver=unpack(c.request.metadata[URI].identity,'receiver');
  c.context.addActivatedExtension(URI);
  const announcement=signed(P,'producer',receiver.requestId);
  const decorated=Object.create(bus);
  decorated.publish=event=>{
    if(event.kind==='task') {
      event.data.metadata={...event.data.metadata,[URI]:{identity:announcement}};
      for(const a of event.data.artifacts) {
        a.metadata={...a.metadata,[URI]:{artifactRef:{producer:P.id,id:randomUUID()},artifactSalt:randomBytes(32).toString('base64url')}};
        a.extensions=[...(a.extensions??[]),URI];
        capturedProducer.set(a,{snapshot:structuredClone(a),receiver:receiver.agentId});
      }
    }
    bus.publish(event);
  };
  await priorExecute(c,decorated);
};
const transport=await new JsonRpcTransportFactory({fetchImpl:async(url,init)=>{
  const ctx=new ServerCallContext({requestedVersion:init.headers['A2A-Version'],
    requestedExtensions:Extensions.parseServiceParameter(init.headers['A2A-Extensions'])});
  responseContexts.push(ctx);
  const response=await rpc.handle(JSON.parse(init.body),ctx);
  return new Response(JSON.stringify(response),{headers:{'Content-Type':'application/json',
    ...(ctx.activatedExtensions?{'A2A-Extensions':ctx.activatedExtensions.join(',')}: {})}});
}}).create(card.supportedInterfaces[0].url,card);
const config={interceptors:[]};
const client=new Client(transport,card,config);
const CALL=Symbol('per-call');
config.interceptors.push({
  async before(a) {
    a.options.context={...(a.options.context??{})};
    a.options.serviceParameters={...a.options.serviceParameters,'A2A-Extensions':URI};
    if(a.input.method==='sendMessage') {
      const rid=randomUUID(); a.options.context[CALL]=rid;
      a.input.value.metadata={...a.input.value.metadata,[URI]:{identity:signed(R,'receiver',rid)}};
    } else if(a.input.method==='getTask') a.options.context[CALL]=taskCorrelations.get(a.input.value.id);
  },
  async after(a) {
    const t=a.result.value;
    const p=unpack(t.metadata[URI].identity,'producer');
    assert.equal(p.requestId,a.options.context[CALL]);
    taskCorrelations.set(t.id,p.requestId);
    for(const artifact of t.artifacts) {
      assert.equal(artifact.metadata[URI].artifactRef.producer,p.agentId);
      capturedReceiver.set(artifact,structuredClone(artifact));
    }
  }
});
const [a,b]=await Promise.all([client.sendMessage(request()),client.sendMessage(request())]);
assert(capturedReceiver.has(a.artifacts[0])); assert(capturedReceiver.has(b.artifacts[0]));
assert.notEqual(a.artifacts[0].metadata[URI].artifactRef.id,b.artifacts[0].metadata[URI].artifactRef.id);
const reread=await client.getTask({id:a.id,tenant:''});
assert.notEqual(reread.artifacts[0],a.artifacts[0]);
assert.deepEqual(reread.artifacts[0].metadata,a.artifacts[0].metadata);
assert.deepEqual(reread.artifacts[0].parts,a.artifacts[0].parts);
console.log('PASS: synchronous executor decoration + mutable client interceptor array; original artifact capture; signed per-call correlation under concurrent sends; JSON-RPC round trip + getTask preserve extension and business metadata on fresh objects');
console.log('Observation: task absent from store immediately after publish:',storeEmptyImmediatelyAfterPublish);
assert(storeEmptyImmediatelyAfterPublish);

await client.sendMessage({...request(),tenant:'tenant-a'});
assert(executorContexts.at(-1).activatedExtensions.includes(URI));
assert.equal(responseContexts.at(-1).activatedExtensions,undefined);
console.log('PASS: tenant clone reproduction: executor activation exists, outer HTTP response context loses it');

assert.equal(Part.fromJSON({data:null}).content,undefined);
assert.equal(Part.fromJSON({text:''}).content.value,'');
assert.equal(Part.fromJSON({data:{nested:null}}).content.value.nested,null);
console.log('PASS: data:null decoder loses oneof; empty text and nested data null preserved');

let unblock; const gate=new Promise(r=>unblock=r); let published; const pub=new Promise(r=>published=r);
const blockExecutor={async execute(c,bus){
  bus.publish(AgentEvent.task(Task.fromJSON({id:c.taskId,contextId:c.contextId,
    status:{state:'TASK_STATE_COMPLETED'},artifacts:[Artifact.toJSON(makeArtifact('block'))]})));
  published(); await gate; // models awaiting rank/service inside execute
},async cancelTask(){}};
const blockHandler=new DefaultRequestHandler(card,new InMemoryTaskStore(),blockExecutor);
let delivered=false;
const pending=blockHandler.sendMessage(request(),context()).then(t=>{delivered=true;return t;});
await pub; await new Promise(r=>setTimeout(r,15));
assert.equal(delivered,false); unblock(); await pending;
console.log('PASS: awaiting service inside executor after terminal Task publish still delays blocking A2A response');

const priv=P.privateKey.export({format:'jwk'}); const derived=createPublicKey(createPrivateKey({format:'jwk',key:priv}));
assert.equal(derived.export({format:'jwk'}).x,priv.x);
const weak=Buffer.alloc(32); weak[0]=1;
const sig=Buffer.alloc(64);sig[0]=1;
const acceptsWeak=verify(null,Buffer.from('different arbitrary statement'),
  createPublicKey({format:'jwk',key:{kty:'OKP',crv:'Ed25519',x:b64(weak)}}),sig);
console.log('Observation: Node crypto.verify accepts identity-point forgery:',acceptsWeak);
const units=4503599627370497;
assert(Number.isSafeInteger(units));
assert.equal(JSON.stringify(units/1e6),'4503599627.370497');
const highUnits=9007199254740991;
console.log('Observation: max safe sumUnits / 1e6:',JSON.stringify(highUnits/1e6),'expected exact decimal 9007199254.740991');

```


## Appendix C — SDK lifecycle and scope probes

```javascript
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Artifact, Task, SendMessageRequest} from '@a2a-js/sdk';
import {AgentEvent, DefaultRequestHandler, InMemoryTaskStore, ServerCallContext,
  DefaultExecutionEventBusManager} from '@a2a-js/sdk/server';
const card={name:'local',description:'probe',version:'1',capabilities:{},supportedInterfaces:[],skills:[],defaultInputModes:[],defaultOutputModes:[]};
const context=(tenant='')=>new ServerCallContext({requestedVersion:'1.0',tenant});
const request=(taskId,nonblocking=false)=>SendMessageRequest.fromJSON({
  message:{messageId:randomUUID(),...(taskId?{taskId}:{}),role:'ROLE_USER',parts:[{text:'hi'}]},
  configuration:{returnImmediately:nonblocking}});
const artifact=id=>Artifact.fromJSON({artifactId:id,parts:[{text:id}],metadata:{business:'retained'}});
const task=(c,state,artifacts=[])=>Task.fromJSON({id:c.taskId,contextId:c.contextId,status:{state},artifacts:artifacts.map(Artifact.toJSON)});

let terminalTaskEvents=0; const seenOriginal=new WeakSet();
const executor={async execute(c,bus){
  const original=artifact('whole-no-chunks'); seenOriginal.add(original);
  bus.publish(AgentEvent.task(task(c,'TASK_STATE_WORKING')));
  bus.publish(AgentEvent.artifactUpdate({taskId:c.taskId,contextId:c.contextId,artifact:original,append:false,lastChunk:true}));
  bus.publish(AgentEvent.statusUpdate({taskId:c.taskId,contextId:c.contextId,status:{state:3}}));
},async cancelTask(){}};
const baseExecute=executor.execute.bind(executor);
executor.execute=async(c,bus)=>{
  const wrapped=Object.create(bus); wrapped.publish=e=>{
    if(e.kind==='task' && [3,4,5,7].includes(e.data.status.state))terminalTaskEvents++;
    bus.publish(e);
  }; await baseExecute(c,wrapped);
};
const handler=new DefaultRequestHandler(card,new InMemoryTaskStore(),executor);
const result=await handler.sendMessage(request(),context());
assert.equal(result.status.state,3); assert.equal(result.artifacts.length,1);
assert.equal(terminalTaskEvents,0); assert(!seenOriginal.has(result.artifacts[0]));
console.log('PASS: one complete (non-fragmented) artifact event + terminal status yields terminal response but no terminal Task publish event; result artifact is a clone');

let advance; const gate=new Promise(r=>advance=r); let done;const finished=new Promise(r=>done=r);
const pollingStore=new InMemoryTaskStore();
const pollingExecutor={async execute(c,bus){
  bus.publish(AgentEvent.task(task(c,'TASK_STATE_WORKING')));
  await gate;
  bus.publish(AgentEvent.task(task(c,'TASK_STATE_COMPLETED',[artifact('later')])));
  done();
},async cancelTask(){}};
const pollingHandler=new DefaultRequestHandler(card,pollingStore,pollingExecutor);
const early=await pollingHandler.sendMessage(request(undefined,true),context());
assert.equal(early.status.state,2);assert.equal(early.artifacts.length,0);
advance();await finished;await new Promise(r=>setTimeout(r,10));
const later=await pollingHandler.getTask({id:early.id,tenant:''},context());
assert.equal(early.artifacts.length,0);assert.equal(later.artifacts.length,1);
console.log('PASS: returnImmediately returns working snapshot; original result stays empty; getTask retrieves complete terminal artifact');

const resumedStore=new InMemoryTaskStore();let call=0;
const resumedExecutor={async execute(c,bus){
  call++;
  const out=task(c,call===1?'TASK_STATE_INPUT_REQUIRED':'TASK_STATE_COMPLETED',[artifact(call===1?'a':'b')]);
  out.metadata={identity:{requestId:'request-'+call}};
  bus.publish(AgentEvent.task(out));
  bus.publish(AgentEvent.statusUpdate({taskId:c.taskId,contextId:c.contextId,status:out.status}));
},async cancelTask(){}};
const resumedHandler=new DefaultRequestHandler(card,resumedStore,resumedExecutor);
const first=await resumedHandler.sendMessage(request(),context());
const last=await resumedHandler.sendMessage(request(first.id),context());
assert.deepEqual(last.artifacts.map(a=>a.artifactId),['a','b']);
assert.equal(last.metadata.identity.requestId,'request-2');
console.log('PASS: continuation final result merges old and new artifacts under newest Task metadata identity; per-artifact provenance is not recovered from one task-level requestId');

// The store scopes identical task IDs, but event-bus manager keys only taskId.
const scopedStore=new InMemoryTaskStore();
const sharedId='existing-same-id';
for(const tenant of ['A','B']) await scopedStore.save(Task.fromJSON({id:sharedId,contextId:'ctx',status:{state:'TASK_STATE_WORKING'}}),context(tenant));
let count=0,release;const barrier=new Promise(r=>release=r);
const scopedExecutor={async execute(c,bus){
  if(++count===2)release(); await barrier;
  bus.publish(AgentEvent.task(task(c,'TASK_STATE_COMPLETED',[artifact('from-'+c.context.tenant)])));
},async cancelTask(){}};
const manager=new DefaultExecutionEventBusManager();
const scopedHandler=new DefaultRequestHandler(card,scopedStore,scopedExecutor,manager);
const scopedResults=await Promise.all(['A','B'].map(t=>scopedHandler.sendMessage(request(sharedId),context(t))));
assert(scopedResults.every(t=>t.artifacts.length===2));
console.log('PASS: simultaneous same taskId in two scoped stores shares event bus:',scopedResults.map(t=>t.artifacts.map(a=>a.artifactId)));

```


## Appendix D — Independent journal-rule model

```javascript
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
// Independent arithmetic/pairing/hash reference model; no service or verifier.
const C=x=>JSON.stringify(x,function(k,v){return v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v;});
const H=(label,x)=>'sha256:'+createHash('sha256').update('aithos-ratings-v0/'+label+'\n'+C(x)).digest('hex');
const fixed={profile:'https://aithos.world/ext/interaction-ratings/v0',type:'rating',logId:'L',issuedAt:'2026-09-17T10:00:00.000Z'};
const F={producer:'P',id:'F'}, G={producer:'P',id:'G'};
const note=(rater,rated,ref=F,digest='d',units=770000)=>({...fixed,artifactRef:ref,
  observation:{artifactId:'a',artifactDigest:digest},rater,rated,ratedRole:rater==='P'?'receiver':'producer',score:units/1e6});
const rows=[],slots=new Map();
function admit(p){
  const slot=C([p.logId,p.artifactRef.producer,p.artifactRef.id,p.rater]);
  const id=H('rating',p), old=slots.get(slot);
  if(old){if(old.id===id)return {status:200,entry:old};return {status:409};}
  const record={rating:p}; // placeholders are NOT wire-valid signature envelopes
  const entry={position:rows.length+1,previousHash:rows.length?rows.at(-1).hash:H('genesis',{profile:fixed.profile,logId:'L'}),recordHash:H('record',record),ratingId:id,artifactRef:p.artifactRef};
  const row={id,p,entry,hash:H('entry',entry)};rows.push(row);slots.set(slot,row);return {status:201,entry:row};
}
function comparison(p,through=rows.length){
  if(p.rated===null)return 'unilateral';
  const q=rows.slice(0,through).map(r=>r.p).find(q=>C(q.artifactRef)===C(p.artifactRef)&&q.rater===p.rated&&q.rated===p.rater&&q.ratedRole!==p.ratedRole);
  if(!q)return 'unilateral';
  return C(q.observation)===C(p.observation)?'matching':'divergent';
}
function summary(id,role,through=rows.length){
  const scores=rows.slice(0,through).filter(r=>r.p.rated===id&&r.p.ratedRole===role).map(r=>BigInt(Math.round(r.p.score*1e6)));
  const count=BigInt(scores.length),sum=scores.reduce((a,b)=>a+b,0n);
  const mean=count?(2n*sum+count)/(2n*count):null;
  return {count:Number(count),sumUnits:Number(sum),averageUnits:mean===null?null:Number(mean)};
}
const r=note('R','P'),p=note('P','R',F,'different',250000),u=note('P',null,G,'g',100000);
assert.equal(admit(r).status,201);const anchor=rows[0].hash;
assert.equal(comparison(r),'unilateral');assert.equal(admit(p).status,201);
assert.equal(comparison(r),'divergent');assert.equal(comparison(r,1),'unilateral');
assert.deepEqual(summary('P','producer'),{count:1,sumUnits:770000,averageUnits:770000});
assert.deepEqual(summary('R','receiver'),{count:1,sumUnits:250000,averageUnits:250000});
assert.equal(admit(r).status,200);assert.equal(admit({...r,issuedAt:'2026-09-17T10:00:01.000Z'}).status,409);
assert.equal(admit(u).status,201);assert.equal(admit(note('S','P',G,'g',200000)).status,201);
assert.equal(comparison(u),'unilateral');assert.equal(comparison(rows.at(-1).p),'unilateral');
assert.deepEqual(summary('S','receiver'),{count:0,sumUnits:0,averageUnits:null});
assert.equal(admit({...u,rated:'S'}).status,409);
assert.deepEqual(summary('P','producer'),{count:2,sumUnits:970000,averageUnits:485000});
assert.deepEqual(summary('P','producer',1),{count:1,sumUnits:770000,averageUnits:770000});
assert.equal(rows[1].entry.previousHash,anchor);
assert.notEqual(H('entry',{...rows[0].entry,ratingId:'different'}),anchor);
assert.equal(rows.length,4);
console.log('PASS: independent rule model: immutable author slots, reciprocal divergence without suppression, fixed-prefix comparisons, permanent null exclusion, role-specific integer means, prefix hash change on alteration');

```
