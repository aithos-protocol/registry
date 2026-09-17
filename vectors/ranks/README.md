# Interaction ratings V0 — planned conformance vectors

This is the checklist for [RANKS.md](../../RANKS.md) **0.0.5**, not executable
fixtures. Each eventual vector must state inputs, expected outputs and its
rule. Use fixed test keys, UUIDs, salts and times, never production credentials.
The independent audit of 0.0.4 does not establish conformance to this revision.

| Area | Required cases |
| --- | --- |
| Identity/encoding (§2) | Strict Ed25519/JWK/JWS, weak-key rejection, exact JCS, duplicate members, invalid Unicode/base64url, wrong `kid`, unknown fields, private-key leakage. Import an Ed25519 private JWK and reject inconsistent `x`/`d`; no silent replacement and no P-256 CLI-key reuse. |
| Automatic identity (§3.1) | Receiver announcement and correlated producer announcement; wrong signature/role/log/request correlation; concurrent requests do not share a last-peer cache; exact retry retains correlation; no assumption that transport user IDs, URLs or Agent Card names are ratings identities. |
| Missing identities (§3.2) | Business work continues without a usable receiver announcement; producer may sign `rated: null`. Receiver without producer context cannot call `rank`. No automatic access-denial feature or inferred identity. |
| Artifact reference (§3.3) | Fresh producer-namespaced UUID per complete instance; same native artifact ID in different tasks/tenants produces different refs; equal contents in distinct instances remain distinct; native/task IDs alone are not global identifiers. |
| Reference persistence (§3.3) | Retransmission, concurrent publication, serialization, task recovery and SDK reads preserve the original ref/salt; restart with persisted artifact preserves it; intentional new output gets a new reference; a note retry never creates a new artifact. |
| Capture/eligibility (§3.4) | No acceptance callback or production terms; capture at producer publication and receiver delivery; complete artifacts supported, fragments/absent artifacts/error objects rejected. Existing complete artifact may be rated despite unrelated task failure. Mutation after capture or untracked copied object rejected; peer-version differences are not local mutation. |
| Commitment (§4) | Every business metadata field and ordered part is covered; only reserved bookkeeping excluded; optional defaults, nested JSON null, empty text, raw bytes, URLs and string whitespace; unsafe/unrepresentable values rejected; salt stays private and identical across copies; each caller hashes its own snapshot. |
| SDK profile (§9.3) | Exact JS 1.1.0/JSON-RPC initialization on both supported surfaces; complete artifacts captured in terminal task snapshots; interrupted/working snapshots and fragmented assembly unsupported by this first adapter; no extra developer metadata/signing/accept calls; null-data codec loss handled before loss or rejected, never signed as an empty part; full business metadata captured; unsupported bindings/copies/streaming fail clearly. No untested cross-SDK equality claim. |
| Rating/roles (§5) | Receiver targets producer; producer targets receiver or null; signer equals author; self-rating/role contradiction rejected. 0, 0.1, 0.77, 0.123456, 1 accepted; missing/string/non-finite/out-of-range/excess-precision scores rejected. Changing any signed reference/digest/identity/role/score/log invalidates the signature. |
| Unknown target (§5.2) | Valid null-target producer note recorded but absent from every agent count/mean. A later receiver note does not attribute, edit, pair or replace it. Multiple receiver claimants trigger no first-claimant assignment. Grouping under an artifact reference is not participation proof. |
| Service boundary (§6) | One-envelope body; extra production/failure envelopes rejected; only the author's key/roles are verified, no certified peer participation claim. Invented references cannot be screened by content checks at a service that never receives content. |
| Uniqueness/retry (§6) | One author slot per log/ref; exact retry returns original receipt, including changed valid signature encoding of the same payload; new score/digest/timestamp/target, including null-to-known, returns `RATING_EXISTS`; peer's slot stays available. Lost commit/POST response recovers the original package. |
| Atomicity (§6) | Concurrent identical submissions append once; different same-slot payloads admit one; opposite authors both append even with divergent snapshots; no receipt exposed before durable commit; blob-first storage gates all reads on committed references. |
| Comparison (§6.1) | Exact reciprocal targets and common ref required. Different native IDs/digests yield divergent; scores/times excluded. Null target or non-reciprocal claims remain unilateral. Both receipts and both targeted scores survive divergence. Invalid signatures are rejection, not divergence. |
| Journal (§7) | Genesis, contiguous positions, bundle/entry/receipt hashes, reference consistency, altered/missing/reordered entries, pinned log key, extension from retained anchors; a fork can be internally valid yet inconsistent with another retained view; receipt cannot recover missing data. |
| Views (§8) | Stable pagination/summary/comparison at fixed prefix; artifact listing includes null-target notes; agent listing excludes them; unknown IDs return empty views; exact decimal sums and half-up means; overflow rejected; no data is not zero. Recompute views from the full prefix; checkpoint alone does not prove their correctness/completeness. |
| Integration/errors (§9) | Private key supplied only at init; rank takes artifact/score; complete verified package returned; service errors versus local ineligibility versus unknown acceptance distinguished. Signing/submission failure does not gate business delivery. No mandatory archive, notification, retroactive target assignment or durable rating retry queue. |

## Concrete scenarios

Use producer `P`, receiver `R`, one complete artifact reference `F`, private
salt `S`, and independently captured snapshots. Run reciprocal cases in both
submission orders. These are future expected outcomes, not executed tests.

| Scenario | Expected result |
| --- | --- |
| Only R rates P at 0.77. | `201`, one receipt, unilateral; P.asProducer count 1, average 0.77 immediately. No provider artifact signature or rating prerequisite. |
| P separately rates R at 0.25; local observations match. | Two receipts, matching; R.asReceiver average 0.25; neither signs the other's score. |
| P and R use F but their native artifact ID or business metadata differs. | Both notes accepted, divergent; both targeted scores count; original confirmations unchanged. |
| P cannot identify R and records a 0.25 artifact note with `rated: null`. | `201`, visible under F; no agent's score is affected. |
| R later rates P using the same F after that null-target note. | R's note affects P.asProducer; P's original note stays null/unilateral and never affects R.asReceiver. No retroactive linkage. |
| P tries to change the prior null target into R, or to change its score. | Valid newly signed replacement receives `409 RATING_EXISTS`; original note remains. |
| R and another key both claim to have received F. | Separate author declarations do not establish actual participation; no reassignment of P's signed target. Pair only with an explicitly reciprocal target. |
| Same P/native `artifactId` in a different task, with a different reference. | Separate artifacts/author slots; no collision caused by native ID reuse. |
| A receipt response is lost and the exact signed note is resent. | `200`, original package, no duplicate position or aggregate contribution. |
| No artifact was produced, regardless of discussion, acceptance or task state. | `rank` rejects locally; no failure-rating payload exists. |

All current fixture claims remain pending implementation. No service, runtime,
cryptographic or SDK conformance is established by this checklist alone.
