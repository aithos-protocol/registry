# Interaction ratings V0 — planned conformance vectors

This is a checklist for [`RANKS.md`](../../RANKS.md), not executable fixtures.
Each eventual vector must include inputs, expected outputs and its governing
section. Use fixed test keys, salts and times; never production credentials.

| Area | Required cases |
| --- | --- |
| Identity and encoding (§2) | Valid Ed25519/JWK/JWS; canonical byte output; duplicate JSON members; invalid Unicode/base64url; altered header; wrong thumbprint; unsupported algorithm; weak key; private material; unknown fields; unsafe integers. |
| Agreement (§3) | Valid request and acceptance; changed terms or salt; acceptance by the wrong provider; replaced requester; wrong request digest; reused exchange for different terms; same task attached to a different production. |
| Observations (§4) | Final artifact without any prior artifact signature; each author signs its own observation; explicit post-acceptance failure for each allowed terminal state; requester failure needs no provider result signature; failure without agreement, partial result, missing designated artifact and timeout rejected; missing peer rating does not block submission. |
| Artifact commitment (§4.5) | Canonical snapshot with all parts, artifact metadata and part metadata; absent versus explicit defaults; structured data and null values; raw bytes; URL covers reference only; both callers use the agreed private salt and compute matching digests for matching content; different salt does not prove different artifact content; mutate content or business metadata; strip metadata; preserve unrelated extension data; exclude only reserved protocol bookkeeping; invalid types/unknown fields rejected; SDK round-trip matches the digest. |
| A2A transport (§4.4) | Preserve agreement envelopes through metadata and streaming; no invented `TaskStatus.metadata`; mismatched enclosing task or local final-artifact context rejected; final snapshot recoverable; lookup never overwrites an already captured local observation with a different peer version. |
| Context resolution (§9.2) | Extract agreement and local context automatically from the artifact or associated task; retrieve missing context through the configured A2A client; colliding artifact IDs in different tasks/providers are not confused; missing/mismatched agreement or salt refused; no fabricated peer agreement signature; peer observation mismatch is not local ineligibility. |
| Rating (§5) | Both directions independently; correct rated role; self-rating and third-party rater rejected; accept 0, 0.1, 0.77, 0.123456 and 1; reject missing/string/non-finite values, negative scores, values above 1 and excess precision; exact decimal-to-unit conversion; modifying score, identities, observation, artifact digest, agreement, log or timestamp invalidates the signature; counterpart score never supplies the local score. |
| Submission (§6) | Three-envelope bundle; both ratings accepted even with different artifacts, metadata digests or outcomes; exact retry returns original receipt; same payload with another valid envelope returns stored bundle; a changed observation or score from the same author returns `RATING_EXISTS`; incompatible agreements return `EXCHANGE_CONFLICT`; alternate service rejected; post-commit response loss recoverable. |
| Atomicity (§6) | Two concurrent identical submissions produce one entry; concurrent different observations/scores for one author slot admit one; concurrent opposite directions admit two consecutive entries even when divergent; failed transaction admits no partial binding, entry or acknowledgment. |
| Comparison (§6.1) | One rating is unilateral, not matching; second matching/different observation changes the derived status only; different scores/timestamps/signatures still allow matching; differing artifact ID, digest, kind or terminal state yields divergent and deterministic `differingFields`; matching failures require the same terminal state; both original receipts and scores survive divergence; invalid signatures rejected rather than labeled as disagreement; no fraud label or automatic penalty. |
| Journal (§7) | Genesis and first entry; consecutive positions; hash every entry field; mutate a bundle/signature/key; altered, omitted or reordered entries; empty head; receipt hash/position/log mismatch; validate extension from a retained anchor. |
| Limits of proof (§7.4) | A fork can be internally consistent yet incompatible with a retained anchor; compare conflicting signed views; missing historical data cannot reconstruct a note; valid participant signatures remain valid despite a bad log view. |
| Read API and means (§8) | Stable bounded pagination and comparison at fixed `through`; comparison before named rating exists returns 404; counterpart rating ID resolves to its receipt; absent rating distinct from score 0; both role means; failure, unilateral and divergent scores included equally; decimal sums and six-place half-up rounding; integer-unit overflow; no history; recompute all views from full prefix; checkpoint alone does not authenticate summary/comparison completeness. |
| Service/SDK (§9) | Body/payload limits; safe errors; no remote key/content fetch; `rank(privateKey, artifact, score)` resolves context, computes its own artifact/metadata digest and signs observation plus supplied score; missing context/key/score rejected; adapter failure context accepted without synthetic artifact or prior provider failure signature; private contents/salts never submitted; full confirmation returned and checked; no peer acknowledgment required; ratings outage does not block delivery. |

## Independent rating scenarios

These are expected behaviors for future fixtures, not executed service tests.
Use one signed production agreement, requester `R`, provider `P`, and a
shared private salt. Each scenario starts with an empty journal unless stated
otherwise. Run every two-author scenario in both submission orders.

| Scenario | Expected result |
| --- | --- |
| Only `R` submits its own signed observation and a score of `0.77` for `P`; there is no provider result signature or provider rating. | `201`; one entry and confirmation, `unilateral`; `P.asProvider` has count 1 and average `0.77` immediately. No waiting state or peer acknowledgment. |
| `R` submits `0.77` for `P`; `P` separately submits `0.25` for `R`; both compute the same artifact observation from their own copies. | Two `201` responses and distinct confirmations; `matching` despite different scores. `P.asProvider` averages `0.77`; `R.asRequester` averages `0.25`. Neither author signs the other's score. |
| Same submissions, but a business metadata value differs between their copies, producing different digests. | Both accepted; one pair with `divergent`, not two unilateral pairs or `EXCHANGE_CONFLICT`. Both original confirmations remain valid and both role aggregates retain their scores. |
| Same submissions, but the artifact IDs differ, or one author declares a final artifact and the other an explicit failure. | Both accepted and paired by the agreed production; `divergent`. No result digest, artifact ID or outcome may be used to hide the disagreement by splitting the pair. |
| `R` already has an accepted rating; `P` never submits, submits much later, or sends a rating with an invalid signature. | `R`'s confirmation and contribution to the mean remain unchanged. No submission keeps the state unilateral; a later valid one creates a second entry and updates only the derived comparison; an invalid signature returns `422 INVALID_SIGNATURE` and adds no entry. |
| An admitted author's score or observation changes on resubmission. | Changing signed bytes without a valid new signature returns `422 INVALID_SIGNATURE`; a valid newly signed replacement returns `409 RATING_EXISTS`. Neither edits the original rating. |
| A valid rating is attached to a different agreement or carries a mismatched `exchangeId`, rater, rated identity or role. | Invalid internal bindings return `422 INVALID_EVIDENCE`; a separately valid but incompatible agreement reusing an existing task/exchange binding returns `409 EXCHANGE_CONFLICT`. These are not result divergences. |

The library fixtures must additionally show that the requester-generated salt
survives the exchange, both libraries compute their own digest, text/metadata
string whitespace changes the commitment, and neither `rank` call requests
a new peer signature. Mutating an already captured local snapshot is distinct
from receiving a version different from the provider's own snapshot: only the
former violates local context integrity.

No multi-language interoperability or implementation conformance is claimed
until these vectors exist and the corresponding checks have run.
