# Interaction ratings V0 — planned conformance vectors

This is a checklist for [`RANKS.md`](../../RANKS.md), not executable fixtures.
Each eventual vector must include inputs, expected outputs and its governing
section. Use fixed test keys, salts and times; never production credentials.

| Area | Required cases |
| --- | --- |
| Identity and encoding (§2) | Valid Ed25519/JWK/JWS; canonical byte output; duplicate JSON members; invalid Unicode/base64url; altered header; wrong thumbprint; unsupported algorithm; weak key; private material; unknown fields; unsafe integers. |
| Agreement (§3) | Valid request and acceptance; changed terms or salt; acceptance by the wrong provider; replaced requester; wrong request digest; reused exchange for different terms; same task attached to a different production. |
| Result (§4) | Final artifact; explicit post-acceptance failure for each allowed terminal state; failure without acceptance; wrong acceptance digest or signer; partial result; missing designated artifact; timeout and unsigned failure rejected; conflicting artifact/failure outcomes. |
| A2A transport (§4.4) | Preserve envelope strings through the chosen SDK's metadata round-trip; final task snapshot and streaming path; no invented `TaskStatus.metadata`; mismatched enclosing task/artifact/state rejected by adapter. |
| Rating (§5) | Both directions independently; correct rated role; self-rating and third-party rater rejected; scores 1 and 5; 0, 6 and fractional score rejected; modified score, identities, result, log or timestamp invalidates original signature. |
| Submission (§6) | Both notes for one result; exact retry returns original receipt; same payload with another valid envelope returns stored bundle; changed score conflicts; conflicting evidence conflicts; alternate service rejected; post-commit response loss recoverable. |
| Atomicity (§6) | Two concurrent identical submissions produce one entry; concurrent different scores for one slot admit one; concurrent opposite directions admit two consecutive entries; failed transaction admits no partial binding, entry or acknowledgment. |
| Journal (§7) | Genesis and first entry; consecutive positions; hash every entry field; mutate a bundle/signature/key; altered, omitted or reordered entries; empty head; receipt hash/position/log mismatch; validate extension from a retained anchor. |
| Limits of proof (§7.4) | A fork can be internally consistent yet incompatible with a retained anchor; compare conflicting signed views; missing historical data cannot reconstruct a note; valid participant signatures remain valid despite a bad log view. |
| Read API and means (§8) | Stable bounded pagination during appends; zero ratings; both role means; failure scores included; exact half-up rounding; agent with no history; recompute filtered history and means from the full prefix; tampered summary not authenticated by its checkpoint alone. |
| Service/SDK (§9) | Body and decoded payload limits; safe errors; no remote key/content fetch; return full confirmation package; reject mismatched acknowledgment; rating-service outage does not block business artifact delivery. |

No multi-language interoperability or implementation conformance is claimed
until these vectors exist and the corresponding checks have run.
