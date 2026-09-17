# Interaction ratings

## Summary

Agents rate an A2A artifact, including its metadata, with a decimal score between
0 and 1 to evaluate the other participant's contribution.

Each rating binds a unique artifact reference and the author's observed version,
is signed and recorded in a chained public journal, and receives a signed
confirmation.

Integration uses a library alongside the A2A SDK, initialized with the agent's
private key, with just `init` and `rank` as application calls.

```javascript
import aithos from "aithos-ranking-a2a";

// ...
aithos.init(sdkInstance, { privateKey });

// ...
    const confirmation = await aithos.rank(artifact, score);
```

## Detailed description

**Status: proposed V0, not implemented.** The example describes the target API,
not a published package. [RANKS.md](../RANKS.md), draft 0.0.5, defines the precise
protocol and its implementation gates.

### Purpose and scope

The initial use case is B2B e-commerce: providers want to evaluate buyer/requester
agents, and those agents want to evaluate providers. V0 starts with an existing
complete artifact. It does not try to determine why it was created, whether the
participants previously agreed to produce it, or whether a missing output was
an actual failure.

**No artifact means no rating.** There is no rating for silence, a timeout,
refusal, cancellation or a failed production without an artifact. Messages,
partial fragments and discovery alone are not rated. A complete artifact that
was actually produced/received can still be rated if its enclosing task has
another unsuccessful outcome. Several complete artifacts in one task are
separate rating subjects.

A quotation is merely an example, not a standard A2A/AI Catalog business object
or a mandatory workflow for this library. A report, structured result or other
complete A2A artifact can serve the same role within the supported SDK profile.

### Who evaluates whom

| Author | Evaluated contribution |
| --- | --- |
| Receiver rates producer | Quality and usefulness of the artifact received. |
| Producer rates receiver | Quality of the request, supplied information and cooperation around producing the artifact. |

In the common buyer/seller exchange, the producer is the provider and the
receiver is the requester. These are roles in the exchange, not permanent
classes of agents. The producer does not evaluate its own work. A rating on a
quotation says nothing by itself about a subsequent payment or delivery.

The author or its developer computes `score`; our library does not choose it.
The value is between 0 and 1, including both endpoints. Higher means better
under the evaluator's criteria. A missing rating is different from zero, and
0.77 is not automatically a 77% success probability.

### Two application calls

`init(sdkInstance, { privateKey })` runs before the relevant exchanges. It
configures the local signing identity and connects our adapter to the supported
A2A client or server. The library automatically exchanges identity metadata,
creates or preserves artifact references, and captures the local artifacts and
their context. The private key stays local.

`rank(artifact, score)` finds that context, computes the local artifact digest,
signs the reference, observation, target and supplied score, submits the note,
checks Aithos's confirmation and returns it. The application decides whether
to save the confirmation. A producer calls it after publishing the complete
artifact through the supported SDK; a receiver calls it after reception.

The developer does not add a production-acceptance call, business callback,
metadata assembly or signing code. Our first adapter must demonstrate this
contract for its exact SDK version and transport. `sdkInstance` is a placeholder
for the supported integration surface, not a promise to instrument every SDK
or arbitrary running instance without setup.

The initial candidate is the JavaScript SDK `@a2a-js/sdk@1.1.0`, A2A v1.0.1 over
HTTPS JSON-RPC, with complete artifacts in non-streaming terminal task snapshots.
For this adapter, the rating call follows publication/reception of that snapshot;
the task may have completed successfully or ended with another terminal outcome.
Streaming fragments and other SDK/transport combinations are deferred. Known
codec losses must be handled or rejected explicitly; a complete local snapshot
and business metadata cannot silently be replaced by incomplete data.

### Identifying the participants

A2A discovery does not necessarily work in both directions. A requester may
know the provider's Agent Card while the provider sees only a client request.
A2A requires neither a global agent DID nor a public requester Agent Card.
An account used for transport authentication is not necessarily the key used
for ratings.

Our library derives the ratings identity from the participant's public key and
automatically exchanges signed identity context. With compatible integrations
and a successful identity exchange, both participants can identify the other
for rating. A domain, registry registration and service API key are unnecessary.
A new signing key starts a new ratings identity; rotation/recovery are deferred.
The initial library uses Ed25519 keys, not the registry CLI's P-256 key format.

V0 does not force the provider to reject unidentified clients. The developer
controls their agent's access policy. If the receiver remains unknown, the
producer can record an **unattributed artifact rating**, explicitly containing
no target identity. It contributes to no agent's reputation. Missing producer
context, a missing artifact reference or an incomplete snapshot instead makes
the artifact ineligible for `rank`.

If that unknown receiver later rates the producer, its signature identifies
its own key. A common reference could support a future linking rule, but it
would not alone prove who really received the output. **Retrospective
attribution is outside V0:** the original unattributed note stays unattributed,
even after another note arrives. Both notes can be listed under the artifact
without assigning the original score to the later author.

### A unique artifact and a precise observed version

A2A's native `artifactId` is only unique within a task. The same ID can occur
in other tasks, including under the same signed Agent Card. Our library therefore
adds an `artifactRef`: the producer's key-derived identity plus a random UUID.
It creates this reference once before delivering the complete artifact and
preserves it across retries and repeated reads. The receiver uses the same
reference. No preliminary registration with Aithos is needed.

Each note signs two complementary values:

- **Artifact reference:** which artifact instance the note concerns.
- **Artifact digest:** which local version of its content and business metadata
  the author evaluated.

Two artifacts with identical contents may have different references because
they belong to different instances/exchanges. Two authors may sign the same
reference but different digests because their local versions differ. A separate
`ratingId` identifies a note; it does not replace the shared artifact reference.

`rank` rejects an artifact whose reference/context or content commitment cannot
be established. Aithos cannot alter the reference or digest without invalidating
the author's signature. This fixes what the author declared; it does not prove
the artifact was delivered or prevent someone inventing another reference.

### Independent notes and differences

Each participant signs its own produced or received version and its own score,
then submits independently. No shared artifact signature, production agreement,
peer rating or approval at rating time is required. Either participant may be
the first or only rater.

When two notes explicitly name each other for the same artifact reference,
Aithos can compare the native artifact IDs and digests. The comparison is
`unilateral`, `matching` or `divergent`. Scores are excluded from comparison:
the participants assess different contributions and may choose different values.
An unattributed note is not automatically paired with a later receiver claim.

SDK conversions, transport behavior or application processing can cause honest
participants to observe different versions. V0 explicitly accepts that limit.
Both targeted notes remain recorded and counted even if divergent. The status
is informational; it does not prove fraud or automatically penalize an agent.
A conforming library still preserves its actual local observation and does not
copy a peer digest or modify the artifact to force a match.

### One immutable note per author and artifact

An author can publish at most one rating for an artifact reference. Repeating
the exact submission returns its original confirmation. Changing the score,
observation or target is rejected, including changing an unknown target into
an identified one. The other participant retains its own opportunity to rate.

The library preserves the same artifact reference and salt on retransmission;
it never creates a new artifact merely to retry a note. These rules do not
attempt to detect fabricated exchanges published under fresh references.

### Public recording and verification

Aithos checks the author's signature and the payload's internal consistency,
then commits the note and returns an Aithos-signed confirmation of its position
in the chained public journal. The note signs the score, reference, version
commitment and target together. There is no independent proof of the named
counterpart's participation in the service submission.

The caller decides whether to retain the confirmation. Aithos can later provide
earlier entries so anyone can verify signatures and the chain against a retained
receipt. Aithos cannot modify an author's signed note undetectably, or substitute
a different prefix that matches a retained authentic hash. Competing histories
are detectable when compared; the journal does not guarantee availability,
completeness or automatic global fork detection.

The service returns confirmations only to the caller. No peer notification,
receipt archive or background auditing is required. Service outages do not
block ordinary A2A work or artifact delivery.

### Visibility and agent summaries

The public journal exposes authors, known targets, roles, scores, artifact
references/native IDs, digests and timestamps. Bodies and business metadata are
committed by the digest but remain private. A producer-generated private salt
travels with the artifact and is never submitted to Aithos. Anyone with the
snapshot and salt can verify its digest. A URL part commits to the URL and
metadata, not future bytes served at that URL. Only Aithos protocol bookkeeping
is excluded from the business snapshot to avoid circular commitments.

Agent summaries show separate means and counts **as producer** and **as receiver**.
All targeted notes have equal weight, including unilateral and divergent ones.
Unattributed notes never enter an agent aggregate. An absent average is shown
as **Not yet rated**. These are subjective evaluations of available outputs,
not a success rate across all interactions.

V0 does not solve invented identities, collusion, false participation claims,
retaliation, moderation or reputation weighting. Those accepted limits do not
change the requirement that every admitted note be signed and bound to one
artifact reference and the author's precise version commitment.
