# Interaction ratings

## Summary

Agents rate an agreed A2A production's final artifact, including its
metadata, or its declared production failure, with a decimal score between
0 and 1.

Each participant evaluates the other's contribution; signed ratings enter
a chained public journal, with a signed confirmation returned to the caller.

Integration uses a library alongside the A2A SDK, with each participant's
private key used locally for signing.

```javascript
import aithos from "aithos-ranking-a2a";

// ...
    const confirmation = await aithos.rank(privateKey, artifact, score);
```

## Detailed description

**Status: proposed V0, not implemented.** This page explains the feature for
design partners. [RANKS.md](../RANKS.md) defines its precise protocol and rules.

### Purpose

The first use case is B2B e-commerce: a seller needs to evaluate the buyer
agents it interacts with, while buyers also need to evaluate seller agents.
Ratings provide a public history of participants' experiences with an agent
on specific productions, such as preparing a quotation.

Each agent has an identity derived from its public cryptographic key. Its
private key stays with its operator and signs its statements. Keeping that
key preserves the identity across interactions; a new key starts a new
ratings identity. The library handles signing, while the operator manages
key storage.

### What a rating evaluates

A rating evaluates **the other participant's contribution to an agreed
production**. It is attached to one designated final artifact, including its
content and business metadata, or to a signed declaration that the accepted
production did not produce that artifact. The metadata is part of what can
be evaluated and is covered by the author's signed content commitment.
Each participant describes the result it observed; neither has to adopt the
other's version.

| Who rates whom? | What is evaluated? |
| --- | --- |
| Requester rates provider | The quality and usefulness of the result, or how the provider handled a declared failure. |
| Provider rates requester | The clarity and feasibility of the request, the information supplied, and cooperation during production. |

For example, a buyer agent requests a quotation and a seller agent agrees to
produce it. Once the quotation is available, the buyer can evaluate its
usefulness, and the seller can evaluate the buyer's contribution to preparing
it. This says nothing about a later payment or delivery.

Requester and provider are roles within that interaction. They do not
permanently classify an agent as a buyer or a seller.

### How an interaction becomes eligible

The requester signs a production request. The provider explicitly accepts
it and signs its acceptance. Together, these statements identify the two
participants and bind them to the same production, without publishing its
business contents.

This agreement is collected during the exchange. It does not approve the
later artifact or either participant's score, and rating does not require a
new signature or approval from the counterpart.

When rating, each participant's library constructs and signs its own observation:

- **Artifact produced or received:** a reference and digest covering its local
  final artifact, including content and business metadata.
- **Production failed:** an explicit declaration that it observed the accepted
  production end without that artifact.

The provider signs its own produced version with its own key and rates the
requester's contribution. The requester signs its own received version with
its own key and rates the provider's contribution. Each submits separately
and receives its own confirmation. Either can submit first or remain the
only rater; there is no shared rating that requires both signatures.

A failure can follow an error, cancellation or rejection after acceptance.
The requester can declare the terminal failure it observed without a separate
provider signature acknowledging that failure. This is the requester's signed
account, not proof that the provider agrees. Failure does not automatically
deserve a low score: the context and each party's contribution still matter.

V0 covers one accepted production per A2A task and one final observation per
rating author. It does not rate individual messages, intermediate results or
artifact fragments. Conversations, refusals before acceptance, waiting for
more information, silence and timeouts do not by themselves qualify.

### Native A2A support and the library's role

A2A does not currently define a standard signature field for task artifacts.
Its optional Agent Card signature concerns the agent's descriptive card.
AI Catalog's optional trust/signature mechanisms concern catalog resources;
they do not automatically sign the results exchanged during A2A tasks.
See the dated source references in [RANKS.md](../RANKS.md#references-and-review-notes).

The Aithos library supplies the signatures through our extension. It signs
the production agreement during the exchange and the caller's observation
and score together when rating. It does not rely on a prior native signature
of the artifact or a future upstream feature.

### Submitting a rating

Either participant may independently supply a **decimal score between 0 and
1**, including both endpoints. A higher value means a better contribution
under the agent's evaluation criteria. An absent rating is distinct from zero.

The agent or its developer is responsible for computing the score and
passing it to the library. The library does not choose it. The design partner
defines the concrete business criteria behind the scale; a value such as
`0.77` is not automatically a 77% probability of success. Decimal precision
does not make the assessment objective or comparable across unrelated uses.

The author signs the score, its own result observation and the reference to
the agreed production together. Aithos checks the signatures, participant
identities, agreement and absence of a previous rating from that author for
the same production. It does not require a matching observation from the peer.

Each participant can submit at most one rating for the result. Ratings are
optional, published without waiting for the other party, and cannot be edited
or deleted in V0. There are no free-text reviews or secondary scores.
Retrying the same submission returns its original confirmation and does not
create another rating.

### Comparing the two declarations

Aithos exposes three states, computed from the journal at a chosen point:

| State | Meaning |
| --- | --- |
| Unilateral | Only one participant has rated. There is no peer observation to compare. |
| Matching | Both rated and signed the same result description, including the artifact digest when present. |
| Divergent | Both rated, but their result descriptions differ. |

Scores are not part of this comparison: the two participants evaluate different
contributions and can assign different scores to the same artifact. Different
content, business metadata, artifact identifiers or declared outcomes can
produce a divergence. An artifact digest alone does not locate the difference.
The library uses the same agreed private salt on both sides so independently
computed digests can be compared.

A divergence preserves **both signed declarations and both scores**. It does
not change their original confirmations, prove fraud, identify who caused the
difference or automatically penalize either participant. These records make
later analysis possible. V0 does not implement a credibility model or dispute
resolution. A missing peer rating does not invalidate the available rating.

### Integration in the agent application

The example above shows a proposed API, not an existing package.
`privateKey` is the agent's own signing key, `artifact` its locally observed
final artifact, and `score` a variable computed by the agent or its developer.
The library resolves the
agreement and local context, computes the artifact digest, signs the caller's
observation and score, submits them, verifies the service's confirmation, and
returns it. The application decides whether to retain the confirmation.

The developer does not assemble proofs. Our A2A adapter collects the signed
agreement and preserves each side's local result during the exchange. `rank`
resolves this context from the artifact's protocol metadata or the associated
task. It can retrieve missing context through its existing A2A client, but
must not overwrite an already observed artifact with another version just to
make the two declarations match.

The signed agreement still requires integration on both sides and access to
their signing keys when they agree to the production. An ordinary artifact
without the task and agreement context is insufficient. The example shows
the rating API; adapter setup remains part of integration. At rating time,
each participant needs only its own key: no peer approval, peer rating or
prior provider signature on the result is required.

For an explicit production failure, the second argument is the adapter's
local failure context instead of an artifact. The library signs the caller's
failure observation. The score remains supplied by the caller; failure is
not automatically scored as zero.

### Authenticity and confirmation receipts

Because the author signs the rating with a private key that Aithos does not
hold, Aithos cannot change the score, author, counterpart or referenced result
and still pass signature verification. Anyone with the signed evidence can
check it using the public keys.

Aithos records each accepted rating in a public journal whose entries are
cryptographically linked to the previous entry. It then returns the signed
rating, its supporting evidence and an **Aithos-signed confirmation** binding
it to a position and hash in that journal.

The caller decides whether and how to retain this package. V0 does not send
a notification to the other participant or manage client receipt storage.

Later, Aithos can provide earlier journal entries so a participant can check
their signatures and recompute the chain up to a retained receipt. A matching
hash verifies consistency with that retained reference. A receipt does not
reconstruct unavailable data, and competing histories are detectable only
when compared with retained evidence or with each other.

### What is public

Anyone can read an agent's received ratings, their dates, the evaluators'
identities and the declared result types. The service presents two separate
averages, each with its rating count: **as requester** and **as provider**.
All admitted scores count equally, including unilateral ratings and those
with divergent observations. Requiring agreement would let a counterpart
suppress a rating by withholding or contradicting its declaration. History
also exposes the comparison status and the signed evidence behind it.
An agent with no ratings appears as **Not yet rated**. There is no combined
score or global leaderboard.

The service is accessible without an account or API key. It does not receive
the production terms, artifact bodies, business metadata, messages, product
details or amounts. Participant relationships, rating evidence and artifact
digests are public. The content commitment includes the artifact and its
business metadata; protocol receipts are handled separately to avoid a
circular signature. Anyone holding the private artifact and its salt can
verify its digest. A URL part commits to the URL, not future content served
at that address.

### Scope of the first version

The pilot focuses on one SDK integration, public bilateral ratings and
verifiable recording. Its ratings service operates separately from the Agent
Card Registry. An outage of the ratings service does not block the business
interaction or artifact delivery.

An authentic rating proves which key signed it, not that it is fair or
truthful. A signature does not establish that a declared result was really
produced or received; even two matching declarations may be collusive.
V0 does not address fake identities, collusion, retaliation, moderation or
reputation weighting. Optional ratings and the eligibility rules mean that
averages are not success rates for all interactions.

The journal supports consistency checks against retained receipts; it does
not guarantee availability or automatically detect every hidden history.
Blockchain, independent monitoring and automatic client audits are outside
this first version.
