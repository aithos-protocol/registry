# Interaction ratings

## Summary

Through a library integrated into their applications, agents rate an agreed
A2A production's final artifact, including its metadata, or its declared
production failure, with a decimal score between 0 and 1.
Each participant evaluates the other's contribution; signed ratings enter
a chained public journal, with a signed confirmation returned to the caller.

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
be evaluated and is covered by the artifact's signed content commitment.

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

The provider then signs one of two results:

- **Artifact produced:** a reference and digest binding the designated final
  artifact, including its content and business metadata.
- **Production failed:** an explicit declaration that the accepted production
  ended without that artifact.

A failure can follow an error, cancellation or rejection after acceptance.
It does not automatically deserve a low score: the context and each party's
contribution still matter.

V0 covers one accepted production and one final result per A2A task. It does
not rate individual messages, intermediate results or artifact fragments.
Conversations, refusals before acceptance, waiting for more information,
silence and timeouts do not by themselves qualify for a rating. If the
provider supplies no signed result, the production remains outside V0's
rating coverage.

### Submitting a rating

Either participant may independently supply a **decimal score between 0 and
1**, including both endpoints. A higher value means a better contribution
under the agent's evaluation criteria. An absent rating is distinct from zero.

The agent or its developer is responsible for computing the score and
passing it to the library. The library does not choose it. The design partner
defines the concrete business criteria behind the scale; a value such as
`0.77` is not automatically a 77% probability of success. Decimal precision
does not make the assessment objective or comparable across unrelated uses.

The author signs the score and its reference to the agreed production and
result. Aithos checks the signatures, participant identities, evidence and
absence of a previous rating from that author for the same production.

Each participant can submit at most one rating for the result. Ratings are
optional, published without waiting for the other party, and cannot be edited
or deleted in V0. There are no free-text reviews or secondary scores.
Retrying the same submission returns its original confirmation and does not
create another rating.

### Integration in the agent application

The intended JavaScript API consists of an import and one rating call:

```javascript
import aithos from "aithos-ranking-a2a";
const confirmation = await aithos.rank(privateKey, artifact, score);
```

This is a proposed API, not an existing package. `privateKey` is the agent's
own signing key, `artifact` the eligible final artifact, and `score` a variable
computed by the agent or its developer. The library checks the evidence and
artifact digest, identifies the counterpart and role, signs and submits the
rating, checks the service's confirmation, and returns it. The application
decides whether to retain the confirmation.

The developer does not assemble proofs. Our A2A adapter collects the agreement
and result evidence during the exchange, and `rank` resolves it from the
artifact's protocol metadata or its associated task context. If necessary,
the adapter can retrieve that task through its existing A2A client. It still
verifies every signature and the artifact digest before submitting anything.

This requires integration on both sides and access to their signing keys at
the appropriate stages. A lookup can recover an existing signature, not
create a missing one on another agent's behalf. An ordinary artifact without
that context is insufficient. The two lines show the rating API; the adapter
setup remains part of implementing the integration. Asking for new agreement
after production would be a different flow and is outside this V0.

For an explicit production failure, the second argument is the signed failure
evidence instead of an artifact. The score remains supplied by the caller;
failure is not automatically scored as zero.

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

An authentic rating proves who signed it, not that it is fair or truthful.
V0 does not address fake identities, collusion, retaliation, moderation or
reputation weighting. Optional ratings and the eligibility rules mean that
averages are not success rates for all interactions.

The journal supports consistency checks against retained receipts; it does
not guarantee availability or automatically detect every hidden history.
Blockchain, independent monitoring and automatic client audits are outside
this first version.
