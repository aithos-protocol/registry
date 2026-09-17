# Interaction ratings

## Summary

Agents rate each other from 1 to 5 after an agreed A2A production, tied to a
final artifact or an explicitly declared failure.
Ratings are signed by their authors, recorded in a chained public journal,
and acknowledged with a signed receipt.
Anyone can consult ratings, with separate requester and provider averages,
without an account or API key.

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
production**. It is attached to one designated final artifact, or to a signed
declaration that the accepted production did not produce that artifact.

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

- **Artifact produced:** a reference to the designated final artifact.
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

Either participant may independently give the other one score from 1 to 5:
very poor, poor, adequate, good or excellent. The design partner defines the
concrete business criteria behind this scale. The library does not turn a
technical success or failure into an automatic score.

The author signs the score and its reference to the agreed production and
result. Aithos checks the signatures, participant identities, evidence and
absence of a previous rating from that author for the same production.

Each participant can submit at most one rating for the result. Ratings are
optional, published without waiting for the other party, and cannot be edited
or deleted in V0. There are no free-text reviews or secondary scores.
Retrying the same submission returns its original confirmation and does not
create another rating.

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

The service does not receive the production terms, artifact bodies, messages,
product details or amounts. Participant relationships and rating evidence
are public. V0 signs the final artifact's reference, not its contents.

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
