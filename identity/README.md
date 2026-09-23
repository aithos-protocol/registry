# Aithos client identity — experimental V0

An optional **server-side admission boundary**, backed by a private identity and
audit provider. It recognizes a caller's persisted signing key before business
logic runs and lets the merchant allow, restrict or refuse that caller.

This is a synthetic research pilot, not a released SDK or a general A2A gateway.
It does not change the public Agent Card registry or require a caller Agent Card.

## What runs where

- Client: generate and securely keep a P-256 private key; sign enrollment and each
  business request. The included `IdentityClient` automates this for Bun/Node-based
  tools. Aithos receives **only the public key**, creates a stable identity ID and
  returns that identity when the same key enrolls again.
- Partner: `Admission` verifies the request and obtains fresh evidence from the
  provider, before session creation, runtime execution or commerce. The existing
  agent runtime and merchant policy remain in place.
- Aithos: private identity records, revocation and tenant-scoped minimal audit;
  no prompts, responses, customer records, Shopware tokens or private keys.

Possession of the same key proves continuity of that key, not that the same LLM,
person or organization is behind it. There is no numerical reputation score.
The provider returns versioned evidence: key possession, observed/insufficient
history and interaction count. A deterministic merchant callback may restrict
permissions or deny admission; it cannot exceed the configured permission ceiling.

## Reproduce locally

Requirements: Bun **1.3.14**, Node.js, Git. No AWS, LLM key, real Shopware, order or
payment is needed for local tests. Run from this directory:

```sh
bun install --frozen-lockfile --ignore-scripts
bun run typecheck
bun run test
bun run prepare:harness
bun run typecheck:integration
bun run test:integration
bun run test:partner
bun run demo
```

`prepare:harness` checks out the pinned upstream version and applies the proposal
in the ignored `.fixtures/harness` directory. It refuses to overwrite a different
checkout. The [partner proposal](partner/README.md) is MIT-licensed; the Aithos
package is Apache-2.0. Dependencies are pinned by `bun.lock`.

The terminal demo starts two HTTP listeners bound **only to 127.0.0.1**, discovers
the Agent Card, receives a 401 before runtime, enrolls, completes a real harness
A2A request, rejects replay, reloads the same client key and resumes its session.
Repeat it to verify continuity across process restarts. Demo keys and SQLite
files persist only in ignored `.local/demo`, with owner-only permissions.

## Partner wiring

The partner patch adds generic hooks, with no mandatory Aithos dependency. Supply
the **same** admission instance to the app and HTTP handler:

```ts
const provider = new HttpProvider(providerOrigin, partnerToken);
const journal = new SqliteJournal('/persistent/merchant/aithos-outbox.sqlite');
const admission = new Admission({
  merchantId: 'shop',
  origin: 'https://seller.example',
  enrollmentUrl: `${providerOrigin}/v0/enroll`,
  provider, journal,
  mode: 'challenge',
  // Optional deterministic rules; use evidence, not an invented trust score.
  evaluate: evidence => evidence.history === 'insufficient'
    ? ['searchProducts', 'getProductDetails']
    : ['searchProducts', 'getProductDetails', 'createCart'],
});
const app = createSalesAgentHarnessApp({ ...existingAppInput, callerAccess: admission });
const handler = createSalesAgentHttpHandler({ app, agentConfig, admission });
```

Imports come from `@aithos/client-identity`, `@aithos/client-identity/sqlite` and
the partner's public API. This package is private/unpublished; use a local path
dependency for evaluation. The SQLite implementation requires **Bun**; the core
HTTP/crypto code and provider Lambda use standard Node APIs.

The partner must also:

1. Use a durable session store; the proposal persists `callerIdentityId` atomically
   with the session. Existing ownerless sessions are refused, never adopted.
   Back up the session database before its additive SQLite migration.
2. Mount admission before every protected entry point. Supply the externally
   visible HTTPS origin. Do not strip paths, normalize signed bytes or let an
   untrusted `Forwarded` header determine the signature target.
3. Keep the partner credential in server secrets and allow outbound HTTPS to the
   provider. Use a distinct credential per tenant; never expose it to the buyer.
4. Run a supervised periodic `admission.flush()` worker and a shutdown drain.
   Each call delivers at most 100 events, with stable IDs and acknowledgements;
   repeat while it returns 100. Log only a fixed delivery-failure event, never
   the credential/body. The demos flush explicitly rather than starting a daemon.
5. Keep one admission/journal process per protected origin in this pilot. Monitor
   provider failures, journal capacity and undelivered events.

## Request flow and API

Public discovery remains readable. An unsigned protected request in `challenge`
mode gets `401`, `WWW-Authenticate: AgentSignature` and machine-readable enrollment
instructions. There is no redirect that could leak a request body or credential.
The client signs and retries; Aithos never runs a client-side agent loop.

For A2A requests the Agent Card advertises required signature support plus the
enrollment endpoint. The client includes `A2A-Extensions` **before signing**.
Missing activation on an otherwise signed request returns JSON-RPC `-32008` or
HTTP+JSON problem `400`. Authentication failures stay HTTP 401. The partner's
existing synchronous binding is preserved, including its `A2A-Version: 1.0.0`
value. This is **not** a claim of complete A2A 1.0 conformance or SDK interoperability.

Provider endpoints, all JSON:

| Endpoint | Authentication | Body / result |
| --- | --- | --- |
| `GET /health` | Public | Health only |
| `POST /v0/enroll` | Request signature | `{publicKey: {kty,crv,x,y}}` → stable identity |
| `POST /v0/resolve` | Partner bearer | `{thumbprint}` → identity/evidence or null |
| `POST /v0/provisional` | Partner bearer | `{}` → tenant-scoped provisional ID |
| `POST /v0/events` | Partner bearer | `{events: [...]}` → accepted count |
| `POST /v0/history` | Partner bearer | `{identityId}` → own tenant's bounded history |
| `POST /v0/admin/revoke` | Separate admin bearer | `{identityId}` → revoked |

Runtime-validated field contracts are in [contracts.ts](src/contracts.ts). Unknown
fields are rejected. An event is an allowlisted operation/outcome/reason plus IDs,
timestamp and rule version, not a transcript. Partner-supplied observations are
not independent proof of good or bad behavior. Event ID collisions with a
different payload fail instead of silently changing history.

Signing uses P-256/SHA-256, RFC 7638 key thumbprints, RFC 9530 body digest and the
RFC 9421 wire format from `agent-request-auth/v2`. Resolution is deliberately a
**private identity resolver** (`aithos-client:<thumbprint>`), not public registry
Agent Card/domain verification. This admission profile additionally requires a
signed, unique `Aithos-Request-Id`. Proofs expire outside a ±60-second window;
replay claims persist across a journal restart. Retrying a business operation
with a fresh request ID is not business-level idempotency.

The client helper signs a fresh request; it refuses pre-existing signatures rather
than merging multiple schemes. Verification tests reuse the auth project's shared
vectors and an independent RFC vector. This is not full conformance certification.

## Two admission policies

- `challenge` (default): require valid proof; no session/runtime/business effect
  before identity and policy acceptance.
- `restricted`: absent proof gets a new provisional ID and catalog-only access.
  It can use a session created inside that request, but cannot resume it later.
  Invalid or revoked proof never falls back to anonymous access. Provisional
  identity is a recorded observation, not recognition of a returning caller.

Successful responses carry `Aithos-Identity-Id`, `Aithos-Identity-Kind` and an
enrollment link. The helper saves a key with permissions 0600; a challenge asks
other clients to persist theirs. No mechanism can force an arbitrary LLM to keep
its key, and compatibility with weak models has not been evaluated yet.

## Deliberate pilot limits

- Supported routes are explicit: public discovery/health; protected POST `/`,
  `/message:send`, `/sessions`, `/chat`, `/commerce/a2a`, `/commerce/customer`.
  Other routes fail closed. Checkout, handoff and payments are disabled. No SSE,
  gRPC, task polling, asynchronous `input-required` or WebSocket coverage yet.
- The journal is single-process. Multiple replicas require a shared atomic replay
  store and leased outbox recovery. Independent journals are **not** replay-safe
  across replicas. No multi-process production deployment is supported here.
- Audit uses durable intent before effects and at-least-once delivery with provider
  deduplication. A crash may leave outcome `unknown`; it never invents success.
  This is not a distributed transaction with Shopware or exactly-once commerce.
- Provider outages or a full journal fail closed. Delivery outages retain events
  locally until capacity; events older than seven days are rejected. A long outage
  needs operator reconciliation, not silent dropping or endless blind retries.
- In-memory limits and a small API Gateway throttle bound the experiment. They are
  **not** a distributed per-agent/IP anti-spam system or a hard cost ceiling.
- History returns up to 1,000 items (and DynamoDB's 1 MiB query bound), not a full
  paginated export. Aggregate interaction counts are not truncated to this page.
  Local SQLite is a development reference with no automatic retention cleanup.
- No probabilistic linkage, OAuth, delegated keys, rotation/migration, private-key
  custody, central A2A client or transcript product. A stolen key impersonates its
  identity until revocation. Key rotation with continuity needs a later design.

## Dev deployment

Terraform in [infra](infra) is pinned to AWS account `373665157800`, us-east-1, with
its own state key `client-identity/dev.tfstate`. It creates an HTTP API, small
Node 22 arm64 Lambda, isolated DynamoDB table, Secrets Manager secret and alarms.
The existing registry and production resources are untouched.

```sh
bun run build:lambda
zip -j dist/provider.zip dist/lambda.mjs
mkdir -p .local
terraform -chdir=infra init -backend-config=dev.backend.hcl
terraform -chdir=infra plan -out=../.local/dev.plan
# Inspect account and plan before applying the saved plan.
terraform -chdir=infra apply ../.local/dev.plan
bun run scripts/seed-dev.ts
bun run test:dev
```

Use a validated dev AWS environment; never shell-source the root credentials file.
`seed-dev.ts` creates separate random partner/admin credentials, writes an ignored
0600 local operator file and provisions Secrets Manager outside Terraform state.
It refuses to replace unknown existing secrets. `live-dev.ts` is pinned to the
pilot endpoint and revokes its synthetic test identity. No credentials are printed.

AWS audit/provisional rows have a seven-day TTL; API history filters logically
expired rows while physical deletion is asynchronous. Stable public-key identity
records and aggregate counts remain until a later lifecycle policy is defined.
DynamoDB uses encryption at rest and point-in-time recovery; backups may outlive
live-row TTL. There is no application-layer transcript encryption because no
transcripts are collected. CloudWatch logs retain 14 days and log fixed errors.
SNS email confirmation remains an operator task; alarms are not a substitute for
verified notification delivery.

See [verification and limits](TEST-REPORT.md) and [protocol sources](SOURCES.md).
