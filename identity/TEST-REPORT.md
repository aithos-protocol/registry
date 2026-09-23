# Verification — 2026-09-23

Scope: synthetic identity/admission pilot, AWS **dev only**. No production feature
deployment, upstream partner PR, package publication, real LLM invocation or
Shopware transaction. Registry base: `3c90242129233a0b452ddb526c9365a6a47e52e6`.

## Automated results

| Check | Result |
| --- | --- |
| `bun run test` | 33 passed, 0 failed; 93 assertions |
| `bun run test:integration` | 7 passed, 0 failed; 41 assertions |
| Partner `bun test` | 140 passed, 0 failed; 374 assertions |
| Aithos `typecheck`, `typecheck:integration`, `format:check` | Passed |
| Aithos frozen dependency installation and `bun audit` | Passed; no known vulnerabilities reported |
| Partner format, lint, types, contracts, fallow, health, audit | Exit 0; warnings detailed below |
| Partner FTA native binary | Exit 0; 111 files analyzed |
| Provider Node bundle import | Passed with synthetic required configuration |
| Terraform format, validate and final drift plan | Passed; final plan exit 0, no changes |
| Real AWS dev integration | 14 checks passed, repeated on final deployed bundle |

The maintained harness integration is re-created by applying the patch to a fresh
checkout of upstream `51efcee7d7680f8e3fe8444a4dbed029129caf94`. The local proposal
commit is `663861d9621e2c6b05fb970eb54520684a2dab24`; patch SHA-256:
`b7a16c4dfb3507645193cf4dd8eed7c6dc6a2a44db0696ae182d8acc00c44205`.

Local demo runs in separate processes retained the same identity
`idn_d3cfcb41-5a55-4569-90bf-811b0a0d517e`. Signed requests, completed tasks and owned
session resumption work; duplicate requests are refused before a second effect.
The last rerun used the freshly reconstructed partner fixture, not an unrecorded
dependency on a developer checkout.

Coverage includes public discovery; unsigned challenge before runtime; signature
vectors and tampering; timestamp/body/header bounds; enrollment continuity;
revocation; deterministic deny/restrict rules; provisional restrictions; REST,
JSON-RPC, direct-commerce and model-tool boundaries; tenant and session ownership;
legacy/expired session protection; concurrent identities and duplicate requests;
outbox capacity, delivery retry/deduplication and recovered unknown outcomes.

## Deployed test service

- Origin: `https://8zbvp0lv2a.execute-api.us-east-1.amazonaws.com`
- AWS account/region: `373665157800` / `us-east-1`.
- Function/table: `aithos-client-identity-dev`.
- Terraform state key: `client-identity/dev.tfstate`, separate from registry.
- Lambda: Node.js 22, arm64, 256 MiB, 15-second timeout, Active/Successful.
- Deployed ZIP SHA-256, base64: `Zcsqww4ZmMlcib0hqJgGpzpJ8xMa4kcxMradEJVne7g=`.
- Last deployment observed: `2026-09-23T10:30:54Z`.
- Final synthetic test identity: `idn_90f84b52-768e-474a-b479-5de3dee3814f`, revoked
  at the end; re-enrollment with that key is refused. Earlier live test identity
  `idn_5a3ec761-f586-4e5c-afac-3020a9ee83c5` is also revoked.
- Synthetic audit/provisional records are retained with seven-day TTL. Stable
  revoked public identities remain as evidence that the key cannot re-enroll.

The live test verifies real Secrets Manager/Lambda/DynamoDB behavior: idempotent
enrollment; signed admission in the real local harness; same-owner continuation;
audit persistence and deduplication; tenant-separated history; provisional scope;
admin/partner credential separation; revocation and no revoked-key reactivation.

Initial Lambda creation hit the account's reserved-concurrency floor. The newly
created function was verified active before removing Terraform's partial-create
taint. No resource was destroyed. The pilot now uses the existing unreserved
account pool and a 2 requests/second, burst 2 API throttle; account quotas were
not changed. This throttle is best-effort, not an isolation or cost guarantee.

## Review notes / remaining work

- This is a tested prototype, not an independent security audit. The partner's
  required `acl-quality-gate` skill was unavailable locally and its referenced
  source could not be retrieved. Its advertised mechanical commands were run
  explicitly, without changing thresholds; upstream CI/review remains authoritative.
- `bun run quality:fta` has an upstream launcher/path issue with `R&D`; invoking
  the shipped native executable directly succeeds. Partner lint retains the
  existing max-lines warning in `tests/app/http-handler.test.ts`. Fallow audit
  returns exit 0 with one duplication warning (22 lines, 0.2%).
- The existing, unused wallet/payment example dependency installation reported
  29 advisories (24 moderate, 5 high). No automatic dependency rewrite was made;
  that example is outside and disabled in this pilot. No known advisory was
  reported by the new Aithos package's own dependency audit.
- Expired or duplicate session IDs cannot overwrite an owner, but the existing
  harness maps the underlying SQLite uniqueness error to HTTP 500. A dedicated
  conflict response is a partner API refinement before a public release.
- A pre-effect journal failure is fail-closed; some in-operation storage errors
  are mapped by the harness to generic HTTP 500 rather than 503. Outcome recovery
  is conservative, not an exactly-once transaction across service boundaries.
- Single-process replay/outbox, bounded history, seven-day delivery window,
  key-loss/rotation, real model onboarding, real Shopware and additional A2A
  transports/task lifecycle all remain explicit limits in the README.
- SNS email subscriptions still need confirmation. An alarm's existence does
  not prove notifications are received.
- The new GitHub workflow repeats unit/integration/demo/build/Terraform checks
  without AWS credentials or a deployment step. Its remote outcome is available
  in the feature branch's Actions runs; it is separate from partner upstream CI.

Next validation: review this boundary and policy with the partner, then run an
authorized sandbox Shopware + real caller-agent exercise. Do not silently enable
checkout, production traffic or multi-replica deployment from this demonstration.
