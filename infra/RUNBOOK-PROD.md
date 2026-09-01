# Production runbook

How `registry.aithos.world` is deployed, watched, and — when the law compels
it — overridden. Written before opening, because the day any of this is needed
is not the day to invent it.

Decisions this encodes (2026-08-31): region **us-east-1** (SCP allows only
us-east-1/us-west-1; the European question is commercial and stays open),
account **aithos-prod (128066560720)** — the one holding the `aithos.world`
zone, so NS delegation is a same-account step — and `write_rate_limit = 20`.

## 0. Preconditions — all of them, no exceptions

- The three leaked tokens (two GitHub PATs, one crates.io) are **revoked** and
  `.env` is gone. Nothing below happens first.
- An SSO profile for aithos-prod exists (`aws sso login --profile registry-prod`).
- The state bucket exists, made by hand per `ACCOUNT-SETUP.md`:
  `aithos-registry-tfstate-prod-128066560720` — versioned, encrypted, private.
- Development is healthy at the commit being deployed: CI green, dev applied
  from the same attested zip, e2e green against dev.

## 1. The zip comes from the commit, or the apply does not happen

```sh
# `gh run download` needs a run id when not interactive — resolve the run
# that built THIS commit, then take its artifact. Overwrite whatever zip is
# sitting in target/lambda: that stale file is exactly the hazard.
sha=$(git rev-parse HEAD)
run=$(gh run list --repo aithos-protocol/registry -w ci -c "$sha" \
      -L1 --json databaseId -q '.[0].databaseId')
rm -f target/lambda/registry.zip
gh run download "$run" --repo aithos-protocol/registry \
  -n "registry-zip-$sha" -D target/lambda
gh attestation verify target/lambda/registry.zip --repo aithos-protocol/registry
ls -l target/lambda/registry.zip   # today's date, or stop here
```

Two audits (27/08, 29/08) predicted a stale workstation zip deploying old
code backwards, and on 31/08 it happened on dev: the download step failed
silently, the apply proceeded, and the environment regressed to a binary from
before the publication proofs — caught within minutes by the e2e suite. The
CI artifact, its attestation, and the `ls -l` glance are the fix; a local
build is for development only, and **an apply never proceeds past a download
that failed**.

## 2. First deploy — two phases, one manual step

```sh
cd infra
export AWS_PROFILE=registry-prod
terraform init -reconfigure -backend-config=env/prod.backend.hcl

# Phase 1: the zone alone.
terraform apply -var-file=env/prod.tfvars -var alarm_email=<you> \
  -target=aws_route53_zone.registry
terraform output nameservers
```

Create the `NS` record for `registry.aithos.world` in the `aithos.world` zone
(`Z09988302Y6VWTN77SVQ8`, same account now). Wait until
`dig +short NS registry.aithos.world` answers those four names — the ACM
certificate blocks until it does, and that blocking is the design working, not
a failure.

```sh
# Phase 2: everything.
terraform apply -var-file=env/prod.tfvars -var alarm_email=<you>
```

`alarm_email` is required for prod by variable validation. On every later
apply, pass the same address — omitting it destroys the SNS subscription.

## 3. Prove the alarms before trusting them

1. Click the SNS confirmation e-mail. An unconfirmed subscription is silence.
2. Fire one real alarm end to end:

```sh
aws cloudwatch set-alarm-state \
  --alarm-name agent-card-registry-prod-errors \
  --state-value ALARM --state-reason "runbook: live delivery test"
```

The e-mail must arrive. It resets itself on the next evaluation.

## 4. Prove the write path before the first real card

```sh
REGISTRY_E2E_ORIGIN=https://registry.aithos.world \
  cargo test -p registry-e2e -- --ignored --test-threads=1
```

The suite publishes its own throwaway entries and ends by withdrawing them —
the only live coverage the withdrawal path gets. The entries are permanent in
the append-only history and served nowhere (decision of 2026-08-31: accepted,
deliberately, before opening rather than after).

Then the smoke checks: `curl -s https://registry.aithos.world/v1/registry | jq
.origin` must echo the origin, and a withdrawn e2e agent must answer 404 on
its card and JWKS.

## 5. Opening checklist

- GitHub: private vulnerability reporting **enabled** (SECURITY.md points at
  it), ruleset protecting `v*` tags from update/delete, branch protection on
  `main`, repository description and topics set.
- Cut `v0.1.0-alpha.2` from the merged main — a **new** tag; a published tag
  never moves. This is the first release whose default registry resolves.
- Regenerate the Homebrew formula from that release
  (`scripts/brew-formula.sh v0.1.0-alpha.2 > Formula/aithos.rb`) and push the
  tap — ideally from a workflow with a scoped secret, never from a `.env`.
- crates.io: publish 0.1.0-alpha.2, then set up trusted publishing so the
  token stops existing.

## 6. What the alarms mean, and the first move for each

| Alarm | It means | First move |
| --- | --- | --- |
| `…-errors` | The API function faulted or timed out | CloudWatch logs of the registry function; recent deploy? |
| `…-api-5xx` | The write path answered 5xx (DynamoDB/S3 failure shows here, not in Errors) | Access logs: which route, which caller; AWS Health |
| `…-reconciler-errors` / `…-reconciler-lag` | The edge is drifting from the register | Reconciler logs; the hourly sweep repairs — confirm it did |
| `…-reconciler-dlq` | A stream record was discarded; the sweep is now the only repair | Read the queue for the shard hint; verify the named agent's pointers after the next sweep |
| `…-sweep-repairs` | Drift existed and was repaired — the stream lost something | Treat as evidence, not incident: correlate with reconciler errors |
| `…-sweeper-errors` / `…-sweeper-stopped` | The repair path itself is broken or not running | Sweeper logs / EventBridge rule state. This one cannot wait |
| `…-invocation-surge` | Write volume that is not growth | WAF sampled requests: one IP or many; tighten `write_rate_limit` if crowd |
| Budget (forecast or actual) | Money is moving | Cost Explorer by service; almost always S3/WAF under abuse |

Reads are unlimited by design; the response to abuse beyond the WAF is human.
These e-mails go to one inbox — the operator's — and that is the on-call
arrangement, stated plainly.

## 7. Takedown — the operator override the protocol does not have

By design nobody, operator included, can alter an entry without its key: no
role holds `DeleteItem`, the API cannot touch `v1/` pointers, and a manual S3
delete is *repaired by the sweeper within the hour*. Do not fight the
machinery — use it. The administrative path mirrors what a key-holder
withdrawal commits, and the reconciler then purges the edge through the normal
pipeline:

```sh
# 1. Read the entry's current seq (and record everything for the case file).
aws dynamodb get-item --table-name agent-card-registry-prod \
  --key '{"pk":{"S":"AGENT#<agentId>"},"sk":{"S":"CURRENT"}}'

# 2. Flip it to WITHDRAWN, conditionally on that seq, stamping the moment.
#    gsi1sk must be "<updatedAt>#<agentId>" — the listing's sort key shape.
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
aws dynamodb update-item --table-name agent-card-registry-prod \
  --key '{"pk":{"S":"AGENT#<agentId>"},"sk":{"S":"CURRENT"}}' \
  --update-expression "SET #s = :w, updatedAt = :t, gsi1sk = :g" \
  --condition-expression "#q = :seq AND #s = :active" \
  --expression-attribute-names '{"#s":"status","#q":"seq"}' \
  --expression-attribute-values "{\":w\":{\"S\":\"WITHDRAWN\"},\":active\":{\"S\":\"ACTIVE\"},\":seq\":{\"N\":\"<seq>\"},\":t\":{\"S\":\"$NOW\"},\":g\":{\"S\":\"$NOW#<agentId>\"}}"

# 3. Within ~a minute: card and JWKS answer 404 at the edge, the record
#    answers 200 WITHDRAWN. Verify both. History stays readable by digest —
#    the record of what was published is not erased, only no longer served.
```

Rules of use: only under legal compulsion or unambiguous illegal content;
never for content someone merely dislikes (the SPEC is explicit that nobody
vouched for card contents); log who decided, when, and on what basis, in this
repository; and remember it is terminal — the identifier can never be used
again, exactly as if the key holder had withdrawn it. If historical version
objects themselves must go (a court order naming the bytes), that is an S3
`versions/<agentId>/<digest>.json` object delete performed by an
administrator, documented the same way — the digest index in the table will
then correctly answer 404 for it. The sweeper only manages `v1/` pointers and
will not resurrect it.

## 8. Later applies, in one line

Same commit rule (§1), same `alarm_email`, `terraform plan` read before
`apply` — and never an apply while the deployed zip is newer than the one on
disk.

## 9. Domain certification — the live fixture

The certification live test (`registry-e2e`,
`a_domain_is_certified_observed_and_released`) works against a **fixture
entry** whose identifier a permanent DNS record declares. Identifiers are
key thumbprints and single-use, so the fixture key must be reproducible: it
derives from a seed, and the seed is the only secret.

The pieces, per environment:

- **The record** — `_a2a.e2e-cert.<hostname>`, deployed by Terraform when
  `e2e_cert_thumbprint` is set (dev: set in `env/dev.tfvars`; prod: empty
  until the suite is meant to certify there). It is permanent by design
  (DOMAIN-CERTIFICATION.md §3.5) — do not clean it up between runs.
- **The seed** — `REGISTRY_E2E_CERT_SEED`, kept wherever operator secrets
  live, never in this repository. The thumbprint in the tfvars is derived
  from it (`Key::from_seed` in the e2e harness).
- **The fixture entry** — created by the test itself on first run, and
  **never withdrawn**: each run re-certifies with a fresh `issuedAt`, checks
  the projection, exercises the replay refusal, then certifies the empty set
  so the fixture is left clean.

Running the certification tests against dev:

```sh
REGISTRY_E2E_ORIGIN=https://registry-dev.aithos.world \
REGISTRY_E2E_CERT_DOMAIN=e2e-cert.registry-dev.aithos.world \
REGISTRY_E2E_CERT_SEED=<the seed> \
  cargo test -p registry-e2e -- --ignored --test-threads=1
```

If the fixture entry was ever withdrawn (the test refuses loudly): pick a new
seed, put its thumbprint in the tfvars, apply, and let the test re-create the
entry — the old identifier stays dead, which is the protocol working.

Two operational notes. The hourly sweeper now also re-resolves every
certified domain (three failed passes remove one; `CertifiedDomainRemovals`
in the `Registry` namespace counts removals — a metric, deliberately no
alarm). And the manifest publishes the revalidation interval from the
`REGISTRY_REVALIDATE_SECONDS` env var, default 3600: if `sweep_schedule`
ever changes, set that variable on the **api** function to match.
