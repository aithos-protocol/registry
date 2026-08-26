# Infrastructure

Terraform for one environment of the Agent Card Registry. Every name carries
`var.environment` and the backend is a partial configuration, so a second
environment is a new tfvars file rather than a change to this code.

Account preparation — the accounts themselves, SSO access and the Terraform
state bucket — is in [`ACCOUNT-SETUP.md`](ACCOUNT-SETUP.md) and happens once,
before any of this.

## What it creates

| | |
| --- | --- |
| **S3** | Published cards. Private; only CloudFront may read it. |
| **DynamoDB** | Agent state, with point-in-time recovery and deletion protection. |
| **Lambda** | The write path. Rust on `provided.al2023`, arm64. |
| **HTTP API** | One catch-all route; the router lives in the binary. |
| **CloudFront** | Two origins: S3 for the hot reads, the API for everything else. |
| **Route 53 + ACM** | This environment's own delegated zone and its certificate. |

The runtime role grants no `DeleteItem` and no `DeleteObject`. The registry is
append-only, so the runtime never needs to remove anything, and withholding the
permission is a stronger guarantee than not calling the API.

## Regions

The organization's service control policy permits **only `us-east-1` and
`us-west-1`**. Every European region is denied, and so is `us-west-2`: the
allowlist is exactly two regions. The policy lives in the management account
and its intent is not documented here.

Development therefore runs in `us-east-1`, which is where CloudFront requires
its certificate anyway, so the whole stack sits in one region.

**The production region is a separate, open decision.** Nothing technical
argues for Europe — every card this registry holds is public by design, so
there is no personal data and no jurisdiction question, and CloudFront serves
readers from an edge near them whatever the origin region. The argument for
Europe is commercial: a Belgian company selling trust infrastructure, hosted
entirely in the United States, is a question that will be asked. Answering it
means amending the service control policy, which is a decision for whoever set
it, not a workaround.

`var.region` deliberately has no default, so no environment inherits a region
by accident. The `us_east_1` provider alias is kept even though development
already runs there, so that moving production to Europe stays a variable
change.

## Prerequisites

- Terraform ≥ 1.11 — `use_lockfile` needs it, and no DynamoDB lock table is
  created anywhere in this stack.
- An SSO profile for the target account (`aws sso login --profile …`).
- The state bucket. For development it already exists:
  `aithos-registry-tfstate-dev-373665157800`, versioned, encrypted, private,
  with non-current versions expiring after 90 days.

## Build the Lambda package

```sh
./build-lambda.sh                     # writes ../target/lambda/registry.zip
```

Needs [`cargo-lambda`](https://cargo-lambda.info) (`pip install cargo-lambda`),
which cross-compiles to `aarch64` without a Docker daemon.

## Deploy

DNS delegation makes this a two-phase apply the first time, and only the first
time. The certificate cannot be issued until `registry-dev.aithos.world`
resolves, which cannot happen until the parent zone delegates to nameservers
that do not exist until Terraform has created the zone.

**1. Initialise**

```sh
export AWS_PROFILE=registry-dev
terraform init -backend-config=env/dev.backend.hcl
```

**2. Create the zone, and only the zone**

```sh
terraform apply -var-file=env/dev.tfvars -target=aws_route53_zone.registry
terraform output nameservers
```

**3. Delegate, by hand, in the account holding `aithos.world`**

The parent zone is `Z09988302Y6VWTN77SVQ8` in account `128066560720`
(`aithos-prod`). It holds 11 records and none of them mention `registry`, so
both hostnames are free.

Create an `NS` record for `registry-dev.aithos.world` there, pointing at the
four nameservers from step 2. Wait for it to resolve:

```sh
dig +short NS registry-dev.aithos.world
```

Nothing below will work until this returns those four names. Terraform blocking
at the certificate step is that condition not being met — not a failure.

**4. Apply everything**

```sh
terraform apply -var-file=env/dev.tfvars
```

The CloudFront distribution takes several minutes to reach `Deployed`.

**5. Smoke test**

```sh
HOST=$(terraform output -raw hostname)
curl -s "https://$HOST/v1/registry" | jq .
```

That endpoint touches Lambda, DynamoDB is not involved, and it returns the
pinned A2A commit and the accepted algorithms. If it answers, the write path is
wired end to end.

## Later environments

```sh
terraform init -reconfigure -backend-config=env/prod.backend.hcl
terraform apply -var-file=env/prod.tfvars
```

Two new files, no code change. Steps 2 and 3 repeat once for the new hostname.

## Two things this deliberately does not manage

**The state bucket.** Terraform cannot create the bucket that holds its own
state; it is made by hand once, per `ACCOUNT-SETUP.md`.

**The `NS` records in the parent zone.** They live in another account. They
could be managed with a cross-account provider, but that would mean this stack
holds credentials into a zone it does not own, to write two records that change
once in the lifetime of the environment.
