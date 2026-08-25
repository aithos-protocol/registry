# AWS account preparation

Instructions for preparing the AWS accounts that will host the Agent Card
Registry. This covers **account structure, access and the Terraform state
backend only**. No application infrastructure is created here — that comes from
the Terraform in this directory.

Hand the section below to whoever (or whatever) prepares the account.

---

## Task

Prepare AWS accounts for a small serverless service, and report back the
identifiers listed at the end. Create no application resources.

### What is being built, for context

A public registry that stores signed [A2A](https://a2a-protocol.org) Agent
Cards, to be served from `registry.aithos.world`. The runtime shape is
deliberately minimal:

- **Lambda** (Rust, `provided.al2023`) behind an **API Gateway HTTP API**, for
  the rare write path
- **DynamoDB** for agent metadata, using conditional writes for concurrency
- **S3** for immutable card bytes, addressed by digest
- **CloudFront** in front of S3 for the public read path, which is the bulk of
  the traffic and never reaches compute
- **CloudWatch Logs**

Idle cost should be near zero.

### 1. Account structure

Create **two accounts** in the existing Aithos AWS Organization, under a new
organizational unit named `registry`:

| Account | Purpose |
| --- | --- |
| `aithos-registry-dev` | development and staging |
| `aithos-registry-prod` | production |

Each account needs its own unique root email address. A plus-alias on an
existing mailbox is fine (`aws+registry-dev@…`, `aws+registry-prod@…`) provided
the mailbox is monitored and not tied to one individual.

Two accounts rather than one is the point: the registry's promise is that
published entries are immutable, so there must be no way to test against
production. If the Organization does not exist yet, or two accounts are not
wanted, fall back to a single account with two fully separate Terraform state
prefixes — **and say so explicitly in the report**, because the Terraform will
be written differently.

For each account: enable MFA on the root user, and confirm the root user has
no access keys.

### 2. Region

Primary region: **`eu-west-3`** (Paris), unless there is a reason to prefer
another European region — say which and why if so.

One AWS constraint to be aware of rather than surprised by: **an ACM
certificate used by CloudFront must live in `us-east-1`**, regardless of where
everything else runs. Do not create it yet; just do not be alarmed when the
Terraform asks for a provider aliased to `us-east-1`.

### 3. Access

Use **IAM Identity Center** (AWS SSO). Do **not** create IAM users.

Create a permission set named `RegistryTerraform`, assigned to the operator's
principal on both accounts, granting only:

```
s3, dynamodb, lambda, apigateway, cloudfront, acm,
logs, cloudwatch, iam, sts, tag, route53
```

`AdministratorAccess` will work and is tempting, but the IAM permissions are
the ones that matter. Constrain them: allow `iam:CreateRole`, `iam:PutRolePolicy`
and friends **only for roles under the path `/registry/`**, and attach a
permissions boundary so a role created by Terraform can never grant itself more
than the stack needs. This is cheap now and unpleasant to retrofit.

Then configure local named profiles with `aws configure sso`:

- `aithos-registry-dev`
- `aithos-registry-prod`

### 4. Terraform state backend

This has to exist before Terraform can run, so create it by hand (or with a
throwaway local-state bootstrap) **in each account**:

An S3 bucket named `aithos-registry-tfstate-<env>-<account-id>` — the account
ID suffix is there because S3 bucket names are globally unique — with:

- **versioning enabled** (this is the recovery path for a corrupted state file)
- **default encryption** (SSE-S3 is sufficient)
- **all public access blocked**
- a lifecycle rule expiring noncurrent versions after 90 days

**Do not create a DynamoDB lock table.** The S3 backend now locks natively via
`use_lockfile = true`; the `dynamodb_table` argument is deprecated and slated
for removal. The bucket policy must therefore allow `s3:DeleteObject` on
`<key>.tflock` in addition to the usual `GetObject`/`PutObject`.

### 5. Guardrails

- An **AWS Budgets** alarm per account with an email notification — roughly €20
  for dev, €50 for prod. The stack should cost close to nothing, so any alarm
  is a signal that something is wrong, not that traffic grew.
- **CloudTrail** enabled, or confirmation that an organization trail already
  covers these accounts.

### 6. DNS

The service will be served from **`aithos.world`**, which already uses Route 53
nameservers (`ns-988.awsdns-59.net`, `ns-1033.awsdns-01.org`,
`ns-1670.awsdns-16.co.uk`, `ns-204.awsdns-25.com`) even though the domain is
registered at IONOS. A hosted zone therefore already exists in **some** AWS
account — very likely not one of the two being created here.

Hostnames:

| Environment | Hostname |
| --- | --- |
| prod | `registry.aithos.world` |
| dev | `registry-dev.aithos.world` |

Find out and report **which AWS account holds the `aithos.world` hosted zone**,
and its zone ID. That account is where the delegation records will have to be
created, and it is almost certainly not where the service will run — so the
Terraform will need a second provider with a cross-account role, or those two
records will have to be created by hand once.

Do not create any hosted zone or record yet. Just report:

- the account ID and zone ID of the existing `aithos.world` hosted zone;
- whether `registry.aithos.world` and `registry-dev.aithos.world` are free of
  existing records;
- whether a cross-account role for Route 53 in that account is acceptable, or
  whether the two `NS` delegation records should be created manually instead.

The plan is to delegate each subdomain to its own hosted zone in the account
that runs it, so that each environment owns its DNS and nothing is shared:

```text
aithos.world zone (existing account)
  ├── registry.aithos.world       NS → hosted zone in aithos-registry-prod
  └── registry-dev.aithos.world   NS → hosted zone in aithos-registry-dev
```

Delegating rather than writing records directly into the parent zone matters
here: the registry's hostname is the thing clients pin, so its DNS should be
owned, versioned and deployed by the same Terraform that deploys the service,
not edited by hand in a zone that belongs to something else.

---

## Do not

- **Do not create IAM users or long-lived access keys.** Identity Center issues
  temporary credentials; that is the whole point.
- **Do not paste any access key, secret or session token into a chat, an
  issue, or a commit.** Credentials belong in the local AWS config, reached
  through a named profile. Nothing sensitive needs to travel as text.
- **Do not create any application resource** — no Lambda, no DynamoDB table, no
  data bucket, no CloudFront distribution, no API Gateway. All of that is
  Terraform's job and creating it by hand guarantees drift.
- Do not enable services beyond those listed above.

## Report back

Plain values, no secrets:

1. The two account IDs, and the OU they sit in.
2. The confirmed primary region.
3. The Identity Center start URL and the permission set name.
4. The two local profile names, and confirmation that
   `aws sts get-caller-identity --profile <name>` succeeds for each.
5. The state bucket name in each account, with versioning and encryption
   confirmed.
6. The DNS answers from section 6: the account and zone ID holding
   `aithos.world`, and how the delegation should be created.
7. Whether the budget alarms and CloudTrail are in place.
8. Anything that had to be done differently from the above, and why.
