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

Create **one account** for now, in the existing Aithos AWS Organization, under
a new organizational unit named `registry`:

| Account | Purpose |
| --- | --- |
| `aithos-registry-dev` | development, and the first deployments |

**Create the development account first, not production.** The first
`terraform apply` of a new stack is a learning exercise: it leaves orphaned
resources, things corrected by hand, and a state file carrying the history of
those corrections. That history should not belong to the account that will
hold real data. Production comes later, created cleanly from Terraform that has
already been proven.

A second account, `aithos-registry-prod`, will be added before the registry
accepts its first card from anyone outside the team. That is the line that
matters: after it, published entries are immutable and every change to the
stack carries real risk. Adding the account then is one `terraform apply`,
provided the Terraform was written for more than one environment from the
start — which it will be.

The account needs its own root email address. A plus-alias on an existing
mailbox is fine (`aws+registry-dev@…`) provided the mailbox is monitored and
not tied to one individual.

Enable MFA on the root user, and confirm the root user has no access keys.

### 2. Region

The organization's service control policy (`p-9hl5sh0c`, in management account
`592931547821`) permits **only `us-east-1` and `us-west-1`**. Every European
region is denied, `us-west-2` too: the allowlist is exactly two regions. This
was discovered by a `CreateBucket` that came back with an explicit deny, not
from reading the policy, which is not readable from the member accounts.

Development runs in **`us-east-1`**. Of the two permitted regions it is the
better one:

- **CloudFront requires its certificate in `us-east-1` regardless.** This is an
  AWS constraint, not a policy one, and it does not go away. Running the stack
  there keeps everything in a single region; running it in `us-west-1` splits
  it across two.
- `us-east-1` has six availability zones, `us-west-1` has two.

If the production region should be European, that means amending the policy —
a decision for whoever set it, and worth understanding before changing.

### 3. Access

Use **IAM Identity Center** (AWS SSO). Do **not** create IAM users.

Create a permission set named `RegistryTerraform`, assigned to the operator's
principal, granting only:

```
s3, dynamodb, lambda, apigateway, cloudfront, acm,
logs, cloudwatch, events, iam, sts, tag, route53,
wafv2, sqs, sns, budgets
```

The second line is what the guardrails and the reconciliation path need:
`wafv2` for the rate rules, `sqs` for the reconciler's failure destination,
`sns` for the alarm topic, `events` for the sweep schedule, `budgets` for the
spend alarm. A first apply into an account missing any of them fails partway.

`AdministratorAccess` will work and is tempting, but the IAM permissions are
the ones that matter. Constrain them: allow `iam:CreateRole`, `iam:PutRolePolicy`
and friends **only for roles under the path `/registry/`**. This is cheap now
and unpleasant to retrofit.

Do **not** require a permissions boundary on those roles unless you also set
`permissions_boundary` on every `aws_iam_role` in `compute.tf`: a boundary
demanded by the permission set and not supplied by the configuration makes
`iam:CreateRole` fail, and the stack cannot be applied at all.

Then configure a local named profile with `aws configure sso`:

- `aithos-registry-dev`

### 4. Terraform state backend

This has to exist before Terraform can run, so create it by hand (or with a
throwaway local-state bootstrap):

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

Two of these are not optional even for a single account:

- **Versioning on the state bucket**, above. It is the only recovery path if a
  state file is corrupted or a wrong apply destroys something.
- An **AWS Budgets** alarm with an email notification — roughly €20. The stack
  should cost close to nothing, so any alarm is a signal that something is
  wrong, not that traffic grew.

Nice to have, and easy to add later:

- **CloudTrail** enabled, or confirmation that an organization trail already
  covers this account.

### 6. DNS

The service will be served from **`aithos.world`**, which already uses Route 53
nameservers (`ns-988.awsdns-59.net`, `ns-1033.awsdns-01.org`,
`ns-1670.awsdns-16.co.uk`, `ns-204.awsdns-25.com`) even though the domain is
registered at IONOS. A hosted zone therefore already exists in **some** AWS
account — very likely not one of the two being created here.

Hostnames:

| Environment | Hostname |
| --- | --- |
| dev (now) | `registry-dev.aithos.world` |
| prod (later) | `registry.aithos.world` |

Find out and report **which AWS account holds the `aithos.world` hosted zone**,
and its zone ID. That account is where the delegation records will have to be
created, and it is almost certainly not where the service will run — so the
Terraform will need a second provider with a cross-account role, or those two
records will have to be created by hand once.

Do not create any hosted zone or record yet. Just report:

- the account ID and zone ID of the existing `aithos.world` hosted zone;
- whether `registry-dev.aithos.world` and `registry.aithos.world` are free of
  existing records — both, so that the production name is known to be
  available before anything depends on it;
- whether a cross-account role for Route 53 in that account is acceptable, or
  whether the two `NS` delegation records should be created manually instead.

The plan is to delegate each subdomain to its own hosted zone in the account
that runs it, so that each environment owns its DNS and nothing is shared:

```text
aithos.world zone (existing account)
  ├── registry-dev.aithos.world   NS → hosted zone in aithos-registry-dev
  └── registry.aithos.world       NS → hosted zone in aithos-registry-prod
                                       (later, same shape)
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

1. The account ID, and the OU it sits in.
2. The confirmed primary region.
3. The Identity Center start URL and the permission set name.
4. The local profile name, and confirmation that
   `aws sts get-caller-identity --profile <name>` succeeds.
5. The state bucket name, with versioning and encryption confirmed.
6. The DNS answers from section 6: the account and zone ID holding
   `aithos.world`, and how the delegation should be created.
7. Whether the budget alarm and CloudTrail are in place.
8. Anything that had to be done differently from the above, and why.
