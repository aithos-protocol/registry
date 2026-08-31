# terraform init -reconfigure -backend-config=env/prod.backend.hcl
#
# The bucket lives in aithos-prod (128066560720) — the account that holds the
# aithos.world zone, and, per the decision of 2026-08-31, the one production
# deploys into. Created by hand once, per ACCOUNT-SETUP.md: versioned,
# encrypted, private, non-current versions expiring after 90 days.
bucket = "aithos-registry-tfstate-prod-128066560720"
key    = "agent-card-registry/prod.tfstate"
region = "us-east-1"
