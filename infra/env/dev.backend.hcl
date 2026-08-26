# Fill in the bucket created by hand during account setup, then:
#   terraform init -backend-config=env/dev.backend.hcl
bucket = "REPLACE_ME_aithos-registry-tfstate-dev-<account-id>"
key    = "agent-card-registry/dev.tfstate"
region = "eu-west-3"
