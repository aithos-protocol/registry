# Naming. Every name carries the environment, and the S3 bucket also carries the
# account ID because bucket names are globally unique across all of AWS.
locals {
  name        = "agent-card-registry-${var.environment}"
  bucket_name = "aithos-agent-card-registry-${var.environment}-${data.aws_caller_identity.current.account_id}"
}

data "aws_caller_identity" "current" {}
