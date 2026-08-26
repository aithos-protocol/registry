terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial configuration: the bucket and key come from `env/<name>.backend.hcl`
  # so that a second environment is a different file, never a code change.
  backend "s3" {
    # Native S3 locking. The `dynamodb_table` argument is deprecated and slated
    # for removal, so no lock table is created anywhere in this stack.
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "agent-card-registry"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# CloudFront can only use a certificate issued in us-east-1, wherever the rest
# of the stack lives. This alias exists for that one resource.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "agent-card-registry"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
