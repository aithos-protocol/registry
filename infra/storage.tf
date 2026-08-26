# --- S3: published cards -----------------------------------------------------
#
# Two kinds of object live here, and the difference matters.
#
# `versions/…` holds every published card, named by its own SHA-256. A modified
# card is necessarily a different key, so nothing is ever overwritten — the
# append-only property is a consequence of the naming, not of a bucket policy.
#
# `v1/agents/…` holds the current-version pointers. Their keys are the request
# paths verbatim, so CloudFront serves the hot read path straight from S3 with
# no URL rewrite.

resource "aws_s3_bucket" "registry" {
  bucket = local.bucket_name
}

# Versioning is not the append-only mechanism — the digest naming is. It is here
# because the current-version pointers *are* overwritten, and because it is the
# only recovery path from an accidental delete.
resource "aws_s3_bucket_versioning" "registry" {
  bucket = aws_s3_bucket.registry.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "registry" {
  bucket = aws_s3_bucket.registry.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# The bucket is private. Everything public goes through CloudFront, which is the
# only principal allowed to read.
resource "aws_s3_bucket_public_access_block" "registry" {
  bucket = aws_s3_bucket.registry.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "AllowCloudFrontRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.registry.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    # Scoped to this distribution, so the bucket is not readable by any other
    # CloudFront distribution in any other account.
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.registry.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "registry" {
  bucket = aws_s3_bucket.registry.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.registry]
}

# --- DynamoDB: agent state ---------------------------------------------------

resource "aws_dynamodb_table" "registry" {
  name         = local.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "S"
  }

  # Listing index. One partition is enough while writes are rare by design; if
  # that stops being true, shard `gsi1pk` and merge the queries.
  global_secondary_index {
    name = "gsi1"

    key_schema {
      attribute_name = "gsi1pk"
      key_type       = "HASH"
    }

    key_schema {
      attribute_name = "gsi1sk"
      key_type       = "RANGE"
    }

    projection_type = "ALL"
  }

  # This table is the only record of who controls which entry. Losing it is not
  # recoverable from S3, because the card objects carry no authorization state.
  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}
