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
  # ListBucket is granted alongside GetObject so that a missing object comes
  # back as 404 rather than 403. Without it S3 refuses to distinguish "absent"
  # from "forbidden", which is the right default for an anonymous caller — but
  # this principal is CloudFront, which has no way to issue a ListObjects call,
  # so nothing here becomes enumerable.
  statement {
    sid     = "AllowCloudFrontRead"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.registry.arn,
      "${aws_s3_bucket.registry.arn}/*",
    ]

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

# Versioning keeps every overwrite, and the current-version pointers under
# `v1/` are overwritten on every publication — so their superseded copies pile
# up without bound while the record that matters already lives, immutably, under
# `versions/`. Those are never overwritten and so have no non-current versions
# for this rule to touch.
resource "aws_s3_bucket_lifecycle_configuration" "registry" {
  bucket = aws_s3_bucket.registry.id

  rule {
    id     = "expire-superseded-pointers"
    status = "Enabled"

    filter {
      prefix = "v1/"
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.registry]
}

# The body CloudFront serves for a miss on the static read path. Keeping the
# shape of an RFC 9457 problem means a client parses one error format whether it
# was answered by the edge or by the API.
resource "aws_s3_object" "not_found" {
  bucket       = aws_s3_bucket.registry.id
  key          = "errors/not-found.json"
  content_type = "application/problem+json"

  content = jsonencode({
    type   = "/problems/not-found"
    title  = "Not found"
    status = 404
    code   = "NOT_FOUND"
    detail = "No such agent card in this registry."
  })
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
