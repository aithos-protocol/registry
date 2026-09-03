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

  # The table carries `deletion_protection_enabled` and `prevent_destroy`; this
  # bucket holds the append-only card corpus, which is the part that cannot be
  # reconstructed from anything else. A `destroy` would fail on a non-empty
  # bucket anyway, but relying on that is relying on an accident.
  lifecycle {
    prevent_destroy = true
  }
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

    # Every withdrawal deletes two pointers, and under versioning a delete is a
    # marker rather than a removal. Once its noncurrent version ages out above,
    # the marker is all that is left — and nothing expired it. Clutter rather
    # than a correctness problem (the marker is what makes S3 answer 404), but
    # it is permanent clutter that grows with every withdrawal.
    expiration {
      expired_object_delete_marker = true
    }
  }

  # The card object is written before the conditional transaction that would
  # make it reachable, so every lost race and every failed transaction leaves an
  # object nothing indexes and nothing reads. They are unreachable — the API
  # requires the `DIGEST#` item, written inside that transaction, before it will
  # serve any bytes — but unreachable is not the same as gone, and this rule is
  # filtered to `v1/`, so nothing collected them.
  #
  # Only *incomplete* uploads and superseded versions are expired here. A
  # committed card under `versions/` is never overwritten and never deleted:
  # that is the whole of the append-only promise.
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
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

# --- the published documentation ---------------------------------------------
#
# Both of these are static documents served from the object store, for the same
# reason the card path is: they change on deploy and never per request, so
# answering them from compute would put a Lambda invocation behind every reader
# of an error message. They are committed to the repository and uploaded from
# it, rather than generated here, so what is served is what was reviewed —
# `crates/registry-api/tests/openapi.rs` is what fails when the files stop
# matching the catalogue they came from.

# The description of the HTTP surface. `/v1/openapi.json` and not `/openapi.json`
# because it describes v1: a second major version would describe itself, at its
# own path, without either document having to say which one is current.
resource "aws_s3_object" "openapi" {
  bucket        = aws_s3_bucket.registry.id
  key           = "v1/openapi.json"
  content_type  = "application/json"
  source        = "${path.module}/../openapi.json"
  etag          = filemd5("${path.module}/../openapi.json")
  cache_control = "public, max-age=300"
}

# One page per problem code. RFC 9457 §3.1.1 says the `type` URI a problem
# document carries should, dereferenced, give human-readable documentation for
# the code — and until these existed it resolved to 404, which is the one place
# the API already promised documentation and the one place it had none.
#
# The keys carry no extension because the `type` member names them without one:
# a document served at a different path from the one the API points at is not
# documentation of anything.
resource "aws_s3_object" "problem_page" {
  for_each = toset([
    for name in fileset("${path.module}/../site/problems", "*") : name
    if name != "index.html"
  ])

  bucket        = aws_s3_bucket.registry.id
  key           = "problems/${each.value}"
  content_type  = "text/html; charset=utf-8"
  source        = "${path.module}/../site/problems/${each.value}"
  etag          = filemd5("${path.module}/../site/problems/${each.value}")
  cache_control = "public, max-age=300"
}

# The index, at both spellings a reader might arrive by. S3 is a key-value store
# reached through CloudFront's REST origin, which resolves no index document, so
# `/problems/` is served by an object whose key literally ends in a slash. Both
# come from one file, so the pair cannot disagree.
resource "aws_s3_object" "problem_index" {
  for_each = toset(["problems/", "problems/index.html"])

  bucket        = aws_s3_bucket.registry.id
  key           = each.value
  content_type  = "text/html; charset=utf-8"
  source        = "${path.module}/../site/problems/index.html"
  etag          = filemd5("${path.module}/../site/problems/index.html")
  cache_control = "public, max-age=300"
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

  # The stream is what gives the public read-path pointers a single writer that
  # sees an agent's transitions in commit order. DynamoDB orders stream records
  # per partition key, and every item of one agent shares one, so consuming it
  # cannot reorder that agent's publications the way a write from the request
  # path can.
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

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
