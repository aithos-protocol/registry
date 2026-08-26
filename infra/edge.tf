# --- CloudFront --------------------------------------------------------------
#
# One distribution, two origins. Reads of the current card and the JWKS — the
# overwhelming majority of traffic — are served from S3 and never reach compute.
# Everything else goes to the API.
#
# The S3 object keys are the request paths verbatim, so no URL rewrite is
# needed: no CloudFront Function, no Lambda@Edge, nothing that could drift out
# of sync with the router.

locals {
  s3_origin  = "s3"
  api_origin = "api"
}

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = local.name
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Managed policy: CachingOptimized. Object cacheability is decided by the
# Cache-Control headers the writer sets, which is where it belongs — immutable
# for version objects, short for current pointers.
data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

# Forwards everything except Host, which must stay the origin's own.
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "registry" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = local.name
  price_class     = var.price_class
  aliases         = [var.hostname]

  origin {
    origin_id                = local.s3_origin
    domain_name              = aws_s3_bucket.registry.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  origin {
    origin_id   = local.api_origin
    domain_name = replace(aws_apigatewayv2_api.registry.api_endpoint, "https://", "")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # Writes and the less common reads. Not cached: a PUT must never be served
  # from an edge, and the record projections follow state that moves.
  default_cache_behavior {
    target_origin_id       = local.api_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    compress                 = true
  }

  # The hot path. A wildcard may sit in the middle of a CloudFront path pattern
  # and matches across slashes, so this reaches every agent's current card.
  ordered_cache_behavior {
    path_pattern           = "/v1/agents/*/agent-card.json"
    target_origin_id       = local.s3_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern           = "/v1/agents/*/jwks.json"
    target_origin_id       = local.s3_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.registry.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
