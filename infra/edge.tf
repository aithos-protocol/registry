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
  web_acl_id      = aws_wafv2_web_acl.registry.arn

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

  # Ordered behaviours are evaluated in the order declared, first match wins,
  # and this one must come first.
  #
  # A CloudFront wildcard matches across slashes, which is what lets the
  # patterns below reach every agent — and also what makes them too greedy:
  # `/v1/agents/*/agent-card.json` matches
  # `/v1/agents/{id}/versions/{digest}/agent-card.json` just as happily, which
  # would send historical versions to an object store that has no such key.
  # They are served by the API, so they are claimed here before the greedy
  # pattern can take them.
  ordered_cache_behavior {
    path_pattern           = "/v1/agents/*/versions/*"
    target_origin_id       = local.api_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.optimized.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    compress                 = true
  }

  # The hot path: every agent's current card, straight from the object store.
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

  # A custom error response applies to the WHOLE distribution, never to a
  # single cache behaviour. Mapping 403 here would therefore rewrite the API's
  # own 403 — a write refused because it carried no authorized key — into a
  # meaningless 404. S3 is made to answer 404 by granting ListBucket instead,
  # and only 404 is reshaped.
  #
  # This still replaces the API's 404 body with the generic one. The two say
  # the same thing, and both are RFC 9457 problems with the same code.
  #
  # The TTL is deliberately short: a miss cached for minutes would make a card
  # invisible in the minute after it was published, which is exactly when its
  # publisher is looking.
  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/errors/not-found.json"
    error_caching_min_ttl = 5
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
