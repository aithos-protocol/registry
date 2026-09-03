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

# Rotating this forces a new value on the next apply, which is the intended way
# to cut off anyone who learned the old one. `keepers` is deliberately empty:
# the value must survive ordinary applies, or every deploy would briefly reject
# in-flight edge requests.
resource "random_password" "edge_secret" {
  length  = 48
  special = false
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

# The record, listing and manifest reads were falling to the default behaviour,
# which is `CachingDisabled` — so the `Cache-Control: public, max-age=60` the
# API sets on them was discarded and every anonymous GET became a Lambda
# invocation and a DynamoDB query. That made "reads are served from the edge,
# they cost almost nothing" — the premise the whole rate-limiting design rests
# on — false for four of the seven public endpoints.
#
# Keyed on the two query parameters the listings actually use, and on nothing
# else: an unkeyed parameter would let one caller poison another's answer, and a
# fully-keyed policy would make the cache useless against a caller varying junk
# parameters.
resource "aws_cloudfront_cache_policy" "records" {
  name        = "${local.name}-records"
  default_ttl = 60
  min_ttl     = 0
  max_ttl     = 300

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "whitelist"

      query_strings {
        items = ["limit", "cursor"]
      }
    }
  }
}

resource "aws_cloudfront_distribution" "registry" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = local.name
  price_class     = var.price_class
  aliases         = [var.hostname]
  web_acl_id      = aws_wafv2_web_acl.registry.arn

  # The apply returns when the distribution exists, not when every edge
  # location carries it. Nothing downstream needs the propagation — the alias
  # records point at a domain name that is valid from creation — and the wait
  # is a quarter of an hour during which an interrupted apply leaves the
  # distribution created but unrecorded in state: an orphan, and a
  # CNAMEAlreadyExists on the retry. The checks that mean something — the
  # smoke tests and the e2e suite — already wait for the edge, deliberately.
  wait_for_deployment = false

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

    # The WAF rate rule that tells an abusive publisher from a legitimate one
    # lives at the edge, and WAFv2 cannot be attached to an HTTP API at all — so
    # without this the API's own `execute-api` hostname is a second front door
    # with no such rule behind it. This header is what the origin checks to know
    # a request came through the distribution. It is not an authorization
    # secret: everything that authorizes a write is a signature. It is the
    # difference between one rate-limited entrance and two, one of which nobody
    # is watching.
    custom_header {
      name  = "x-aithos-edge"
      value = random_password.edge_secret.result
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

    # No origin request policy, deliberately. `CachingOptimized` keys on the
    # path alone, and this origin *does* vary on `If-None-Match` — it answers a
    # matching validator with a bodiless 304. Forwarding the viewer's
    # conditional header to an origin whose response is not part of the cache
    # key is how one conditional request poisons a permanently cached URL with
    # an empty response. These objects are immutable, so a client holding one
    # has no reason to revalidate, and CloudFront handles revalidation against
    # its own cache without the origin's help.
    cache_policy_id = data.aws_cloudfront_cache_policy.optimized.id
    compress        = true
  }

  # `/v1/agents/{id}/versions` — a GET-only projection. Declared before the
  # greedy card pattern for the same reason `/versions/*` is: wildcards match
  # across slashes.
  ordered_cache_behavior {
    path_pattern           = "/v1/agents/*/versions"
    target_origin_id       = local.api_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = aws_cloudfront_cache_policy.records.id
    compress               = true
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

  # Reads that follow state, and so cannot be `immutable` — but that also do
  # not need to be fresh to the second. Sixty seconds bounds how long a
  # withdrawal can be invisible here, which matches what the API already asks
  # for in its own `Cache-Control`.
  ordered_cache_behavior {
    path_pattern           = "/v1/agents"
    target_origin_id       = local.api_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = aws_cloudfront_cache_policy.records.id
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern           = "/v1/registry"
    target_origin_id       = local.api_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = aws_cloudfront_cache_policy.records.id
    compress               = true
  }

  # The two documentation paths, both static objects. Declared before the
  # `/errors/*` behaviour only for reading order; neither pattern can collide
  # with anything above, since no agent path contains `/problems/` and no agent
  # is named `openapi.json`.
  #
  # `/v1/openapi.json` needs a behaviour of its own: without one it falls to the
  # default, which is the API, which has no such route — the document would be
  # answered by a Lambda with a 404.
  ordered_cache_behavior {
    path_pattern           = "/v1/openapi.json"
    target_origin_id       = local.s3_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  # `*` matches across slashes and also matches nothing, so this one pattern
  # covers `/problems/withdrawn` and `/problems/` alike.
  ordered_cache_behavior {
    path_pattern           = "/problems/*"
    target_origin_id       = local.s3_origin
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  # The custom error page below is fetched through this same behaviour table —
  # it is an ordinary request, not a special case — so without this behaviour it
  # would fall to the default one and be requested from the API, which has no
  # such route. The error object would never be served, and every 404 on a
  # missing card would cost a Lambda invocation on an uncached path: an
  # anonymous, unthrottled read turned into compute. It cannot collide with the
  # patterns above; no agent path contains `/errors/`.
  ordered_cache_behavior {
    path_pattern           = "/errors/*"
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
