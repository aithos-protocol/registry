# --- DNS and TLS -------------------------------------------------------------
#
# This environment owns its own hosted zone. The parent zone (aithos.world)
# lives in another account and delegates to it with NS records, created once by
# hand from the `nameservers` output.
#
# Delegating rather than writing records into the parent zone matters: the
# hostname is what clients pin, so it is deployed by the same Terraform as the
# service rather than hand-edited in a zone belonging to something else.

resource "aws_route53_zone" "registry" {
  name    = var.hostname
  comment = "Delegated from ${var.parent_zone_name}; owned by ${var.environment}."
}

# CloudFront only accepts a certificate from us-east-1, wherever the stack runs.
resource "aws_acm_certificate" "registry" {
  provider = aws.us_east_1

  domain_name       = var.hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for option in aws_acm_certificate.registry.domain_validation_options :
    option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  zone_id         = aws_route53_zone.registry.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

# Issuance waits on the delegation being live. Until the NS records exist in the
# parent zone, this blocks — which is the correct behaviour, not a failure.
resource "aws_acm_certificate_validation" "registry" {
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.registry.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}

resource "aws_route53_record" "a" {
  zone_id = aws_route53_zone.registry.zone_id
  name    = var.hostname
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.registry.domain_name
    zone_id                = aws_cloudfront_distribution.registry.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "aaaa" {
  zone_id = aws_route53_zone.registry.zone_id
  name    = var.hostname
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.registry.domain_name
    zone_id                = aws_cloudfront_distribution.registry.hosted_zone_id
    evaluate_target_health = false
  }
}
