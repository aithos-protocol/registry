output "hostname" {
  description = "The public hostname of this environment."
  value       = var.hostname
}

output "registry_origin" {
  description = "The canonical origin. It appears in signed withdrawal payloads, so it must match REGISTRY_ORIGIN exactly."
  value       = "https://${var.hostname}"
}

output "nameservers" {
  description = "Create NS records for `hostname` in the parent zone pointing at these. This is the one manual step, because the parent zone lives in another account."
  value       = aws_route53_zone.registry.name_servers
}

output "bucket" {
  description = "S3 bucket holding published cards."
  value       = aws_s3_bucket.registry.id
}

output "table" {
  description = "DynamoDB table holding agent state."
  value       = aws_dynamodb_table.registry.name
}

output "cloudfront_domain" {
  description = "The distribution's own domain, useful for testing before DNS is delegated."
  value       = aws_cloudfront_distribution.registry.domain_name
}

output "function_name" {
  description = "Lambda function name, for reading logs."
  value       = aws_lambda_function.registry.function_name
}
