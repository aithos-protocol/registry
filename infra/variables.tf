variable "environment" {
  description = "Environment name. Every resource name carries it, so a second environment is a new tfvars file rather than a refactor."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "The environment name must be lowercase alphanumeric with hyphens, 2 to 16 characters."
  }
}

variable "region" {
  description = "Primary AWS region."
  type        = string
  default     = "eu-west-3"
}

variable "hostname" {
  description = "Public hostname this environment answers on, for example registry-dev.aithos.world."
  type        = string
}

variable "parent_zone_name" {
  description = "The parent DNS zone that will delegate `hostname`, for example aithos.world. Delegation records are created by hand in whichever account holds it."
  type        = string
}

variable "lambda_package" {
  description = "Path to the Lambda deployment zip containing the `bootstrap` binary."
  type        = string
  default     = "../target/lambda/registry.zip"
}

variable "lambda_memory_mb" {
  description = "Lambda memory. CPU scales with it, and the write path spends its time on signature verification."
  type        = number
  default     = 512
}

variable "log_retention_days" {
  description = "CloudWatch log retention. Never leave this unset: logs kept forever eventually cost more than the service."
  type        = number
  default     = 30
}

variable "price_class" {
  description = "CloudFront price class. The default keeps edge locations to Europe and North America."
  type        = string
  default     = "PriceClass_100"
}
