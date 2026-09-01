variable "environment" {
  description = "Environment name. Every resource name carries it, so a second environment is a new tfvars file rather than a refactor."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "The environment name must be lowercase alphanumeric with hyphens, 2 to 16 characters."
  }
}

variable "region" {
  description = "Primary AWS region. No default: the organization's service control policy restricts which regions are usable, so this must be a deliberate choice per environment rather than something inherited silently."
  type        = string
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

variable "write_rate_limit" {
  description = "Writes allowed per source address per five minutes, before WAF blocks. Publishing is rare by nature, so this can be tight without inconveniencing anyone real."
  type        = number
  default     = 100
}

variable "sweep_schedule" {
  description = "How often the read path is reconciled against the register. Hourly is far more often than a dropped stream record is expected, and a sweep over a small register costs almost nothing."
  type        = string
  default     = "rate(1 hour)"
}

variable "read_rate_limit" {
  description = "Requests of any kind allowed per source address per five minutes. Must stay below what the stage throttle can serve (20 rps = 6000 per five minutes), or one address staying legal under every rule can still saturate the shared throttle and deny every write. 3000 is half of that, and still far above what any real consumer does."
  type        = number
  default     = 3000
}

variable "agent_write_rate_limit" {
  description = "Writes allowed against a single agentId per five minutes, before WAF blocks. Higher than the per-address limit: this exists to stop a crowd aimed at one entry, not to constrain one publisher retrying."
  type        = number
  default     = 300
}

variable "invocation_alarm_threshold" {
  description = "Lambda invocations in five minutes that count as unusual. Writes are rare, so a sustained rate is not growth."
  type        = number
  default     = 500
}

# Renamed from `monthly_budget_eur`: AWS Budgets bills this limit in USD, and a
# variable whose name promises euros while its unit says dollars is a mistake
# waiting for the month the exchange rate makes it matter. The stack at rest
# runs ~8–10 a month, most of it the WAF's fixed fee.
variable "monthly_budget" {
  description = "Monthly cost ceiling for the alarm, in USD — the currency AWS Budgets bills in."
  type        = string
  default     = "20"
}

variable "alarm_email" {
  description = "Address that receives alarms and budget notifications. Alarms with no subscriber are alarms nobody reads."
  type        = string
  default     = null

  # Development may run with no subscriber; an environment named like
  # production may not. An alarm topic with zero subscriptions fails silent in
  # exactly the circumstances alarms exist for, and forgetting the -var at
  # apply time is the easiest mistake in this file to make.
  validation {
    condition     = !contains(["prod", "production"], var.environment) || var.alarm_email != null
    error_message = "A production environment must set alarm_email: alarms and budget notifications with no subscriber are read by nobody."
  }
}

# The public thumbprint of the domain-certification e2e fixture key
# (`registry-e2e/tests/live.rs`, `a_domain_is_certified_observed_and_released`).
# Empty disables the fixture record — prod stays empty until the suite is meant
# to certify there. Not a secret: the secret is the seed the key derives from,
# which never enters Terraform (RUNBOOK §9).
variable "e2e_cert_thumbprint" {
  type    = string
  default = ""
}
