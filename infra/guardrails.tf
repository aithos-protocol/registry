# --- Rate limiting -----------------------------------------------------------
#
# "The key is the account" makes identities free: a keypair is generated offline
# in microseconds, so nothing bounds how many entries one source can create. And
# every entry is permanent — the registry is append-only and the runtime holds
# no right to remove a record — so junk written today is paid for forever.
#
# The API's own throttle bounds the total rate, which caps the bill, but it does
# not tell an attacker from a publisher: saturating it denies service to
# legitimate writes at no cost. This is the part that distinguishes them.
#
# Reads are deliberately not rate limited. They are served from the edge, they
# cost almost nothing, and a public registry that throttles readers is not doing
# its job.

resource "aws_wafv2_web_acl" "registry" {
  # A CloudFront web ACL must live in us-east-1 whatever the region of the rest.
  provider = aws.us_east_1

  name  = local.name
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "writes-per-ip"
    priority = 0

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.write_rate_limit
        aggregate_key_type = "IP"

        # Only writes are counted. Without this the rule would also see the
        # read traffic, which is far larger and would mask the thing it is
        # meant to catch.
        scope_down_statement {
          or_statement {
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "put"

                field_to_match {
                  method {}
                }

                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }

            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "delete"

                field_to_match {
                  method {}
                }

                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "writes-per-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }
}

# --- Alarms ------------------------------------------------------------------
#
# An error logged loudly with nobody watching is an error nobody sees. These are
# the three signals that mean something is wrong in a service whose normal state
# is almost no traffic at all.

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "alarms" {
  count = var.alarm_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "function_errors" {
  alarm_name          = "${local.name}-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The write path is failing. At this traffic level a single error is signal, not noise."
  dimensions        = { FunctionName = aws_lambda_function.registry.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# The pointer refresh that follows a commit logs an error when it fails, and
# without this nobody would ever read that log. A stale pointer means the edge
# serves a superseded card until the next publication, which may never come.
resource "aws_cloudwatch_log_metric_filter" "pointer_failures" {
  name           = "${local.name}-pointer-failures"
  log_group_name = aws_cloudwatch_log_group.lambda.name
  pattern        = "{ $.level = \"ERROR\" && $.fields.message = \"*pointer*\" }"

  metric_transformation {
    name          = "PointerRefreshFailures"
    namespace     = "AgentCardRegistry/${var.environment}"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "pointer_failures" {
  alarm_name          = "${local.name}-pointer-failures"
  namespace           = "AgentCardRegistry/${var.environment}"
  metric_name         = aws_cloudwatch_log_metric_filter.pointer_failures.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "A published card is not visible at the edge and will stay that way until the next publication."
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# Invocation volume is the cheapest proxy for the abuse this stack is exposed
# to: writes are rare by nature, so a sustained rate is not growth.
resource "aws_cloudwatch_metric_alarm" "invocation_surge" {
  alarm_name          = "${local.name}-invocation-surge"
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.invocation_alarm_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "Unusual write volume. Every entry accepted is stored permanently, so this is a cost signal as much as an availability one."
  dimensions        = { FunctionName = aws_lambda_function.registry.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# --- Budget ------------------------------------------------------------------
#
# The stack costs about a euro a month at rest, so any alarm here means
# something is wrong rather than that the service grew.

resource "aws_budgets_budget" "monthly" {
  name         = local.name
  budget_type  = "COST"
  limit_amount = var.monthly_budget_eur
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alarm_email == null ? [] : [80, 100]

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_email_addresses = [var.alarm_email]
    }
  }
}
