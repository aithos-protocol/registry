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
# Reads are cheap but not free. The card and JWKS paths are served from S3 and
# cached; the record, listing and manifest reads are cached at the edge too, but
# `/v1/agents/{id}` shares a behaviour with the write path and so cannot be —
# every GET of it is a Lambda invocation and a DynamoDB read, against a listing
# index that is one logical partition by design.
#
# So there is a read limit, set far above anything a real consumer does: it
# exists to stop one address turning an anonymous GET into sustained compute,
# not to throttle readers. A public registry that rate-limits its readers at a
# level they can notice is not doing its job.

# §9 says every refusal the registry makes is an RFC 9457 problem document, and
# a rate block is a refusal. WAF's default block response is CloudFront's HTML
# error page, which a client written against §9 cannot read — and it arrives
# during an incident, which is exactly when the machine-readable reason matters.
locals {
  rate_limited_problem = jsonencode({
    type   = "/problems/rate-limited"
    title  = "Too many requests"
    status = 429
    code   = "RATE_LIMITED"
    detail = "This address or agent has made too many requests. Wait and retry."
  })
}

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
      block {
        custom_response {
          # 429, not WAF's default 403: the request was well-formed and the
          # caller is not forbidden, only too fast — and the difference decides
          # whether a client retries or gives up.
          response_code            = 429
          custom_response_body_key = "rate-limited"

          # WAF's body content-type enum has no `problem+json`, and the media
          # type is what RFC 9457 makes the identifying signal — a client that
          # dispatches on it would misclassify this exactly during an incident.
          # The header overrides what the enum could not express.
          response_header {
            name  = "content-type"
            value = "application/problem+json"
          }
        }
      }
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

  # No method scope-down: this one counts everything, reads included.
  rule {
    name     = "requests-per-ip"
    priority = 2

    action {
      block {
        custom_response {
          # 429, not WAF's default 403: the request was well-formed and the
          # caller is not forbidden, only too fast — and the difference decides
          # whether a client retries or gives up.
          response_code            = 429
          custom_response_body_key = "rate-limited"

          # WAF's body content-type enum has no `problem+json`, and the media
          # type is what RFC 9457 makes the identifying signal — a client that
          # dispatches on it would misclassify this exactly during an incident.
          # The header overrides what the enum could not express.
          response_header {
            name  = "content-type"
            value = "application/problem+json"
          }
        }
      }
    }

    statement {
      rate_based_statement {
        limit              = var.read_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "requests-per-ip"
      sampled_requests_enabled   = true
    }
  }

  # `SPEC.md` §8 promises a limit per source address *and* per `agentId`. The
  # rule above is only the first half: a few hundred addresses each staying
  # under the per-IP limit can aim every request at one victim's entry, and each
  # one costs up to eight signature verifications before it is refused.
  #
  # The `agentId` is the last path segment of a write, so aggregating on the URI
  # path is aggregating on the identifier. The limit is higher than the per-IP
  # one: a single publisher legitimately retries, and the point is to stop a
  # crowd, not a person.
  rule {
    name     = "writes-per-agent"
    priority = 1

    action {
      block {
        custom_response {
          # 429, not WAF's default 403: the request was well-formed and the
          # caller is not forbidden, only too fast — and the difference decides
          # whether a client retries or gives up.
          response_code            = 429
          custom_response_body_key = "rate-limited"

          # WAF's body content-type enum has no `problem+json`, and the media
          # type is what RFC 9457 makes the identifying signal — a client that
          # dispatches on it would misclassify this exactly during an incident.
          # The header overrides what the enum could not express.
          response_header {
            name  = "content-type"
            value = "application/problem+json"
          }
        }
      }
    }

    statement {
      rate_based_statement {
        limit              = var.agent_write_rate_limit
        aggregate_key_type = "CUSTOM_KEYS"

        custom_key {
          uri_path {
            # WAF does not decode the URI before matching, while the router
            # does — so `/v1/agents/%4EzbL…` and `/v1/agents/NzbL…` would be two
            # rate keys reaching one agent, and the per-`agentId` half of §8
            # would collapse.
            #
            # Decode only. No case folding: an `agentId` is unpadded base64url
            # and case-sensitive, so folding merges *distinct* identifiers onto
            # one key — it makes the limit blunter, never sharper.
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }

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
      metric_name                = "writes-per-agent"
      sampled_requests_enabled   = true
    }
  }

  custom_response_body {
    key          = "rate-limited"
    content      = local.rate_limited_problem
    content_type = "APPLICATION_JSON"
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

  alarm_description = "The registry function faulted or timed out."
  dimensions        = { FunctionName = aws_lambda_function.registry.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# `AWS/Lambda Errors` counts faults and timeouts. The most likely write-path
# failure is not one: a DynamoDB or S3 error becomes a 500 *response* from an
# invocation that completed successfully, which that metric never sees. This is
# the alarm that actually watches the write path.
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.name}-api-5xx"
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The write path is failing: the API answered 5xx. At this traffic level a single one is signal, not noise."
  dimensions        = { ApiId = aws_apigatewayv2_api.registry.id }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# A record the stream gave up on. Every message here is a public read path that
# disagrees with the record — a card the edge is not serving, or a withdrawn one
# it still is — and nothing else in the system will notice.
resource "aws_cloudwatch_metric_alarm" "reconciler_dlq" {
  alarm_name          = "${local.name}-reconciler-dlq"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The reconciler discarded a record. The edge no longer reflects the register."
  dimensions        = { QueueName = aws_sqs_queue.reconciler_dlq.name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# The reconciler owns the read-path pointers. If it fails, a published card is
# not visible at the edge and a withdrawn one is still being served — neither of
# which the API would notice, since it answers correctly from the table either
# way. This is the only signal that the public surface has drifted from the
# record.
resource "aws_cloudwatch_metric_alarm" "reconciler_errors" {
  alarm_name          = "${local.name}-reconciler-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The public read path has drifted from the committed state: a card is published but invisible, or withdrawn but still served."
  dimensions        = { FunctionName = aws_lambda_function.reconciler.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# A sweep that had to repair something means the stream lost a record — which
# is the failure the sweep exists to survive, not one to leave unexamined. The
# sweeper logs an error in that case, so the Lambda `Errors` metric would not
# see it; this watches the log instead.
resource "aws_cloudwatch_log_metric_filter" "sweep_repairs" {
  name           = "${local.name}-sweep-repairs"
  log_group_name = aws_cloudwatch_log_group.sweeper.name
  pattern        = "{ $.fields.repaired > 0 }"

  metric_transformation {
    name          = "SweepRepairs"
    namespace     = "Registry"
    value         = "$.fields.repaired"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "sweep_repairs" {
  alarm_name          = "${local.name}-sweep-repairs"
  namespace           = "Registry"
  metric_name         = "SweepRepairs"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The read path had drifted from the register and was repaired. A stream record was lost."
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# A sweep that cannot run leaves the repair path itself unavailable, which is
# invisible until something else needs it.
resource "aws_cloudwatch_metric_alarm" "sweeper_errors" {
  alarm_name          = "${local.name}-sweeper-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The reconciliation sweep is failing; nothing is repairing a lost stream record."
  dimensions        = { FunctionName = aws_lambda_function.sweeper.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# A sweep that never runs is silent: the repair alarm sees no data and the error
# alarm sees no invocation. This watches for the schedule itself stopping — a
# disabled rule, a detached target, a deleted function.
resource "aws_cloudwatch_metric_alarm" "sweeper_stopped" {
  alarm_name          = "${local.name}-sweeper-stopped"
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  statistic           = "Sum"
  period              = 10800
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  # Missing data is the failure here, not the absence of one.
  treat_missing_data = "breaching"

  alarm_description = "The reconciliation sweep has not run. Nothing is repairing a lost stream record."
  dimensions        = { FunctionName = aws_lambda_function.sweeper.function_name }
  alarm_actions     = [aws_sns_topic.alarms.arn]
}

# Sustained lag, not a discard. With `batch_size = 1` and five retries a poison
# record is dropped within tens of seconds, so iterator age never approaches
# five minutes — the DLQ alarm above is what catches that. This one catches the
# other failure: the reconciler keeping up badly rather than failing loudly.
resource "aws_cloudwatch_metric_alarm" "reconciler_lag" {
  alarm_name          = "${local.name}-reconciler-lag"
  namespace           = "AWS/Lambda"
  metric_name         = "IteratorAge"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 300000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_description = "The reconciler is falling behind the stream."
  dimensions        = { FunctionName = aws_lambda_function.reconciler.function_name }
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
