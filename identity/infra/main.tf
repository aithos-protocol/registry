terraform {
  required_version = ">= 1.11"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  backend "s3" {}
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["373665157800"]
  default_tags { tags = { Project = "aithos-client-identity", Environment = "dev", Data = "synthetic-pilot" } }
}

variable "lambda_package" {
  type    = string
  default = "../dist/provider.zip"
}

locals { name = "aithos-client-identity-dev" }

resource "aws_dynamodb_table" "identities" {
  name                        = local.name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
  lifecycle { prevent_destroy = true }
}

resource "aws_secretsmanager_secret" "credentials" {
  name                    = "${local.name}/server-credentials"
  recovery_window_in_days = 7
  description             = "Synthetic pilot partner/admin credentials. Values provisioned outside Terraform state."
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role" "provider" {
  name               = local.name
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_cloudwatch_log_group" "provider" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 14
}
resource "aws_iam_role_policy" "provider" {
  name = "private-identity-store"
  role = aws_iam_role.provider.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:ConditionCheckItem"], Resource = aws_dynamodb_table.identities.arn },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.credentials.arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.provider.arn}:*" }
  ] })
}
resource "aws_apigatewayv2_api" "provider" {
  name          = local.name
  protocol_type = "HTTP"
}
resource "aws_lambda_function" "provider" {
  function_name    = local.name
  role             = aws_iam_role.provider.arn
  runtime          = "nodejs22.x"
  handler          = "lambda.handler"
  architectures    = ["arm64"]
  filename         = var.lambda_package
  source_code_hash = filebase64sha256(var.lambda_package)
  memory_size      = 256
  timeout          = 15
  # This dev account cannot reserve concurrency while retaining AWS's minimum
  # unreserved pool. Do not change account-wide quotas for this synthetic pilot.
  reserved_concurrent_executions = -1
  environment {
    variables = {
      IDENTITY_TABLE          = aws_dynamodb_table.identities.name
      IDENTITY_SECRET_ARN     = aws_secretsmanager_secret.credentials.arn
      IDENTITY_ORIGIN         = aws_apigatewayv2_api.provider.api_endpoint
      IDENTITY_RETENTION_DAYS = "7"
    }
  }
  depends_on = [aws_iam_role_policy.provider]
}
resource "aws_apigatewayv2_integration" "provider" {
  api_id                 = aws_apigatewayv2_api.provider.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.provider.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 20000
}
resource "aws_apigatewayv2_route" "provider" {
  api_id    = aws_apigatewayv2_api.provider.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.provider.id}"
}
resource "aws_apigatewayv2_stage" "provider" {
  api_id      = aws_apigatewayv2_api.provider.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 2
    throttling_rate_limit  = 2
  }
}
resource "aws_lambda_permission" "provider" {
  statement_id  = "AllowIdentityAPI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.provider.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.provider.execution_arn}/*/*"
}
resource "aws_cloudwatch_log_metric_filter" "errors" {
  name           = "${local.name}-errors"
  log_group_name = aws_cloudwatch_log_group.provider.name
  pattern        = "identity_provider_unavailable"
  metric_transformation {
    name      = "Unavailable"
    namespace = "Aithos/ClientIdentityDev"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.name}-errors"
  namespace           = "Aithos/ClientIdentityDev"
  metric_name         = "Unavailable"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = ["arn:aws:sns:us-east-1:373665157800:agent-card-registry-dev-alarms"]
}
output "origin" { value = aws_apigatewayv2_api.provider.api_endpoint }
output "secret_arn" { value = aws_secretsmanager_secret.credentials.arn }
output "table" { value = aws_dynamodb_table.identities.name }
