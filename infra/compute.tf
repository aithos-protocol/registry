# --- Lambda: the write path --------------------------------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Roles are created under /registry/ so that the Terraform principal can be
# constrained to that path and cannot mint arbitrary roles elsewhere.
resource "aws_iam_role" "lambda" {
  name               = local.name
  path               = "/registry/"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid = "Table"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:TransactWriteItems",
    ]
    resources = [
      aws_dynamodb_table.registry.arn,
      "${aws_dynamodb_table.registry.arn}/index/*",
    ]
  }

  # No DeleteItem and no DeleteObject anywhere in this policy. The registry is
  # append-only, so the runtime has no need to remove anything, and not granting
  # the permission is a stronger guarantee than not calling the API.
  statement {
    sid       = "Objects"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.registry.arn}/*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "registry"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

# Created explicitly rather than letting Lambda create it implicitly, so that
# retention is set from the first invocation instead of defaulting to forever.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "registry" {
  function_name = local.name
  role          = aws_iam_role.lambda.arn

  filename         = var.lambda_package
  source_code_hash = filebase64sha256(var.lambda_package)

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]

  memory_size = var.lambda_memory_mb
  timeout     = 15

  environment {
    variables = {
      REGISTRY_TABLE  = aws_dynamodb_table.registry.name
      REGISTRY_BUCKET = aws_s3_bucket.registry.id
      REGISTRY_ORIGIN = "https://${var.hostname}"
      RUST_LOG        = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# --- HTTP API ----------------------------------------------------------------

resource "aws_apigatewayv2_api" "registry" {
  name          = local.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.registry.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.registry.invoke_arn
  payload_format_version = "2.0"
}

# One catch-all route: the router lives in the Rust binary, not in API Gateway.
# Duplicating the route table in two places is a way to have them disagree.
resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.registry.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.registry.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 50
    throttling_rate_limit  = 20
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.registry.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.registry.execution_arn}/*/*"
}
