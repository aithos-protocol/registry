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

  # No DeleteItem anywhere: agent state is append-only and the runtime never
  # needs to remove a row.
  statement {
    sid       = "Objects"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.registry.arn}/*"]
  }

  # The API holds no right to delete anything, and no longer writes the
  # read-path pointers at all: those belong to the reconciler, which is the
  # only component that sees an agent's transitions in order.
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
      REGISTRY_ROLE   = "api"
      REGISTRY_TABLE  = aws_dynamodb_table.registry.name
      REGISTRY_BUCKET = aws_s3_bucket.registry.id
      REGISTRY_ORIGIN = "https://${var.hostname}"
      RUST_LOG        = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# --- The reconciler ----------------------------------------------------------
#
# Same artifact as the API, a different role. Shipping one zip means the two can
# never run different versions of the key layout they share.

resource "aws_cloudwatch_log_group" "reconciler" {
  name              = "/aws/lambda/${local.name}-reconciler"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "reconciler" {
  name               = "${local.name}-reconciler"
  path               = "/registry/"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "reconciler" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.reconciler.arn}:*"]
  }

  statement {
    sid = "Stream"
    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams",
    ]
    resources = [aws_dynamodb_table.registry.stream_arn]
  }

  # It reads immutable cards and writes the pointers, and that is all. No
  # access to the table's items: its whole input is the stream.
  statement {
    sid       = "ReadPublishedCards"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.registry.arn}/versions/*"]
  }

  statement {
    sid       = "OwnThePointers"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.registry.arn}/v1/*"]
  }
}

resource "aws_iam_role_policy" "reconciler" {
  name   = "reconciler"
  role   = aws_iam_role.reconciler.id
  policy = data.aws_iam_policy_document.reconciler.json
}

resource "aws_lambda_function" "reconciler" {
  function_name = "${local.name}-reconciler"
  role          = aws_iam_role.reconciler.arn

  filename         = var.lambda_package
  source_code_hash = filebase64sha256(var.lambda_package)

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]

  memory_size = 256
  timeout     = 30

  environment {
    variables = {
      REGISTRY_ROLE   = "reconciler"
      REGISTRY_BUCKET = aws_s3_bucket.registry.id
      RUST_LOG        = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.reconciler]
}

resource "aws_lambda_event_source_mapping" "reconciler" {
  event_source_arn  = aws_dynamodb_table.registry.stream_arn
  function_name     = aws_lambda_function.reconciler.arn
  starting_position = "LATEST"

  # One record at a time. Batching would trade a little cost for the chance of
  # one poisoned record blocking a shard, and publications are rare enough that
  # there is nothing to save.
  batch_size = 1

  # A shard that cannot make progress must not stall an agent's pointers
  # forever; failures surface on the alarm instead.
  maximum_retry_attempts = 5
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
