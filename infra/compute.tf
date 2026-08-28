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
  # The API writes immutable version objects and reads them back; it does not
  # write the read-path pointers under `v1/` — those belong to the reconciler,
  # the only component that sees an agent's transitions in order. Scoping the
  # grant is what makes that a guarantee rather than a convention: withholding
  # the permission is stronger than not calling the API.
  statement {
    sid       = "Versions"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.registry.arn}/versions/*"]
  }

  # Same reason as the sweeper's: without `s3:ListBucket` a genuinely missing
  # object answers 403, which the store cannot tell from a real permission
  # failure, and a request for a version that does not exist becomes a 500
  # instead of the 404 §7.3 promises.
  statement {
    sid       = "DistinguishAbsentFromForbidden"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.registry.arn]
  }

  # The API holds no right to delete anything, anywhere.
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
      REGISTRY_ROLE        = "api"
      REGISTRY_TABLE       = aws_dynamodb_table.registry.name
      REGISTRY_BUCKET      = aws_s3_bucket.registry.id
      REGISTRY_ORIGIN      = "https://${var.hostname}"
      REGISTRY_EDGE_SECRET = random_password.edge_secret.result
      RUST_LOG             = "info"
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

  # The stream says *which* agent changed; what to do comes from a consistent
  # read of that agent's record. Denying this was the earlier design — "its
  # whole input is the stream" — and it was the cause of the defect it was meant
  # to avoid: applying a record's content meant a replay from the stream horizon
  # walked an agent's history forward and republished each superseded card in
  # turn, including one that had since been withdrawn. Per-partition ordering
  # guarantees the final state, not the intermediate ones, and the intermediate
  # ones were being served.
  #
  # One item at a time, read-only, no `Query` and no index: it can read the
  # agent a record names and nothing else.
  statement {
    sid       = "ReadOneRecord"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.registry.arn]
  }

  # It reads immutable cards and writes the pointers.
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

  statement {
    sid       = "DistinguishAbsentFromForbidden"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.registry.arn]
  }

  # Lambda writes the discarded record to this queue on its own behalf, using
  # the function's role.
  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.reconciler_dlq.arn]
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
      REGISTRY_TABLE  = aws_dynamodb_table.registry.name
      REGISTRY_BUCKET = aws_s3_bucket.registry.id
      RUST_LOG        = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.reconciler]
}

# --- The sweeper -------------------------------------------------------------
#
# The stream is fast and not durable enough alone. An event-source mapping that
# exhausts its retries *discards* the record, and its failure destination
# receives batch metadata — a shard id and two sequence numbers — not the record
# itself; past the stream's 24-hour retention there is nothing left to replay
# from. Since withdrawal is terminal, a dropped withdrawal would leave the card
# and JWKS served at the edge permanently, and §6.5's "MUST stop serving" would
# be quietly false for that entry forever.
#
# This is the pass that makes that recoverable: it reads what is committed and
# makes the read path match. It repairs nothing on a healthy day, which is why
# a repair is worth an alarm.

resource "aws_cloudwatch_log_group" "sweeper" {
  name              = "/aws/lambda/${local.name}-sweeper"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "sweeper" {
  name               = "${local.name}-sweeper"
  path               = "/registry/"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "sweeper" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.sweeper.arn}:*"]
  }

  # Reads the register. This is the one component allowed to enumerate it, and
  # it is read-only: the sweeper never changes what is committed, only what is
  # served.
  #
  # Two actions, because it makes two different calls: `Query` on the index to
  # list identifiers, and `GetItem` on the table to read each agent's committed
  # state consistently at the moment it acts on it. The index ARN does not cover
  # `GetItem`, and a policy granting only the first fails on the very first
  # agent of every sweep.
  statement {
    sid       = "ListTheRegister"
    actions   = ["dynamodb:Query"]
    resources = ["${aws_dynamodb_table.registry.arn}/index/gsi1"]
  }

  statement {
    sid       = "ReadOneRecord"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.registry.arn]
  }

  statement {
    sid       = "ReadPublishedCards"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.registry.arn}/versions/*"]
  }

  statement {
    sid       = "RepairThePointers"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.registry.arn}/v1/*"]
  }

  # S3 only distinguishes "absent" from "forbidden" for a caller that holds
  # `s3:ListBucket`; without it a HEAD on a missing key answers 403. The sweep's
  # whole job is to notice absent pointers, so without this grant it would fail
  # on precisely the object it came to create — and abort the rest of the sweep
  # with it. Read-only, and it enumerates nothing a public GET does not already
  # reach.
  statement {
    sid       = "DistinguishAbsentFromForbidden"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.registry.arn]
  }
}

resource "aws_iam_role_policy" "sweeper" {
  name   = "sweeper"
  role   = aws_iam_role.sweeper.id
  policy = data.aws_iam_policy_document.sweeper.json
}

resource "aws_lambda_function" "sweeper" {
  function_name = "${local.name}-sweeper"
  role          = aws_iam_role.sweeper.arn

  filename         = var.lambda_package
  source_code_hash = filebase64sha256(var.lambda_package)

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]

  memory_size = 256
  # It walks every agent serially — one consistent read and two HEADs each, plus
  # a second read for any agent it repairs — so this bounds a pass at roughly a
  # few thousand agents. The listing is newest-updated first, so the agents that
  # would stop being reached are the oldest and quietest, and a timeout raises
  # `sweeper-errors` rather than passing silently. Beyond that scale this needs
  # to checkpoint and resume, or fan out; it is sized for a register that is
  # small by design and instrumented so that outgrowing it is visible.
  timeout = 300

  environment {
    variables = {
      REGISTRY_ROLE   = "sweeper"
      REGISTRY_TABLE  = aws_dynamodb_table.registry.name
      REGISTRY_BUCKET = aws_s3_bucket.registry.id
      RUST_LOG        = "info"
    }
  }

  depends_on = [aws_cloudwatch_log_group.sweeper]
}

# EventBridge invokes Lambda asynchronously, so a sweep that reports a failure —
# which it does when even one agent could not be converged — is retried twice
# automatically, re-walking the entire register each time. The schedule already
# retries every hour, and a permanently unconvergeable agent would otherwise
# cost three full passes per tick for no new information.
resource "aws_lambda_function_event_invoke_config" "sweeper" {
  function_name          = aws_lambda_function.sweeper.function_name
  maximum_retry_attempts = 0
}

resource "aws_cloudwatch_event_rule" "sweep" {
  name                = "${local.name}-sweep"
  description         = "Reconcile the public read path against the register."
  schedule_expression = var.sweep_schedule
}

resource "aws_cloudwatch_event_target" "sweep" {
  rule = aws_cloudwatch_event_rule.sweep.name
  arn  = aws_lambda_function.sweeper.arn
}

resource "aws_lambda_permission" "sweep" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sweeper.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweep.arn
}

resource "aws_lambda_event_source_mapping" "reconciler" {
  event_source_arn = aws_dynamodb_table.registry.stream_arn
  function_name    = aws_lambda_function.reconciler.arn
  # TRIM_HORIZON, not LATEST. If this mapping is ever replaced — a stream ARN
  # change, a manual delete, a taint — LATEST resumes at the moment of
  # recreation and every record committed in the gap is skipped with no error
  # and no alarm, leaving those agents' pointers permanently wrong. From the
  # horizon the reconciler replays them instead; its actions are idempotent (it
  # writes the current pointer for a record it has already seen, or a later one)
  # and per-partition ordering means a replay cannot resurrect a superseded
  # card.
  starting_position = "TRIM_HORIZON"

  # One record at a time. Batching would trade a little cost for the chance of
  # one poisoned record blocking a shard, and publications are rare enough that
  # there is nothing to save.
  batch_size = 1

  # Each accepted write commits three items under one partition key; only the
  # `CURRENT` one says anything about what should be served. Without this the
  # other two are delivered and immediately ignored, which triples both the cost
  # and — more to the point — the length of any replay from the stream horizon.
  filter_criteria {
    filter {
      pattern = jsonencode({
        dynamodb = {
          Keys = {
            sk = { S = ["CURRENT"] }
          }
        }
      })
    }
  }

  # A shard that cannot make progress must not stall an agent's pointers
  # forever. But "give up after five tries" means the record is *discarded*: a
  # withdrawal whose S3 deletes were throttled would leave the card and JWKS
  # served at the edge, and withdrawal is terminal, so nothing on the stream
  # would ever overwrite them.
  #
  # The destination below does not solve that — it cannot, since it receives
  # batch metadata rather than the record. It is the alarm. The *sweeper* is the
  # recovery: it reads what is committed and makes the read path match, which
  # works whatever the stream lost and however long ago.
  maximum_retry_attempts = 5

  destination_config {
    on_failure {
      destination_arn = aws_sqs_queue.reconciler_dlq.arn
    }
  }
}

# Records the stream gave up on — or rather, what Lambda sends about them: for a
# stream source the failure destination receives batch metadata (a shard id and
# two sequence numbers), never the record itself. So this is a *signal*, not a
# recovery: it says a record was dropped and roughly where, and the sweeper is
# what puts the read path right. Fourteen days is the SQS maximum and the right
# choice, because the cost of a missed record is a public read path that
# disagrees with the register, which nobody may notice quickly.
resource "aws_sqs_queue" "reconciler_dlq" {
  name                      = "${local.name}-reconciler-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

# --- HTTP API ----------------------------------------------------------------

resource "aws_apigatewayv2_api" "registry" {
  name          = local.name
  protocol_type = "HTTP"
}

# The stage throttle is stage-wide: it cannot tell an attacker from a publisher,
# so a flood through it denies service to everyone. The rule that *can* tell
# them apart is the WAF one, and WAFv2 does not attach to HTTP APIs — it only
# exists at the edge. The Lambda therefore refuses any request that did not
# arrive with the distribution's header, which is what makes the edge the only
# way in.


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

  # Entries here are permanent and the stated abuse is bulk publication, so
  # "which address published what, and when" is the one question an operator
  # will need answered after the fact. Without this, nothing anywhere records
  # it.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId = "$context.requestId"
      # `sourceIp` is the immediate peer, which behind CloudFront is an edge
      # server — kept because it distinguishes an edge request from a direct
      # one. The publisher's own address arrives in `x-forwarded-for`, which
      # CloudFront always appends and which the origin request policy forwards.
      #
      # Not logged: `cloudfront-viewer-address`. It is generated by CloudFront
      # rather than sent by the viewer, and `AllViewerExceptHostHeader` forwards
      # viewer headers only — so the field would have been empty on every line.
      ip             = "$context.identity.sourceIp"
      forwardedFor   = "$request.header.x-forwarded-for"
      requestTime    = "$context.requestTime"
      method         = "$context.httpMethod"
      path           = "$context.path"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      latency        = "$context.responseLatency"
      integrationErr = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.registry.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.registry.execution_arn}/*/*"
}
