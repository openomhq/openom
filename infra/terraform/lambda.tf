locals {
  fn_name = "openom-${var.stack_name}-api"
  # The Lambda + its URL + log group only exist once a built artifact is available. The admin's first
  # apply (artifact key empty) stands up the IAM/role scaffolding; CI's deploy (OPE-20) sets the
  # SHA-keyed artifact and brings the function up. So nobody has to cross-compile Rust locally.
  lambda_on = var.lambda_artifact_key != "" ? 1 : 0
}

# --- Lambda execution role (admin-managed, boundary-capped) ---
# Created here as a STATIC resource under the disjoint openom-<stack>-exec-* namespace (never the
# ci-deploy role). CI never creates IAM roles — it only passes this one to the function — so there's
# no role-creation escalation surface. The permissions boundary caps it regardless.
data "aws_iam_policy_document" "exec_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "exec_boundary" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/openom-${var.stack_name}-*"]
  }
}

resource "aws_iam_policy" "exec_boundary" {
  name   = "openom-${var.stack_name}-exec-boundary"
  policy = data.aws_iam_policy_document.exec_boundary.json
}

resource "aws_iam_role" "exec" {
  name                 = "openom-${var.stack_name}-exec"
  assume_role_policy   = data.aws_iam_policy_document.exec_assume.json
  permissions_boundary = aws_iam_policy.exec_boundary.arn
}

# The function talks to Neon/R2/Supabase over the network (not AWS APIs), and secrets arrive as env
# vars — so the exec role needs only to write its own logs.
data "aws_iam_policy_document" "exec_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.fn_name}:*"]
  }
}

resource "aws_iam_role_policy" "exec_logs" {
  name   = "logs"
  role   = aws_iam_role.exec.id
  policy = data.aws_iam_policy_document.exec_logs.json
}

# --- The function, its URL, and its log group (all gated on an artifact existing) ---
resource "aws_cloudwatch_log_group" "api" {
  count             = local.lambda_on
  name              = "/aws/lambda/${local.fn_name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "api" {
  count         = local.lambda_on
  function_name = local.fn_name
  role          = aws_iam_role.exec.arn
  architectures = ["arm64"]
  runtime       = "provided.al2023" # Rust custom runtime (cargo lambda → bootstrap)
  handler       = "bootstrap"
  s3_bucket     = aws_s3_bucket.artifacts.id
  s3_key        = var.lambda_artifact_key
  memory_size   = 256
  timeout       = 15
  publish       = true # immutable versions, so the alias promotes/rolls back atomically
  depends_on    = [aws_iam_role_policy.exec_logs, aws_cloudwatch_log_group.api]

  environment {
    variables = {
      # Identity / behaviour (storage=cloud + auth=jwt are presets of OPENOM_RUNTIME=remote).
      OPENOM_RUNTIME = "remote"
      OPENOM_ENV     = var.stack_name
      OPENOM_STACK   = var.stack_name
      OPENOM_OTEL    = "1"
      # Non-secret env-specific config (CI supplies from the GitHub `staging` variables).
      OTEL_EXPORTER_OTLP_ENDPOINT = var.otlp_endpoint
      S3_ENDPOINT                 = var.s3_endpoint
      S3_PUBLIC_ENDPOINT          = var.s3_public_endpoint
      S3_BUCKET                   = var.s3_bucket
      S3_REGION                   = var.s3_region
      AUTH_JWT_ALG                = "ES256" # Supabase = asymmetric ES256 via JWKS (no shared secret)
      AUTH_JWKS_URL               = var.jwks_url
      AUTH_JWT_ISS                = var.jwt_issuer
      AUTH_JWT_AUD                = var.jwt_audience
      OPENOM_WEB_ORIGINS          = var.web_origins
      # Secrets (CI supplies from the GitHub `staging` secrets as TF_VAR_*).
      DATABASE_URL               = var.database_url
      S3_ACCESS_KEY              = var.s3_access_key
      S3_SECRET_KEY              = var.s3_secret_key
      OTEL_EXPORTER_OTLP_HEADERS = var.otlp_headers
      OPENOM_INTERNAL_GC_TOKEN   = var.internal_gc_token
    }
  }
}

# The "live" alias the Function URL serves. CI promotes it to each newly published version; a
# rollback re-points it to the prior version with no code change.
resource "aws_lambda_alias" "live" {
  count            = local.lambda_on
  name             = "live"
  function_name    = aws_lambda_function.api[0].function_name
  function_version = aws_lambda_function.api[0].version
}

# Public front door → the ALIAS (not $LATEST). The app enforces JWT auth; CORS is handled in-app
# (the CorsLayer), so no Function-URL CORS block (it would shadow the app + split the source of truth).
resource "aws_lambda_function_url" "api" {
  count              = local.lambda_on
  function_name      = aws_lambda_function.api[0].function_name
  qualifier          = aws_lambda_alias.live[0].name
  authorization_type = "NONE"
}

# AuthType NONE needs an explicit public invoke grant, scoped to the alias. Since Oct 2025 AWS
# requires BOTH lambda:InvokeFunctionUrl AND lambda:InvokeFunction on the resource policy or the URL
# 403s — so there are two permissions, both scoped to NONE-URL invocations.
resource "aws_lambda_permission" "url_public" {
  count                  = local.lambda_on
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.api[0].function_name
  qualifier              = aws_lambda_alias.live[0].name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_public_invoke" {
  count                  = local.lambda_on
  statement_id           = "AllowPublicFunctionUrlInvoke"
  action                 = "lambda:InvokeFunction"
  function_name          = aws_lambda_function.api[0].function_name
  qualifier              = aws_lambda_alias.live[0].name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# --- CI-perms extension (OPE-17) ---
# Grows the deploy role so CI (OPE-20) can create/update the function + its URL + log group and PASS
# the exec role — but NOT create/modify IAM roles (the exec role is admin-managed above). Applied by
# the admin, since the DenySelfMutation in oidc.tf stops CI widening its own policy.
data "aws_iam_policy_document" "ci_deploy_lambda" {
  statement {
    sid     = "Function"
    effect  = "Allow"
    actions = ["lambda:*"]
    resources = [
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.fn_name}",
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.fn_name}:*",
    ]
  }
  # A few Lambda calls the API only allows at "*" (no resource-level support).
  statement {
    sid       = "FunctionAccountScoped"
    effect    = "Allow"
    actions   = ["lambda:GetAccountSettings", "lambda:ListFunctions"]
    resources = ["*"]
  }
  # DescribeLogGroups has no resource-level scoping (it's account-wide) — must be on "*".
  statement {
    sid       = "LogGroupDescribe"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
  # Full control of ONLY the function's own log group (+ its streams) — low-risk, avoids the
  # tag/retention API whack-a-mole.
  statement {
    sid       = "LogGroupManage"
    effect    = "Allow"
    actions   = ["logs:*"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.fn_name}*"]
  }
  # Pass (only) the exec role to Lambda + read it/the boundary for state refresh. No CreateRole.
  statement {
    sid       = "PassExecRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.exec.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadExecRoleAndBoundary"
    effect    = "Allow"
    actions   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags", "iam:ListInstanceProfilesForRole", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
    resources = [aws_iam_role.exec.arn, aws_iam_policy.exec_boundary.arn]
  }
}

resource "aws_iam_role_policy" "ci_deploy_lambda" {
  name   = "openom-${var.stack_name}-ci-deploy-lambda"
  role   = aws_iam_role.ci_deploy.id
  policy = data.aws_iam_policy_document.ci_deploy_lambda.json
}

output "api_url" {
  description = "Public Function URL of the staging API (populated once a Lambda artifact is deployed)."
  value       = local.lambda_on == 1 ? aws_lambda_function_url.api[0].function_url : null
}
