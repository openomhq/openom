terraform {
  required_version = "~> 1.13.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "preview-spike"
      ManagedBy   = "terraform"
      Project     = "openom"
      Temporary   = "true"
    }
  }
}

variable "aws_region" {
  description = "Region for the temporary probe Lambdas."
  type        = string
  default     = "eu-central-1"
}

variable "expected_account_id" {
  description = "AWS account in which the temporary spike is allowed to run."
  type        = string
  default     = "841547768414"
}

data "aws_caller_identity" "current" {}

resource "terraform_data" "account_guard" {
  input = data.aws_caller_identity.current.account_id

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "Refusing to create preview-spike resources outside the configured openom AWS account."
    }
  }
}

locals {
  lambda_names = {
    a   = "openom-preview-spike-a"
    b   = "openom-preview-spike-b"
    web = "openom-preview-spike-web"
  }
  probe_token = "openom-preview-spike-token"
}

data "archive_file" "probe" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.js"
  output_path = "${path.module}/.terraform/probe.zip"
}

resource "aws_iam_role" "probe" {
  name = "openom-preview-spike-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "probe_logs" {
  name = "logs"
  role = aws_iam_role.probe.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/openom-preview-spike-*:*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "probe" {
  for_each          = local.lambda_names
  name              = "/aws/lambda/${each.value}"
  retention_in_days = 1
}

resource "aws_lambda_function" "probe" {
  for_each = local.lambda_names

  function_name    = each.value
  role             = aws_iam_role.probe.arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.probe.output_path
  source_code_hash = data.archive_file.probe.output_base64sha256
  architectures    = ["arm64"]
  memory_size      = 128
  timeout          = 5

  environment {
    variables = {
      PROBE_MARKER       = each.key
      PROBE_REQUIRE_AUTH = each.key == "web" ? "false" : "true"
      PROBE_TOKEN        = local.probe_token
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.probe,
    aws_iam_role_policy.probe_logs,
    terraform_data.account_guard,
  ]
}

resource "aws_lambda_function_url" "probe" {
  for_each           = aws_lambda_function.probe
  function_name      = each.value.function_name
  authorization_type = each.key == "web" ? "NONE" : "AWS_IAM"
  invoke_mode        = "BUFFERED"
}

resource "aws_cloudfront_key_value_store" "routes" {
  name    = "openom-preview-spike-routes"
  comment = "Temporary dynamic Lambda origin proof"
}

resource "aws_cloudfront_function" "router" {
  name                         = "openom-preview-spike-router"
  runtime                      = "cloudfront-js-2.0"
  comment                      = "Temporary dynamic Lambda origin proof"
  publish                      = true
  code                         = file("${path.module}/router.js")
  key_value_store_associations = [aws_cloudfront_key_value_store.routes.arn]
}

resource "aws_cloudfront_origin_access_control" "probe" {
  name                              = "openom-preview-spike-oac"
  description                       = "Temporary dynamic Lambda origin proof"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "spike" {
  enabled             = true
  is_ipv6_enabled     = true
  wait_for_deployment = true
  http_version        = "http2"
  comment             = "Temporary openom dynamic-origin security spike"
  price_class         = "PriceClass_100"

  origin {
    domain_name              = trimsuffix(trimprefix(aws_lambda_function_url.probe["a"].function_url, "https://"), "/")
    origin_id                = "protected-lambda"
    origin_access_control_id = aws_cloudfront_origin_access_control.probe.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "protected-lambda"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.router.arn
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

resource "aws_lambda_permission" "cloudfront_invoke_url" {
  for_each = { for key, value in aws_lambda_function.probe : key => value if key != "web" }

  statement_id  = "AllowCloudFrontInvokeFunctionUrl"
  action        = "lambda:InvokeFunctionUrl"
  function_name = each.value.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.spike.arn
}

resource "aws_lambda_permission" "cloudfront_invoke" {
  for_each = { for key, value in aws_lambda_function.probe : key => value if key != "web" }

  statement_id  = "AllowCloudFrontInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = each.value.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.spike.arn
}

resource "aws_lambda_permission" "web_public_url" {
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.probe["web"].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "web_public_invoke" {
  statement_id  = "AllowPublicFunctionUrlInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.probe["web"].function_name
  principal     = "*"
}

output "spike" {
  value = {
    account_id       = data.aws_caller_identity.current.account_id
    aws_region       = var.aws_region
    distribution_url = "https://${aws_cloudfront_distribution.spike.domain_name}"
    kvs_arn          = aws_cloudfront_key_value_store.routes.arn
    lambda_urls      = { for key, value in aws_lambda_function_url.probe : key => value.function_url }
    lambda_hosts = {
      for key, value in aws_lambda_function_url.probe :
      key => trimsuffix(trimprefix(value.function_url, "https://"), "/")
    }
    probe_token = local.probe_token
  }
  sensitive = true
}
