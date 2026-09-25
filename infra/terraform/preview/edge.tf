data "aws_caller_identity" "current" {}

resource "terraform_data" "account_guard" {
  input = data.aws_caller_identity.current.account_id

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_aws_account_id
      error_message = "Refusing to create preview resources outside the configured openom AWS account."
    }
  }
}

data "archive_file" "router_sink" {
  type        = "zip"
  source_file = "${path.module}/sink/index.mjs"
  output_path = "${path.module}/.terraform/router-sink.zip"
}

resource "aws_iam_role" "router_sink" {
  name = "openom-preview-router-sink-exec"
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

resource "aws_iam_role_policy" "router_sink_logs" {
  name = "logs"
  role = aws_iam_role.router_sink.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.router_sink.arn}:*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "router_sink" {
  name              = "/aws/lambda/openom-preview-router-sink"
  retention_in_days = 7
}

resource "aws_lambda_function" "router_sink" {
  function_name    = "openom-preview-router-sink"
  role             = aws_iam_role.router_sink.arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.router_sink.output_path
  source_code_hash = data.archive_file.router_sink.output_base64sha256
  architectures    = ["arm64"]
  memory_size      = 128
  timeout          = 3

  depends_on = [
    aws_cloudwatch_log_group.router_sink,
    aws_iam_role_policy.router_sink_logs,
    terraform_data.account_guard,
  ]
}

resource "aws_lambda_function_url" "router_sink" {
  function_name      = aws_lambda_function.router_sink.function_name
  authorization_type = "AWS_IAM"
  invoke_mode        = "BUFFERED"
}

resource "aws_cloudfront_key_value_store" "routes" {
  name    = "openom-preview-routes"
  comment = "Branch-slug routes for openom pull-request previews"
}

resource "aws_cloudfront_function" "router" {
  name                         = "openom-preview-router"
  runtime                      = "cloudfront-js-2.0"
  comment                      = "Route preview app and API hosts from the shared KVS"
  publish                      = true
  code                         = file("${path.module}/router.js")
  key_value_store_associations = [aws_cloudfront_key_value_store.routes.arn]
}

resource "aws_cloudfront_origin_access_control" "preview_api" {
  name                              = "openom-preview-api"
  description                       = "Sign shared-edge requests to protected preview Lambda URLs"
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

resource "aws_cloudfront_distribution" "preview" {
  aliases             = [var.app_domain, var.api_domain]
  comment             = "Shared edge for openom pull-request previews"
  enabled             = true
  http_version        = "http2"
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100"
  wait_for_deployment = true

  origin {
    domain_name              = trimsuffix(trimprefix(aws_lambda_function_url.router_sink.function_url, "https://"), "/")
    origin_id                = "protected-lambda-sink"
    origin_access_control_id = aws_cloudfront_origin_access_control.preview_api.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "protected-lambda-sink"
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

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.preview.certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
}

resource "aws_lambda_permission" "cloudfront_invoke_sink_url" {
  statement_id  = "AllowCloudFrontInvokeFunctionUrl"
  action        = "lambda:InvokeFunctionUrl"
  function_name = aws_lambda_function.router_sink.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.preview.arn
}

resource "aws_lambda_permission" "cloudfront_invoke_sink" {
  statement_id  = "AllowCloudFrontInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.router_sink.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.preview.arn
}
