data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "preview_api_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "preview_api_boundary" {
  statement {
    sid    = "FunctionLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/openom-preview-*-api",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/openom-preview-*-api:*",
    ]
  }
}

resource "aws_iam_policy" "preview_api_boundary" {
  name   = "openom-preview-api-boundary"
  policy = data.aws_iam_policy_document.preview_api_boundary.json
}

resource "aws_iam_role" "preview_api" {
  name                 = "openom-preview-api-exec"
  assume_role_policy   = data.aws_iam_policy_document.preview_api_assume.json
  permissions_boundary = aws_iam_policy.preview_api_boundary.arn

  depends_on = [terraform_data.account_guard]
}

resource "aws_iam_role_policy" "preview_api_logs" {
  name   = "logs"
  role   = aws_iam_role.preview_api.id
  policy = data.aws_iam_policy_document.preview_api_boundary.json
}

data "aws_iam_policy_document" "preview_deploy_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_owner}@*/${var.github_repository}@*:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "preview_deploy" {
  name                 = "openom-preview-deploy"
  assume_role_policy   = data.aws_iam_policy_document.preview_deploy_assume.json
  max_session_duration = 3600

  depends_on = [terraform_data.account_guard]
}

data "aws_iam_policy_document" "preview_deploy" {
  statement {
    sid    = "PreviewFunctions"
    effect = "Allow"
    actions = [
      "lambda:CreateAlias",
      "lambda:CreateFunction",
      "lambda:DeleteAlias",
      "lambda:DeleteFunction",
      "lambda:GetAlias",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:GetPolicy",
      "lambda:ListAliases",
      "lambda:ListTags",
      "lambda:ListVersionsByFunction",
      "lambda:PublishVersion",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:UpdateAlias",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
    ]
    resources = [
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:openom-preview-*-api",
      "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:openom-preview-*-api:*",
    ]
  }

  statement {
    sid    = "ProtectedFunctionUrls"
    effect = "Allow"
    actions = [
      "lambda:CreateFunctionUrlConfig",
      "lambda:UpdateFunctionUrlConfig",
    ]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:openom-preview-*-api*"]

    condition {
      test     = "StringEquals"
      variable = "lambda:FunctionUrlAuthType"
      values   = ["AWS_IAM"]
    }
  }

  statement {
    sid    = "ReadDeleteFunctionUrls"
    effect = "Allow"
    actions = [
      "lambda:DeleteFunctionUrlConfig",
      "lambda:GetFunctionUrlConfig",
    ]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:openom-preview-*-api*"]
  }

  statement {
    sid       = "CloudFrontInvokeGrant"
    effect    = "Allow"
    actions   = ["lambda:AddPermission"]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:openom-preview-*-api*"]

    condition {
      test     = "StringEquals"
      variable = "lambda:Principal"
      values   = ["cloudfront.amazonaws.com"]
    }
  }

  statement {
    sid    = "PreviewLogGroups"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:ListTagsForResource",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/openom-preview-*-api*"]
  }

  statement {
    sid       = "DescribeLogGroups"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  statement {
    sid    = "PreviewArtifacts"
    effect = "Allow"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.artifacts.arn}/previews/*"]
  }

  statement {
    sid       = "PreviewArtifactsBucketRead"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation"]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid       = "PreviewArtifactsList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["previews/*"]
    }
  }

  statement {
    sid    = "PreviewRoutes"
    effect = "Allow"
    actions = [
      "cloudfront-keyvaluestore:DeleteKey",
      "cloudfront-keyvaluestore:DescribeKeyValueStore",
      "cloudfront-keyvaluestore:GetKey",
      "cloudfront-keyvaluestore:ListKeys",
      "cloudfront-keyvaluestore:PutKey",
      "cloudfront-keyvaluestore:UpdateKeys",
    ]
    resources = [aws_cloudfront_key_value_store.routes.arn]
  }

  statement {
    sid       = "PassPreviewExecutionRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.preview_api.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid    = "ReadPreviewExecutionRole"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = [aws_iam_role.preview_api.arn]
  }

  statement {
    sid    = "DenyDeployRoleMutation"
    effect = "Deny"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePermissionsBoundary",
      "iam:PutRolePolicy",
      "iam:UpdateAssumeRolePolicy",
    ]
    resources = [aws_iam_role.preview_deploy.arn]
  }
}

resource "aws_iam_role_policy" "preview_deploy" {
  name   = "openom-preview-deploy"
  role   = aws_iam_role.preview_deploy.id
  policy = data.aws_iam_policy_document.preview_deploy.json
}
