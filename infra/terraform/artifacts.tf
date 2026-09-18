# Lambda deploy artifacts: CI uploads the built zip keyed by git SHA (openom/<sha>.zip); the Lambda
# promotes a specific key (var.lambda_artifact_key). Private, versioned, encrypted.
resource "aws_s3_bucket" "artifacts" {
  bucket = "openom-${var.stack_name}-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Refuse any non-TLS request to the bucket — standard S3 hardening.
data "aws_iam_policy_document" "artifacts_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls_only.json
}

output "artifacts_bucket" {
  description = "S3 bucket CI uploads the SHA-keyed Lambda zip to."
  value       = aws_s3_bucket.artifacts.id
}

output "ci_deploy_role_arn" {
  description = "ARN of the OIDC deploy role CI assumes — set as the GitHub `staging` secret AWS_DEPLOY_ROLE_ARN."
  value       = aws_iam_role.ci_deploy.arn
}
