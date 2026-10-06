locals {
  state_noncurrent_version_retention_days = 30
}

# This existing bucket is imported in place. It stores this root's own state, so prevent_destroy is
# the final guard against an accidental teardown after state recovery or configuration refactoring.
resource "aws_s3_bucket" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = var.state_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = aws_s3_bucket.state[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = aws_s3_bucket.state[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }

    bucket_key_enabled       = true
    blocked_encryption_types = ["SSE-C"]
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = aws_s3_bucket.state[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = aws_s3_bucket.state[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  provider = aws.state_region
  count    = var.manage_state_bucket ? 1 : 0
  bucket   = aws_s3_bucket.state[0].id

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = local.state_noncurrent_version_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}
