resource "cloudflare_r2_bucket" "preview" {
  account_id    = var.cloudflare_account_id
  name          = var.r2_bucket_name
  location      = "weur"
  storage_class = "Standard"
}

resource "cloudflare_r2_bucket_cors" "preview" {
  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.preview.name

  rules = [{
    id = "preview-app-media"
    allowed = {
      origins = ["https://${var.app_domain}"]
      methods = ["GET", "HEAD", "PUT"]
      headers = [
        "content-type",
        "x-amz-checksum-sha256",
      ]
    }
    expose_headers  = ["etag", "x-amz-checksum-sha256"]
    max_age_seconds = 7200
  }]
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = var.artifacts_bucket_name
  force_destroy = true

  depends_on = [terraform_data.account_guard]
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

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

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-preview-artifacts"
    status = "Enabled"

    filter {}

    expiration {
      days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_ownership_controls.artifacts]
}
