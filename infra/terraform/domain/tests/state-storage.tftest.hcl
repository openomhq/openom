mock_provider "aws" {
  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn = "arn:aws:cloudfront::123456789012:distribution/EXAMPLE"
    }
  }
}

mock_provider "aws" {
  alias = "app_region"

  mock_data "aws_lambda_function_url" {
    defaults = {
      function_url = "https://example.lambda-url.eu-central-1.on.aws/"
    }
  }
}

mock_provider "aws" {
  alias = "state_region"
}

mock_provider "cloudflare" {}

variables {
  stack_name          = "test"
  api_domain          = "api.test.openom.org"
  cloudflare_zone_id  = "00000000000000000000000000000000"
  manage_state_bucket = true
  state_bucket_name   = "openom-test-state"
}

run "state_bucket_controls" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state[0].bucket == var.state_bucket_name
    error_message = "The state bucket must use the explicitly configured existing bucket name."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.state[0].versioning_configuration).status == "Enabled"
    error_message = "State versioning must remain enabled."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state[0].rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    error_message = "The state bucket must retain SSE-S3 default encryption."
  }

  assert {
    condition     = length(one(aws_s3_bucket_server_side_encryption_configuration.state[0].rule).blocked_encryption_types) == 1 && one(aws_s3_bucket_server_side_encryption_configuration.state[0].rule).blocked_encryption_types[0] == "SSE-C"
    error_message = "The state bucket must reject SSE-C uploads."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.state[0].block_public_acls,
      aws_s3_bucket_public_access_block.state[0].block_public_policy,
      aws_s3_bucket_public_access_block.state[0].ignore_public_acls,
      aws_s3_bucket_public_access_block.state[0].restrict_public_buckets,
    ])
    error_message = "Every S3 public-access block must remain enabled."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.state[0].rule).object_ownership == "BucketOwnerEnforced"
    error_message = "The state bucket must keep bucket-owner-enforced ownership."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.state[0].rule[0].noncurrent_version_expiration[0].noncurrent_days == 30
    error_message = "Only noncurrent state versions should expire, after 30 days."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.state[0].rule[0].expiration) == 0
    error_message = "Current state objects must never receive an expiration rule."
  }
}

run "non_owner_creates_no_state_storage" {
  command = plan

  variables {
    manage_state_bucket = false
    state_bucket_name   = ""
  }

  assert {
    condition = alltrue([
      length(aws_s3_bucket.state) == 0,
      length(aws_s3_bucket_versioning.state) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.state) == 0,
      length(aws_s3_bucket_public_access_block.state) == 0,
      length(aws_s3_bucket_ownership_controls.state) == 0,
      length(aws_s3_bucket_lifecycle_configuration.state) == 0,
    ])
    error_message = "A non-owning environment must not manage any shared state-bucket resource."
  }
}
