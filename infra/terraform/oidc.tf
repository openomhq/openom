data "aws_caller_identity" "current" {}

# --- GitHub OIDC provider (an account-global SINGLETON) ---
# AWS allows only one provider per URL per account, so only the stack that OWNS it creates it
# (manage_oidc_provider = true); every other stack/env in the account looks it up as a data source.
# Without this split, applying a second environment into account 841547768414 fails with
# EntityAlreadyExists. Fetch GitHub's TLS thumbprint dynamically (it rotates).
data "tls_certificate" "github" {
  count = var.manage_oidc_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.manage_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github[0].certificates[0].sha1_fingerprint]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.manage_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

locals {
  github_oidc_provider_arn = one(concat(
    aws_iam_openid_connect_provider.github[*].arn,
    data.aws_iam_openid_connect_provider.github[*].arn,
  ))
}

# --- CI deploy role: trust ---
# SECURITY-CRITICAL. Scoped to exactly this repo AND the protected `staging` environment: only a
# `staging`-gated job in openomhq/openom can assume it. This is only meaningful if the GitHub
# `staging` environment actually has protection (branch policy → main + required reviewers); confirm
# that before wiring AWS_DEPLOY_ROLE_ARN into CI (see README).
data "aws_iam_policy_document" "ci_deploy_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Match the clean `repository` + `environment` claims, NOT `sub`: this org's OIDC subs carry
    # immutable numeric ids (repo:owner@<id>/repo@<id>:...), so a plain sub string never matches.
    # Together these pin the assume to exactly openomhq/openom's staging-gated jobs.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository"
      values   = ["${var.github_owner}/${var.github_repo}"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:environment"
      values   = [var.github_environment]
    }
  }
}

resource "aws_iam_role" "ci_deploy" {
  name                 = "openom-${var.stack_name}-ci-deploy"
  assume_role_policy   = data.aws_iam_policy_document.ci_deploy_trust.json
  max_session_duration = 3600
}

# --- CI deploy role: permissions ---
# SKELETON scope only — what CI needs to `terraform plan/apply` the resources THIS config manages:
# the per-env state, the artifacts bucket (+ its sub-resources), and read-only refresh of the OIDC
# provider + its own role. Deliberately NO iam:CreateRole/AttachRolePolicy/lambda/secrets here: the
# exec role and compute resources arrive in OPE-17, which extends this policy with a DISJOINT
# `openom-<stack>-exec-*` role namespace + a permissions boundary (so CI can never mint an
# admin-capable role). That extension is a platform change applied by the admin, not by CI (the Deny
# below stops CI widening its own policy).
data "aws_iam_policy_document" "ci_deploy_perms" {
  statement {
    sid       = "TerraformStateObject"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.tf_state_bucket}/${var.stack_name}/*"]
  }
  # Prefix-scoped listing so staging's role can't enumerate another env's state objects.
  statement {
    sid       = "TerraformStateList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.tf_state_bucket}"]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.stack_name}/*"]
    }
  }
  # Full control of the ARTIFACTS bucket only (build zips — non-secret). Deliberately broad: the aws
  # provider's S3 refresh probes ~a dozen GetBucket* sub-configs, tedious + brittle to enumerate one
  # by one. Scoped to the single openom-<stack>-artifacts bucket, so blast radius is minimal — and
  # bucket reads/writes are not an IAM-escalation vector.
  statement {
    sid       = "Artifacts"
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
  }
  # Read-only refresh of the OIDC provider (only present in the owning stack) + CI's own role.
  statement {
    sid       = "OidcProviderRead"
    effect    = "Allow"
    actions   = ["iam:GetOpenIDConnectProvider", "iam:TagOpenIDConnectProvider", "iam:ListOpenIDConnectProviderTags"]
    resources = [local.github_oidc_provider_arn]
  }
  statement {
    sid       = "SelfRoleRead"
    effect    = "Allow"
    actions   = ["iam:GetRole", "iam:ListRoleTags", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole"]
    resources = [aws_iam_role.ci_deploy.arn]
  }
  # HARD DENY (a Deny always wins): CI can never mutate its OWN role or trust. Closes the
  # self-escalation path structurally, independent of any prefix/namespace change above.
  statement {
    sid    = "DenySelfMutation"
    effect = "Deny"
    actions = [
      "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:DetachRolePolicy",
      "iam:UpdateAssumeRolePolicy", "iam:DeleteRole", "iam:PutRolePermissionsBoundary",
    ]
    resources = [aws_iam_role.ci_deploy.arn]
  }
}

resource "aws_iam_role_policy" "ci_deploy" {
  name   = "openom-${var.stack_name}-ci-deploy"
  role   = aws_iam_role.ci_deploy.id
  policy = data.aws_iam_policy_document.ci_deploy_perms.json
}
