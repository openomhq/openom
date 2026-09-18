# openom infrastructure (Terraform)

The server deployment as code: the API on AWS Lambda (behind a Function URL), the GitHub-OIDC role CI
assumes to deploy it, the SHA-keyed artifact bucket, and the custom API domain (CloudFront + ACM +
Cloudflare DNS).

> A deeper, step-by-step operator guide (first-time account bring-up, secrets, promotion, rollback,
> incident runbooks) will live in a separate `DEPLOYMENT.md`. This file explains **how the code is
> laid out and why**; that one will explain **how to run a deploy end to end**.

## Layout

```
infra/terraform/
├── *.tf                     app ROOT — the Lambda, its exec role + boundary, Function URL,
│   ├── lambda.tf            log group, and the CI deploy role. Applied by CI on every deploy
│   ├── oidc.tf              (via the narrow GitHub-OIDC role) and by an admin for the parts CI
│   ├── artifacts.tf         can't touch (IAM, the OIDC provider).
│   └── …
├── env/                     per-env config for the app root (staging.tfvars + staging.s3.tfbackend)
├── modules/
│   └── api-domain/          REUSABLE module: CloudFront + DNS-validated ACM cert + Cloudflare DNS
│                            in front of a Lambda Function URL. Instantiated per (env, domain).
└── domain/                  domain ROOT — a thin per-env caller of modules/api-domain. Applied by an
    └── env/                 ADMIN only (needs CloudFront/ACM/Cloudflare rights CI doesn't have).
```

There are **two roots** (two independent state files), split by *who applies them* and *how often*:

| root        | applier                        | cadence        | state key               |
| ----------- | ------------------------------ | -------------- | ----------------------- |
| app (`./`)  | CI (GitHub OIDC role) + admin  | every deploy   | `staging/terraform.tfstate` |
| `domain/`   | admin (local, via SSO)         | rarely         | `domain/staging.tfstate`    |

Why split: CloudFront, ACM, and Cloudflare are **not** in the CI role's rights (and there is no
Cloudflare token in CI). Keeping the domain in the app root would force either widening the CI role or
having each apply plan to destroy the other's resources. Separate roots keep each applier's blast
radius to its own state. The domain root reads only the app Lambda's Function URL — via a direct
`aws_lambda_function_url` data lookup, **not** `terraform_remote_state`, so app-root secrets never get
copied into the domain state.

## Design principles

- **No DynamoDB.** State locking uses S3's native lock (`use_lockfile`, Terraform ≥ 1.10). Do not
  create a lock table.
- **Per-env state** in one shared, versioned state bucket, via partial backend config
  (`env/<env>.s3.tfbackend`). Resource names + tags carry `stack_name`.
- **No long-lived AWS keys.** The first/admin applies run under an IAM Identity Center session
  (`aws sso login`); CI thereafter federates via GitHub OIDC. No static credentials anywhere.
- **State-key layout enforces the split.** The CI role's state grant is scoped to `staging/*`, so the
  app state (`staging/terraform.tfstate`) is reachable by CI but the domain state (`domain/…`) is not.
- **Reusable where reuse is natural.** The CloudFront/ACM/DNS logic is a module so staging, production,
  and preview envs share one implementation. The Lambda app root is a flat per-env root (production is
  just new `env/*` files) — not modularized, because a single stack per env is the natural shape.

## Deploying the app (CI)

The deploy workflow assumes the CI role over OIDC (its job needs `environment: staging` and
`permissions: id-token: write`), builds the Lambda zip, uploads it SHA-keyed to the artifact bucket,
runs migrations, and `terraform apply`s the app root against `env/staging.tfvars`. Rollback is
re-pointing the `live` alias at a previous artifact.

## Admin apply (app root — for the IAM/OIDC parts CI can't create)

```sh
cd infra/terraform
aws sso login --profile <admin-profile>
export AWS_PROFILE=<admin-profile>

terraform init  -backend-config=env/staging.s3.tfbackend
terraform apply -var-file=env/staging.tfvars

terraform output ci_deploy_role_arn   # → GitHub 'staging' secret AWS_DEPLOY_ROLE_ARN
```

## API custom domain

See `domain/README.md`. In short: an admin runs `terraform apply` in `domain/` with an SSO session and
`CLOUDFLARE_API_TOKEN` set; it stands up CloudFront + an ACM cert for `api.<env>.openom.org` and points
Cloudflare DNS at it. Deploy the app stack first (the domain reads its Function URL).

## Adding production later

- **App root:** add `env/production.tfvars` (`stack_name = "production"`, its own state `key`,
  `manage_oidc_provider = false` — staging already owns the account-global OIDC provider) and
  `env/production.s3.tfbackend`, then `init -reconfigure` + apply as admin; wire the new role ARN into
  a GitHub `production` environment.
- **Domain root:** add `domain/env/production.tfvars` (`api_domain = "api.openom.org"`, the same
  openom.org zone id) and `domain/env/production.s3.tfbackend` (`key = "domain/production.tfstate"`).
  No module change.

## Security notes

- **CI deploy role is minimal.** It holds Lambda-on-the-function + logs + its own state/artifacts, a
  scoped `PassRole` for the exec role, and a `DenySelfMutation` guard — no `iam:*` role management, so
  it cannot widen itself. The exec role + permissions boundary live in a disjoint
  `openom-<stack>-exec-*` namespace, admin-applied.
- **OIDC trust** pins the token `sub` to this repo + the `staging` environment. It is only as strong as
  the GitHub environment protection (restrict the `staging` environment to `main`, add a required
  reviewer, and confirm fork PRs can't reach its secrets).
- **The raw Function URL stays public.** The Lambda Function URL is `AuthType NONE` and remains
  reachable at its `*.on.aws` host even with CloudFront in front. The app enforces JWT + CORS itself,
  so this is acceptable for **staging**, but it means edge-only controls (WAF, rate limiting) are
  bypassable via the origin host. **Before production**, lock the origin — a CloudFront-injected shared
  secret header the app requires is the pragmatic fit (native OAC signs the `Authorization` header,
  which collides with the API's `Bearer` JWT).

## Prerequisites (AWS side, done once)

1. An S3 **state bucket** (versioning + encryption + block-public-access). Put its name in both
   `env/staging.s3.tfbackend` (`bucket`) and `env/staging.tfvars` (`tf_state_bucket`).
2. Terraform ≥ 1.10 and the AWS CLI, with an Identity Center admin profile (`aws configure sso`).
3. **GitHub `staging` environment protection** limiting it to `main` (see OIDC trust note above).
