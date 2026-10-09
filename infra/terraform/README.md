# openom infrastructure (OpenTofu)

The server deployment as code: the API on AWS Lambda (behind a Function URL), the GitHub-OIDC role CI
assumes to deploy it, the SHA-keyed artifact bucket, and the custom API domain (CloudFront + ACM +
Cloudflare DNS).

Use OpenTofu 1.13 or newer. The Terraform CLI is not a supported substitute because the state-encryption
configuration is OpenTofu-specific. The existing `infra/terraform/` path remains to avoid needless path churn.

> A deeper, step-by-step operator guide (first-time account bring-up, secrets, promotion, rollback,
> incident runbooks) will live in a separate `DEPLOYMENT.md`. This file explains **how the code is
> laid out and why**; that one will explain **how to run a deploy end to end**.

## Layout

```
infra/terraform/
├── *.tf                     server ROOT — the Lambda, its exec role + boundary, Function URL,
│   ├── lambda.tf            log group, and the CI deploy role. Applied by CI on every deploy
│   ├── oidc.tf              (via the narrow GitHub-OIDC role) and by an admin for the parts CI
│   ├── artifacts.tf         can't touch (IAM, the OIDC provider).
│   └── …
├── env/                     per-env config for the server root (staging.tfvars + staging.s3.tfbackend)
├── modules/
│   └── api-domain/          REUSABLE module: CloudFront + DNS-validated ACM cert + Cloudflare DNS
│                            in front of a Lambda Function URL. Instantiated per (env, domain).
├── domain/                  admin ROOT — API domain plus the shared state bucket's controls.
├── web/                     web ROOT — the admin-applied Cloudflare Pages project and custom domain.
└── preview/                 preview-platform ROOT — shared routing and deployment infrastructure.
```

There are **four persistent roots** with independent state and encryption custody:

| root | applier | cadence | state key |
| --- | --- | --- | --- |
| server (`./`) | CI (GitHub OIDC role) + admin | every deploy | `staging/terraform.tfstate` |
| `domain/` | admin (local, via SSO) | rarely | `domain/staging.tfstate` |
| `web/` | admin (local) | rarely | `web/staging.tfstate` |
| `preview/` | admin (local) | rarely | `preview/terraform.tfstate` |

Why split: CloudFront, ACM, and Cloudflare are **not** in the CI role's rights (and there is no
Cloudflare token in CI). Keeping the domain in the server root would force either widening the CI role or
having each apply plan to destroy the other's resources. Separate roots keep each applier's blast
radius to its own state. The domain root reads only the server Lambda's Function URL — via a direct
`aws_lambda_function_url` data lookup, **not** `terraform_remote_state`, so server-root secrets never get
copied into the domain state.

The existing shared state bucket is managed from the staging `domain/` state. This keeps its control
plane outside CI without introducing a fifth persistent root or encryption passphrase. Other domain
environments must leave `manage_state_bucket = false`.

## Design principles

- **No DynamoDB.** State locking uses S3's native lock (`use_lockfile`, OpenTofu 1.13). Do not
  create a lock table.
- **Per-env state** in one shared, versioned state bucket, via partial backend config
  (`env/<env>.s3.tfbackend`). Resource names + tags carry `stack_name`.
- **No long-lived AWS keys.** The first/admin applies run under an IAM Identity Center session
  (`aws sso login`); CI thereafter federates via GitHub OIDC. No static credentials anywhere.
- **State-key layout enforces the split.** The CI role's state grant is scoped to `staging/*`, so the
  server state (`staging/terraform.tfstate`) is reachable by CI but the admin roots are not.
- **State is encrypted client-side.** Each root requires its own sensitive, ephemeral passphrase before
  OpenTofu can read state. See `STATE_ENCRYPTION.md` for custody, rotation, and recovery.
- **Reusable where reuse is natural.** The CloudFront/ACM/DNS logic is a module so staging, production,
  and preview envs share one implementation. The Lambda server root is a flat per-env root (production is
  just new `env/*` files) — not modularized, because a single stack per env is the natural shape.

## Deploying the server (CI)

The deploy workflow assumes the CI role over OIDC (its job needs `environment: staging` and
`permissions: id-token: write`), builds the Lambda zip, uploads it SHA-keyed to the artifact bucket,
runs migrations, and applies the server root against `env/staging.tfvars`. Rollback is
re-pointing the `live` alias at a previous artifact.

## Local server-root administration

> **Do not run an un-targeted local `tofu apply` in this root.** The deployed Lambda is count-gated
> by `lambda_artifact_key`. A local command that omits CI's artifact input evaluates that count as zero
> and plans deletion of the Lambda, alias, Function URL, and log group.

The server root currently mixes CI-deployed compute with admin-owned IAM/OIDC resources. Until those
admin resources move to their dedicated bootstrap root, local use is read-only: initialize the backend,
inspect state or outputs, and stop. IAM/OIDC changes require an explicitly reviewed target-only recovery
plan; do not improvise the target set from this README.

```sh
cd infra/terraform
aws sso login --profile <admin-profile>
export AWS_PROFILE=<admin-profile>

infisical run --env=staging --path=/github --command \
  'export TF_VAR_state_passphrase="$TOFU_STATE_PASSPHRASE_SERVER"; tofu init -backend-config=env/staging.s3.tfbackend && tofu output -raw ci_deploy_role_arn'
```

The output is non-secret configuration. Store it as the GitHub `staging` environment variable
`AWS_DEPLOY_ROLE_ARN`, not as an Infisical/GitHub secret.

## API custom domain

See `domain/README.md`. In short: an admin runs `tofu apply` in `domain/` with an SSO session and
`CLOUDFLARE_API_TOKEN` set; it stands up CloudFront + an ACM cert for `api.<env>.openom.org` and points
Cloudflare DNS at it. Deploy the server stack first (the domain reads its Function URL).

## Adding production later

- **Server root:** add `env/production.tfvars` (`stack_name = "production"`, its own state `key`,
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
- **Origin lock via a toggle.** The Function URL's auth is `var.lambda_url_auth_type`: `NONE` = public
  (reachable at its `*.on.aws` host), `AWS_IAM` = only CloudFront can invoke it (via OAC — the
  Origin Access Control + the CloudFront-principal grant live in the admin-applied `domain/` root).
  Under `AWS_IAM` the raw host 403s everyone else, so edge controls (WAF, rate-limit) can't be
  bypassed. Because OAC claims the `Authorization` header for its SigV4 signature, the client carries
  its JWT in `Openom-Auth` and a body digest in `x-amz-content-sha256` (both built into the app +
  client). Flip order matters — see the cutover below.

### Origin-lock cutover (NONE → AWS_IAM)

1. **App + client already speak it** — the server accepts `Openom-Auth` (falling back to
   `Authorization`), the client sends `Openom-Auth` + `x-amz-content-sha256`. Just deploy normally.
2. **Admin applies `domain/`** — adds the OAC + the CloudFront-principal invoke grant. Harmless while
   the URL is still `NONE` (additive).
3. **Flip:** set `lambda_url_auth_type = "AWS_IAM"` in `env/staging.tfvars` and apply the server root
   (CI or admin). The raw `*.on.aws` host now 403s; the custom domain keeps working via OAC.
4. Verify `https://api.<stack>.openom.org/health` still returns 200 (it flows through CloudFront).
   Reverse (`AWS_IAM` → `NONE`) is just the tfvar back; do it before step 2's teardown if rolling back.

## Prerequisites (AWS side, done once)

1. An S3 **state bucket** for first bootstrap. It is subsequently managed in place by the staging
   `domain/` root with versioning, encryption, SSE-C blocking, public-access blocking, ownership
   controls, and noncurrent-version retention. Put its name in each root's backend config and the
   server root's `tf_state_bucket` variable.
2. The OpenTofu version pinned in `.opentofu-version` and the AWS CLI, with an Identity Center admin
   profile (`aws configure sso`).
3. **GitHub `staging` environment protection** limiting it to `main` (see OIDC trust note above).
