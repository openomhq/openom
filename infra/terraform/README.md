# openom infrastructure (Terraform)

The staging/prod deployment as code. This is the **skeleton** (OPE-508): per-env remote state,
a `stack_name` identity, the GitHub-OIDC deploy role CI assumes, and the SHA-keyed Lambda artifact
bucket. The Lambda function itself (URL, exec role, Secrets Manager) lands next in **OPE-17**.

## Design notes

- **No DynamoDB.** State locking uses S3's native lock (`use_lockfile`, Terraform ≥ 1.10) — one less
  resource to run. Do **not** create a DynamoDB lock table.
- **Per-env state.** Each environment has its own state object in the one shared state bucket, via a
  partial backend config: `env/<env>.s3.tfbackend`. Resources + secret paths carry `stack_name`.
- **No long-lived AWS keys.** The **first** apply (which creates the OIDC role) runs with your IAM
  Identity Center admin session (`aws sso login`). CI thereafter federates via GitHub OIDC — no
  static credentials anywhere.

## Prerequisites (OPE-468, done by you at the AWS side)

1. An S3 **state bucket** (versioning + encryption + block-public-access on). Put its name in
   **both** `env/staging.s3.tfbackend` (`bucket`) and `env/staging.tfvars` (`tf_state_bucket`).
2. Terraform ≥ 1.10 and the AWS CLI locally, with an Identity Center admin profile configured
   (`aws configure sso`).
3. **GitHub `staging` environment protection** — REQUIRED for the OIDC trust to mean anything.
   In repo Settings → Environments → `staging`, add a deployment-branch rule limiting it to `main`
   (and ideally a required reviewer). Without it, any branch or PR that adds `environment: staging`
   to a job could assume the deploy role. Also confirm fork-PR workflows can't reach secrets.

## First apply (admin, local, via SSO)

```sh
cd infra/terraform
aws sso login --profile <your-admin-profile>
export AWS_PROFILE=<your-admin-profile>

terraform init -backend-config=env/staging.s3.tfbackend
terraform plan  -var-file=env/staging.tfvars
terraform apply -var-file=env/staging.tfvars
```

Then wire CI to the role it just created:

```sh
terraform output ci_deploy_role_arn   # → set as the GitHub 'staging' secret AWS_DEPLOY_ROLE_ARN
```

From here, the deploy workflow (OPE-20) assumes that role over OIDC — its job needs
`environment: staging` and `permissions: id-token: write` for the trust condition to match.

## Adding production later

Copy `env/staging.*` → `env/production.*`: set `stack_name = "production"`, its own state `key`, and
**`manage_oidc_provider = false`** (staging already created the account-global GitHub OIDC provider;
production looks it up). Then `init -reconfigure -backend-config=env/production.s3.tfbackend` and apply.

## Security notes

- The CI deploy role is **skeleton-minimal** (state + artifacts + read-only refresh) — it holds no
  `iam:CreateRole`/`AttachRolePolicy`/`lambda`/`secretsmanager`, so it cannot escalate. OPE-17 extends
  it with the Lambda + an exec role under a DISJOINT `openom-<stack>-exec-*` namespace plus a
  permissions boundary; apply that extension as the admin (a `DenySelfMutation` statement stops CI
  widening its own policy).
- `ci_deploy_trust` pins `sub` to `repo:openomhq/openom:environment:staging` — never widen to
  `repo:owner/repo:*`, and it's only as strong as the GitHub environment protection (prerequisite 3).
- After the first apply, sanity-check the provider once:
  `aws iam get-open-id-connect-provider --open-id-connect-provider-arn <arn>`.
