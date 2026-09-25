# Preview standing infrastructure

## What it is — and is not

This Terraform root owns the shared infrastructure used by every pull-request preview: the edge router,
wildcard domains, Pages project, preview object-store bucket, artifact bucket, and tightly scoped deployment
roles. It does not create per-preview Lambda functions, Neon branches, Pages deployments, KVS entries, or
object-store prefixes; preview workflows own those ephemeral resources.

The root is applied administratively. Pull-request code must never run Terraform here or receive its
Cloudflare and standing-infrastructure credentials.

The shared distribution serves only HTTP/2, keeps caching disabled, and points both unproxied wildcard DNS
records at the same edge. Unknown routes terminate at the edge. The declared origin is a protected Lambda
that always returns 404; its only purpose is to supply the OAC configuration inherited by dynamically selected
preview API origins.

The Pages project is direct-upload only; GitHub integration is intentionally absent so untrusted pull-request
code cannot trigger provider-side deployments. R2 permits presigned media access only from the preview app
wildcard. Every server still receives its own `OBJECT_STORE_KEY_PREFIX`; CORS is not an isolation boundary.
Lambda artifacts are private, encrypted at rest, and expire after seven days.

The shared API execution role can write only matching preview Lambda logs. The GitHub OIDC deployment role
can manage only `openom-preview-*-api` functions and log groups, `previews/*` artifact objects, and this root's
single KVS. It can pass only the shared execution role, cannot mutate IAM roles, cannot modify the standing
CloudFront distribution, and can create or update Function URLs only with `AWS_IAM` authorization.

## Route contract

The CloudFront KeyValueStore uses the normalized preview slug as its key. Its value is JSON:

```json
{
  "version": 1,
  "slug": "feat-ope-123",
  "sourceBranch": "feat/ope-123",
  "pullRequestNumber": 123,
  "commitSha": "0123456789abcdef0123456789abcdef01234567",
  "mode": "full",
  "webOrigin": "feat-ope-123.openom-preview.pages.dev",
  "apiOrigin": "abc123.lambda-url.eu-central-1.on.aws"
}
```

`mode` is `web` or `full`; `apiOrigin` is required only for `full`. The router rejects malformed records,
cross-slug records, unknown modes, untrusted origin suffixes, and unknown hosts. App routes explicitly disable
the protected Lambda origin's OAC. API routes replace only the origin hostname and inherit OAC signing.

## Administrative use

Authenticate the administrator profiles, export the provider-standard `CLOUDFLARE_API_TOKEN`, and initialize
with the preview backend configuration:

```sh
export AWS_PROFILE=openom-admin
export CLOUDFLARE_API_TOKEN=...
terraform -chdir=infra/terraform/preview init -backend-config=env/preview.s3.tfbackend
terraform -chdir=infra/terraform/preview plan -var-file=env/preview.tfvars -out=.terraform/preview.tfplan
terraform -chdir=infra/terraform/preview show -json .terraform/preview.tfplan | node scripts/preview-plan-check.mjs
```

The token is deliberately vendor-prefixed. The per-preview application namespace is not: workflows set the
server's vendor-independent `OBJECT_STORE_KEY_PREFIX=previews/<slug>/` regardless of the object-store provider.

Run the exact router-source tests from the repository root:

```sh
node --test scripts/preview-router.test.mjs
node --test scripts/preview-sink.test.mjs
```
