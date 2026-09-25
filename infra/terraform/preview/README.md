# Preview standing infrastructure

## What it is — and is not

This Terraform root owns the shared infrastructure used by every pull-request preview: the edge router,
wildcard domains, Pages project, preview object-store bucket, artifact bucket, and tightly scoped deployment
roles. It does not create per-preview Lambda functions, Neon branches, Pages deployments, KVS entries, or
object-store prefixes; preview workflows own those ephemeral resources.

The root is applied administratively. Pull-request code must never run Terraform here or receive its
Cloudflare and standing-infrastructure credentials.

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
terraform -chdir=infra/terraform/preview plan -var-file=env/preview.tfvars
```

The token is deliberately vendor-prefixed. The per-preview application namespace is not: workflows set the
server's vendor-independent `OBJECT_STORE_KEY_PREFIX=previews/<slug>/` regardless of the object-store provider.

Run the exact router-source tests from the repository root:

```sh
node --test scripts/preview-router.test.mjs
```
