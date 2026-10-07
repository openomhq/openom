# Preview standing infrastructure

## Deployment status

The standing platform was first applied on 2026/10/06. Its encrypted OpenTofu state is stored under
`preview/terraform.tfstate`, and the non-secret outputs consumed by lifecycle workflows are published as
variables on the GitHub `preview` environment. A post-apply plan is clean. Both wildcard hosts return the
router's deterministic, non-cacheable 404 for unknown slugs, while direct access to the protected sink
Function URL is rejected with `403 Forbidden`.

## What it is — and is not

This OpenTofu root owns the shared infrastructure used by every pull-request preview: the edge router,
wildcard domains, Pages project, EU-jurisdiction preview object-store bucket, artifact bucket, and tightly scoped deployment
roles. It does not create per-preview Lambda functions, Neon branches, Pages deployments, KVS entries, or
object-store prefixes; preview workflows own those ephemeral resources.

The root is applied administratively. Pull-request code must never run OpenTofu here or receive its
Cloudflare and standing-infrastructure credentials.

The GitHub `preview` environment is the credential boundary. It accepts only `main`, and lifecycle jobs use
`environment.deployment: false` so accessing its variables, secrets, and AWS OIDC identity does not create a
misleading deployment for `main`. Successful previews are instead recorded against the exact pull-request SHA
in the separate, non-secret `preview-deployments` record environment.

The shared distribution serves only HTTP/2, keeps caching disabled, and points both unproxied wildcard DNS
records at the same edge. Unknown routes terminate at the edge. The declared origin is a protected Lambda
that always returns 404; its only purpose is to supply the OAC configuration inherited by dynamically selected
preview API origins.

The Pages project is direct-upload only; GitHub integration is intentionally absent so untrusted pull-request
code cannot trigger provider-side deployments. R2 is created with the `eu` jurisdiction restriction and permits
presigned media access only from the preview app wildcard. Every server still receives its own
`OBJECT_STORE_KEY_PREFIX`; CORS is not an isolation boundary.
Lambda artifacts are private, encrypted at rest, and expire after seven days.

The shared API execution role can write only matching preview Lambda logs. The GitHub OIDC deployment role
can manage only `openom-preview-*-api` functions and log groups, `previews/*` artifact objects, and this root's
single KVS. It can pass only the shared execution role, cannot mutate IAM roles, cannot modify the standing
CloudFront distribution, and can create or update Function URLs only with `AWS_IAM` authorization.

Ephemeral resources carry the source branch, pull-request number, and normalized slug as ownership metadata.
Cleanup removes the public route first, waits for deterministic edge 404 responses, then deletes the owned
Lambda and logs, Neon branch, exact object-store and artifact prefixes, and finally retires the GitHub
deployment record. A nightly janitor reconciles tagged resources against currently approved same-repository
pull requests. These machine-readable ownership and lifecycle records are also the intended observation
surface for future operational tooling; they are not a substitute for provider-side authorization checks.

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

Authenticate the administrator profile, then initialize through Infisical so the provider token and independent
preview-state passphrase exist only in the child shell:

```sh
export AWS_PROFILE=openom-admin
cd infra/terraform/preview
infisical run --env=prod --path=/admin --command \
  'export TF_VAR_state_passphrase="$TOFU_STATE_PASSPHRASE_PREVIEW_PLATFORM"; tofu init -backend-config=env/preview.s3.tfbackend && tofu plan -var-file=env/preview.tfvars -out=.terraform/preview.tfplan'
cd ../../..
tofu -chdir=infra/terraform/preview show -json .terraform/preview.tfplan | node scripts/preview-plan-check.mjs
```

The token is deliberately vendor-prefixed. The per-preview application namespace is not: workflows set the
server's vendor-independent `OBJECT_STORE_KEY_PREFIX=previews/<slug>/` regardless of the object-store provider.

Run the exact router-source tests from the repository root:

```sh
node --test scripts/preview-router.test.mjs
node --test scripts/preview-sink.test.mjs
```

## Preview lifecycle

Previews are deliberately not automatic. A maintainer adds `preview` for a web-only preview or `full-preview`
for an isolated full stack, then manually runs `preview.deploy` from `main` with the pull-request number and
matching mode. The workflow rechecks that the actor has `maintain` or `admin` permission, resolves the current
head SHA, and builds that SHA without credentials. Only trusted automation checked out from `main` can access
the `preview` environment, deploy the artifact, or update the route store.

Later commits do not alter the deployed preview. A maintainer explicitly dispatches the workflow again to pin
and deploy the new head. A web-only run publishes the app and leaves the API route as a deterministic 404. A
full-stack run reconciles the pull request's owned Neon branch, applies its migrations, deploys a protected
versioned Lambda behind the `live` alias, assigns the dedicated R2 prefix, publishes both routes, and runs the
deployed Supabase account round trip before advertising success. Route and Lambda rollback checkpoints are
written before later fallible operations so an interrupted acceptance can restore the previously advertised
stack.

The Supabase credentials in the `preview` environment must belong to a dedicated disposable preview fixture,
not the staging acceptance account. Deployed pull-request JavaScript participates in the browser acceptance;
isolating the fixture prevents an approved but untrusted preview from acquiring credentials that can access
staging application data.

Removing the last preview-approval label or closing the pull request emits an unprivileged lifecycle signal.
Trusted automation from `main` rechecks current GitHub state before cleanup. A scheduled janitor handles
missed signals and abandoned resources. A maintainer can replay the same lifecycle path by manually running
`preview.lifecycle` from `main` with the pull-request number; the trusted cleanup validates both the actor and
pull request before touching resources. On branch rename, the old stack remains reachable until the newly
named route exists, after which the janitor removes the old owned stack. The direct-upload Pages branch may
remain as a static artifact; it has no application credentials or server-side data, and the official wildcard
route no longer resolves to it after cleanup.
