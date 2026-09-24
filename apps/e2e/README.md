# apps/e2e
> one-line: the Playwright browser e2e suite
**Status:** built · test harness · (no design ref)
**Last updated:** 2026-09-24

## Run
One-time: `cd apps && pnpm install --ignore-scripts && pnpm exec playwright install chromium`
Then, from `apps/`: `pnpm test:e2e` (default — excludes `@integration`), `pnpm test:e2e:full`
(everything), or `pnpm test:e2e:account` for the Docker-backed account acceptance. Playwright starts
`scripts/serve.mjs` itself; the account runner also starts the real local server stack and waits for `/ready`.
Run `pnpm test:e2e:durable-identity` for the OPE-547 DAG acceptance against an ephemeral
`AUTH=jwt` / HS256 server on port 6061; it leaves the ordinary development server untouched.
Run `pnpm test:e2e:supabase-auth` for the isolated local GoTrue ES256/JWKS sign-up/sign-in round trip and a
second confirmation-required sign-up. The staging web deployment additionally runs `staging-auth.e2e.ts`
against the deployed app, CSP, Supabase project, and API using credentials from the protected `staging`
environment.

```sh
cd apps
pnpm test:e2e
```

## What it covers
- `vault.e2e.ts` + `vault-harness.html` — the compiled WASM sealer/vault alone (no app boot):
  cross-device unlock, wrong-passphrase rejection, ciphertext-at-rest.
- `sealer-worker.e2e.ts` + `sealer-worker-harness.html` — the same, through the real crypto Web
  Worker + Comlink boundary (provision/seal/open proxied to the worker; keys never leave it).
- `sync-worker.e2e.ts` + `sync-worker-harness.html` — the max-Rust app-core sync path in a real
  browser: two Web Workers (two devices of one tree) running the wasm engine + sealer + docsync loop
  + local store + replicator, meeting through an in-page transport. Asserts they converge and that an
  un-pushed offline mint is still offered outbound once a transport attaches. It also runs two workers for one
  browser profile and verifies that an account re-wrap invalidates the peer's stale account/tree custody, and
  that stale backup acknowledgements cannot clear a newer pending journal entry. Chain and DAG fault-injection
  cases also prove a web tick republishes a locally committed membership change before allowing an attributed
  data delta onto the remote channel.
- `sqlite.e2e.ts` + `sqlite-harness.html` / `sqlite-harness.worker.js` — WASM SQLite over the
  OPFS-SAHPool VFS, run in a module Worker; asserts data survives a page reload, header-free
  (no COOP/COEP).
- `smoke.e2e.ts` (`@integration`, `test:e2e:full` only) — boots the whole app: welcome/demo gate,
  create → recovery code → onboarding → reload/unlock, change-passphrase, lock-now, and
  forgot-passphrase recovery.
- `account-roundtrip.e2e.ts` + `account-roundtrip-harness.html` (`@integration`, dedicated
  `test:e2e:account`) — uses the production account facade, worker, remote store, and tree projection
  against the Docker server. Two isolated browser contexts prove register → backup → fresh-device restore
  → same durable member ID → decrypted tree reopen for both chain and DAG. The ordinary runner uses a fixed
  dev-auth subject; the Supabase runner signs up through the production `SupabaseAuth` provider against local GoTrue,
  then signs in from the fresh restore context.
- `durable-identity.e2e.ts` + `durable-identity-harness.html` (`@integration`, dedicated
  `test:e2e:durable-identity`) — runs the DAG engine against a Docker server in real `AUTH=jwt` mode with
  self-minted HS256 tokens whose provider subject deliberately differs from the durable member ID. It proves
  both onboarding orders (register before the first tree, or register after an offline local tree), verifies
  the latter does not change the owner or DAG anchor, and checks passphrase change and recovery preserve the
  identity, keyring, and tree contents.
- `staging-auth.e2e.ts` (`@staging`, deployment workflow only) — unlocks the real staging Pages gate,
  verifies its build marker matches the dispatched commit and its secure admission cookie is set, checks the
  assembled Supabase metadata and CSP, then uses deployed production modules to sign in, force a token refresh,
  bind/backup the stable test identity, and restore it in a fresh browser context. The dedicated account
  passphrase never enters committed fixtures or test output.

## Conventions
`.e2e.ts` = Playwright browser test (vitest only matches `*.test`/`*.spec`, so these are
invisible to it). Specs live in `./e2e`; a matching `*-harness.html` loads just the WASM/worker
under test with no app shell. Tests tagged `@integration` are excluded from the default `test:e2e` run;
most boot the full app, while the account round-trip intentionally uses a production-module harness to
control two independent auth/storage contexts.
