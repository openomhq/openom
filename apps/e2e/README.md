# apps/e2e
> one-line: the Playwright browser e2e suite
**Status:** built · test harness · (no design ref)
**Last updated:** 2026-09-23

## Run
One-time: `cd apps && pnpm install --ignore-scripts && pnpm exec playwright install chromium`
Then, from `apps/`: `pnpm test:e2e` (default — excludes `@integration`), `pnpm test:e2e:full`
(everything), or `pnpm test:e2e:account` for the Docker-backed account acceptance. Playwright starts
`scripts/serve.mjs` itself; the account runner also starts the real local server stack and waits for `/ready`.

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
  → same durable member ID → decrypted tree reopen for both chain and DAG. Its fixed dev-auth subject exists
  only in the harness so the empty second context can authenticate before restoring custody; normal local
  development continues to use production `DevAuth`.

## Conventions
`.e2e.ts` = Playwright browser test (vitest only matches `*.test`/`*.spec`, so these are
invisible to it). Specs live in `./e2e`; a matching `*-harness.html` loads just the WASM/worker
under test with no app shell. Tests tagged `@integration` are excluded from the default `test:e2e` run;
most boot the full app, while the account round-trip intentionally uses a production-module harness to
control two independent auth/storage contexts.
