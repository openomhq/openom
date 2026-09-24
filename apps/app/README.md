# apps/app

> The buildless web client — plain ES modules the browser loads directly, driving the same Rust
> core (via wasm) that Tauri bundles for desktop/mobile.

**Status:** built · the web shell of the one-core-three-shells architecture · design §ref: none
(the module-level `§`-refs — SERVER-DATA-FORMAT, the launch-gate design — live inline in the
`core/` files they govern, not in one apps/app-level doc)

**Last updated:** 2026-09-24

## Run / verify

All commands run from `apps/` (this unit has no `package.json` of its own — `apps/package.json`
is the one that defines these scripts).

```sh
cd apps
pnpm install
pnpm serve                 # this app on http://localhost:5173 (store = IndexedDB); serve.mjs is a
                            # tiny static server, needed only because file:// blocks ES modules/IndexedDB
pnpm serve:preview          # serves apps/preview/desktop.html instead, same server
pnpm test:core              # unit (*.test) + integration (*.int) tests for src/, via vitest
pnpm test:e2e               # Playwright, browser-driven (excludes @integration-tagged specs)
pnpm test:e2e:full          # Playwright, the full suite including @integration specs
pnpm typecheck              # strict main-thread + Web Worker checking, without emitting build output
pnpm check:locales          # every locale in app/locales/ carries the same keys as en.ftl
```

`pnpm test:core` runs vitest **inside a Docker container** (`node ../scripts/vitest.mjs`) — not
because of cargo, but because this host's supply-chain policy makes `pnpm install`'s esbuild
build-script check fatal; a container's pnpm has no such policy. Docker Desktop must be running.

`pnpm typecheck` likewise runs the pinned TypeScript checker inside Docker. It uses separate strict
main-thread and Web Worker configurations, emits nothing, and therefore preserves the buildless runtime.
The generated `src/vendor/app-core/openom_app_core.d.ts` must exist first; build it from the repository
root with `node scripts/build-app-core.mjs` when the runner reports that it is missing. App-owned declarations
under `src/core/types/` restore domain distinctions erased by wasm-bindgen; compile-only fixtures under
`apps/typecheck/` prove that same-representation swaps remain checker errors. The shared app-core RPC
contract models the production surface once for both the Comlink worker and native host; browser-only extensions
live separately rather than becoming accidental native requirements. Files enter checking through the explicit,
fail-closed roots in `tsconfig.main.json`, `tsconfig.native.json`, and `tsconfig.worker.json`; do not rely on
per-file `// @ts-check` pragmas. The blocking `web` CI workflow regenerates the gitignored app-core declarations
before running the same Docker-backed checker.

Two things this app *depends on* but does not itself build:

- **The wasm engines** (`src/vendor/vault/`, `src/vendor/tree/`) are generated, gitignored
  output — `node scripts/build-vault.mjs` / `node scripts/build-tree.mjs` **from the repo
  root**. Both compile Rust→wasm inside Docker (the host can't run cargo build scripts under
  company policy — same reason `scripts/cargo.mjs` uses Docker/WSL2 for native crate tests), then
  run `wasm-bindgen` on the host. Run these once before `pnpm serve` if `src/vendor/{sealer,tree}/`
  is empty.
- **`pnpm test:store`** (from `apps/`) runs `node ../scripts/cargo.mjs test -p store-log -p openom`
  — the native-crate store-conformance suite, not this app's JS — and on Windows that cargo run
  goes through WSL2/Docker too.

## What it is — and is not

This is the **web binding** of the shared Rust core: plain `<script type="module">` ES modules
(`src/main.js` as the entry point, loaded from `index.html`), served as static files. There is no
bundler, no transpile step, no `dist/` — the file you edit is the file the browser runs. Tauri
bundles this exact same `apps/app/` tree for the desktop/mobile shell, so the boundary is load-bearing:
**no bundler, framework, or build step may be introduced into `src/`** — anything that needed one
would no longer be the same tree Tauri serves.

It talks to the family-tree engine and the crypto sealer as **wasm modules vendored under
`src/vendor/`** (openom-data-tree and openom-sealer, compiled from `packages/`) — this app owns no
domain logic in Rust and re-implements none of it in JS; `src/core/` is the JS orchestration
*around* those wasm cores (storage, sync, sessions), not a parallel engine. openom-data-tree is the
claim-model engine (an openom-data-crdt set-union fold + an openom-data-projection read model); it replaced
the former treelog engine at the claim-model cutover.

The production web path hosts one unlocked durable account inside `appCore.worker.js`; the native path mirrors
that ownership inside `openom-app-core-host`. `accountSession.js` is the sole app-level source of cryptographic
identity (`member_id`); `session.js` is only the provider-auth seam (`sub`/auth subject). The opaque wrapped
keystore is persisted once per profile (IndexedDB on web, native SQLite under Tauri) inside one identity-scoped
record carrying its authenticated generation/hash, anti-rollback floor, portable record revision, and sync
checkpoints; tree keyrings, watermarks, and logs stay per document. Browser mutations hold a profile Web Lock,
use IndexedDB's separate opaque CAS token as a fail-safe, and verify an exact read-back before installing the
live handle. Committed revisions cross tabs through `BroadcastChannel`; a peer drops resident account and tree
handles when their exact source blob is stale. Persistent-browser-storage requests are best-effort; only a
confirmed remote backup supplies a redundant identity copy. A passphrase re-wrap commits `backup` intent, while
local recovery or account-root rotation commits stronger `revoke` intent; neither can be downgraded before network
I/O, and acknowledgement compare-clears only the exact uploaded blob version. `accountComposition.js` is the
production composition root: it initializes the sole `AccountSession`, wraps provider auth, constructs the
account transport, and attaches them before exposing the unit. `main.js` observes only facade state/events and
never interprets provider subjects or constructs a competing lifecycle. The facade's observable auth, custody,
and binding axes remain independent.
It probes `/me` before every binding decision, signs the exact pinned token claims for registration, and resumes an
interrupted register-then-backup flow from durable binding/pending state. Account backup writes use the server's strong
`ETag` with `If-Match`; reconciliation stays machine-readable in facade state and never silently adopts remote custody.
Concurrent `enableSync()` callers share one serialized operation, and a successful upload only clears the exact pending
version it acknowledged. Credential mutations report local completion separately from remote effectiveness, retain
their durable pending state after upload failure, and coalesce retries through a separate profile Web Lock on
initialization, auth changes, online or visible wakes, and tree-sync ticks without repeating credential rotation.
Owned and joined trees both borrow that account handle;
joined-tree reopen selects the founder or admitted-member path from the already-trusted keyring head rather than
from a second persisted member credential. A first successful owner sync publishes the signed genesis keyring
before clearing its durable create marker. Every shared-tree web or native tick then reconciles and republishes
a locally newer chain tail or DAG anchor before transferring data; a failed membership upload aborts that tick
so an attributed delta cannot outrun the authorization material needed to verify it. On a fresh device,
founder-tree restore verifies the complete chain walk or DAG anchor, binds it to the restored account, and only
then commits the local keyring head and opens the tree. In development, the singleton `DevAuth` observes that
account handle and exposes its durable member ID only as the raw development bearer; it does not own accounts.
The worker and native adapter expose the same account lifecycle boundary (create, unlock, recover, change
passphrase, snapshot, verified candidate adoption, revoke credentials, public identity, and registration proof), while
keeping every secret handle in Rust/wasm. Candidate adoption verifies the fetched wrapped bytes before replacing
the active persisted snapshot and resident account, while retaining displaced wrapped custody for its trees.

### AccountSession local × remote classification

Binding is default-deny. Local custody is `none`, `unbound` (unlocked without a server binding),
or `bound` (`memberId` bound to the provider subject). Remote `/me` is `unregistered`,
`bound-no-backup`, or `bound-with-backup`; `same`/`different` compares the applicable member
identity, and is otherwise `n/a`.

| Local | Remote `/me` | Relation | Automatic action |
|---|---|---|---|
| `none` | `unregistered` | `n/a` | Remain without local custody; no adoption. |
| `none` | `bound-no-backup` | `n/a` | Park `identity_conflict`; no auto-adopt. |
| `none` | `bound-with-backup` | `n/a` | Offer server restore; do not auto-adopt. |
| `unbound` | `unregistered` | `n/a` | May register the local identity. |
| `unbound` | `bound-no-backup` | `same` | Confirm the binding; backup remains available. |
| `unbound` | `bound-no-backup` | `different` | Park machine-readable conflict; remote restore is impossible. |
| `unbound` | `bound-with-backup` | `same` | Confirm the binding, then reconcile the verified backup. |
| `unbound` | `bound-with-backup` | `different` | Offer explicit soft adoption; never auto-adopt. |
| `bound` | `unregistered` | `n/a` | Park machine-readable conflict; no auto-adopt. |
| `bound` | `bound-no-backup` | `same` | Confirm binding; otherwise park conflict. |
| `bound` | `bound-no-backup` | `different` | Park machine-readable conflict; remote restore is impossible. |
| `bound` | `bound-with-backup` | `same` | Reconcile; otherwise park conflict. |
| `bound` | `bound-with-backup` | `different` | Offer explicit soft adoption; never auto-adopt. |

Any differing or ambiguous relation parks a machine-readable conflict and never auto-adopts
remote custody. Adoption is a soft replacement only: after verification, the remote record may
become active while prior encrypted `{ memberId, blob, floor }` custody is retained and exposed
only as non-secret state. Phase 2 has no account switcher or account-switching UI. Local recovery
is distinct from server restore; a recovery restore remains pending until its CAS upload is
acknowledged. A persisted local binding for another `{ issuer, subject }` is always ambiguous and
parks a conflict regardless of the member-id relation.

It is **not** a general-purpose SPA: there is no client-side router beyond the app's own
`data-view` state, no CSS framework, and no dependency-injection container — `src/ui/dom.js`'s `h()`
plus `tree.revision`-driven re-render is the entire rendering model.

## Layout

```
index.html            entry HTML: loads src/main.js as a module, %SITE_URL%/%LANDING% placeholders
                       substituted at serve/deploy time.
src/main.js            wires the store stack, the sealer/vault, the lock policy, and the view
                       router into one running app.

src/core/              orchestration — no UI, no rendering.
  types/                  branded values plus shared wasm, account-record, and app-core RPC contracts.
  wasmAppCore.js           checked anti-corruption layer: branded app values in, raw wasm-bindgen primitives out.
  nativeHost.js            checked Tauri command boundary: typed payloads and fail-closed result codecs.
  appCore.worker.js       owns the profile account handle plus every open tree core; account secrets stay in wasm.
  accountRecord.js        validates/codecs the portable identity-scoped account record and its three counters.
  accountRecordStore.js   serializes profile mutations and broadcasts verified IndexedDB-CAS commits.
  authSessionStore.js     serializes rotating provider refresh-token custody across browser tabs.
  authProvider.js         selects DevAuth or SupabaseAuth from public build-time configuration.
  accountComposition.js   constructs the sole AccountSession + provider-auth + remote transport unit.
  accountSession.js       observable local/auth/binding facade; probes, registers, and CAS-backs up account custody.
  gotrueClient.js         validates the direct Supabase Auth REST wire; owns no session or identity state.
  membership.js, sharing.js   resumable invite/claim orchestration and verified chain/DAG join bootstrap.
  store.js               DocStore contract: opaque-bytes persistence (memory / IndexedDB / Tauri).
  indexedDbStore.js       the browser DocStore implementation.
  storeStack.js           composition root: assembles the store layers by mode, fail-closed
                          (real user data is always sealed; only demo data may be plaintext).
  sealedStore.js          DocStore decorator: seals on write, opens on read — everything below
                          only ever sees ciphertext.
  syncStore.js            layers remote sync over a durable local DocStore; surfaces conflicts,
                          does not resolve them (it only ever handles opaque bytes).
  sync.js                 SyncController: client half of the delta-log sync protocol.
  syncedDeltaSync.js       wires SyncController together with landed-entry verification (§B3).
  replicator.js            drives a SyncStore to convergence: pull/push + the plaintext merge loop.
  remoteStore.js           DocStore over HTTP to the openom server (opaque bytes, no crypto); normalizes the
                           shared, registry-backed RFC 9457 error contract for account and tree routes.
  familyTree.js            the opened tree, backed by the openom-data-tree claim engine (wasm). The engine
                           owns a monotonic HLC and stamps each op's createdAt itself (no JS clock).
  tree/                    the web shim over packages/openom-data-tree (wasm): index.js wraps the engine.
  tabSync.js               cross-tab convergence via BroadcastChannel (merge-the-tail on append).
  sealer/                  the crypto vault + session, see below.
  model.js                 the v2 document shape (names/events/parent+child links).
  queries.js, sort.js, dates.js   read-side helpers: ancestor/descendant walks, collation, tolerant
                           date parsing.
  library.js, seed.js, seedKhaldun.js, schema.js   the bundled demo datasets + custom-field defs.
  identity.js              device id + logical clock, persisted across restarts.
  session.js               provider-auth seam; supplies atomic token+issuer+subject registration attempts.
                           DevAuth derives only a dev bearer from the unlocked AccountSession; SupabaseAuth keeps
                           access tokens in memory and serializes rotating refresh custody across browser tabs.
  lockPolicy.js            decides WHEN to auto-lock; platform-agnostic (calls back into the app).
  watermarks.js            anti-rollback: refuses a keyring/snapshot older than one already seen.
  blobs.js                 content-addressed file storage, alongside the document not inside it.
  transfer.js               format-independent import/export (e.g. GEDCOM).
  theme.js                 accent-color picker, clamped to a readable/contrast-safe range.
  profile.js                opt-in hot-path timing, no-op unless explicitly enabled.
  i18n.js                  Fluent-backed translation lookup + locale switch.

src/core/sealer/        the crypto vault: the sole holder of key material.
  index.js                 entry point: createAppVault() (passphrase vault) / createLibrarySealer()
                           (demo, dev key). Backend-selects web-worker vs. Tauri invoke.
  vault.js, keyringStore.js, invokeSealer.js   web vault orchestration, keyring persistence, and
                           the Tauri-invoke backend (DEK stays in the Rust host, never the webview).
  workerSealer.js, sealer.worker.js   the main-thread Comlink handle and the actual crypto worker
                           (the only place unlocked keys live on web).
  session.js, entryVerifier.js   the stateful seal/open bridge, and the launch-gate entry verifier.

src/ui/                generic view-layer helpers, no domain knowledge.
  dom.js                   h()/render(): the whole "framework" — no vdom, no framework dependency.
  components.js             shared widgets (portrait/initials tile, person card, etc).
  icons.js, menu.js, popover.js, personPicker.js, viewport.js   icon set, dropdown/menu, anchored
                           popovers, the person-search picker, and the narrow/compact breakpoints.

src/views/             one file per screen, composed from ui/ + core/ read helpers: ancestors.js,
                       detail.js, editor.js, fan.js, gate.js (pre-unlock flow), graph.js,
                       onboarding.js, people.js, settings.js, transfer.js.

src/vendor/            generated + third-party, never hand-edited.
  app-core/, tree/        wasm-bindgen output for openom-app-core / openom-data-tree — gitignored,
                          rebuilt by scripts/build-app-core.mjs / build-tree.mjs (repo root).
  sqlite/                 vendored sqlite-wasm (OPFS-SAHPool) bundle, checked in — the persistent
                          browser-SQLite spike (apps/e2e/sqlite*.e2e.ts exercises it).
  comlink.js, fluent.js   vendored third-party libraries (worker RPC, Fluent i18n runtime).

locales/               one .ftl file per language (en.ftl is the reference; check:locales enforces
                       key parity across the rest).
fonts/                 vendored woff2 subsets (vendor-fonts.mjs) — never fetched from a CDN at
                       runtime.
styles/                tokens.css (design tokens), app.css (app styles), fonts.css (@font-face).
```

## Conventions

- **Module boundary = file boundary.** Every `src/` file is a plain ES module imported by
  relative path; there is no barrel/index re-export convention to keep in sync.
- **Layer discipline in `core/`:** each store-stack file states, in its header comment, exactly
  what it does *not* do (e.g. `syncStore.js` surfaces conflicts but never resolves them;
  `remoteStore.js` moves bytes but knows nothing about encryption) — preserve that when editing;
  collapsing layers to "simplify" reintroduces the coupling they were split to avoid.
- **Tests:** `.test` = unit (dependencies faked), `.int` = integration (two-plus real units
  wired together) — both under `apps/test/`, run by vitest. `.e2e` = browser, under `apps/e2e/`,
  run by Playwright only.
