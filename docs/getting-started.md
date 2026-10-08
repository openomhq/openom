# Local development

The repository-level `Taskfile.yml` is the development entry point. It keeps the browser app, Rust API,
local services, checks, tests, and destructive resets behind memorable cross-platform commands.

## Requirements

- **Core toolchain:** Git, Node.js 20+, pnpm 11.20.0, Rust through rustup, and Task 3+. The checked-in
  `rust-toolchain.toml` selects Rust 1.97.1 plus Clippy and rustfmt.
- **Local services and reloads:** Docker with Compose v2 and Watchexec 2+. Watchexec is required on the
  host for native API development and is already included in the Docker development image.
- **Desktop and mobile only:** install the platform-specific [Tauri prerequisites][tauri-prerequisites].
  Windows 11 already includes WebView2; native Windows builds also need the Microsoft C++ Build Tools.

SQLite is compiled through `rusqlite`'s `bundled` feature. PostgreSQL and the S3-compatible object store
run through Docker Compose; neither needs a separate host installation.

## Initial setup

From the repository root:

```sh
task setup
```

This installs the pinned pnpm dependencies, generates the two browser WebAssembly modules, and checks the
API. The first Rust or Docker build downloads and compiles dependencies; later builds reuse Cargo registry
and target caches.

Configuration is optional for ordinary development. To override machine-specific behavior, copy
`.env.example` to the gitignored `.env` and edit it there.

## Run the full stack

```sh
task dev
```

The command starts:

| Component | Address | Notes |
| --- | --- | --- |
| Browser app | `http://localhost:5173` | Buildless ES modules backed by IndexedDB. |
| API | `http://localhost:6060` | Long-running local Axum adapter for the same router deployed to Lambda. |
| PostgreSQL | `localhost:5432` | Local metadata database. |
| S3-compatible storage | `http://localhost:9000` | Local encrypted-blob storage; console on port `9001`. |

Browser JavaScript, HTML, and CSS need only a page refresh. Watchexec rebuilds and restarts the API after
relevant Rust, SQL migration, or Cargo manifest changes. Changes to Rust compiled into browser WebAssembly
need an explicit rebuild:

```sh
task build:web-core
```

Press Ctrl+C to stop the attached browser and API processes. PostgreSQL and object storage retain their
data; stop all local Compose services with `task stop`.

## Focused development

Use a narrower task when the full stack is unnecessary:

| Command | Purpose |
| --- | --- |
| `task dev:web` | Browser app only. |
| `task dev:server` | API plus PostgreSQL and object storage. |
| `task dev:desktop` | Native Tauri shell backed by SQLite. |
| `task services` | PostgreSQL and object storage in the background. |
| `task status` | Current Compose service status. |
| `task logs` | Follow Docker-hosted API logs. |

Tauri serves the same `apps/app/` source as the browser. There is one application and one Rust core, not a
separate desktop implementation.

## Native and Docker runners

`OPENOM_RUNNER` in `.env` controls where Rust commands run:

- `auto` is the default. The long-running development API runs natively; finite repository runners try the
  host first and may fall back to Docker.
- `local` forces native Rust execution.
- `docker` runs Rust and Watchexec inside Docker. Use it when host policy blocks locally built executables.

Docker mode polls the bind-mounted source tree because native file events do not reliably cross the
Windows-to-container boundary. Its watcher is restricted to source, migration, and manifest paths so build
outputs are not scanned.

## Checks and tests

```sh
task check:web
task check:server
task test:web
task test:server
```

The server integration task starts its required services and uses disposable test state. Rust changes must
also satisfy the crate-specific all-feature Clippy requirements in `AGENTS.md` before commit.

Ordinary local development uses `DevAuth`. To test the real Supabase Auth protocol without a cloud project:

```sh
pnpm --dir apps test:e2e:supabase-auth
```

That runner starts pinned GoTrue services through the optional `supabase-auth` Compose profile and exercises
password sign-in, refresh rotation, JWKS verification, and the unregistered-account boundary.

## Reset local data

All reset tasks ask for confirmation and preserve dependency downloads and Cargo build caches:

| Command | Deleted data |
| --- | --- |
| `task reset:database` | Recreates the local `openom` PostgreSQL database. |
| `task reset:objects` | Empties the local object-store bucket. |
| `task reset:server` | Performs both resets. |

SQLx records a checksum for the exact bytes of every applied migration. Migration files are pinned to LF
line endings and must not be edited after they are shared; add a new migration instead. Switching to a branch
whose migration history is older or incompatible can still produce `VersionMissing` or `VersionMismatch`.
For disposable local development data, `task reset:database` is the clean recovery path.

Run `task --list` for the authoritative task list.

[tauri-prerequisites]: https://v2.tauri.app/start/prerequisites/
