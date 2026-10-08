# openom

<img src="assets/tree.svg" alt="openom logo — a tree" width="120" align="right">

[![main branch health](https://github.com/openomhq/openom/actions/workflows/ci.main.yml/badge.svg?branch=main&event=push)](https://github.com/openomhq/openom/actions/workflows/ci.main.yml)
[![Docs](https://readthedocs.org/projects/openom/badge/?version=latest)](https://openom.readthedocs.io/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)

**openom** is a **local-first, end-to-end-encrypted family tree**. One Rust core runs everywhere — a
desktop/mobile app (Tauri) and a buildless web app — and syncs through a **zero-knowledge** server that
only ever stores opaque encrypted blobs. Your genealogy, your keys, your device.

**The name.** *openom* is **open** + **ኦም** (*om*), which is "tree" in Tigrinya, a language of the Tigray 
Region of Ethiopia and of Eritrea. An open, local-first family tree.

- **Local-first** — the tree lives on your device and works offline; the server is a sync relay, not the source of truth.
- **Zero-knowledge** — the client seals every tree before upload; the server holds ciphertext + non-secret metadata, never a key.
- **One core, three shells** — the same Rust engine drives desktop, Android/iOS, and the browser; no second implementation.
- **Buildless web** — `apps/app/` is ES modules the browser loads directly; nothing is bundled. Edit, reload, done.
- **CRDT + real sharing** — an op-based CRDT converges edits across devices; a signed keyring gives role-based sharing (Viewer → Owner).

> **Status: prototype.** The architecture, crypto, sync, and sharing are built and tested; persistence and UX polish are ongoing.

## Concept

openom treats a family tree as a **local-first, end-to-end-encrypted document**. The client is the
stateful, key-holding side; the server is stateless and keyless — it stores only opaque sealed blobs and
non-secret metadata, and can never read a tree. Trust lives on the device, not in the backend.

State is a **log, not a row**. Edits are self-contained CRDT operations appended to a sealed, append-only
log; the visible tree is derived by replaying that log (with snapshots for speed). Because the operations
commute, independent devices converge without a merge server — the backend only relays bytes it cannot read.

The engine is **one Rust core**, compiled native for the desktop/mobile shell and to WebAssembly for the
browser, behind narrow, swappable seams: a content-agnostic store, a domain-agnostic CRDT, a family-tree
layer on top, a sealer that is the sole holder of keys, and a signed keyring that makes sharing and roles a
client-verified guarantee rather than a server promise.

## Quick start

### Requirements

- **Core toolchain:** Node.js 20+, pnpm 11.20.0, Rust through rustup (the repository pins 1.97.1), and Task 3+.
- **Local services and reloads:** Docker with Compose v2; Watchexec 2+ for native API development (bundled in Docker mode).
- **Desktop and mobile only:** the platform-specific [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

From the repository root:

```sh
task setup
task dev
```

The browser app is available at `http://localhost:5173` and the local API at
`http://localhost:6060`. Browser source is buildless: edit it and refresh the page. Relevant Rust,
migration, and Cargo manifest changes automatically rebuild and restart the API.

| Command | Purpose |
| --- | --- |
| `task setup` | Install dependencies, generate browser WebAssembly, and check the server. |
| `task dev` | Run the browser app, API, Postgres, and local S3-compatible storage. |
| `task dev:web` | Run only the browser app. |
| `task dev:server` | Run only the API and its required services. |
| `task dev:desktop` | Run the native Tauri development shell. |
| `task build:web-core` | Regenerate browser WebAssembly after changing its Rust sources. |
| `task check:web` / `task check:server` | Run focused checks; matching `test:*` tasks run the tests. |
| `task reset:database` | Recreate an incompatible local database after switching migration histories; asks before deleting data. |

Run `task --list` for the complete command list. Detailed setup, runner configuration, local data
management, and troubleshooting live in [the development guide](docs/getting-started.md).

Ordinary local development uses `DevAuth`. To exercise the real Supabase Auth wire locally without a cloud
project, run `pnpm --dir apps test:e2e:supabase-auth`. The runner starts pinned GoTrue services through the
optional `supabase-auth` Compose profile and tests the complete authentication boundary.

## Continuous integration

CI is organized by role; the workflow files are the detailed source of truth rather than this README serving
as an inventory of every check.

| Role | When | Purpose |
| --- | --- | --- |
| Main branch health | Every push to `main` | `ci.main` finishes quickly after a validated PR merge and runs path-aware repository and Rust checks after an administrator bypass push. Its badge reports the health of committed main, not the latest contributor branch. |
| Required change gates | Pull requests and the merge queue | Web checks, the live server-contract suite, and desktop Clippy/build validation prevent an unverified candidate from entering `main`. The expensive desktop matrix is reserved for the merge queue. |
| Extended assurance | Scheduled, path-targeted, or manual | Mobile build drift, mutation testing, telemetry export, and other focused checks cover risks that do not justify delaying every change. |

Deployment workflows for demo, preview, and staging environments are operational automation, not CI health,
and are intentionally excluded from this summary.

## Brand

`assets/` (repo root) is the single source of truth for the mark — wordmark, monogram, app icon, favicon,
and the social previews — shared by the web app (served at `/assets`), the docs, and GitHub. The Tauri shell
generates its own `apps/src-tauri/icons/` from `assets/icon.svg`.

## Contributing

Changes use an issue-first pull-request workflow with task-linked branches and commits. See
[CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, validation, preview, and tracker conventions.

## License

This project is licensed under the GNU Affero General Public License v3.0 or later.

```text
SPDX-License-Identifier: AGPL-3.0-or-later
```

For full license details, please see the [LICENSE](LICENSE) file.

**openom** — local-first family tree  
Copyright (C) 2026 Mikael Beyene
