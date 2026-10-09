// Build openom-data-tree to WebAssembly — the claim-model family-tree engine for the web app. Rust
// compilation uses the repository's local/docker/auto Cargo runner; wasm-bindgen glue runs on the
// host. Output: apps/app/src/vendor/tree/ (gitignored).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CRATE = path.join(REPO, 'packages', 'openom-data-tree');

// The HOST triple for the wasm-bindgen CLI download — the Rust build runs in Docker (Linux), but the
// bindings generator runs natively on THIS machine, so it must match the host OS/arch.
const TRIPLE = (() => {
  if (process.platform === 'win32') return 'x86_64-pc-windows-msvc';
  if (process.platform === 'darwin') return process.arch === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
  // wasm-bindgen publishes Linux binaries as static MUSL archives.
  return process.arch === 'arm64' ? 'aarch64-unknown-linux-musl' : 'x86_64-unknown-linux-musl';
})();
const BINDGEN_BIN = process.platform === 'win32' ? 'wasm-bindgen.exe' : 'wasm-bindgen';
const TARGET_SUBDIR = 'target-wasm';
const PROFILE = process.env.WASM_PROFILE || 'wasm-release';
const RUSTFLAGS = process.env.WASM_RUSTFLAGS || '';

const WASM = path.join(CRATE, TARGET_SUBDIR, 'wasm32-unknown-unknown', PROFILE, 'openom_data_tree.wasm');
// Reuse the sealer's downloaded wasm-bindgen CLI (same version, pinned to Cargo.lock).
const TOOLS_DIR = path.join(REPO, 'packages', 'openom-sealer', 'tools');
const PKG_DIR = path.join(REPO, 'apps', 'app', 'src', 'vendor', 'tree');

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', stdio: 'inherit', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(' ')}… failed (code ${r.status})`);
}

console.log(`[·] Building openom-data-tree → wasm (runner=${process.env.OPENOM_RUNNER || 'auto'} · profile=${PROFILE})…`);
run(process.execPath, [
  'scripts/rust/cargo.mjs', 'build', '--profile', PROFILE, '--target', 'wasm32-unknown-unknown',
  '-p', 'openom-data-tree', '--no-default-features', '--features', 'wasm',
], {
  cwd: REPO,
  env: {
    ...process.env,
    OPENOM_CARGO_TARGET_DIR: path.relative(REPO, path.join(CRATE, TARGET_SUBDIR)),
    RUSTFLAGS,
  },
});
if (!fs.existsSync(WASM)) throw new Error(`expected wasm at ${WASM} after the configured build; not found`);
console.log(`[✓] Compiled ${path.relative(REPO, WASM)} (${(fs.statSync(WASM).size / 1024).toFixed(0)} kb)`);

function resolvedBindgenVersion() {
  const lock = fs.readFileSync(path.join(REPO, 'Cargo.lock'), 'utf8');
  const m = lock.match(/name = "wasm-bindgen"\r?\nversion = "([^"]+)"/);
  if (!m) throw new Error('could not find the resolved wasm-bindgen version in Cargo.lock');
  return m[1];
}

async function ensureWasmBindgen(ver) {
  const dir = path.join(TOOLS_DIR, `wasm-bindgen-${ver}-${TRIPLE}`);
  const exe = path.join(dir, BINDGEN_BIN);
  if (fs.existsSync(exe)) return exe;
  const name = `wasm-bindgen-${ver}-${TRIPLE}`;
  const url = `https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${ver}/${name}.tar.gz`;
  const tarball = path.join(TOOLS_DIR, `${name}.tar.gz`);
  fs.mkdirSync(TOOLS_DIR, { recursive: true });
  console.log(`[·] Downloading wasm-bindgen CLI ${ver} (matches Cargo.lock)…`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed (${res.status}) for ${url}`);
  await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(tarball));
  run('tar', ['-xzf', path.basename(tarball)], { cwd: TOOLS_DIR });
  fs.rmSync(tarball, { force: true });
  if (!fs.existsSync(exe)) throw new Error(`${BINDGEN_BIN} not found after extracting ${name}`);
  console.log(`[✓] Installed wasm-bindgen CLI to ${path.relative(REPO, dir)}`);
  return exe;
}

const ver = resolvedBindgenVersion();
const bindgen = await ensureWasmBindgen(ver);
console.log('[·] Generating JS/TS bindings with wasm-bindgen (--target web)…');
run(bindgen, ['--target', 'web', '--out-dir', PKG_DIR, '--typescript', WASM]);
console.log(`[✓] Build complete → ${path.relative(REPO, PKG_DIR)}/`);
