#!/usr/bin/env node
// Integration-test runner: runs the `#[ignore]`d tests that need the live local
// stack (Postgres + MinIO) — the in-process API tests (openom/tests/api.rs) and the
// checksum-enforcement test (openom/src/storage.rs).
//
//   docker compose up -d          # the stack must be running first
//   node scripts/itest.mjs        # runs all ignored tests against it
//   node scripts/itest.mjs media_lifecycle_and_gc   # filter to one test
//   node scripts/itest.mjs --fresh register_         # recreate the dedicated test DB first
//
// Like scripts/cargo.mjs it runs cargo inside a Linux container (this host's policy
// blocks executing freshly built binaries), reusing the same cargo cache volumes so
// it's incremental. The container reaches the host-published stack via
// host.docker.internal, and points both S3 endpoints there so presigned URLs it mints
// are reachable from inside the container too.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Reuse .env only for the cargo image choice.
try {
  for (const raw of fs.readFileSync(path.join(REPO, '.env'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (k && process.env[k] === undefined) process.env[k] = v;
  }
} catch {}

const IMAGE = process.env.OPENOM_CARGO_IMAGE || 'rust:1.97.1-bookworm';
const HOST = 'host.docker.internal';
const cliArgs = process.argv.slice(2);
const fresh = cliArgs.includes('--fresh');
const filter = cliArgs.filter((arg) => arg !== '--fresh'); // optional test-name filter passed to cargo test
const database = fresh ? 'openom_itest' : 'openom';

function runPostgres(sql) {
  const result = spawnSync(
    'docker',
    [
      'compose', 'exec', '-T', 'postgres',
      'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'openom', '-d', 'postgres', '-c', sql,
    ],
    { cwd: REPO, stdio: 'inherit' },
  );
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (fresh) {
  console.error(`[itest] recreating dedicated database ${database}`);
  runPostgres(`DROP DATABASE IF EXISTS ${database} WITH (FORCE);`);
  runPostgres(`CREATE DATABASE ${database} OWNER openom;`);
}

const env = {
  CARGO_TARGET_DIR: '/tmp/target',
  DATABASE_URL: `postgres://openom:openom@${HOST}:5432/${database}`,
  S3_ENDPOINT: `http://${HOST}:9000`,
  S3_PUBLIC_ENDPOINT: `http://${HOST}:9000`,
  S3_BUCKET: 'openom-trees',
  S3_REGION: 'us-east-1',
  S3_ACCESS_KEY: 'openom',
  S3_SECRET_KEY: 'openompw123',
};

const args = [
  'run', '--rm', '--init',
  '-v', `${REPO}:/work`,
  '-v', 'openom-cargo-registry:/usr/local/cargo/registry',
  '-v', 'openom-cargo-target:/tmp/target',
  '-w', '/work',
  '--add-host', `${HOST}:host-gateway`,
];
for (const [k, v] of Object.entries(env)) args.push('-e', `${k}=${v}`);
// --test-threads=1: these integration tests share ONE Postgres + MinIO and use GLOBAL operations
// (POST /dev/media/gc sweeps ALL expired proposals/blobs, not just the test's tree), so running them in
// parallel makes the shared-state assertions non-deterministic (proposals_ttl_swept flaked). Serialize.
args.push(IMAGE, 'cargo', 'test', '-p', 'openom', ...filter, '--', '--ignored', '--nocapture', '--test-threads=1');

console.error(`[itest] cargo test -p openom ${filter.join(' ')} -- --ignored  (db=${database}, stack via ${HOST})`);
const r = spawnSync('docker', args, { stdio: 'inherit' });
process.exit(r.status ?? 1);
