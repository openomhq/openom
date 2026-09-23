#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APP_CORE_TYPES = path.join(
  REPO,
  'apps',
  'app',
  'src',
  'vendor',
  'app-core',
  'openom_app_core.d.ts',
);

if (!fs.existsSync(APP_CORE_TYPES)) {
  console.error(
    '[typecheck] missing generated app-core declarations; run `node scripts/build-app-core.mjs` first',
  );
  process.exit(1);
}

try {
  for (const raw of fs.readFileSync(path.join(REPO, '.env'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
} catch {}

const image = process.env.OPENOM_NODE_IMAGE || 'node:22-bookworm-slim';
const inner = [
  'corepack enable',
  'pnpm install --store-dir /pnpm-store --frozen-lockfile --config.confirmModulesPurge=false',
  'pnpm exec tsc --project tsconfig.main.json',
  'pnpm exec tsc --project tsconfig.native.json',
  'pnpm exec tsc --project tsconfig.worker.json',
].join(' && ');

const dockerArgs = [
  'run',
  '--rm',
  '--init',
  '-v',
  `${REPO}:/work`,
  '-v',
  'openom-apps-node-modules:/work/apps/node_modules',
  '-v',
  'openom-pnpm-store:/pnpm-store',
  '-v',
  'openom-corepack:/corepack',
  '-w',
  '/work/apps',
  '-e',
  'CI=true',
  '-e',
  'COREPACK_HOME=/corepack',
  '-e',
  'COREPACK_ENABLE_DOWNLOAD_PROMPT=0',
  image,
  'sh',
  '-c',
  inner,
];

console.error(`[typecheck runner=docker] image=${image}`);
const result = spawnSync('docker', dockerArgs, { stdio: 'inherit' });
process.exit(result.status ?? 1);
