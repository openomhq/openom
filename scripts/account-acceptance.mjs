#!/usr/bin/env node
// Runs the browser account acceptance against the real Docker-backed local server. The test uses two
// isolated browser contexts and both keyring engines to prove register -> backup -> fresh-device restore
// -> tree reopen. The server stack remains running after the test for faster follow-up runs.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPS = path.join(REPO, 'apps');

try {
  for (const raw of fs.readFileSync(path.join(REPO, '.env'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim().replace(/^["']|["']$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
} catch {}

const port = process.env.OPENOM_HTTP_PORT ?? '6060';
const serverUrl = `http://localhost:${port}`;
const readyUrl = `${serverUrl}/ready`;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: REPO,
    stdio: 'inherit',
    ...options,
  });
  if (result.error) {
    console.error(`[account acceptance] failed to launch ${command}: ${result.error.message}`);
  }
  if (result.status !== 0) process.exit(result.status ?? 1);
}

async function waitForServer() {
  const deadline = Date.now() + 10 * 60_000;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(readyUrl);
      if (response.ok) return;
      lastError = new Error(`${response.status} ${response.statusText}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  console.error(`[account acceptance] server did not become ready at ${readyUrl}: ${lastError}`);
  spawnSync('docker', ['compose', 'logs', '--tail=200', 'server'], { cwd: REPO, stdio: 'inherit' });
  process.exit(1);
}

console.error('[account acceptance] starting the Docker-backed local server');
run('docker', ['compose', 'up', '-d', 'server']);
await waitForServer();

console.error('[account acceptance] running the two-context account and tree round trip');
run('pnpm', ['exec', 'playwright', 'test', 'e2e/account-roundtrip.e2e.ts'], {
  cwd: APPS,
  env: {
    ...process.env,
    OPENOM_ACCOUNT_ACCEPTANCE: '1',
    OPENOM_ACCOUNT_SERVER_URL: serverUrl,
  },
});
