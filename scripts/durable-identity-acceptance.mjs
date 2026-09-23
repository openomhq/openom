#!/usr/bin/env node
// OPE-547: run the browser durable-identity acceptance against an ephemeral local AUTH=jwt / HS256
// server. The ordinary dev server remains untouched; Postgres and MinIO are shared, while random JWT
// subjects and tree ids isolate each run.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPS = path.join(REPO, 'apps');
const port = process.env.OPENOM_DURABLE_IDENTITY_PORT ?? '6061';
const serverUrl = `http://localhost:${port}`;
const readyUrl = `${serverUrl}/ready`;
const jwtSecret = process.env.OPENOM_DURABLE_IDENTITY_JWT_SECRET ?? 'openom-ope547-local-hs256-secret';
const jwtIssuer = process.env.OPENOM_DURABLE_IDENTITY_JWT_ISSUER ?? 'https://ope547.local.openom.test';
const containerName = `openom-ope547-${process.pid}`;

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    cwd: REPO,
    stdio: 'inherit',
    ...options,
  });
  if (result.error) throw new Error(`failed to launch ${commandName}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${commandName} exited with status ${result.status ?? 1}`);
  return result;
}

function removeServer() {
  spawnSync('docker', ['rm', '--force', containerName], { cwd: REPO, stdio: 'ignore' });
}

function startServer() {
  removeServer();
  command('docker', ['compose', 'up', '-d', 'postgres', 'minio']);
  const result = spawnSync('docker', [
    'compose', 'run', '--build', '--rm', '--detach', '--no-deps',
    '--name', containerName,
    '-e', 'AUTH=jwt',
    '-e', 'AUTH_JWT_ALG=HS256',
    '-e', `AUTH_JWT_SECRET=${jwtSecret}`,
    '-e', `AUTH_JWT_ISS=${jwtIssuer}`,
    '-e', 'AUTH_JWT_AUD=authenticated',
    '-e', `OPENOM_HTTP_ADDR=0.0.0.0:${port}`,
    '-p', `${port}:${port}`,
    'server', 'cargo', 'run', '-p', 'openom', '--bin', 'openom',
  ], { cwd: REPO, encoding: 'utf8' });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`failed to start the OPE-547 server (status ${result.status ?? 1})`);
  }
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
  throw new Error(`server did not become ready at ${readyUrl}: ${lastError}`);
}

let failed = false;
try {
  console.error('[OPE-547] starting an ephemeral Docker AUTH=jwt / HS256 server');
  startServer();
  await waitForServer();
  console.error('[OPE-547] running DAG onboarding and credential-stability acceptance');
  command('pnpm', ['exec', 'playwright', 'test', 'e2e/durable-identity.e2e.ts'], {
    cwd: APPS,
    env: {
      ...process.env,
      OPENOM_DURABLE_IDENTITY_ACCEPTANCE: '1',
      OPENOM_DURABLE_IDENTITY_SERVER_URL: serverUrl,
      OPENOM_DURABLE_IDENTITY_JWT_SECRET: jwtSecret,
      OPENOM_DURABLE_IDENTITY_JWT_ISSUER: jwtIssuer,
    },
  });
} catch (error) {
  failed = true;
  console.error(`[OPE-547] ${error instanceof Error ? error.message : String(error)}`);
  spawnSync('docker', ['logs', '--tail=200', containerName], { cwd: REPO, stdio: 'inherit' });
} finally {
  removeServer();
}

if (failed) process.exit(1);
