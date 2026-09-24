#!/usr/bin/env node
// Prove the real local Supabase Auth wire through both the direct protocol boundary and the browser's
// production provider/account facades. The runner uses pinned GoTrue with an ephemeral ES256 key, then
// launches a separate openom JWT server so ordinary DevAuth remains untouched. Tokens and signing material
// stay in memory and are never printed.
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APPS = path.join(REPO, 'apps');
const authProject = `openom-auth-${process.pid}`;
const serverContainer = `${authProject}-server`;
const keyId = `local-auth-${process.pid}`;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: REPO,
    stdio: 'inherit',
    ...options,
  });
  if (result.error) throw new Error(`failed to launch ${command}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${command} exited with status ${result.status ?? 1}`);
  return result;
}

function dockerCompose(args, env, options = {}) {
  return run('docker', ['compose', '-p', authProject, '--profile', 'supabase-auth', ...args], {
    env,
    ...options,
  });
}

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('failed to allocate a local acceptance port'));
        return;
      }
      const { port } = address;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function signingKeys() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' });
  return JSON.stringify([{
    ...jwk,
    kid: keyId,
    alg: 'ES256',
    use: 'sig',
    key_ops: ['sign', 'verify'],
  }]);
}

function jwtPart(token, index) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('GoTrue returned a malformed access token');
  try {
    return JSON.parse(Buffer.from(parts[index], 'base64url').toString('utf8'));
  } catch {
    throw new Error('GoTrue returned an access token with malformed JSON claims');
  }
}

function tokenResponse(value, operation) {
  if (!value || typeof value !== 'object'
    || typeof value.access_token !== 'string' || value.access_token.length === 0
    || typeof value.refresh_token !== 'string' || value.refresh_token.length === 0) {
    throw new Error(`${operation} returned an invalid token response`);
  }
  return value;
}

async function jsonRequest(url, init, expectedStatus = 200) {
  const response = await fetch(url, init);
  let body = null;
  try {
    body = await response.json();
  } catch {
    // The caller validates whether its expected response needs a body.
  }
  if (response.status !== expectedStatus) {
    const providerCode = body && typeof body === 'object'
      ? body.error_code ?? body.code ?? 'unknown'
      : 'non_json_response';
    throw new Error(`${init.method ?? 'GET'} ${url} returned ${response.status} (${providerCode})`);
  }
  return { response, body };
}

async function waitForJson(url, description, deadlineMs = 120_000) {
  const deadline = Date.now() + deadlineMs;
  let lastStatus = 'not reachable';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      lastStatus = `${response.status} ${response.statusText}`;
      if (response.ok) return response.json();
    } catch (error) {
      lastStatus = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`${description} did not become ready at ${url}: ${lastStatus}`);
}

async function waitForOk(url, description, deadlineMs = 120_000) {
  const deadline = Date.now() + deadlineMs;
  let lastStatus = 'not reachable';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      lastStatus = `${response.status} ${response.statusText}`;
      if (response.ok) return;
    } catch (error) {
      lastStatus = error instanceof Error ? error.message : String(error);
    }
    if (description === 'openom JWT server') {
      const inspected = spawnSync(
        'docker',
        ['inspect', '--format', '{{.State.Status}} (exit {{.State.ExitCode}})', serverContainer],
        { cwd: REPO, encoding: 'utf8' },
      );
      const containerStatus = inspected.status === 0 ? inspected.stdout.trim() : '';
      if (containerStatus.startsWith('exited') || containerStatus.startsWith('dead')) {
        throw new Error(`${description} stopped before becoming ready: ${containerStatus}`);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`${description} did not become ready at ${url}: ${lastStatus}`);
}

function removeServer() {
  spawnSync('docker', ['rm', '--force', serverContainer], { cwd: REPO, stdio: 'ignore' });
}

function removeAuthStack(env) {
  spawnSync(
    'docker',
    ['compose', '-p', authProject, '--profile', 'supabase-auth', 'down', '--volumes', '--remove-orphans'],
    { cwd: REPO, env, stdio: 'ignore' },
  );
}

const authPort = await availablePort();
let serverPort = await availablePort();
while (serverPort === authPort) serverPort = await availablePort();
const authBaseUrl = `http://localhost:${authPort}/auth/v1`;
const serverUrl = `http://localhost:${serverPort}`;
const composeEnv = {
  ...process.env,
  OPENOM_SUPABASE_AUTH_PORT: String(authPort),
  OPENOM_SUPABASE_JWT_KEYS: signingKeys(),
};
const authHeaders = {
  apikey: 'openom-local-publishable-key',
  'content-type': 'application/json',
};

function userCredentials(label) {
  return {
    email: `auth-${label}-${randomUUID()}@openom.local`,
    password: `Local-auth-${randomUUID()}!`,
  };
}

async function seedUser(label) {
  const credentials = userCredentials(label);
  await jsonRequest(`${authBaseUrl}/signup`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(credentials),
  });
  return credentials;
}

let cleaning = false;
function cleanup() {
  if (cleaning) return;
  cleaning = true;
  removeServer();
  removeAuthStack(composeEnv);
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    cleanup();
    process.exit(128 + (signal === 'SIGINT' ? 2 : 15));
  });
}

let failed = false;
try {
  removeServer();
  removeAuthStack(composeEnv);

  console.error('[Auth] starting isolated Supabase Auth services');
  dockerCompose(['up', '-d', 'supabase-auth-gateway'], composeEnv);
  const jwks = await waitForJson(
    `${authBaseUrl}/.well-known/jwks.json`,
    'Supabase Auth JWKS',
  );
  const publicKey = Array.isArray(jwks?.keys) ? jwks.keys[0] : null;
  if (!publicKey || publicKey.alg !== 'ES256' || publicKey.kid !== keyId || 'd' in publicKey) {
    throw new Error('Supabase Auth exposed an unexpected JWKS');
  }

  console.error('[Auth] starting an ephemeral openom ES256/JWKS server');
  run('docker', ['compose', 'up', '-d', 'postgres', 'minio']);
  run('docker', [
    'compose', 'run', '--build', '--detach', '--no-deps',
    '--name', serverContainer,
    '-e', 'AUTH=jwt',
    '-e', 'AUTH_JWT_ALG=ES256',
    '-e', 'AUTH_JWKS_URL=http://supabase-auth-gateway:9999/auth/v1/.well-known/jwks.json',
    '-e', `AUTH_JWT_ISS=${authBaseUrl}`,
    '-e', 'AUTH_JWT_AUD=authenticated',
    '-e', `OPENOM_HTTP_ADDR=0.0.0.0:${serverPort}`,
    '-p', `${serverPort}:${serverPort}`,
    'server', 'cargo', 'run', '-p', 'openom', '--bin', 'openom',
  ], { encoding: 'utf8' });
  run('docker', ['network', 'connect', `${authProject}_default`, serverContainer]);
  await waitForOk(`${serverUrl}/ready`, 'openom JWT server', 10 * 60_000);

  const wireCredentials = await seedUser('wire');
  const credentials = {
    chain: userCredentials('chain'),
    dag: userCredentials('dag'),
  };
  const signInResult = await jsonRequest(`${authBaseUrl}/token?grant_type=password`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(wireCredentials),
  });
  const signedIn = tokenResponse(signInResult.body, 'password sign-in');
  const header = jwtPart(signedIn.access_token, 0);
  const claims = jwtPart(signedIn.access_token, 1);
  if (header.alg !== 'ES256' || header.kid !== keyId
    || claims.iss !== authBaseUrl || claims.aud !== 'authenticated'
    || typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new Error('Supabase Auth minted JWT claims that do not match the server contract');
  }

  const refreshResult = await jsonRequest(`${authBaseUrl}/token?grant_type=refresh_token`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ refresh_token: signedIn.refresh_token }),
  });
  const refreshed = tokenResponse(refreshResult.body, 'refresh');
  if (refreshed.refresh_token === signedIn.refresh_token) {
    throw new Error('Supabase Auth did not rotate the refresh token');
  }

  const meResult = await jsonRequest(`${serverUrl}/v1/me`, {
    method: 'GET',
    headers: { authorization: `Bearer ${refreshed.access_token}` },
  }, 403);
  if (!meResult.body || typeof meResult.body !== 'object' || meResult.body.code !== 'unregistered') {
    throw new Error('openom did not classify the verified, unbound Supabase subject as unregistered');
  }

  const logoutResponse = await fetch(`${authBaseUrl}/logout?scope=local`, {
    method: 'POST',
    headers: {
      ...authHeaders,
      authorization: `Bearer ${refreshed.access_token}`,
    },
  });
  if (!logoutResponse.ok) throw new Error(`local-scope logout returned ${logoutResponse.status}`);

  console.error('[Auth] running the two-context account round trip through SupabaseAuth');
  run('pnpm', ['exec', 'playwright', 'test', 'e2e/account-roundtrip.e2e.ts'], {
    cwd: APPS,
    env: {
      ...process.env,
      OPENOM_ACCOUNT_ACCEPTANCE: '1',
      OPENOM_ACCOUNT_SERVER_URL: serverUrl,
      OPENOM_ACCOUNT_AUTH_PROVIDER: 'supabase',
      OPENOM_ACCOUNT_AUTH_URL: `http://localhost:${authPort}`,
      OPENOM_ACCOUNT_PUBLISHABLE_KEY: authHeaders.apikey,
      OPENOM_ACCOUNT_CREDENTIALS: JSON.stringify(credentials),
      OPENOM_ACCOUNT_SIGN_UP: '1',
    },
  });

  console.error('[Auth] real Supabase Auth wire and browser account round trip passed');
} catch (error) {
  failed = true;
  console.error(`[Auth] ${error instanceof Error ? error.message : String(error)}`);
  spawnSync('docker', ['logs', '--tail=200', serverContainer], { cwd: REPO, stdio: 'inherit' });
  spawnSync(
    'docker',
    ['compose', '-p', authProject, '--profile', 'supabase-auth', 'logs', '--tail=200'],
    { cwd: REPO, env: composeEnv, stdio: 'inherit' },
  );
} finally {
  cleanup();
}

if (failed) process.exit(1);
