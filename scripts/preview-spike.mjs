#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOFU_ROOT = path.join(REPO, 'infra', 'terraform', 'preview-spike');
const EXPECTED_ACCOUNT = '841547768414';
const KVS_REGION = 'us-east-1';
const WAIT_TIMEOUT_MS = 180_000;

function command(commandName, args, { capture = false, allowFailure = false } = {}) {
  const result = spawnSync(commandName, args, {
    cwd: TOFU_ROOT,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  });
  if (result.error) throw new Error(`failed to launch ${commandName}: ${result.error.message}`);
  if (!allowFailure && result.status !== 0) {
    const detail = capture ? `: ${(result.stderr || result.stdout).trim()}` : '';
    throw new Error(`${commandName} exited with status ${result.status ?? 1}${detail}`);
  }
  return result;
}

function tofu(args, options) {
  return command('tofu', args, options);
}

function aws(args, options) {
  return command('aws', args, options);
}

function parseJson(result, operation) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${operation} returned malformed JSON`);
  }
}

function assertAccount() {
  const identity = parseJson(
    aws(['sts', 'get-caller-identity', '--output', 'json'], { capture: true }),
    'AWS identity lookup',
  );
  if (identity.Account !== EXPECTED_ACCOUNT) {
    throw new Error(`refusing AWS account ${identity.Account}; expected ${EXPECTED_ACCOUNT}`);
  }
  console.log(`[Preview spike] authenticated to AWS account ${identity.Account}`);
}

function initAndValidate() {
  tofu(['init', '-input=false']);
  tofu(['fmt', '-check', '-recursive']);
  tofu(['validate']);
}

function outputs() {
  const all = parseJson(tofu(['output', '-json'], { capture: true }), 'OpenTofu output');
  const value = all.spike?.value;
  if (!value || typeof value.distribution_url !== 'string' || typeof value.kvs_arn !== 'string') {
    throw new Error('OpenTofu did not return the expected spike output');
  }
  return value;
}

function describeKvs(kvsArn) {
  return parseJson(aws([
    'cloudfront-keyvaluestore',
    'describe-key-value-store',
    '--kvs-arn', kvsArn,
    '--region', KVS_REGION,
    '--output', 'json',
  ], { capture: true }), 'KVS description');
}

function updateKvs(kvsArn, etag, puts, { allowFailure = false } = {}) {
  return aws([
    'cloudfront-keyvaluestore',
    'update-keys',
    '--kvs-arn', kvsArn,
    '--if-match', etag,
    '--puts', JSON.stringify(puts.map(([Key, Value]) => ({ Key, Value }))),
    '--region', KVS_REGION,
    '--output', 'json',
  ], { capture: true, allowFailure });
}

function bodyHash(body = '') {
  return createHash('sha256').update(body).digest('hex');
}

async function routedRequest(baseUrl, route, token, method, body = '') {
  const response = await fetch(`${baseUrl}/${route}/probe`, {
    method,
    headers: {
      'openom-auth': `Bearer ${token}`,
      'x-amz-content-sha256': bodyHash(body),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body } : {}),
  });
  const responseText = await response.text();
  let payload = null;
  try {
    payload = JSON.parse(responseText);
  } catch {
    // Propagation and origin errors commonly return HTML; the retry caller reports the status.
  }
  return { response, responseText, payload };
}

function assertProbe({ response, responseText, payload }, marker, method, body) {
  if (!response.ok) {
    const xCache = response.headers.get('x-cache') ?? 'no x-cache header';
    const detail = responseText.replace(/\s+/g, ' ').trim().slice(0, 240);
    throw new Error(`route returned HTTP ${response.status} (${xCache}): ${detail}`);
  }
  if (payload?.marker !== marker) throw new Error(`expected marker ${marker}, got ${payload?.marker}`);
  if (payload.method !== method) throw new Error(`expected method ${method}, got ${payload.method}`);
  if (payload.appAuthAccepted !== true) throw new Error('Openom-Auth did not reach the origin');
  if (payload.bodyHash !== bodyHash(body)) throw new Error('origin observed a different request body hash');
}

async function waitForProbe(config, route, marker, method = 'GET', body = '') {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const result = await routedRequest(
        config.distribution_url,
        route,
        config.probe_token,
        method,
        body,
      );
      assertProbe(result, marker, method, body);
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 3_000));
    }
  }
  throw new Error(`route ${route} did not converge: ${lastError?.message ?? 'unknown error'}`);
}

async function verifyDirectOrigins(config) {
  for (const marker of ['a', 'b']) {
    const url = config.lambda_urls[marker];
    const response = await fetch(url, {
      headers: {
        'openom-auth': `Bearer ${config.probe_token}`,
        'x-amz-content-sha256': bodyHash(),
      },
    });
    if (response.status !== 403) {
      throw new Error(`direct origin ${marker} returned ${response.status}; expected 403`);
    }
  }
  console.log('[Preview spike] direct Function URLs reject unsigned requests');

  const webResponse = await fetch(config.lambda_urls.web);
  if (!webResponse.ok) {
    throw new Error(`direct public web probe returned HTTP ${webResponse.status}`);
  }
  const webPayload = await webResponse.json();
  if (webPayload.marker !== 'web') throw new Error('direct public web probe returned an unexpected marker');
}

async function verifyWebRoute(config) {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  let lastError = null;
  while (Date.now() < deadline) {
    const response = await fetch(`${config.distribution_url}/web/probe`);
    try {
      const payload = await response.json();
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
      if (payload.marker !== 'web') throw new Error('route reached an unexpected origin');
      if (payload.originAuthorizationPresent !== false) {
        throw new Error('origin unexpectedly received an Authorization header');
      }
      console.log('[Preview spike] web origin works without Lambda OAC');
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 3_000));
    }
  }
  throw new Error(`unsigned web route did not converge: ${lastError?.message ?? 'unknown error'}`);
}

async function verifyDynamicOrigins(config) {
  const initial = describeKvs(config.kvs_arn);
  parseJson(updateKvs(config.kvs_arn, initial.ETag, [
    ['a', config.lambda_hosts.a],
    ['b', config.lambda_hosts.b],
    ['web', config.lambda_hosts.web],
  ]), 'KVS seed');

  const stale = updateKvs(
    config.kvs_arn,
    initial.ETag,
    [['a', config.lambda_hosts.b]],
    { allowFailure: true },
  );
  if (stale.status === 0) throw new Error('KVS accepted a stale ETag');
  console.log('[Preview spike] KVS rejects stale compare-and-swap writes');

  await waitForProbe(config, 'a', 'a');
  await waitForProbe(config, 'b', 'b');
  console.log('[Preview spike] KVS selects two protected dynamic Lambda origins');

  for (const method of ['POST', 'PUT']) {
    const body = JSON.stringify({ method, proof: 'dynamic-origin-oac' });
    await waitForProbe(config, 'a', 'a', method, body);
  }
  console.log('[Preview spike] signed body-bearing methods preserve the payload hash');

  await waitForProbe(config, 'a', 'a', 'DELETE');
  console.log('[Preview spike] protected DELETE requests reach the origin');

  const current = describeKvs(config.kvs_arn);
  parseJson(updateKvs(config.kvs_arn, current.ETag, [['a', config.lambda_hosts.b]]), 'KVS route switch');
  await waitForProbe(config, 'a', 'b');
  console.log('[Preview spike] KVS switches an origin without a distribution deployment');

  await verifyWebRoute(config);
}

async function verify() {
  const config = outputs();
  await verifyDirectOrigins(config);
  await verifyDynamicOrigins(config);
  console.log('[Preview spike] all live assertions passed');
}

function destroy() {
  tofu(['destroy', '-auto-approve', '-input=false']);
}

async function run() {
  const operation = process.argv[2] ?? 'plan';
  if (!['plan', 'run', 'destroy'].includes(operation)) {
    throw new Error('usage: node scripts/preview-spike.mjs [plan|run|destroy]');
  }

  assertAccount();
  initAndValidate();

  if (operation === 'plan') {
    tofu(['plan', '-input=false']);
    return;
  }
  if (operation === 'destroy') {
    destroy();
    return;
  }

  let applyStarted = false;
  try {
    applyStarted = true;
    tofu(['apply', '-auto-approve', '-input=false']);
    await verify();
  } finally {
    if (applyStarted) {
      console.log('[Preview spike] destroying temporary resources');
      destroy();
    }
  }
}

run().catch((error) => {
  console.error(`[Preview spike] ${error.message}`);
  process.exitCode = 1;
});
