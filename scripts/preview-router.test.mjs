#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../infra/terraform/preview/router.js', import.meta.url), 'utf8');

function route(overrides = {}) {
  return JSON.stringify({
    version: 1,
    slug: 'feat-ope-123',
    sourceBranch: 'feat/ope-123',
    pullRequestNumber: 123,
    commitSha: '0123456789abcdef0123456789abcdef01234567',
    mode: 'full',
    webOrigin: 'feat-ope-123.openom-preview.pages.dev',
    apiOrigin: 'abc123.lambda-url.eu-central-1.on.aws',
    ...overrides,
  });
}

function harness(entries = {}) {
  const originUpdates = [];
  const context = {
    __cf: {
      kvs: () => ({
        get: async (key) => {
          if (!(key in entries)) throw new Error('missing route');
          return entries[key];
        },
      }),
      updateRequestOrigin: (update) => originUpdates.push(update),
    },
  };
  vm.createContext(context);
  const executable = source
    .replace("import cf from 'cloudfront';", 'const cf = globalThis.__cf;')
    .concat('\nglobalThis.__handler = handler;');
  vm.runInContext(executable, context);
  return { handler: context.__handler, originUpdates };
}

function request(host, uri = '/trees/one') {
  return { request: { headers: { host: { value: host } }, method: 'GET', uri } };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test('routes app hosts to Pages while explicitly disabling Lambda OAC', async () => {
  const { handler, originUpdates } = harness({ 'feat-ope-123': route() });
  const event = request('feat-ope-123.app.dev.openom.org');

  assert.equal(await handler(event), event.request);
  assert.deepEqual(plain(originUpdates), [{
    domainName: 'feat-ope-123.openom-preview.pages.dev',
    originAccessControlConfig: { enabled: false },
  }]);
  assert.equal(event.request.uri, '/trees/one');
});

test('routes full API hosts by replacing only the protected origin hostname', async () => {
  const { handler, originUpdates } = harness({ 'feat-ope-123': route() });
  const event = request('feat-ope-123.api.dev.openom.org');

  assert.equal(await handler(event), event.request);
  assert.deepEqual(plain(originUpdates), [{
    domainName: 'abc123.lambda-url.eu-central-1.on.aws',
  }]);
});

test('does not expose an API route for a web-only preview', async () => {
  const { handler, originUpdates } = harness({
    'feat-ope-123': route({ mode: 'web', apiOrigin: undefined }),
  });

  const response = await handler(request('feat-ope-123.api.dev.openom.org'));
  assert.equal(response.statusCode, 404);
  assert.deepEqual(originUpdates, []);
});

test('rejects unknown hosts and missing records', async () => {
  const { handler, originUpdates } = harness();

  assert.equal((await handler(request('dev.openom.org'))).statusCode, 404);
  assert.equal((await handler(request('missing.app.dev.openom.org'))).statusCode, 404);
  assert.deepEqual(originUpdates, []);
});

test('rejects malformed slugs and host suffix confusion', async () => {
  const { handler } = harness({ 'feat-ope-123': route() });

  assert.equal((await handler(request('-bad.app.dev.openom.org'))).statusCode, 404);
  assert.equal((await handler(request('feat-ope-123.app.dev.openom.org.evil.test'))).statusCode, 404);
  assert.equal((await handler(request('a.b.app.dev.openom.org'))).statusCode, 404);
});

test('rejects malformed and cross-slug records', async () => {
  for (const record of ['not-json', route({ version: 2 }), route({ slug: 'other' })]) {
    const { handler } = harness({ 'feat-ope-123': record });
    assert.equal((await handler(request('feat-ope-123.app.dev.openom.org'))).statusCode, 404);
  }
});

test('rejects untrusted web and API origins', async () => {
  for (const record of [
    route({ webOrigin: 'attacker.test' }),
    route({ webOrigin: 'safe.pages.dev.evil.test' }),
    route({ apiOrigin: 'attacker.test' }),
    route({ apiOrigin: 'safe.lambda-url.us-east-1.on.aws' }),
  ]) {
    const { handler, originUpdates } = harness({ 'feat-ope-123': record });
    assert.equal((await handler(request('feat-ope-123.api.dev.openom.org'))).statusCode, 404);
    assert.deepEqual(originUpdates, []);
  }
});

test('returns a deterministic non-cacheable problem response', async () => {
  const { handler } = harness();
  const response = await handler(request('missing.app.dev.openom.org'));

  assert.equal(response.statusCode, 404);
  assert.equal(response.headers['cache-control'].value, 'no-store');
  assert.equal(response.headers['content-type'].value, 'application/problem+json');
  assert.deepEqual(JSON.parse(response.body), { code: 'preview_not_found' });
});
