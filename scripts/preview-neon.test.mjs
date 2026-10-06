import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  PreviewNeonError,
  reconcilePreviewDatabase,
  runPreviewNeonCli,
} from './preview-neon.mjs';

const CONFIG = Object.freeze({
  apiKey: 'neon-api-key',
  baseBranchId: 'br-preview-base',
  branchName: 'preview/feat-ope-637',
  databaseName: 'neondb',
  maxFullStacks: 3,
  projectId: 'preview-project',
  pullRequestNumber: 42,
  roleName: 'neondb_owner',
  sourceBranch: 'feat/ope-637',
});

const OWNER = Object.freeze({
  'openom-preview-pull-request': '42',
  'openom-preview-source-branch': 'feat/ope-637',
});

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function baseBranch() {
  return { id: CONFIG.baseBranchId, name: 'preview-base' };
}

function previewBranch(overrides = {}) {
  return {
    id: 'br-preview-42',
    name: CONFIG.branchName,
    parent_id: CONFIG.baseBranchId,
    ...overrides,
  };
}

function listing(branches, owner = OWNER) {
  const branch = branches.find((candidate) => candidate.name === CONFIG.branchName);
  return {
    annotations: branch ? {
      [branch.id]: {
        value: owner,
      },
    } : {},
    branches,
  };
}

function successfulFetch({ existing = false } = {}) {
  const calls = [];
  let created = existing;
  const fetchImplementation = async (urlValue, options) => {
    const url = new URL(urlValue);
    calls.push({ body: options.body ? JSON.parse(options.body) : null, method: options.method, url });
    assert.equal(options.headers.authorization, 'Bearer neon-api-key');

    if (url.pathname.endsWith('/branches') && options.method === 'GET') {
      return response(listing(created ? [baseBranch(), previewBranch()] : [baseBranch()]));
    }
    if (url.pathname.endsWith('/branches') && options.method === 'POST') {
      created = true;
      return response({ branch: previewBranch() }, 201);
    }
    if (url.pathname.endsWith('/branches/br-preview-42/endpoints')) {
      return response({ endpoints: [{ id: 'ep-preview-42', type: 'read_write' }] });
    }
    if (url.pathname.endsWith('/connection_uri')) {
      const pooled = url.searchParams.get('pooled') === 'true';
      return response({
        uri: `postgresql://owner:password@ep-preview-42${pooled ? '-pooler' : ''}.example.test/neondb`,
      });
    }
    return response({}, 404);
  };
  return { calls, fetchImplementation };
}

test('creates an owned branch and returns distinct pooled and migration URLs', async () => {
  const api = successfulFetch();
  const result = await reconcilePreviewDatabase({ ...CONFIG, fetchImplementation: api.fetchImplementation });

  assert.deepEqual(result, {
    branchId: 'br-preview-42',
    branchName: CONFIG.branchName,
    databaseUrl: 'postgresql://owner:password@ep-preview-42-pooler.example.test/neondb',
    endpointId: 'ep-preview-42',
    migrationDatabaseUrl: 'postgresql://owner:password@ep-preview-42.example.test/neondb',
  });
  const creation = api.calls.find((call) => call.method === 'POST');
  assert.deepEqual(creation.body, {
    annotation_value: OWNER,
    branch: {
      name: CONFIG.branchName,
      parent_id: CONFIG.baseBranchId,
      protected: false,
    },
    endpoints: [{ type: 'read_write' }],
  });
  assert.equal(api.calls.filter((call) => call.url.pathname.endsWith('/branches')).length, 3);
});

test('reuses an existing branch owned by the same pull request', async () => {
  const api = successfulFetch({ existing: true });
  await reconcilePreviewDatabase({ ...CONFIG, fetchImplementation: api.fetchImplementation });
  assert.equal(api.calls.filter((call) => call.method === 'POST').length, 0);
});

test('capacity applies only when allocating another full stack', async () => {
  const fetchImplementation = async (urlValue, options) => {
    const url = new URL(urlValue);
    if (url.pathname.endsWith('/branches') && options.method === 'GET') {
      return response(listing([
        baseBranch(),
        { id: 'br-one', name: 'preview/one' },
        { id: 'br-two', name: 'preview/two' },
      ]));
    }
    throw new Error('capacity rejection must not mutate Neon');
  };
  await assert.rejects(
    reconcilePreviewDatabase({ ...CONFIG, fetchImplementation, maxFullStacks: 2 }),
    (error) => error instanceof PreviewNeonError && error.code === 'preview_capacity_reached',
  );

  const existing = successfulFetch({ existing: true });
  await assert.doesNotReject(reconcilePreviewDatabase({
    ...CONFIG,
    fetchImplementation: existing.fetchImplementation,
    maxFullStacks: 1,
  }));
});

test('fails closed when the branch parent or ownership does not match', async () => {
  for (const [branch, owner, code] of [
    [previewBranch({ parent_id: 'br-main' }), OWNER, 'preview_neon_parent_mismatch'],
    [previewBranch(), { ...OWNER, 'openom-preview-pull-request': '99' }, 'preview_neon_owner_mismatch'],
  ]) {
    const fetchImplementation = async () => response(listing([baseBranch(), branch], owner));
    await assert.rejects(
      reconcilePreviewDatabase({ ...CONFIG, fetchImplementation }),
      (error) => error instanceof PreviewNeonError && error.code === code,
    );
  }
});

test('reconciles an uncertain branch create instead of issuing a duplicate create', async () => {
  let branchExists = false;
  let createCalls = 0;
  const fetchImplementation = async (urlValue, options) => {
    const url = new URL(urlValue);
    if (url.pathname.endsWith('/branches') && options.method === 'GET') {
      return response(listing(branchExists ? [baseBranch(), previewBranch()] : [baseBranch()]));
    }
    if (url.pathname.endsWith('/branches') && options.method === 'POST') {
      createCalls += 1;
      branchExists = true;
      throw new Error('connection reset after Neon accepted the request');
    }
    if (url.pathname.endsWith('/branches/br-preview-42/endpoints')) {
      return response({ endpoints: [{ id: 'ep-preview-42', type: 'read_write' }] });
    }
    if (url.pathname.endsWith('/connection_uri')) {
      return response({ uri: 'postgresql://owner:password@example.test/neondb' });
    }
    return response({}, 404);
  };

  await assert.doesNotReject(reconcilePreviewDatabase({ ...CONFIG, fetchImplementation }));
  assert.equal(createCalls, 1);
});

test('waits for a created branch and its ownership annotation to become visible', async () => {
  let branchLists = 0;
  const pauses = [];
  const fetchImplementation = async (urlValue, options) => {
    const url = new URL(urlValue);
    if (url.pathname.endsWith('/branches') && options.method === 'GET') {
      branchLists += 1;
      if (branchLists <= 2) return response(listing([baseBranch()]));
      if (branchLists === 3) {
        return response({ branches: [baseBranch(), previewBranch()], annotations: {} });
      }
      return response(listing([baseBranch(), previewBranch()]));
    }
    if (url.pathname.endsWith('/branches') && options.method === 'POST') {
      return response({ branch: previewBranch() });
    }
    if (url.pathname.endsWith('/branches/br-preview-42/endpoints')) {
      return response({ endpoints: [{ id: 'ep-preview-42', type: 'read_write' }] });
    }
    if (url.pathname.endsWith('/connection_uri')) {
      return response({ uri: 'postgresql://owner:password@example.test/neondb' });
    }
    return response({}, 404);
  };

  await assert.doesNotReject(reconcilePreviewDatabase({
    ...CONFIG,
    attempts: 4,
    fetchImplementation,
    pause: async (milliseconds) => pauses.push(milliseconds),
  }));
  assert.equal(branchLists, 4);
  assert.deepEqual(pauses, [250, 500]);
});

test('retries documented transient responses with a bounded delay', async () => {
  const api = successfulFetch({ existing: true });
  let first = true;
  const pauses = [];
  const fetchImplementation = async (url, options) => {
    if (first) {
      first = false;
      return response({}, 503);
    }
    return api.fetchImplementation(url, options);
  };
  await reconcilePreviewDatabase({
    ...CONFIG,
    fetchImplementation,
    pause: async (milliseconds) => pauses.push(milliseconds),
  });
  assert.deepEqual(pauses, [250]);
});

test('writes credentials only to the requested private output file', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'openom-preview-neon-'));
  const outputFile = path.join(directory, 'database.json');
  const api = successfulFetch({ existing: true });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = api.fetchImplementation;
  try {
    const publicResult = await runPreviewNeonCli([
      'reconcile',
      '--branch', CONFIG.branchName,
      '--source-branch', CONFIG.sourceBranch,
      '--pull-request', String(CONFIG.pullRequestNumber),
      '--output-file', outputFile,
    ], {
      NEON_API_KEY: CONFIG.apiKey,
      NEON_DATABASE_NAME: CONFIG.databaseName,
      NEON_PREVIEW_BASE_BRANCH_ID: CONFIG.baseBranchId,
      NEON_PROJECT_ID: CONFIG.projectId,
      NEON_ROLE_NAME: CONFIG.roleName,
      PREVIEW_MAX_FULL_STACKS: String(CONFIG.maxFullStacks),
    });
    const stored = JSON.parse(readFileSync(outputFile, 'utf8'));
    assert.deepEqual(publicResult, {
      branchId: 'br-preview-42',
      branchName: CONFIG.branchName,
      endpointId: 'ep-preview-42',
    });
    assert.match(stored.databaseUrl, /^postgresql:\/\//);
    if (process.platform !== 'win32') assert.equal(statSync(outputFile).mode & 0o777, 0o600);
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});
