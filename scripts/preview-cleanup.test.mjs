import assert from 'node:assert/strict';
import test from 'node:test';

import { previewIdentity } from './preview-name.mjs';
import {
  cleanupPreview,
  deletePreviewArtifactPrefix,
  deletePreviewObjectPrefix,
  janitorPreviewResources,
  listDesiredPullRequests,
  PreviewCleanupError,
  reconcilePreviewResources,
  selectOrphanedPreviews,
} from './preview-cleanup.mjs';

const IDENTITY = previewIdentity('feat/ope-638', 42);
const ENVIRONMENT = Object.freeze({
  AWS_CLOUDFRONT_KVS_ARN: 'arn:aws:cloudfront::123456789012:key-value-store/example',
  AWS_PREVIEW_ARTIFACTS_BUCKET: 'openom-preview-artifacts',
  GITHUB_API_URL: 'https://api.github.com',
  GITHUB_REPOSITORY: 'openomhq/openom',
  GITHUB_RUN_ID: '99',
  GITHUB_SERVER_URL: 'https://github.com',
  GITHUB_TOKEN: 'token',
  NEON_API_KEY: 'neon-token',
  NEON_PREVIEW_BASE_BRANCH_ID: 'br-preview-base',
  NEON_PROJECT_ID: 'preview-project',
  R2_ACCESS_KEY_ID: 'r2-access',
  R2_BUCKET: 'openom-preview',
  R2_ENDPOINT: 'https://account.eu.r2.cloudflarestorage.com',
  R2_SECRET_ACCESS_KEY: 'r2-secret',
});

test('removes a preview in fail-closed lifecycle order', async () => {
  const phases = [];
  const operation = (name, result) => async () => {
    phases.push(name);
    return result;
  };
  const result = await cleanupPreview({
    environment: ENVIRONMENT,
    identity: IDENTITY,
    operations: {
      deleteArtifactPrefix: operation('artifacts', { deletedPrefix: 'artifacts' }),
      deleteDatabase: operation('database', { deleted: true }),
      deleteDeployment: operation('deployment', { retired: 1 }),
      deleteLambda: operation('lambda', { deleted: true }),
      deleteObjectPrefix: operation('object-store', { deletedPrefix: 'objects' }),
      deleteRoute: operation('route', { deleted: true }),
      waitForRouteRemoval: operation('route-convergence', { converged: true }),
    },
  });
  assert.deepEqual(phases, [
    'route',
    'route-convergence',
    'lambda',
    'database',
    'object-store',
    'artifacts',
    'deployment',
  ]);
  assert.deepEqual(result.phases, phases);
});

test('keeps deletion commands inside exact preview prefixes', () => {
  const calls = [];
  const execute = (binary, args, options) => {
    calls.push({ args, binary, options });
    return { status: 0, stderr: '', stdout: '' };
  };
  deletePreviewObjectPrefix({
    accessKeyId: 'access',
    bucket: 'openom-preview',
    endpoint: 'https://account.eu.r2.cloudflarestorage.com',
    execute,
    identity: IDENTITY,
    secretAccessKey: 'secret',
  });
  deletePreviewArtifactPrefix({
    bucket: 'openom-preview-artifacts',
    execute,
    identity: IDENTITY,
  });
  assert.equal(calls[0].binary, 'docker');
  assert.ok(calls[0].args.includes('s3://openom-preview/previews/feat-ope-638/'));
  assert.equal(calls[0].options.env.AWS_ACCESS_KEY_ID, 'access');
  assert.equal(calls[1].binary, 'aws');
  assert.ok(calls[1].args.includes('s3://openom-preview-artifacts/previews/feat-ope-638/'));
});

test('lists desired modes for every open same-repository pull request', async () => {
  const fetchImplementation = async () => ({
    ok: true,
    status: 200,
    async json() {
      return [
        { head: { ref: 'feat/one', repo: { full_name: 'openomhq/openom' } }, labels: [{ name: 'preview' }], number: 1, state: 'open' },
        { head: { ref: 'feat/two', repo: { full_name: 'fork/openom' } }, labels: [{ name: 'full-preview' }], number: 2, state: 'open' },
        { head: { ref: 'feat/three', repo: { full_name: 'openomhq/openom' } }, labels: [], number: 3, state: 'open' },
      ];
    },
  });
  const listed = await listDesiredPullRequests({
    fetchImplementation,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.deepEqual(listed.map(({ identity, mode }) => [identity.pullRequestNumber, mode]), [
    [1, 'web'],
    [3, 'none'],
  ]);
});

test('reconciles actual resources against the current desired mode', async () => {
  const scenarios = [
    {
      desiredMode: 'full',
      discovered: { database: [IDENTITY], deployment: [IDENTITY], lambda: [IDENTITY], route: [{ identity: IDENTITY, mode: 'full' }] },
      expectedCleanup: false,
    },
    {
      desiredMode: 'web',
      discovered: { database: [], deployment: [IDENTITY], lambda: [], route: [{ identity: IDENTITY, mode: 'web' }] },
      expectedCleanup: false,
    },
    {
      desiredMode: 'web',
      discovered: { database: [IDENTITY], deployment: [IDENTITY], lambda: [IDENTITY], route: [{ identity: IDENTITY, mode: 'full' }] },
      expectedCleanup: true,
    },
    {
      desiredMode: 'none',
      discovered: { database: [], deployment: [IDENTITY], lambda: [], route: [{ identity: IDENTITY, mode: 'web' }] },
      expectedCleanup: true,
    },
  ];
  for (const scenario of scenarios) {
    const cleaned = [];
    const result = await reconcilePreviewResources({
      desiredMode: scenario.desiredMode,
      environment: ENVIRONMENT,
      identity: IDENTITY,
      operations: {
        cleanup: async ({ identity }) => {
          cleaned.push(identity.slug);
          return { identity };
        },
        discover: async () => scenario.discovered,
      },
    });
    assert.equal(cleaned.length > 0, scenario.expectedCleanup);
    assert.equal(result.comments.length > 0, scenario.expectedCleanup);
    if (scenario.desiredMode === 'web' && scenario.expectedCleanup) {
      assert.equal(result.comments[0].redeployMode, 'web');
    }
  }
});

test('janitor removes full-stack resources that exceed preview-only approval', () => {
  const identity = previewIdentity('feat/web-only', 7);
  const approved = [{ identity, mode: 'web' }];
  assert.equal(selectOrphanedPreviews({
    desired: approved,
    discovered: [{ identity, routeMode: 'web', sources: new Set(['deployment', 'route']) }],
  }).length, 0);
  for (const record of [
    { identity, routeMode: 'full', sources: new Set(['deployment', 'route']) },
    { identity, routeMode: 'web', sources: new Set(['database', 'deployment', 'route']) },
    { identity, routeMode: 'web', sources: new Set(['deployment', 'lambda', 'route']) },
  ]) {
    assert.deepEqual(selectOrphanedPreviews({ desired: approved, discovered: [record] }), [record]);
  }
});

test('keeps renamed previews until the replacement route is live', () => {
  const previous = previewIdentity('feat/old', 42);
  const replacement = previewIdentity('feat/new', 42);
  assert.deepEqual(selectOrphanedPreviews({
    desired: [replacement],
    discovered: [{ identity: previous, sources: new Set(['lambda', 'route']) }],
  }), []);
  const orphaned = selectOrphanedPreviews({
    desired: [replacement],
    discovered: [
      { identity: previous, sources: new Set(['lambda', 'route']) },
      { identity: replacement, sources: new Set(['route']) },
    ],
  });
  assert.deepEqual(orphaned.map((record) => record.identity.slug), ['feat-old']);
});

test('janitor cleans closed and unapproved resource owners once', async () => {
  const active = previewIdentity('feat/active', 1);
  const orphan = previewIdentity('feat/orphan', 2);
  const cleaned = [];
  const result = await janitorPreviewResources({
    environment: ENVIRONMENT,
    operations: {
      cleanup: async ({ identity }) => {
        cleaned.push(identity.slug);
        return { identity };
      },
      discover: async () => ({
        database: [active, orphan],
        deployment: [active, orphan],
        lambda: [orphan],
        route: [active, orphan],
      }),
      listDesired: async () => [active],
    },
  });
  assert.deepEqual(cleaned, ['feat-orphan']);
  assert.equal(result.discovered, 2);
  assert.equal(result.cleaned.length, 1);
  assert.deepEqual(result.comments, []);
});

test('janitor comments when it cleans a downgraded open pull request', async () => {
  const identity = previewIdentity('feat/web-only', 7);
  const result = await janitorPreviewResources({
    environment: ENVIRONMENT,
    operations: {
      cleanup: async ({ identity: cleanedIdentity }) => ({ identity: cleanedIdentity }),
      discover: async () => ({
        database: [identity],
        deployment: [identity],
        lambda: [identity],
        route: [{ identity, mode: 'full' }],
      }),
      listDesired: async () => [{ identity, mode: 'web' }],
    },
  });
  assert.deepEqual(result.comments, [{
    apiUrl: identity.apiUrl,
    appUrl: identity.appUrl,
    branch: identity.sourceBranch,
    pullRequestNumber: 7,
    redeployMode: 'web',
  }]);
});

test('janitor resumes cleanup when only the deployment inventory survived', async () => {
  const orphan = previewIdentity('feat/orphan', 2);
  const cleaned = [];
  await janitorPreviewResources({
    environment: ENVIRONMENT,
    operations: {
      cleanup: async ({ identity }) => cleaned.push(identity.slug),
      discover: async () => ({
        database: [],
        deployment: [orphan],
        lambda: [],
        route: [],
      }),
      listDesired: async () => [],
    },
  });
  assert.deepEqual(cleaned, ['feat-orphan']);
});

test('rejects conflicting ownership for one normalized slug', async () => {
  await assert.rejects(
    janitorPreviewResources({
      environment: ENVIRONMENT,
      operations: {
        discover: async () => ({
          database: [],
          deployment: [],
          lambda: [previewIdentity('feat/conflict', 1)],
          route: [previewIdentity('feat-conflict', 2)],
        }),
        listDesired: async () => [],
      },
    }),
    (error) => error instanceof PreviewCleanupError
      && error.code === 'preview_cleanup_identity_collision',
  );
});
