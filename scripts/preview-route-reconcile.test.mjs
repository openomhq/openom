import assert from 'node:assert/strict';
import test from 'node:test';

import { previewIdentity } from './preview-name.mjs';
import {
  assertWebPreviewDeployable,
  deletePreviewRoute,
  listPreviewRoutes,
  PreviewRouteError,
  putPreviewRoute,
  restorePreviewRoute,
} from './preview-route.mjs';

const SHA = '0123456789abcdef0123456789abcdef01234567';
const IDENTITY = previewIdentity('feat/ope-513', 42);

function result(status, body = {}, stderr = '') {
  return { status, stdout: JSON.stringify(body), stderr };
}

function commandName(args) {
  return args[1];
}

test('publishes a web route with the current KVS ETag', async () => {
  const calls = [];
  const execute = (binary, args) => {
    calls.push([binary, args]);
    if (commandName(args) === 'get-key') return result(254, {}, 'ResourceNotFoundException');
    if (commandName(args) === 'describe-key-value-store') return result(0, { ETag: 'KV1' });
    if (commandName(args) === 'put-key') return result(0, { ETag: 'KV2' });
    throw new Error('unexpected command');
  };
  const published = await putPreviewRoute({
    commitSha: SHA,
    execute,
    identity: IDENTITY,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
    pagesProject: 'openom-preview',
  });
  assert.deepEqual(published, {
    previous: null,
    record: {
      version: 1,
      slug: 'feat-ope-513',
      sourceBranch: 'feat/ope-513',
      pullRequestNumber: 42,
      commitSha: SHA,
      mode: 'web',
      webOrigin: 'feat-ope-513.openom-preview.pages.dev',
    },
  });
  assert.deepEqual(calls.map(([, args]) => commandName(args)), [
    'get-key',
    'describe-key-value-store',
    'put-key',
  ]);
  assert.ok(calls[2][1].includes('KV1'));
});

test('refuses a web deploy until an existing full preview is cleaned', () => {
  const existing = {
    version: 1,
    slug: IDENTITY.slug,
    sourceBranch: IDENTITY.sourceBranch,
    pullRequestNumber: IDENTITY.pullRequestNumber,
    commitSha: SHA,
    mode: 'full',
    webOrigin: 'feat-ope-513.openom-preview.pages.dev',
    apiOrigin: 'example.lambda-url.eu-central-1.on.aws',
  };
  assert.throws(
    () => assertWebPreviewDeployable({
      execute: () => result(0, { Value: JSON.stringify(existing) }),
      identity: IDENTITY,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
    }),
    (error) => error instanceof PreviewRouteError
      && error.code === 'preview_downgrade_requires_cleanup',
  );
  assert.doesNotThrow(() => assertWebPreviewDeployable({
    execute: () => result(0, { Value: JSON.stringify({ ...existing, mode: 'web' }) }),
    identity: IDENTITY,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
  }));
});

test('retries an ETag conflict against fresh route ownership and state', async () => {
  let describeCount = 0;
  let putCount = 0;
  const pauses = [];
  const execute = (binary, args) => {
    if (commandName(args) === 'get-key') return result(254, {}, 'ResourceNotFoundException');
    if (commandName(args) === 'describe-key-value-store') {
      describeCount += 1;
      return result(0, { ETag: `KV${describeCount}` });
    }
    putCount += 1;
    return putCount === 1
      ? result(255, {}, 'PreconditionFailedException')
      : result(0, { ETag: 'KV3' });
  };
  await putPreviewRoute({
    commitSha: SHA,
    execute,
    identity: IDENTITY,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
    pagesProject: 'openom-preview',
    pause: async (milliseconds) => pauses.push(milliseconds),
  });
  assert.equal(putCount, 2);
  assert.deepEqual(pauses, [250]);
});

test('refuses to replace a colliding branch slug', async () => {
  const existing = {
    version: 1,
    slug: IDENTITY.slug,
    sourceBranch: 'feat/ope-513-other',
    pullRequestNumber: 99,
  };
  const execute = (binary, args) => {
    if (commandName(args) === 'get-key') return result(0, { Value: JSON.stringify(existing) });
    throw new Error('route mutation must not continue after a collision');
  };
  await assert.rejects(
    putPreviewRoute({
      commitSha: SHA,
      execute,
      identity: IDENTITY,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
      pagesProject: 'openom-preview',
    }),
    (error) => error.code === 'preview_slug_collision',
  );
});

test('fails closed on a malformed existing route', async () => {
  const execute = () => result(0, { Value: 'not-json' });
  await assert.rejects(
    putPreviewRoute({
      commitSha: SHA,
      execute,
      identity: IDENTITY,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
      pagesProject: 'openom-preview',
    }),
    (error) => error instanceof PreviewRouteError && error.code === 'invalid_existing_route',
  );
});

test('stops after bounded compare-and-swap contention', async () => {
  const execute = (binary, args) => {
    if (commandName(args) === 'get-key') return result(254, {}, 'ResourceNotFoundException');
    if (commandName(args) === 'describe-key-value-store') return result(0, { ETag: 'KV1' });
    return result(255, {}, 'PreconditionFailedException');
  };
  await assert.rejects(
    putPreviewRoute({
      attempts: 2,
      commitSha: SHA,
      execute,
      identity: IDENTITY,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
      pagesProject: 'openom-preview',
      pause: async () => {},
    }),
    (error) => error instanceof PreviewRouteError && error.code === 'preview_route_contention',
  );
});

test('removes a newly installed route when public acceptance fails', async () => {
  const installed = {
    version: 1,
    slug: IDENTITY.slug,
    sourceBranch: IDENTITY.sourceBranch,
    pullRequestNumber: IDENTITY.pullRequestNumber,
    commitSha: SHA,
    mode: 'web',
    webOrigin: 'feat-ope-513.openom-preview.pages.dev',
  };
  const operations = [];
  const execute = (binary, args) => {
    operations.push(commandName(args));
    if (commandName(args) === 'get-key') return result(0, { Value: JSON.stringify(installed) });
    if (commandName(args) === 'describe-key-value-store') return result(0, { ETag: 'KV2' });
    return result(0, { ETag: 'KV3' });
  };
  await restorePreviewRoute({
    execute,
    identity: IDENTITY,
    installed,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
    previous: null,
  });
  assert.deepEqual(operations, ['get-key', 'describe-key-value-store', 'delete-key']);
});

test('refuses rollback after another deployment changed the route', async () => {
  const installed = { version: 1, slug: IDENTITY.slug, commitSha: SHA };
  const execute = () => result(0, {
    Value: JSON.stringify({ ...installed, commitSha: 'f'.repeat(40) }),
  });
  await assert.rejects(
    restorePreviewRoute({
      execute,
      identity: IDENTITY,
      installed,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
      previous: null,
    }),
    (error) => error instanceof PreviewRouteError && error.code === 'preview_route_changed',
  );
});

test('deletes only the route owned by the requested pull request', async () => {
  const existing = {
    version: 1,
    slug: IDENTITY.slug,
    sourceBranch: IDENTITY.sourceBranch,
    pullRequestNumber: IDENTITY.pullRequestNumber,
  };
  const operations = [];
  const execute = (binary, args) => {
    operations.push(commandName(args));
    if (commandName(args) === 'get-key') return result(0, { Value: JSON.stringify(existing) });
    if (commandName(args) === 'describe-key-value-store') return result(0, { ETag: 'KV1' });
    return result(0, { ETag: 'KV2' });
  };
  assert.deepEqual(await deletePreviewRoute({
    execute,
    identity: IDENTITY,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
  }), { deleted: true });
  assert.deepEqual(operations, ['get-key', 'describe-key-value-store', 'delete-key']);

  await assert.rejects(
    deletePreviewRoute({
      execute: () => result(0, { Value: JSON.stringify({
        ...existing,
        pullRequestNumber: 99,
      }) }),
      identity: IDENTITY,
      kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
    }),
    (error) => error.code === 'preview_slug_collision',
  );
});

test('treats an already absent route as cleaned', async () => {
  const cleaned = await deletePreviewRoute({
    execute: () => result(254, {}, 'ResourceNotFoundException'),
    identity: IDENTITY,
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
  });
  assert.deepEqual(cleaned, { deleted: false });
});

test('discovers owned routes for lifecycle reconciliation', () => {
  const record = {
    version: 1,
    slug: IDENTITY.slug,
    sourceBranch: IDENTITY.sourceBranch,
    pullRequestNumber: IDENTITY.pullRequestNumber,
    mode: 'web',
  };
  const listed = listPreviewRoutes({
    execute: () => result(0, {
      Items: [{ Key: IDENTITY.slug, Value: JSON.stringify(record) }],
    }),
    kvsArn: 'arn:aws:cloudfront::123456789012:key-value-store/example',
  });
  assert.deepEqual(listed, [IDENTITY]);
});
