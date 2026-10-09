import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PREVIEW_CLEANUP_MARKER,
  berlinTimestamp,
  previewCleanupComment,
  reconcilePreviewCleanupComment,
  runPreviewCleanupCommentCli,
} from './preview-cleanup-comment.mjs';

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function githubFetch(comments = []) {
  const requests = [];
  const fetchImplementation = async (url, options) => {
    requests.push({ body: options.body && JSON.parse(options.body), method: options.method, url });
    assert.equal(options.headers.authorization, 'Bearer token');
    if (url.endsWith('/issues/42/comments?per_page=100')) return response(comments);
    if (url.endsWith('/issues/42/comments') && options.method === 'POST') {
      return response({ id: 100 }, 201);
    }
    if (url.endsWith('/issues/comments/99') && options.method === 'PATCH') {
      return response({ id: 99 });
    }
    return response({}, 404);
  };
  return { fetchImplementation, requests };
}

function cleanup() {
  return {
    apiUrl: 'https://fix-ope-601.api.dev.openom.org',
    appUrl: 'https://fix-ope-601.app.dev.openom.org',
    branch: 'fix/ope-601',
    completedAt: new Date('2026-10-07T16:05:00Z'),
    runId: 37649128750,
    runNumber: 4,
    serverUrl: 'https://github.com',
  };
}

test('formats cleanup time in Berlin with daylight saving', () => {
  assert.equal(berlinTimestamp('2026-10-07T16:05:00Z'), '2026/10/07 18:05 CEST');
  assert.equal(berlinTimestamp('2026-12-07T16:05:00Z'), '2026/12/07 17:05 CET');
});

test('builds the cleanup comment with resource and workflow details', () => {
  const body = previewCleanupComment({ ...cleanup(), repository: 'openomhq/openom' });
  assert.match(body, new RegExp(PREVIEW_CLEANUP_MARKER));
  assert.match(body, /Cleanup is idempotent/);
  assert.match(body, /\| app \| `https:\/\/fix-ope-601\.app\.dev\.openom\.org` \| Removed \|/);
  assert.match(body, /\| api \| `https:\/\/fix-ope-601\.api\.dev\.openom\.org` \| Removed \|/);
  assert.match(body, /\*2026\/10\/07 18:05 CEST\*/);
  assert.match(body, /\[preview\.cleanup #4\]\(https:\/\/github\.com\/openomhq\/openom\/actions\/runs\/37649128750\)/);
});

test('explains how to redeploy a still-approved web preview', () => {
  const body = previewCleanupComment({
    ...cleanup(),
    redeployMode: 'web',
    repository: 'openomhq/openom',
  });
  assert.match(body, /still allows a web preview/);
  assert.match(body, /Run `preview\.deploy` in `web` mode/);
});

test('creates a cleanup comment when none exists', async () => {
  const github = githubFetch();
  const result = await reconcilePreviewCleanupComment({
    cleanup: cleanup(),
    fetchImplementation: github.fetchImplementation,
    pullRequest: 42,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.deepEqual(result, { action: 'created', commentId: 100, pullRequestNumber: 42 });
  assert.equal(github.requests[1].method, 'POST');
});

test('updates the existing bot-owned cleanup comment on a replay', async () => {
  const github = githubFetch([
    { body: PREVIEW_CLEANUP_MARKER, id: 99, user: { login: 'github-actions[bot]' } },
  ]);
  const result = await reconcilePreviewCleanupComment({
    cleanup: cleanup(),
    fetchImplementation: github.fetchImplementation,
    pullRequest: 42,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.deepEqual(result, { action: 'updated', commentId: 99, pullRequestNumber: 42 });
  assert.equal(github.requests[1].method, 'PATCH');
});

test('does not overwrite a contributor-owned marker comment', async () => {
  const github = githubFetch([
    { body: PREVIEW_CLEANUP_MARKER, id: 7, user: { login: 'contributor' } },
  ]);
  await reconcilePreviewCleanupComment({
    cleanup: cleanup(),
    fetchImplementation: github.fetchImplementation,
    pullRequest: 42,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(github.requests[1].method, 'POST');
});

test('reconciles every cleanup emitted by lifecycle or janitor runs', async () => {
  const github = githubFetch();
  const result = await runPreviewCleanupCommentCli({
    GITHUB_API_URL: 'https://api.github.com',
    GITHUB_REPOSITORY: 'openomhq/openom',
    GITHUB_RUN_ID: '37649128750',
    GITHUB_RUN_NUMBER: '4',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_TOKEN: 'token',
    PREVIEW_CLEANUPS: JSON.stringify([{
      apiUrl: cleanup().apiUrl,
      appUrl: cleanup().appUrl,
      branch: cleanup().branch,
      pullRequestNumber: 42,
      redeployMode: 'web',
    }]),
  }, github.fetchImplementation);
  assert.deepEqual(result, [{ action: 'created', commentId: 100, pullRequestNumber: 42 }]);
  assert.match(github.requests[1].body.body, /still allows a web preview/);
});
