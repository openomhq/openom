import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PreviewCleanupRequestError,
  resolvePreviewCleanupRequest,
} from './preview-cleanup-request.mjs';

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}

function pullRequest(overrides = {}) {
  return {
    head: { ref: 'feat/ope-638', repo: { full_name: 'openomhq/openom' } },
    labels: [],
    number: 42,
    state: 'closed',
    ...overrides,
  };
}

function workflowRunEvent() {
  return { workflow_run: { pull_requests: [{ number: 42 }] } };
}

test('cleans a closed same-repository pull request from a trusted workflow run', async () => {
  const result = await resolvePreviewCleanupRequest({
    event: workflowRunEvent(),
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest()),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'cleanup');
  assert.equal(result.slug, 'feat-ope-638');
});

test('skips an open pull request that retains either approval label', async () => {
  for (const label of ['preview', 'full-preview']) {
    const result = await resolvePreviewCleanupRequest({
      event: workflowRunEvent(),
      eventName: 'workflow_run',
      fetchImplementation: async () => response(pullRequest({
        labels: [{ name: label }],
        state: 'open',
      })),
      repository: 'openomhq/openom',
      token: 'token',
    });
    assert.equal(result.mode, 'skip');
  }
});

test('ignores fork pull requests even after closure', async () => {
  const result = await resolvePreviewCleanupRequest({
    event: workflowRunEvent(),
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest({
      head: { ref: 'feat/ope-638', repo: { full_name: 'fork/openom' } },
    })),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'skip');
});

test('requires maintainer permission for manual cleanup', async () => {
  const fetchImplementation = async (url) => response(
    url.includes('/collaborators/') ? { permission: 'write' } : pullRequest(),
  );
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event: {},
      eventName: 'workflow_dispatch',
      fetchImplementation,
      manualPullRequest: '42',
      repository: 'openomhq/openom',
      token: 'token',
      triggeringActor: 'developer',
    }),
    (error) => error instanceof PreviewCleanupRequestError
      && error.code === 'preview_cleanup_actor_forbidden',
  );
});

test('emits janitor mode for the nightly schedule', async () => {
  assert.deepEqual(await resolvePreviewCleanupRequest({
    event: {},
    eventName: 'schedule',
    repository: 'openomhq/openom',
    token: 'token',
  }), {
    api_url: '',
    app_url: '',
    mode: 'janitor',
    pull_request_number: '',
    should_cleanup: 'false',
    slug: '',
    source_branch: '',
  });
});
