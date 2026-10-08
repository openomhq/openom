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
    base: { ref: 'main', repo: { full_name: 'openomhq/openom' } },
    head: {
      ref: 'feat/ope-638',
      repo: { full_name: 'openomhq/openom' },
      sha: '0123456789abcdef0123456789abcdef01234567',
    },
    labels: [],
    number: 42,
    state: 'closed',
    ...overrides,
  };
}

function workflowRunEvent() {
  return {
    workflow_run: {
      conclusion: 'success',
      display_title: 'attacker-controlled title for PR #999',
      event: 'pull_request',
      head_branch: 'feat/ope-638',
      head_repository: { full_name: 'openomhq/openom' },
      head_sha: 'fedcba9876543210fedcba9876543210fedcba98',
      pull_requests: [{ number: 42 }],
    },
  };
}

test('reconciles the server-associated pull request and ignores the run title', async () => {
  const result = await resolvePreviewCleanupRequest({
    event: workflowRunEvent(),
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest()),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'reconcile');
  assert.equal(result.desired_mode, 'none');
  assert.equal(result.should_cleanup, 'true');
  assert.equal(result.pull_request_number, 42);
  assert.equal(result.resolution_source, 'workflow_run.pull_requests');
});

test('falls back to the unique pull request associated with the workflow commit', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  const routes = [];
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async (url) => {
      routes.push(url);
      return response(url.includes('/commits/') ? [pullRequest()] : pullRequest());
    },
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'reconcile');
  assert.equal(result.pull_request_number, 42);
  assert.equal(result.resolution_source, 'workflow_run.head_sha');
  assert.match(routes[0], /\/commits\/fedcba9876543210fedcba9876543210fedcba98\/pulls$/);
});

test('falls back to the unique pull request matching the workflow branch and SHA', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  const matchedPullRequest = pullRequest({
    head: {
      ref: event.workflow_run.head_branch,
      repo: { full_name: 'openomhq/openom' },
      sha: event.workflow_run.head_sha,
    },
  });
  const routes = [];
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async (url) => {
      routes.push(url);
      if (url.includes('/commits/')) return response([]);
      if (url.includes('/pulls?')) return response([matchedPullRequest]);
      return response(matchedPullRequest);
    },
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'reconcile');
  assert.equal(result.pull_request_number, 42);
  assert.equal(result.resolution_source, 'workflow_run.head_branch');
  assert.match(routes[1], /pulls\?state=all&base=main&head=openomhq%3Afeat%2Fope-638&per_page=100$/);
});

test('skips when GitHub provides no unique pull request association', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async () => response([]),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'skip');
  assert.equal(result.resolution_source, 'workflow_run.unresolved');
});

test('skips an ambiguous commit association', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async () => response([
      pullRequest(),
      pullRequest({ number: 43 }),
    ]),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'skip');
});

test('rejects lifecycle runs that did not originate from pull_request', async () => {
  const event = workflowRunEvent();
  event.workflow_run.event = 'workflow_dispatch';
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event,
      eventName: 'workflow_run',
      fetchImplementation: async () => response(pullRequest()),
      repository: 'openomhq/openom',
      token: 'token',
    }),
    (error) => error instanceof PreviewCleanupRequestError
      && error.code === 'invalid_lifecycle_event',
  );
});

for (const [labels, desiredMode] of [
  [[], 'none'],
  [['preview'], 'web'],
  [['full-preview'], 'full'],
  [['preview', 'full-preview'], 'full'],
]) {
  test(`reconciles an open pull request whose desired mode is ${desiredMode}`, async () => {
    const result = await resolvePreviewCleanupRequest({
      event: workflowRunEvent(),
      eventName: 'workflow_run',
      fetchImplementation: async () => response(pullRequest({
        labels: labels.map((name) => ({ name })),
        state: 'open',
      })),
      repository: 'openomhq/openom',
      token: 'token',
    });
    assert.equal(result.mode, 'reconcile');
    assert.equal(result.desired_mode, desiredMode);
  });
}

test('ignores fork pull requests even after closure', async () => {
  const result = await resolvePreviewCleanupRequest({
    event: workflowRunEvent(),
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest({
      head: {
        ref: 'feat/ope-638',
        repo: { full_name: 'fork/openom' },
        sha: '0123456789abcdef0123456789abcdef01234567',
      },
    })),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'skip');
});

test('rejects a source branch containing shell metacharacters', async () => {
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event: workflowRunEvent(),
      eventName: 'workflow_run',
      fetchImplementation: async () => response(pullRequest({
        head: {
          ref: 'fix/x;echo',
          repo: { full_name: 'openomhq/openom' },
          sha: '0123456789abcdef0123456789abcdef01234567',
        },
      })),
      repository: 'openomhq/openom',
      token: 'token',
    }),
    (error) => error?.code === 'invalid_source_branch',
  );
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
    desired_mode: 'none',
    mode: 'janitor',
    pull_request_number: '',
    resolution_source: 'schedule',
    should_cleanup: 'false',
    slug: '',
    source_branch: '',
  });
});
