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
      display_title: 'preview lifecycle for PR #42',
      event: 'pull_request',
      head_branch: 'feat/ope-638',
      head_sha: '0123456789abcdef0123456789abcdef01234567',
      pull_requests: [{ number: 42 }],
    },
  };
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

test('recovers the pull request from the trusted run title when GitHub omits associations', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest()),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'cleanup');
  assert.equal(result.pull_request_number, 42);
});

test('fails when a lifecycle run has no validated pull request identity', async () => {
  const event = workflowRunEvent();
  event.workflow_run.pull_requests = [];
  event.workflow_run.display_title = 'OPE-638: cleanup';
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event,
      eventName: 'workflow_run',
      fetchImplementation: async () => response(pullRequest()),
      repository: 'openomhq/openom',
      token: 'token',
    }),
    (error) => error instanceof PreviewCleanupRequestError
      && error.code === 'invalid_pull_request_number',
  );
});

test('requires maintainer permission for a manually dispatched lifecycle signal', async () => {
  const event = workflowRunEvent();
  event.workflow_run.event = 'workflow_dispatch';
  event.workflow_run.pull_requests = [];
  event.workflow_run.triggering_actor = { login: 'developer' };
  const fetchImplementation = async (url) => response(
    url.includes('/collaborators/') ? { permission: 'write' } : pullRequest(),
  );
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event,
      eventName: 'workflow_run',
      fetchImplementation,
      repository: 'openomhq/openom',
      token: 'token',
    }),
    (error) => error instanceof PreviewCleanupRequestError
      && error.code === 'preview_cleanup_actor_forbidden',
  );
});

test('accepts a manually dispatched lifecycle signal from a maintainer', async () => {
  const event = workflowRunEvent();
  event.workflow_run.event = 'workflow_dispatch';
  event.workflow_run.pull_requests = [];
  event.workflow_run.triggering_actor = { login: 'maintainer' };
  const fetchImplementation = async (url) => response(
    url.includes('/collaborators/') ? { permission: 'maintain' } : pullRequest(),
  );
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'cleanup');
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

test('cleans the full preview when full-preview is removed but preview remains', async () => {
  const event = workflowRunEvent();
  event.workflow_run.display_title = 'preview lifecycle for PR #42 after removing full-preview';
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest({
      labels: [{ name: 'preview' }],
      state: 'open',
    })),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'cleanup');
});

test('does not clean an approved preview after an unrelated label is removed', async () => {
  const event = workflowRunEvent();
  event.workflow_run.display_title = 'preview lifecycle for PR #42 after removing documentation';
  const result = await resolvePreviewCleanupRequest({
    event,
    eventName: 'workflow_run',
    fetchImplementation: async () => response(pullRequest({
      labels: [{ name: 'preview' }],
      state: 'open',
    })),
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(result.mode, 'skip');
});

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
  const event = workflowRunEvent();
  event.workflow_run.head_branch = 'fix/x;echo';
  await assert.rejects(
    resolvePreviewCleanupRequest({
      event,
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
    mode: 'janitor',
    pull_request_number: '',
    should_cleanup: 'false',
    slug: '',
    source_branch: '',
  });
});
