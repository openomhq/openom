import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PREVIEW_INSTRUCTIONS_MARKER,
  PreviewInstructionsError,
  previewInstructions,
  reconcilePreviewInstructions,
} from './preview-instructions.mjs';

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function pullRequest({
  base = 'main',
  headRepository = 'openomhq/openom',
  labels = ['preview'],
  state = 'open',
} = {}) {
  return {
    base: { ref: base, repo: { full_name: 'openomhq/openom' } },
    head: { repo: { full_name: headRepository } },
    labels: labels.map((name) => ({ name })),
    state,
  };
}

function githubFetch({ comments = [], record = pullRequest() } = {}) {
  const requests = [];
  const fetchImplementation = async (url, options) => {
    requests.push({ body: options.body && JSON.parse(options.body), method: options.method, url });
    assert.equal(options.headers.authorization, 'Bearer token');
    if (url.endsWith('/pulls/42')) return response(record);
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

function reconcile(overrides = {}) {
  const github = githubFetch();
  return {
    github,
    result: reconcilePreviewInstructions({
      fetchImplementation: github.fetchImplementation,
      pullRequest: 42,
      repository: 'openomhq/openom',
      token: 'token',
      ...overrides,
    }),
  };
}

test('builds actionable instructions for the selected pull request', () => {
  const body = previewInstructions(42);
  assert.match(body, new RegExp(PREVIEW_INSTRUCTIONS_MARKER));
  assert.match(body, /preview\.deploy\.yml/);
  assert.match(body, /\| Web preview \| `42` \| `web` \|/);
  assert.match(body, /\| Full preview \| `42` \| `full` \|/);
  assert.match(body, /uses automatic DevAuth/);
  assert.match(body, /adds Supabase sign-in/);
});

test('creates instructions for an approved same-repository pull request', async () => {
  const { github, result } = reconcile();
  assert.deepEqual(await result, { action: 'created', commentId: 100, pullRequestNumber: 42 });
  assert.equal(github.requests[2].method, 'POST');
  assert.match(github.requests[2].body.body, /`42`/);
});

test('updates the existing bot-owned instructions instead of duplicating them', async () => {
  const github = githubFetch({
    comments: [{ body: PREVIEW_INSTRUCTIONS_MARKER, id: 99, user: { login: 'github-actions[bot]' } }],
  });
  const result = await reconcilePreviewInstructions({
    fetchImplementation: github.fetchImplementation,
    pullRequest: 42,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.deepEqual(result, { action: 'updated', commentId: 99, pullRequestNumber: 42 });
  assert.equal(github.requests[2].method, 'PATCH');
});

test('does not trust a contributor-owned marker comment', async () => {
  const github = githubFetch({
    comments: [{ body: PREVIEW_INSTRUCTIONS_MARKER, id: 7, user: { login: 'contributor' } }],
  });
  await reconcilePreviewInstructions({
    fetchImplementation: github.fetchImplementation,
    pullRequest: 42,
    repository: 'openomhq/openom',
    token: 'token',
  });
  assert.equal(github.requests[2].method, 'POST');
});

test('rejects malformed GitHub comment responses', async () => {
  const github = githubFetch({ comments: {} });
  await assert.rejects(
    reconcilePreviewInstructions({
      fetchImplementation: github.fetchImplementation,
      pullRequest: 42,
      repository: 'openomhq/openom',
      token: 'token',
    }),
    (error) => error instanceof PreviewInstructionsError
      && error.code === 'github_response_invalid',
  );
});

for (const [name, record, code] of [
  ['a closed pull request', pullRequest({ state: 'closed' }), 'preview_pull_request_closed'],
  ['a pull request targeting another branch', pullRequest({ base: 'develop' }), 'preview_base_invalid'],
  ['a fork pull request', pullRequest({ headRepository: 'contributor/openom' }), 'preview_fork_forbidden'],
  ['a pull request without approval', pullRequest({ labels: [] }), 'preview_approval_missing'],
]) {
  test(`rejects ${name}`, async () => {
    const github = githubFetch({ record });
    await assert.rejects(
      reconcilePreviewInstructions({
        fetchImplementation: github.fetchImplementation,
        pullRequest: 42,
        repository: 'openomhq/openom',
        token: 'token',
      }),
      (error) => error instanceof PreviewInstructionsError && error.code === code,
    );
    assert.equal(github.requests.length, 1);
  });
}
