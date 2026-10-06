import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  PreviewRequestError,
  resolvePreviewRequest,
  runPreviewRequestCli,
} from './preview-request.mjs';

const SHA = '0123456789abcdef0123456789abcdef01234567';

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function githubFetch({
  headRepository = 'openomhq/openom',
  labels = ['preview'],
  permission = { permission: 'write', role_name: 'maintain' },
  state = 'open',
} = {}) {
  return async (url, options) => {
    assert.equal(options.headers.authorization, 'Bearer token');
    if (url.endsWith('/collaborators/maintainer/permission')) return response(permission);
    if (url.endsWith('/pulls/42')) {
      return response({
        base: { repo: { full_name: 'openomhq/openom' } },
        head: { ref: 'feat/ope-513', repo: { full_name: headRepository }, sha: SHA },
        labels: labels.map((name) => ({ name })),
        state,
      });
    }
    return response({}, 404);
  };
}

function request(overrides = {}) {
  return resolvePreviewRequest({
    actor: 'maintainer',
    fetchImplementation: githubFetch(),
    pullRequest: 42,
    ref: 'refs/heads/main',
    repository: 'openomhq/openom',
    token: 'token',
    ...overrides,
  });
}

test('authorizes a maintainer and pins the current same-repository pull request SHA', async () => {
  assert.deepEqual(await request(), {
    actor: 'maintainer',
    apiUrl: 'https://feat-ope-513.api.dev.openom.org',
    appUrl: 'https://feat-ope-513.app.dev.openom.org',
    commitSha: SHA,
    mode: 'web',
    pullRequestNumber: 42,
    slug: 'feat-ope-513',
    sourceBranch: 'feat/ope-513',
  });
});

for (const [name, overrides, code] of [
  ['an untrusted workflow ref', { ref: 'refs/heads/feat/ope-513' }, 'untrusted_workflow_ref'],
  ['an actor with write permission', {
    fetchImplementation: githubFetch({ permission: { permission: 'write', role_name: 'write' } }),
  }, 'preview_actor_forbidden'],
  ['a fork pull request', {
    fetchImplementation: githubFetch({ headRepository: 'contributor/openom' }),
  }, 'preview_fork_forbidden'],
  ['a pull request without approval', {
    fetchImplementation: githubFetch({ labels: [] }),
  }, 'preview_approval_missing'],
  ['a closed pull request', {
    fetchImplementation: githubFetch({ state: 'closed' }),
  }, 'preview_pull_request_closed'],
]) {
  test(`rejects ${name}`, async () => {
    await assert.rejects(
      request(overrides),
      (error) => error instanceof PreviewRequestError && error.code === code,
    );
  });
}

test('requires the dedicated full-preview approval for a full stack', async () => {
  const full = await request({
    fetchImplementation: githubFetch({ labels: ['full-preview'] }),
    mode: 'full',
  });
  assert.equal(full.mode, 'full');

  await assert.rejects(
    request({ mode: 'full' }),
    (error) => error instanceof PreviewRequestError && error.code === 'preview_approval_missing',
  );
});

test('rejects an unknown preview mode before reading pull-request state', async () => {
  await assert.rejects(
    request({ mode: 'automatic' }),
    (error) => error instanceof PreviewRequestError && error.code === 'invalid_preview_mode',
  );
});

test('writes only validated values to GitHub outputs', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'openom-preview-request-'));
  const output = path.join(directory, 'output');
  try {
    await runPreviewRequestCli(['--pull-request', '42'], {
      GITHUB_API_URL: 'https://api.github.test',
      GITHUB_OUTPUT: output,
      GITHUB_REF: 'refs/heads/main',
      GITHUB_REPOSITORY: 'openomhq/openom',
      GITHUB_TOKEN: 'token',
      GITHUB_TRIGGERING_ACTOR: 'maintainer',
    }, githubFetch());
    assert.equal(readFileSync(output, 'utf8'), [
      'api_url=https://feat-ope-513.api.dev.openom.org',
      'app_url=https://feat-ope-513.app.dev.openom.org',
      `commit_sha=${SHA}`,
      'mode=web',
      'pull_request_number=42',
      'slug=feat-ope-513',
      'source_branch=feat/ope-513',
      '',
    ].join('\n'));
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
