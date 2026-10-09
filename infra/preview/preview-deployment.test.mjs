import assert from 'node:assert/strict';
import test from 'node:test';

import {
  listActivePreviewDeployments,
  publishPreviewDeployment,
  retirePreviewDeployments,
} from './preview-deployment.mjs';

test('publishes a successful native deployment for the pinned pull request SHA', async () => {
  const requests = [];
  const fetchImplementation = async (url, options) => {
    requests.push({ url, options, body: JSON.parse(options.body) });
    return {
      ok: true,
      status: 201,
      async json() {
        return requests.length === 1 ? { id: 1234 } : { id: 5678 };
      },
    };
  };
  const deploymentId = await publishPreviewDeployment({
    appUrl: 'https://feat-ope-513.app.dev.openom.org',
    commitSha: '0123456789abcdef0123456789abcdef01234567',
    fetchImplementation,
    logUrl: 'https://github.com/openomhq/openom/actions/runs/99',
    pullRequestNumber: 42,
    repository: 'openomhq/openom',
    slug: 'feat-ope-513',
    sourceBranch: 'feat/ope-513',
    token: 'token',
  });
  assert.equal(deploymentId, 1234);
  assert.equal(requests[0].url, 'https://api.github.com/repos/openomhq/openom/deployments');
  assert.deepEqual(requests[0].body, {
    auto_merge: false,
    description: 'Preview for pull request #42',
    environment: 'preview-deployments',
    payload: {
      pullRequestNumber: 42,
      slug: 'feat-ope-513',
      sourceBranch: 'feat/ope-513',
    },
    production_environment: false,
    ref: '0123456789abcdef0123456789abcdef01234567',
    required_contexts: [],
    transient_environment: true,
  });
  assert.equal(
    requests[1].url,
    'https://api.github.com/repos/openomhq/openom/deployments/1234/statuses',
  );
  assert.equal(requests[1].body.state, 'success');
  assert.equal(requests[1].body.environment_url, 'https://feat-ope-513.app.dev.openom.org');
});

test('marks every matching native preview deployment inactive', async () => {
  const requests = [];
  const fetchImplementation = async (url, options) => {
    requests.push({ body: options.body ? JSON.parse(options.body) : null, method: options.method, url });
    if (options.method === 'GET') {
      return {
        ok: true,
        status: 200,
        async json() {
          return [
            {
              environment: 'preview-deployments',
              id: 10,
              payload: { pullRequestNumber: 42, slug: 'feat-ope-513' },
            },
            {
              environment: 'preview-deployments',
              id: 11,
              payload: { pullRequestNumber: 99, slug: 'feat-ope-513' },
            },
          ];
        },
      };
    }
    return { ok: true, status: 201, async json() { return {}; } };
  };
  const result = await retirePreviewDeployments({
    fetchImplementation,
    logUrl: 'https://github.com/openomhq/openom/actions/runs/99',
    pullRequestNumber: 42,
    repository: 'openomhq/openom',
    slug: 'feat-ope-513',
    token: 'token',
  });
  assert.deepEqual(result, { retired: 1 });
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[1].url, 'https://api.github.com/repos/openomhq/openom/deployments/10/statuses');
  assert.equal(requests[1].body.state, 'inactive');
});

test('discovers successful deployment records as durable preview inventory', async () => {
  const fetchImplementation = async (url, options) => {
    if (url.includes('/statuses?')) {
      return {
        ok: true,
        status: 200,
        async json() { return [{ state: url.includes('/10/') ? 'success' : 'inactive' }]; },
      };
    }
    assert.equal(options.method, 'GET');
    return {
      ok: true,
      status: 200,
      async json() {
        return [
          {
            environment: 'preview-deployments',
            id: 10,
            payload: {
              pullRequestNumber: 42,
              slug: 'feat-ope-513',
              sourceBranch: 'feat/ope-513',
            },
          },
          {
            environment: 'preview-deployments',
            id: 11,
            payload: {
              pullRequestNumber: 99,
              slug: 'feat-other',
              sourceBranch: 'feat/other',
            },
          },
        ];
      },
    };
  };
  assert.deepEqual(await listActivePreviewDeployments({
    fetchImplementation,
    repository: 'openomhq/openom',
    token: 'token',
  }), [{
    apiUrl: 'https://feat-ope-513.api.dev.openom.org',
    appUrl: 'https://feat-ope-513.app.dev.openom.org',
    lambdaName: 'openom-preview-feat-ope-513-api',
    neonBranch: 'preview/feat-ope-513',
    objectStoreKeyPrefix: 'previews/feat-ope-513/',
    pagesBranch: 'feat-ope-513',
    pullRequestNumber: 42,
    slug: 'feat-ope-513',
    sourceBranch: 'feat/ope-513',
  }]);
});
