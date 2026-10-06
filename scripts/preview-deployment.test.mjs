import assert from 'node:assert/strict';
import test from 'node:test';

import { publishPreviewDeployment } from './preview-deployment.mjs';

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
    token: 'token',
  });
  assert.equal(deploymentId, 1234);
  assert.equal(requests[0].url, 'https://api.github.com/repos/openomhq/openom/deployments');
  assert.deepEqual(requests[0].body, {
    auto_merge: false,
    description: 'Preview for pull request #42',
    environment: 'preview-deployments',
    payload: { pullRequestNumber: 42, slug: 'feat-ope-513' },
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
