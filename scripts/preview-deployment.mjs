#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { previewIdentity } from './preview-name.mjs';

export class PreviewDeploymentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewDeploymentError';
    this.code = code;
  }
}

function requiredString(value, name) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewDeploymentError('invalid_deployment_input', `${name} is required`);
}

function validatedRepositoryAccess(input) {
  const repository = requiredString(input.repository, 'repository');
  const token = requiredString(input.token, 'token');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'repository is invalid');
  }
  return { repository, token };
}

function validatedDeployment(input) {
  const { repository, token } = validatedRepositoryAccess(input);
  const slug = requiredString(input.slug, 'slug');
  const sourceBranch = requiredString(input.sourceBranch, 'source branch');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,43}[a-z0-9])?$/.test(slug)) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'slug is invalid');
  }
  if (!/^[a-f0-9]{40}$/.test(input.commitSha ?? '')) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'commit SHA is invalid');
  }
  if (!Number.isSafeInteger(input.pullRequestNumber) || input.pullRequestNumber < 1) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'pull request number is invalid');
  }
  const expectedAppUrl = `https://${slug}.app.dev.openom.org`;
  if (input.appUrl !== expectedAppUrl) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'app URL does not match the preview slug');
  }
  if (previewIdentity(sourceBranch, input.pullRequestNumber).slug !== slug) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'source branch does not match the preview slug');
  }
  const logUrl = new URL(requiredString(input.logUrl, 'log URL'));
  if (logUrl.protocol !== 'https:' || logUrl.hostname !== 'github.com') {
    throw new PreviewDeploymentError('invalid_deployment_input', 'log URL is invalid');
  }
  return { ...input, logUrl: logUrl.href, repository, slug, sourceBranch, token };
}

async function githubRequest(fetchImplementation, apiUrl, token, route, body, method = 'POST') {
  const response = await fetchImplementation(`${apiUrl}${route}`, {
    method,
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    throw new PreviewDeploymentError(
      'github_deployment_failed',
      `GitHub deployment request ${route} failed with status ${response.status}`,
    );
  }
  return response.json();
}

export async function retirePreviewDeployments({
  apiUrl = 'https://api.github.com',
  fetchImplementation = fetch,
  logUrl,
  pullRequestNumber,
  repository,
  slug,
  token,
}) {
  const validated = validatedDeploymentIdentity({
    logUrl,
    pullRequestNumber,
    repository,
    slug,
    token,
  });
  const deployments = await listDeployments(fetchImplementation, apiUrl, validated);
  const owned = deployments.filter((deployment) => (
    deployment?.environment === 'preview-deployments'
    && Number(deployment.payload?.pullRequestNumber) === validated.pullRequestNumber
    && deployment.payload?.slug === validated.slug
  ));
  for (const deployment of owned) {
    if (!Number.isSafeInteger(deployment.id)) {
      throw new PreviewDeploymentError('invalid_github_deployment', 'GitHub returned an invalid deployment');
    }
    await githubRequest(
      fetchImplementation,
      apiUrl,
      validated.token,
      `/repos/${validated.repository}/deployments/${deployment.id}/statuses`,
      {
        auto_inactive: false,
        description: 'Preview was removed',
        environment: 'preview-deployments',
        log_url: validated.logUrl,
        state: 'inactive',
      },
    );
  }
  return { retired: owned.length };
}

async function listDeployments(fetchImplementation, apiUrl, validated) {
  const deployments = [];
  for (let page = 1; ; page += 1) {
    const batch = await githubRequest(
      fetchImplementation,
      apiUrl,
      validated.token,
      `/repos/${validated.repository}/deployments?environment=preview-deployments&per_page=100&page=${page}`,
      undefined,
      'GET',
    );
    if (!Array.isArray(batch)) {
      throw new PreviewDeploymentError('invalid_github_deployment', 'GitHub omitted deployment records');
    }
    deployments.push(...batch);
    if (batch.length < 100) return deployments;
  }
}

export async function listActivePreviewDeployments({
  apiUrl = 'https://api.github.com',
  fetchImplementation = fetch,
  repository,
  token,
}) {
  const validated = validatedRepositoryAccess({ repository, token });
  const deployments = await listDeployments(fetchImplementation, apiUrl, validated);
  const identities = [];
  for (const deployment of deployments) {
    if (!Number.isSafeInteger(deployment?.id)) {
      throw new PreviewDeploymentError('invalid_github_deployment', 'GitHub returned an invalid deployment');
    }
    const statuses = await githubRequest(
      fetchImplementation,
      apiUrl,
      validated.token,
      `/repos/${validated.repository}/deployments/${deployment.id}/statuses?per_page=1`,
      undefined,
      'GET',
    );
    if (!Array.isArray(statuses)) {
      throw new PreviewDeploymentError('invalid_github_deployment', 'GitHub omitted deployment statuses');
    }
    if (statuses[0]?.state !== 'success') continue;
    const sourceBranch = deployment.payload?.sourceBranch;
    if (typeof sourceBranch !== 'string') continue;
    const identity = previewIdentity(sourceBranch, deployment.payload?.pullRequestNumber);
    if (deployment.payload?.slug !== identity.slug) {
      throw new PreviewDeploymentError(
        'invalid_github_deployment',
        `GitHub deployment ${deployment.id} has inconsistent preview ownership`,
      );
    }
    identities.push(identity);
  }
  return identities;
}

function validatedDeploymentIdentity(input) {
  const { repository, token } = validatedRepositoryAccess(input);
  const slug = requiredString(input.slug, 'slug');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,43}[a-z0-9])?$/.test(slug)) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'slug is invalid');
  }
  if (!Number.isSafeInteger(input.pullRequestNumber) || input.pullRequestNumber < 1) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'pull request number is invalid');
  }
  const logUrl = new URL(requiredString(input.logUrl, 'log URL'));
  if (logUrl.protocol !== 'https:' || logUrl.hostname !== 'github.com') {
    throw new PreviewDeploymentError('invalid_deployment_input', 'log URL is invalid');
  }
  return { ...input, logUrl: logUrl.href, repository, slug, token };
}

export async function publishPreviewDeployment({
  apiUrl = 'https://api.github.com',
  appUrl,
  commitSha,
  fetchImplementation = fetch,
  logUrl,
  pullRequestNumber,
  repository,
  slug,
  sourceBranch,
  token,
}) {
  const validated = validatedDeployment({
    appUrl,
    commitSha,
    logUrl,
    pullRequestNumber,
    repository,
    slug,
    sourceBranch,
    token,
  });
  const deployment = await githubRequest(
    fetchImplementation,
    apiUrl,
    validated.token,
    `/repos/${validated.repository}/deployments`,
    {
      auto_merge: false,
      description: `Preview for pull request #${validated.pullRequestNumber}`,
      environment: 'preview-deployments',
      payload: {
        pullRequestNumber: validated.pullRequestNumber,
        slug: validated.slug,
        sourceBranch: validated.sourceBranch,
      },
      production_environment: false,
      ref: validated.commitSha,
      required_contexts: [],
      transient_environment: true,
    },
  );
  if (!Number.isSafeInteger(deployment.id)) {
    throw new PreviewDeploymentError(
      'invalid_github_deployment',
      'GitHub did not return a deployment identifier',
    );
  }
  await githubRequest(
    fetchImplementation,
    apiUrl,
    validated.token,
    `/repos/${validated.repository}/deployments/${deployment.id}/statuses`,
    {
      auto_inactive: false,
      description: 'Preview is ready',
      environment: 'preview-deployments',
      environment_url: validated.appUrl,
      log_url: validated.logUrl,
      state: 'success',
    },
  );
  return deployment.id;
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewDeploymentError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export async function runPreviewDeploymentCli(args, environment = process.env) {
  if (args[0] === 'retire') {
    return retirePreviewDeployments({
      apiUrl: environment.GITHUB_API_URL,
      logUrl: `${environment.GITHUB_SERVER_URL}/${environment.GITHUB_REPOSITORY}/actions/runs/${environment.GITHUB_RUN_ID}`,
      pullRequestNumber: Number(argumentValue(args, '--pull-request')),
      repository: environment.GITHUB_REPOSITORY,
      slug: argumentValue(args, '--slug'),
      token: environment.GITHUB_TOKEN,
    });
  }
  return publishPreviewDeployment({
    apiUrl: environment.GITHUB_API_URL,
    appUrl: argumentValue(args, '--app-url'),
    commitSha: argumentValue(args, '--commit'),
    logUrl: `${environment.GITHUB_SERVER_URL}/${environment.GITHUB_REPOSITORY}/actions/runs/${environment.GITHUB_RUN_ID}`,
    pullRequestNumber: Number(argumentValue(args, '--pull-request')),
    repository: environment.GITHUB_REPOSITORY,
    slug: argumentValue(args, '--slug'),
    sourceBranch: argumentValue(args, '--source-branch'),
    token: environment.GITHUB_TOKEN,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = await runPreviewDeploymentCli(process.argv.slice(2));
    console.log(`[Preview] ${typeof result === 'number' ? `published GitHub deployment ${result}` : JSON.stringify(result)}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
