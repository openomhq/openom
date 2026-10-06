#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

function validatedDeployment(input) {
  const repository = requiredString(input.repository, 'repository');
  const slug = requiredString(input.slug, 'slug');
  const token = requiredString(input.token, 'token');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new PreviewDeploymentError('invalid_deployment_input', 'repository is invalid');
  }
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
  const logUrl = new URL(requiredString(input.logUrl, 'log URL'));
  if (logUrl.protocol !== 'https:' || logUrl.hostname !== 'github.com') {
    throw new PreviewDeploymentError('invalid_deployment_input', 'log URL is invalid');
  }
  return { ...input, logUrl: logUrl.href, repository, slug, token };
}

async function githubRequest(fetchImplementation, apiUrl, token, route, body) {
  const response = await fetchImplementation(`${apiUrl}${route}`, {
    method: 'POST',
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new PreviewDeploymentError(
      'github_deployment_failed',
      `GitHub deployment request ${route} failed with status ${response.status}`,
    );
  }
  return response.json();
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
  token,
}) {
  const validated = validatedDeployment({
    appUrl,
    commitSha,
    logUrl,
    pullRequestNumber,
    repository,
    slug,
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
  return publishPreviewDeployment({
    apiUrl: environment.GITHUB_API_URL,
    appUrl: argumentValue(args, '--app-url'),
    commitSha: argumentValue(args, '--commit'),
    logUrl: `${environment.GITHUB_SERVER_URL}/${environment.GITHUB_REPOSITORY}/actions/runs/${environment.GITHUB_RUN_ID}`,
    pullRequestNumber: Number(argumentValue(args, '--pull-request')),
    repository: environment.GITHUB_REPOSITORY,
    slug: argumentValue(args, '--slug'),
    token: environment.GITHUB_TOKEN,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const deploymentId = await runPreviewDeploymentCli(process.argv.slice(2));
    console.log(`[Preview] published GitHub deployment ${deploymentId}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
