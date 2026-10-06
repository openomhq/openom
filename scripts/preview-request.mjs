#!/usr/bin/env node
import { appendFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { previewIdentity } from './preview-name.mjs';

export class PreviewRequestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewRequestError';
    this.code = code;
  }
}

function requiredString(value, code, message) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewRequestError(code, message);
}

function pullRequestNumber(value) {
  const parsed = Number(value);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  throw new PreviewRequestError('invalid_pull_request', 'pull request number must be a positive integer');
}

async function githubJson(fetchImplementation, apiUrl, token, route) {
  const response = await fetchImplementation(`${apiUrl}${route}`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'x-github-api-version': '2022-11-28',
    },
  });
  if (!response.ok) {
    throw new PreviewRequestError(
      'github_api_failed',
      `GitHub API request ${route} failed with status ${response.status}`,
    );
  }
  return response.json();
}

function assertAuthorizedActor(permission, actor) {
  const roleName = permission?.role_name;
  if (roleName === 'maintain' || roleName === 'admin' || permission?.permission === 'admin') return;
  throw new PreviewRequestError(
    'preview_actor_forbidden',
    `${actor} must have maintain or admin repository permission`,
  );
}

function assertEligiblePullRequest(pullRequest, repository, requiredLabel) {
  if (pullRequest?.state !== 'open') {
    throw new PreviewRequestError('preview_pull_request_closed', 'pull request must be open');
  }
  if (pullRequest.base?.repo?.full_name !== repository || pullRequest.head?.repo?.full_name !== repository) {
    throw new PreviewRequestError(
      'preview_fork_forbidden',
      'preview deployments are limited to same-repository pull requests',
    );
  }
  const labels = Array.isArray(pullRequest.labels)
    ? pullRequest.labels.map((label) => label?.name).filter(Boolean)
    : [];
  if (!labels.includes(requiredLabel)) {
    throw new PreviewRequestError(
      'preview_approval_missing',
      `pull request must have the ${requiredLabel} label`,
    );
  }
  requiredString(pullRequest.head?.ref, 'missing_preview_branch', 'pull request head branch is missing');
  if (!/^[a-f0-9]{40}$/.test(pullRequest.head?.sha ?? '')) {
    throw new PreviewRequestError('invalid_preview_sha', 'pull request head SHA is invalid');
  }
}

export async function resolvePreviewRequest({
  actor,
  apiUrl = 'https://api.github.com',
  fetchImplementation = fetch,
  pullRequest,
  ref,
  repository,
  requiredLabel = 'preview',
  token,
}) {
  if (ref !== 'refs/heads/main') {
    throw new PreviewRequestError(
      'untrusted_workflow_ref',
      'preview deployment workflow must run from refs/heads/main',
    );
  }
  const repositoryName = requiredString(
    repository,
    'missing_repository',
    'GITHUB_REPOSITORY is required',
  );
  const actorName = requiredString(
    actor,
    'missing_actor',
    'GITHUB_TRIGGERING_ACTOR is required',
  );
  const bearer = requiredString(token, 'missing_github_token', 'GITHUB_TOKEN is required');
  const number = pullRequestNumber(pullRequest);
  const permission = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryName}/collaborators/${encodeURIComponent(actorName)}/permission`,
  );
  assertAuthorizedActor(permission, actorName);
  const pullRequestRecord = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryName}/pulls/${number}`,
  );
  assertEligiblePullRequest(pullRequestRecord, repositoryName, requiredLabel);
  const identity = previewIdentity(pullRequestRecord.head.ref, number);
  return {
    actor: actorName,
    apiUrl: identity.apiUrl,
    appUrl: identity.appUrl,
    commitSha: pullRequestRecord.head.sha,
    pullRequestNumber: number,
    slug: identity.slug,
    sourceBranch: pullRequestRecord.head.ref,
  };
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewRequestError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

function writeOutputs(outputPath, request) {
  const outputs = {
    api_url: request.apiUrl,
    app_url: request.appUrl,
    commit_sha: request.commitSha,
    pull_request_number: request.pullRequestNumber,
    slug: request.slug,
    source_branch: request.sourceBranch,
  };
  appendFileSync(
    outputPath,
    `${Object.entries(outputs).map(([name, value]) => `${name}=${value}`).join('\n')}\n`,
  );
}

export async function runPreviewRequestCli(
  args,
  environment = process.env,
  fetchImplementation = fetch,
) {
  const request = await resolvePreviewRequest({
    actor: environment.GITHUB_TRIGGERING_ACTOR,
    apiUrl: environment.GITHUB_API_URL,
    fetchImplementation,
    pullRequest: argumentValue(args, '--pull-request'),
    ref: environment.GITHUB_REF,
    repository: environment.GITHUB_REPOSITORY,
    requiredLabel: argumentValue(args, '--label') ?? 'preview',
    token: environment.GITHUB_TOKEN,
  });
  const outputPath = requiredString(
    environment.GITHUB_OUTPUT,
    'missing_github_output',
    'GITHUB_OUTPUT is required',
  );
  writeOutputs(outputPath, request);
  return request;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const request = await runPreviewRequestCli(process.argv.slice(2));
    console.log(JSON.stringify(request));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
