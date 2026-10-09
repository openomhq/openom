#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { previewIdentity } from './preview-name.mjs';
import { desiredPreviewMode } from './preview-policy.mjs';

const MAINTAINER_PERMISSIONS = new Set(['admin', 'maintain']);
const COMMIT_SHA = /^[0-9a-f]{40}$/;

export class PreviewCleanupRequestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewCleanupRequestError';
    this.code = code;
  }
}

function requiredString(value, code, message) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewCleanupRequestError(code, message);
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
    throw new PreviewCleanupRequestError(
      'github_cleanup_request_failed',
      `GitHub cleanup request failed with status ${response.status}`,
    );
  }
  return response.json();
}

function sameRepositoryPullRequest(pullRequest, repository) {
  if (pullRequest?.head?.repo?.full_name !== repository) return null;
  if (pullRequest?.base?.repo?.full_name !== repository || pullRequest?.base?.ref !== 'main') return null;
  return pullRequest;
}

function associatedPullRequestNumber(workflowRun) {
  const numbers = [...new Set(
    (Array.isArray(workflowRun?.pull_requests) ? workflowRun.pull_requests : [])
      .map((pullRequest) => Number(pullRequest?.number))
      .filter((number) => Number.isSafeInteger(number) && number > 0),
  )];
  return numbers.length === 1 ? numbers[0] : null;
}

async function commitPullRequestNumber({
  apiUrl,
  fetchImplementation,
  repository,
  token,
  workflowRun,
}) {
  const headSha = workflowRun?.head_sha;
  if (typeof headSha !== 'string' || !COMMIT_SHA.test(headSha)) return null;
  const candidates = await githubJson(
    fetchImplementation,
    apiUrl,
    token,
    `/repos/${repository}/commits/${headSha}/pulls`,
  );
  if (!Array.isArray(candidates)) return null;
  const numbers = [...new Set(candidates
    .filter((pullRequest) => sameRepositoryPullRequest(pullRequest, repository))
    .map((pullRequest) => Number(pullRequest.number))
    .filter((number) => Number.isSafeInteger(number) && number > 0))];
  return numbers.length === 1 ? numbers[0] : null;
}

async function branchPullRequestNumber({
  apiUrl,
  fetchImplementation,
  repository,
  token,
  workflowRun,
}) {
  const headBranch = workflowRun?.head_branch;
  const headRepository = workflowRun?.head_repository?.full_name;
  const headSha = workflowRun?.head_sha;
  if (headRepository !== repository) return null;
  if (typeof headBranch !== 'string' || headBranch.length === 0) return null;
  if (typeof headSha !== 'string' || !COMMIT_SHA.test(headSha)) return null;
  const [owner] = repository.split('/');
  if (!owner) return null;
  const head = encodeURIComponent(`${owner}:${headBranch}`);
  const candidates = await githubJson(
    fetchImplementation,
    apiUrl,
    token,
    `/repos/${repository}/pulls?state=all&base=main&head=${head}&per_page=100`,
  );
  if (!Array.isArray(candidates)) return null;
  const numbers = [...new Set(candidates
    .filter((pullRequest) => sameRepositoryPullRequest(pullRequest, repository))
    .filter((pullRequest) => pullRequest.head?.ref === headBranch && pullRequest.head?.sha === headSha)
    .map((pullRequest) => Number(pullRequest.number))
    .filter((number) => Number.isSafeInteger(number) && number > 0))];
  return numbers.length === 1 ? numbers[0] : null;
}

function outputRecord(mode, identity = null, desiredMode = 'none', resolutionSource = 'none') {
  return {
    desired_mode: desiredMode,
    mode,
    resolution_source: resolutionSource,
    should_cleanup: ['cleanup', 'reconcile'].includes(mode) ? 'true' : 'false',
    source_branch: identity?.sourceBranch ?? '',
    pull_request_number: identity?.pullRequestNumber ?? '',
    slug: identity?.slug ?? '',
    app_url: identity?.appUrl ?? '',
    api_url: identity?.apiUrl ?? '',
  };
}

export async function resolvePreviewCleanupRequest({
  apiUrl = 'https://api.github.com',
  event,
  eventName,
  fetchImplementation = fetch,
  manualPullRequest,
  manualSourceBranch,
  repository,
  token,
  triggeringActor,
}) {
  if (eventName === 'schedule') return outputRecord('janitor', null, 'none', 'schedule');

  let pullRequestNumber;
  let resolutionSource;
  let requireMaintainer = false;
  let workflowRun = null;
  if (eventName === 'workflow_run') {
    workflowRun = event?.workflow_run;
    if (workflowRun?.conclusion !== 'success') {
      throw new PreviewCleanupRequestError(
        'lifecycle_signal_failed',
        'preview lifecycle signal did not complete successfully',
      );
    }
    if (workflowRun?.event !== 'pull_request') {
      throw new PreviewCleanupRequestError(
        'invalid_lifecycle_event',
        'preview lifecycle signal has an invalid source event',
      );
    }
    pullRequestNumber = associatedPullRequestNumber(workflowRun);
    if (pullRequestNumber) {
      resolutionSource = 'workflow_run.pull_requests';
    } else {
      pullRequestNumber = await commitPullRequestNumber({
        apiUrl,
        fetchImplementation,
        repository,
        token,
        workflowRun,
      });
      if (pullRequestNumber) resolutionSource = 'workflow_run.head_sha';
    }
    if (!pullRequestNumber) {
      pullRequestNumber = await branchPullRequestNumber({
        apiUrl,
        fetchImplementation,
        repository,
        token,
        workflowRun,
      });
      if (pullRequestNumber) resolutionSource = 'workflow_run.head_branch';
    }
    if (!pullRequestNumber) {
      return outputRecord('skip', null, 'none', 'workflow_run.unresolved');
    }
  } else if (eventName === 'workflow_dispatch') {
    pullRequestNumber = Number(manualPullRequest);
    requireMaintainer = true;
    resolutionSource = 'workflow_dispatch';
  } else {
    throw new PreviewCleanupRequestError(
      'invalid_cleanup_event',
      'preview cleanup must run from workflow_run, workflow_dispatch, or schedule',
    );
  }
  if (!Number.isSafeInteger(pullRequestNumber) || pullRequestNumber < 1) {
    throw new PreviewCleanupRequestError('invalid_pull_request_number', 'pull request number is invalid');
  }

  if (requireMaintainer) {
    const permission = await githubJson(
      fetchImplementation,
      apiUrl,
      token,
      `/repos/${repository}/collaborators/${encodeURIComponent(triggeringActor)}/permission`,
    );
    if (!MAINTAINER_PERMISSIONS.has(permission?.permission)) {
      throw new PreviewCleanupRequestError(
        'preview_cleanup_actor_forbidden',
        'preview cleanup requires maintain or admin permission',
      );
    }
  }

  const pullRequest = sameRepositoryPullRequest(await githubJson(
    fetchImplementation,
    apiUrl,
    token,
    `/repos/${repository}/pulls/${pullRequestNumber}`,
  ), repository);
  if (!pullRequest) return outputRecord('skip', null, 'none', resolutionSource);
  const sourceBranch = manualSourceBranch || requiredString(
    pullRequest.head?.ref,
    'missing_preview_branch',
    'pull request head branch is missing',
  );
  const identity = previewIdentity(sourceBranch, pullRequestNumber);
  const desiredMode = desiredPreviewMode(pullRequest);
  return outputRecord(
    requireMaintainer ? 'cleanup' : 'reconcile',
    identity,
    desiredMode,
    resolutionSource,
  );
}

export async function runPreviewCleanupRequestCli(environment = process.env) {
  const event = JSON.parse(readFileSync(
    requiredString(environment.GITHUB_EVENT_PATH, 'missing_event_path', 'GITHUB_EVENT_PATH is required'),
    'utf8',
  ));
  const result = await resolvePreviewCleanupRequest({
    apiUrl: environment.GITHUB_API_URL,
    event,
    eventName: environment.GITHUB_EVENT_NAME,
    manualPullRequest: environment.INPUT_PULL_REQUEST,
    manualSourceBranch: environment.INPUT_SOURCE_BRANCH,
    repository: requiredString(
      environment.GITHUB_REPOSITORY,
      'missing_repository',
      'GITHUB_REPOSITORY is required',
    ),
    token: requiredString(environment.GITHUB_TOKEN, 'missing_token', 'GITHUB_TOKEN is required'),
    triggeringActor: environment.GITHUB_TRIGGERING_ACTOR,
  });
  const outputPath = environment.GITHUB_OUTPUT;
  if (outputPath) {
    appendFileSync(outputPath, `${Object.entries(result).map(([key, value]) => `${key}=${value}`).join('\n')}\n`);
  }
  return result;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await runPreviewCleanupRequestCli()));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
