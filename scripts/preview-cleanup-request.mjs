#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { previewIdentity } from './preview-name.mjs';

const APPROVAL_LABELS = new Set(['preview', 'full-preview']);
const MAINTAINER_PERMISSIONS = new Set(['admin', 'maintain']);
const LIFECYCLE_RUN_TITLE = /^preview lifecycle for PR #([1-9][0-9]*)$/;

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

function lifecyclePullRequestNumber(workflowRun) {
  const pullRequests = workflowRun?.pull_requests;
  if (Array.isArray(pullRequests) && pullRequests.length === 1) {
    return pullRequests[0].number;
  }
  const match = LIFECYCLE_RUN_TITLE.exec(workflowRun?.display_title ?? '');
  return match ? Number(match[1]) : null;
}

function approved(pullRequest) {
  return Array.isArray(pullRequest?.labels)
    && pullRequest.labels.some((label) => APPROVAL_LABELS.has(label?.name));
}

function outputRecord(mode, identity = null) {
  return {
    mode,
    should_cleanup: mode === 'cleanup' ? 'true' : 'false',
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
  if (eventName === 'schedule') return outputRecord('janitor');

  let pullRequestNumber;
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
    if (!['pull_request', 'workflow_dispatch'].includes(workflowRun?.event)) {
      throw new PreviewCleanupRequestError(
        'invalid_lifecycle_event',
        'preview lifecycle signal has an invalid source event',
      );
    }
    pullRequestNumber = lifecyclePullRequestNumber(workflowRun);
    if (workflowRun.event === 'workflow_dispatch') {
      requireMaintainer = true;
      triggeringActor = workflowRun?.triggering_actor?.login;
    }
  } else if (eventName === 'workflow_dispatch') {
    pullRequestNumber = Number(manualPullRequest);
    requireMaintainer = true;
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
  if (!pullRequest) return outputRecord('skip');
  if (workflowRun?.event === 'pull_request') {
    if (pullRequest.head?.sha !== workflowRun.head_sha || pullRequest.head?.ref !== workflowRun.head_branch) {
      throw new PreviewCleanupRequestError(
        'lifecycle_pull_request_mismatch',
        'preview lifecycle signal does not match the resolved pull request head',
      );
    }
  }
  if (!requireMaintainer && pullRequest.state === 'open' && approved(pullRequest)) {
    return outputRecord('skip');
  }
  const sourceBranch = manualSourceBranch || requiredString(
    pullRequest.head?.ref,
    'missing_preview_branch',
    'pull request head branch is missing',
  );
  return outputRecord('cleanup', previewIdentity(sourceBranch, pullRequestNumber));
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
