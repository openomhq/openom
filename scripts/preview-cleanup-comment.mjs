#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PREVIEW_CLEANUP_MARKER = '<!-- openom-preview-cleanup -->';

export class PreviewCleanupCommentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewCleanupCommentError';
    this.code = code;
  }
}

function requiredString(value, code, message) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewCleanupCommentError(code, message);
}

function positiveInteger(value, code, message) {
  const parsed = Number(value);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  throw new PreviewCleanupCommentError(code, message);
}

function repositoryName(value) {
  const repository = requiredString(value, 'missing_repository', 'GITHUB_REPOSITORY is required');
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) return repository;
  throw new PreviewCleanupCommentError('invalid_repository', 'GITHUB_REPOSITORY is invalid');
}

async function githubJson(
  fetchImplementation,
  apiUrl,
  token,
  route,
  { body, method = 'GET' } = {},
) {
  const response = await fetchImplementation(`${apiUrl}${route}`, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
    },
    method,
  });
  if (!response.ok) {
    throw new PreviewCleanupCommentError(
      'github_api_failed',
      `GitHub API ${method} ${route} failed with status ${response.status}`,
    );
  }
  return response.status === 204 ? null : response.json();
}

export function berlinTimestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new PreviewCleanupCommentError('invalid_completed_at', 'cleanup completion time is invalid');
  }
  const parts = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    hour: '2-digit',
    hourCycle: 'h23',
    minute: '2-digit',
    month: '2-digit',
    timeZone: 'Europe/Berlin',
    timeZoneName: 'short',
    year: 'numeric',
  }).formatToParts(date);
  const part = (type) => parts.find((entry) => entry.type === type)?.value;
  return `${part('year')}/${part('month')}/${part('day')} ${part('hour')}:${part('minute')} ${part('timeZoneName')}`;
}

export function previewCleanupComment({
  apiUrl,
  appUrl,
  branch,
  completedAt,
  repository,
  runId,
  runNumber,
  serverUrl = 'https://github.com',
}) {
  const workflowUrl = `${serverUrl}/${repository}/actions/runs/${runId}`;
  return `${PREVIEW_CLEANUP_MARKER}
## Preview cleanup

[![Preview cleaned up](https://img.shields.io/badge/Preview-Cleaned%20up-6e7781?style=for-the-badge&logo=githubactions&logoColor=white)](${workflowUrl})

Preview resources for \`${branch}\` have been removed.
Cleanup is idempotent; rerunning it safely reconciles any remaining preview resources.

| Resource | Former address | Status |
| --- | --- | --- |
| app | \`${appUrl}\` | Removed |
| api | \`${apiUrl}\` | Removed |

Cleanup completed: *${berlinTimestamp(completedAt)}* in workflow [preview.cleanup #${runNumber}](${workflowUrl}).
`;
}

export async function reconcilePreviewCleanupComment({
  apiUrl = 'https://api.github.com',
  cleanup,
  fetchImplementation = fetch,
  pullRequest,
  repository,
  token,
}) {
  const repositoryValue = repositoryName(repository);
  const bearer = requiredString(token, 'missing_github_token', 'GITHUB_TOKEN is required');
  const number = positiveInteger(
    pullRequest,
    'invalid_pull_request',
    'pull request number must be a positive integer',
  );
  const comments = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryValue}/issues/${number}/comments?per_page=100`,
  );
  if (!Array.isArray(comments)) {
    throw new PreviewCleanupCommentError(
      'github_response_invalid',
      'GitHub comments response must be an array',
    );
  }
  const existing = comments.find((comment) => (
    comment?.user?.login === 'github-actions[bot]'
      && typeof comment.body === 'string'
      && comment.body.includes(PREVIEW_CLEANUP_MARKER)
  ));
  const body = previewCleanupComment({ ...cleanup, repository: repositoryValue });
  if (existing) {
    await githubJson(
      fetchImplementation,
      apiUrl,
      bearer,
      `/repos/${repositoryValue}/issues/comments/${existing.id}`,
      { body: { body }, method: 'PATCH' },
    );
    return { action: 'updated', commentId: existing.id, pullRequestNumber: number };
  }
  const created = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryValue}/issues/${number}/comments`,
    { body: { body }, method: 'POST' },
  );
  if (!Number.isSafeInteger(created?.id)) {
    throw new PreviewCleanupCommentError(
      'github_response_invalid',
      'GitHub create-comment response is missing its id',
    );
  }
  return { action: 'created', commentId: created.id, pullRequestNumber: number };
}

export async function runPreviewCleanupCommentCli(
  environment = process.env,
  fetchImplementation = fetch,
) {
  return reconcilePreviewCleanupComment({
    apiUrl: environment.GITHUB_API_URL,
    cleanup: {
      apiUrl: requiredString(environment.PREVIEW_API_URL, 'missing_api_url', 'PREVIEW_API_URL is required'),
      appUrl: requiredString(environment.PREVIEW_APP_URL, 'missing_app_url', 'PREVIEW_APP_URL is required'),
      branch: requiredString(environment.PREVIEW_BRANCH, 'missing_branch', 'PREVIEW_BRANCH is required'),
      completedAt: new Date(),
      runId: positiveInteger(environment.GITHUB_RUN_ID, 'invalid_run_id', 'GITHUB_RUN_ID is invalid'),
      runNumber: positiveInteger(
        environment.GITHUB_RUN_NUMBER,
        'invalid_run_number',
        'GITHUB_RUN_NUMBER is invalid',
      ),
      serverUrl: environment.GITHUB_SERVER_URL,
    },
    fetchImplementation,
    pullRequest: environment.PREVIEW_PULL_REQUEST,
    repository: environment.GITHUB_REPOSITORY,
    token: environment.GITHUB_TOKEN,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = await runPreviewCleanupCommentCli();
    console.log(`[Preview] ${result.action} cleanup comment on pull request ${result.pullRequestNumber}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
