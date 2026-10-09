#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PREVIEW_INSTRUCTIONS_MARKER = '<!-- openom-preview-instructions -->';

const APPROVAL_LABELS = new Set(['preview', 'full-preview']);

export class PreviewInstructionsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PreviewInstructionsError';
    this.code = code;
  }
}

function requiredString(value, code, message) {
  if (typeof value === 'string' && value.length > 0) return value;
  throw new PreviewInstructionsError(code, message);
}

function pullRequestNumber(value) {
  const parsed = Number(value);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  throw new PreviewInstructionsError(
    'invalid_pull_request',
    'pull request number must be a positive integer',
  );
}

function repositoryName(value) {
  const repository = requiredString(value, 'missing_repository', 'GITHUB_REPOSITORY is required');
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) return repository;
  throw new PreviewInstructionsError('invalid_repository', 'GITHUB_REPOSITORY is invalid');
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
    throw new PreviewInstructionsError(
      'github_api_failed',
      `GitHub API ${method} ${route} failed with status ${response.status}`,
    );
  }
  return response.status === 204 ? null : response.json();
}

function assertEligiblePullRequest(pullRequest, repository) {
  if (pullRequest?.state !== 'open') {
    throw new PreviewInstructionsError('preview_pull_request_closed', 'pull request must be open');
  }
  if (pullRequest.base?.repo?.full_name !== repository || pullRequest.base?.ref !== 'main') {
    throw new PreviewInstructionsError(
      'preview_base_invalid',
      'pull request must target the main branch of this repository',
    );
  }
  if (pullRequest.head?.repo?.full_name !== repository) {
    throw new PreviewInstructionsError(
      'preview_fork_forbidden',
      'preview deployments are limited to same-repository pull requests',
    );
  }
  const labels = Array.isArray(pullRequest.labels)
    ? pullRequest.labels.map((label) => label?.name).filter(Boolean)
    : [];
  if (!labels.some((label) => APPROVAL_LABELS.has(label))) {
    throw new PreviewInstructionsError(
      'preview_approval_missing',
      'pull request must have the preview or full-preview label',
    );
  }
}

export function previewInstructions(pullRequest) {
  const number = pullRequestNumber(pullRequest);
  return `${PREVIEW_INSTRUCTIONS_MARKER}
## Preview deployment

To start a preview deployment, pick the appropriate mode below and run the linked deployment workflow from the \`main\` branch.

[![Deploy preview](https://img.shields.io/badge/Deploy-Preview-2ea44f?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/openomhq/openom/actions/workflows/preview.deploy.yml)

| Deployment mode | Pull request | Preview resources |
| --- | --- | --- |
| Web preview | \`${number}\` | \`web\` |
| Full preview | \`${number}\` | \`full\` |

\`web\` uses automatic DevAuth and stores the account and tree only in this browser; email/password sign-in, server backup, restore, and cross-device sync are unavailable. \`full\` adds Supabase sign-in and an isolated API, database branch, and object-storage namespace for end-to-end sync testing.

### Requirements

- Select the \`main\` branch on the workflow page.
- Web previews require the \`preview\` or \`full-preview\` label.
- Full previews require the \`full-preview\` label.
- The workflow verifies maintainer permission and deploys the current pull-request revision.
`;
}

export async function reconcilePreviewInstructions({
  apiUrl = 'https://api.github.com',
  fetchImplementation = fetch,
  pullRequest,
  repository,
  token,
}) {
  const repositoryValue = repositoryName(repository);
  const bearer = requiredString(token, 'missing_github_token', 'GITHUB_TOKEN is required');
  const number = pullRequestNumber(pullRequest);
  const pullRequestRecord = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryValue}/pulls/${number}`,
  );
  assertEligiblePullRequest(pullRequestRecord, repositoryValue);

  const comments = await githubJson(
    fetchImplementation,
    apiUrl,
    bearer,
    `/repos/${repositoryValue}/issues/${number}/comments?per_page=100`,
  );
  if (!Array.isArray(comments)) {
    throw new PreviewInstructionsError(
      'github_response_invalid',
      'GitHub comments response must be an array',
    );
  }
  const existing = comments.find((comment) => (
    comment?.user?.login === 'github-actions[bot]'
      && typeof comment.body === 'string'
      && comment.body.includes(PREVIEW_INSTRUCTIONS_MARKER)
  ));
  const body = previewInstructions(number);
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
    throw new PreviewInstructionsError(
      'github_response_invalid',
      'GitHub create-comment response is missing its id',
    );
  }
  return { action: 'created', commentId: created.id, pullRequestNumber: number };
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new PreviewInstructionsError('missing_argument_value', `${name} requires a value`);
  }
  return value;
}

export async function runPreviewInstructionsCli(
  args,
  environment = process.env,
  fetchImplementation = fetch,
) {
  return reconcilePreviewInstructions({
    apiUrl: environment.GITHUB_API_URL,
    fetchImplementation,
    pullRequest: argumentValue(args, '--pull-request'),
    repository: environment.GITHUB_REPOSITORY,
    token: environment.GITHUB_TOKEN,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = await runPreviewInstructionsCli(process.argv.slice(2));
    console.log(`[Preview] ${result.action} deployment instructions on pull request ${result.pullRequestNumber}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Preview] ${message}`);
    process.exitCode = 1;
  }
}
