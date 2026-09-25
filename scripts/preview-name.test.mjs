import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  LAMBDA_NAME_LIMIT,
  MAX_PREVIEW_SLUG_LENGTH,
  PreviewNameError,
  assertPreviewSlugAvailable,
  normalizePreviewSlug,
  previewIdentity,
  runPreviewNameCli,
} from './preview-name.mjs';

test('normalizes documented branch examples', () => {
  assert.equal(normalizePreviewSlug('feat/ope-123'), 'feat-ope-123');
  assert.equal(normalizePreviewSlug('feat/ope-123/user-auth'), 'feat-ope-123-user-auth');
  assert.equal(normalizePreviewSlug('bug/ope-456/token-ttl'), 'bug-ope-456-token-ttl');
});

test('collapses punctuation and removes non-ASCII characters deterministically', () => {
  assert.equal(normalizePreviewSlug('--Feature///Auth__Flow--'), 'feature-auth-flow');
  assert.equal(normalizePreviewSlug('feat/Grüße/東京'), 'feat-gr-e');
});

test('rejects branch names that produce an empty slug', () => {
  assert.throws(
    () => normalizePreviewSlug('///東京---'),
    (error) => error instanceof PreviewNameError && error.code === 'empty_preview_slug',
  );
});

test('derives the maximum slug length from the Lambda name limit', () => {
  assert.equal(MAX_PREVIEW_SLUG_LENGTH, 45);
  const identity = previewIdentity('a'.repeat(MAX_PREVIEW_SLUG_LENGTH), 123);
  assert.equal(identity.lambdaName.length, LAMBDA_NAME_LIMIT);
  assert.throws(
    () => previewIdentity('a'.repeat(MAX_PREVIEW_SLUG_LENGTH + 1), 123),
    (error) => error instanceof PreviewNameError && error.code === 'preview_slug_too_long',
  );
});

test('derives every preview resource name from one slug', () => {
  assert.deepEqual(previewIdentity('Feat/OPE-123', '42'), {
    slug: 'feat-ope-123',
    sourceBranch: 'Feat/OPE-123',
    pullRequestNumber: 42,
    appUrl: 'https://feat-ope-123.app.dev.openom.org',
    apiUrl: 'https://feat-ope-123.api.dev.openom.org',
    lambdaName: 'openom-preview-feat-ope-123-api',
    neonBranch: 'preview/feat-ope-123',
    objectStoreKeyPrefix: 'previews/feat-ope-123/',
    pagesBranch: 'feat-ope-123',
  });
});

test('rejects a normalized-slug collision owned by another branch or pull request', () => {
  const identity = previewIdentity('feat/ope-123', 42);
  for (const livePreview of [
    { slug: identity.slug, sourceBranch: 'feat-ope_123', pullRequestNumber: 43 },
    { slug: identity.slug, sourceBranch: identity.sourceBranch, pullRequestNumber: 43 },
  ]) {
    assert.throws(
      () => assertPreviewSlugAvailable(identity, [livePreview]),
      (error) => error instanceof PreviewNameError && error.code === 'preview_slug_collision',
    );
  }
});

test('allows reconciliation by the existing branch and pull request', () => {
  const identity = previewIdentity('feat/ope-123', 42);
  assert.equal(
    assertPreviewSlugAvailable(identity, [
      { slug: identity.slug, sourceBranch: identity.sourceBranch, pullRequestNumber: 42 },
    ]),
    identity,
  );
});

test('fails closed on malformed live-preview metadata', () => {
  const identity = previewIdentity('feat/ope-123', 42);
  for (const record of [
    { slug: identity.slug },
    { slug: identity.slug, sourceBranch: identity.sourceBranch },
  ]) {
    assert.throws(
      () => assertPreviewSlugAvailable(identity, [record]),
      (error) => error instanceof PreviewNameError && error.code === 'invalid_live_preview_record',
    );
  }
  assert.throws(
    () => assertPreviewSlugAvailable(previewIdentity('feat/ope-123'), []),
    (error) => error instanceof PreviewNameError && error.code === 'missing_pull_request_number',
  );
});

test('writes stable GitHub outputs', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'openom-preview-name-'));
  const outputPath = path.join(directory, 'github-output');
  try {
    runPreviewNameCli([
      '--branch', 'feat/ope-123',
      '--pr-number', '42',
      '--github-output', outputPath,
    ]);
    const output = readFileSync(outputPath, 'utf8');
    assert.match(output, /^slug=feat-ope-123$/m);
    assert.match(output, /^app_url=https:\/\/feat-ope-123\.app\.dev\.openom\.org$/m);
    assert.match(output, /^api_url=https:\/\/feat-ope-123\.api\.dev\.openom\.org$/m);
    assert.match(output, /^object_store_key_prefix=previews\/feat-ope-123\/$/m);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
