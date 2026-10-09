import assert from 'node:assert/strict';
import test from 'node:test';

import { desiredPreviewMode } from './preview-policy.mjs';

for (const [state, labels, expected] of [
  ['open', ['full-preview', 'preview'], 'full'],
  ['open', ['full-preview'], 'full'],
  ['open', ['preview'], 'web'],
  ['open', [], 'none'],
  ['closed', ['full-preview', 'preview'], 'none'],
  ['closed', ['full-preview'], 'none'],
  ['closed', ['preview'], 'none'],
]) {
  test(`${state} pull request with ${labels.join(', ') || 'no labels'} desires ${expected}`, () => {
    assert.equal(desiredPreviewMode({
      labels: labels.map((name) => ({ name })),
      state,
    }), expected);
  });
}
