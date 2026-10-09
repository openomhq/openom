#!/usr/bin/env node
import assert from 'node:assert/strict';
import test from 'node:test';

import { handler } from '../sink/index.mjs';

test('the standing origin always returns the deterministic preview 404', async () => {
  const response = await handler({
    headers: { 'openom-auth': 'Bearer must-not-be-reflected' },
    rawPath: '/anything',
  });

  assert.deepEqual(response, {
    statusCode: 404,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/problem+json',
    },
    body: JSON.stringify({ code: 'preview_not_found' }),
  });
  assert.equal(JSON.stringify(response).includes('must-not-be-reflected'), false);
});
