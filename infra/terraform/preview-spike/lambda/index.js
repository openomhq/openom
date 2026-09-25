'use strict';

const { createHash } = require('node:crypto');

function response(statusCode, body) {
  return {
    statusCode,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  };
}

exports.handler = async (event) => {
  const headers = Object.fromEntries(
    Object.entries(event.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
  );
  if (process.env.PROBE_REQUIRE_AUTH !== 'true') {
    return response(200, {
      marker: process.env.PROBE_MARKER,
      method: event.requestContext?.http?.method ?? null,
      originAuthorizationPresent: Boolean(headers.authorization),
    });
  }

  const appAuthAccepted = headers['openom-auth'] === `Bearer ${process.env.PROBE_TOKEN}`;
  if (!appAuthAccepted) return response(401, { code: 'probe_auth_rejected' });

  const encodedBody = event.body ?? '';
  const body = event.isBase64Encoded
    ? Buffer.from(encodedBody, 'base64')
    : Buffer.from(encodedBody, 'utf8');
  const bodyHash = createHash('sha256').update(body).digest('hex');
  if (headers['x-amz-content-sha256'] !== bodyHash) {
    return response(400, { code: 'probe_body_hash_mismatch' });
  }

  return response(200, {
    marker: process.env.PROBE_MARKER,
    method: event.requestContext?.http?.method ?? null,
    appAuthAccepted,
    bodyHash,
  });
};
