import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { onRequest } from '../staging-gate/_middleware.js';

const env = {
  STAGING_APP_GATE_PASSWORD: 'correct password',
  CF_PAGES_COMMIT_SHA: 'abcdef0123456789',
  CF_PAGES_BRANCH: 'main',
};

describe('staging gate middleware', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      database: true,
      auth: true,
      storage: true,
    }), { status: 200, headers: { 'content-type': 'application/json' } })));
  });

  afterEach(() => vi.unstubAllGlobals());

  it('renders the cookie login form as a successful HTML representation', async () => {
    const next = vi.fn();
    const response = await onRequest({
      request: new Request('https://app.staging.openom.org/'),
      env,
      next,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.text()).resolves.toContain('form method="POST" action="/__gate"');
    expect(next).not.toHaveBeenCalled();
  });

  it('keeps a wrong password on the renderable form response', async () => {
    const response = await onRequest({
      request: gateSubmission('wrong password'),
      env,
      next: vi.fn(),
    });

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toContain('Wrong password');
    expect(response.headers.get('set-cookie')).toBeNull();
  });

  it('redirects a correct password with the secure admission cookie', async () => {
    const response = await onRequest({
      request: gateSubmission(env.STAGING_APP_GATE_PASSWORD),
      env,
      next: vi.fn(),
    });

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe('/');
    expect(response.headers.get('set-cookie')).toMatch(
      /^openom_staging_gate=[0-9a-f]{64}; HttpOnly; Secure; SameSite=Lax; Path=\/;/,
    );
  });
});

function gateSubmission(password) {
  const body = new URLSearchParams({ password });
  return new Request('https://app.staging.openom.org/__gate', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
}
