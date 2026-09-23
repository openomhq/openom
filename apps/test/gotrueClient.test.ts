import { describe, expect, it, vi } from 'vitest';
import { GoTrueClient } from '../app/src/core/gotrueClient.js';

const tokenBody = (overrides = {}) => ({
  access_token: 'access-token',
  refresh_token: 'refresh-token',
  expires_at: 2_000_000_000,
  ...overrides,
});

const response = ({ status = 200, body = tokenBody(), jsonError = null as unknown } = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => {
    if (jsonError) throw jsonError;
    return body;
  },
}) as Response;

const client = (fetch: typeof globalThis.fetch, options = {}) => new GoTrueClient({
  url: 'https://project.supabase.co',
  publishableKey: 'publishable-key',
  fetch,
  ...options,
});

describe('GoTrueClient request contract', () => {
  it('sends password sign-in to the exact hosted endpoint and validates the token response', async () => {
    const fetch = vi.fn(async () => response());
    const tokens = await client(fetch).signInWithPassword({ email: 'person@example.test', password: 'secret' });

    expect(tokens).toEqual({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 2_000_000_000,
    });
    expect(fetch).toHaveBeenCalledWith(
      'https://project.supabase.co/auth/v1/token?grant_type=password',
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          apikey: 'publishable-key',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ email: 'person@example.test', password: 'secret' }),
      },
    );
  });

  it('sends the rotating refresh token with no bearer header', async () => {
    const fetch = vi.fn(async () => response({ body: tokenBody({ refresh_token: 'replacement' }) }));
    await expect(client(fetch).refresh('parent-token')).resolves.toEqual({
      accessToken: 'access-token',
      refreshToken: 'replacement',
      expiresAt: 2_000_000_000,
    });
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe('https://project.supabase.co/auth/v1/token?grant_type=refresh_token');
    expect(init?.headers).not.toHaveProperty('authorization');
    expect(JSON.parse(String(init?.body))).toEqual({ refresh_token: 'parent-token' });
  });

  it('uses local-scope logout with the exact bearer and publishable key', async () => {
    const fetch = vi.fn(async () => response({ status: 204, body: null }));
    await client(fetch).signOut('access-token');
    expect(fetch).toHaveBeenCalledWith(
      'https://project.supabase.co/auth/v1/logout?scope=local',
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          apikey: 'publishable-key',
          authorization: 'Bearer access-token',
          'content-type': 'application/json',
        },
      },
    );
  });

  it('binds the browser default fetch to its global receiver', async () => {
    const fetch = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError('Illegal invocation');
      return Promise.resolve(response());
    });
    vi.stubGlobal('fetch', fetch);
    try {
      const auth = new GoTrueClient({ url: 'https://project.supabase.co', publishableKey: 'key' });
      await auth.signInWithPassword({ email: 'person@example.test', password: 'secret' });
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('GoTrueClient fail-closed decoding', () => {
  it('derives expiresAt from expires_in when the absolute expiry is absent', async () => {
    const fetch = vi.fn(async () => response({
      body: tokenBody({ expires_at: undefined, expires_in: 3600 }),
    }));
    const auth = client(fetch, { now: () => 1_700_000_000_000 });
    await expect(auth.refresh('refresh-token')).resolves.toMatchObject({ expiresAt: 1_700_003_600 });
  });

  it.each([
    null,
    {},
    tokenBody({ access_token: '' }),
    tokenBody({ refresh_token: '' }),
    tokenBody({ expires_at: undefined, expires_in: undefined }),
    tokenBody({ expires_at: 'tomorrow' }),
  ])('rejects malformed successful token response %#', async (body) => {
    const fetch = vi.fn(async () => response({ body }));
    await expect(client(fetch).refresh('refresh-token')).rejects.toMatchObject({ code: 'request_failed' });
  });

  it('rejects malformed success JSON without exposing parser details', async () => {
    const fetch = vi.fn(async () => response({ jsonError: new Error('secret parser detail') }));
    const error = await client(fetch).refresh('refresh-token').catch((caught) => caught);
    expect(error).toMatchObject({ code: 'request_failed', httpStatus: 200 });
    expect(JSON.stringify(error)).not.toContain('secret parser detail');
  });

  it.each([
    ['not a URL', 'key'],
    ['ftp://project.example', 'key'],
    ['https://project.example/path', 'key'],
    ['https://project.example', ''],
  ])('rejects invalid construction (%s)', (url, publishableKey) => {
    expect(() => new GoTrueClient({ url, publishableKey, fetch: vi.fn() })).toThrow(TypeError);
  });
});

describe('GoTrueClient error hygiene', () => {
  it.each([400, 401, 403, 422])('maps password rejection %s to generic sign_in_failed', async (status) => {
    const fetch = vi.fn(async () => response({
      status,
      body: { error_code: 'provider_specific', msg: 'email address is unknown' },
    }));
    const error = await client(fetch)
      .signInWithPassword({ email: 'person@example.test', password: 'wrong' })
      .catch((caught) => caught);
    expect(error).toMatchObject({ code: 'sign_in_failed', httpStatus: status });
    expect(JSON.stringify(error)).not.toContain('provider_specific');
    expect(JSON.stringify(error)).not.toContain('email address is unknown');
  });

  it.each([400, 401, 403])('maps definitive refresh rejection %s to session_expired', async (status) => {
    const fetch = vi.fn(async () => response({ status, body: { msg: 'refresh token leaked' } }));
    const error = await client(fetch).refresh('sensitive-refresh-token').catch((caught) => caught);
    expect(error).toMatchObject({ code: 'session_expired', httpStatus: status });
    expect(JSON.stringify(error)).not.toContain('sensitive-refresh-token');
    expect(JSON.stringify(error)).not.toContain('refresh token leaked');
  });

  it.each([429, 500, 503])('keeps transient provider status %s retriable', async (status) => {
    const fetch = vi.fn(async () => response({ status }));
    await expect(client(fetch).refresh('refresh-token')).rejects.toMatchObject({
      code: 'request_failed',
      retriable: true,
      httpStatus: status,
    });
  });

  it('maps network/CORS rejection to request_failed without logging or retaining secrets', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const fetch = vi.fn(async () => { throw new Error('request included sensitive-refresh-token'); });
    try {
      const error = await client(fetch).refresh('sensitive-refresh-token').catch((caught) => caught);
      expect(error).toMatchObject({ code: 'request_failed', retriable: true });
      expect(JSON.stringify(error)).not.toContain('sensitive-refresh-token');
      expect(log).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
      expect(errorLog).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      errorLog.mockRestore();
    }
  });

  it('rejects empty credentials locally without making a request', async () => {
    const fetch = vi.fn();
    await expect(client(fetch).signInWithPassword({ email: '', password: '' }))
      .rejects.toMatchObject({ code: 'sign_in_failed' });
    await expect(client(fetch).refresh('')).rejects.toMatchObject({ code: 'session_expired' });
    await expect(client(fetch).signOut('')).rejects.toMatchObject({ code: 'session_expired' });
    expect(fetch).not.toHaveBeenCalled();
  });
});
