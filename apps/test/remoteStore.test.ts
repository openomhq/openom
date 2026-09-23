import { describe, it, expect, vi } from 'vitest';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { ERROR_CODES } from '../app/src/core/errorCodes.generated.js';
import { ConflictError } from '../app/src/core/store.js';

// A minimal fetch Response stand-in.
function res({ status = 200, etag = null as string | null, body = new Uint8Array(), text = '' } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (n: string) => (n.toLowerCase() === 'etag' ? etag : null) },
    arrayBuffer: async () => body.buffer,
    text: async () => text,
  };
}

// A JSON Response stand-in (for endpoints the caller reads via res.json()).
function jsonRes({ status = 200, json = {} as any } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    json: async () => json,
    text: async () => JSON.stringify(json),
  };
}

// The shared #send machinery (per-request bearer, the single 401 forced-refresh retry, the timeout) is exercised
// here through a surviving method — blobGet for GETs, putKeyring for PUTs. (The V1 snapshot / V2 delta-log methods
// that used to vehicle these were removed; the blob quartet + keyring + access + invites are the live surface.)
describe('RemoteStore', () => {
  it('binds the browser default fetch to its global receiver', async () => {
    const fetch = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError('Illegal invocation');
      return Promise.resolve(res({ status: 200 }));
    });
    vi.stubGlobal('fetch', fetch);
    try {
      const store = new RemoteStore({ baseUrl: 'http://x' });
      await store.blobGet('t/x');
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('fetches the bearer PER REQUEST from the AuthSession seam (never captured at construction)', async () => {
    const fetch = vi.fn(async () => res({ status: 200 }));
    // A seam whose token rotates between calls — a construction-time token would strand the second.
    let n = 0;
    const auth = { getAccessToken: vi.fn(async () => `jwt-${++n}`) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    await store.blobGet('t/snapshot');
    await store.blobGet('t/snapshot');
    expect((fetch.mock.calls[0][1] as any).headers['openom-auth']).toBe('Bearer jwt-1');
    expect((fetch.mock.calls[1][1] as any).headers['openom-auth']).toBe('Bearer jwt-2');
    expect(auth.getAccessToken).toHaveBeenCalledTimes(2);
  });

  it('accepts a bare getAccessToken function as the seam', async () => {
    const fetch = vi.fn(async () => res({ status: 200 }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth: async () => 'jwt-fn' });
    await store.blobGet('t/x');
    expect((fetch.mock.calls[0][1] as any).headers['openom-auth']).toBe('Bearer jwt-fn');
  });

  it('omits the auth header when no auth seam is given', async () => {
    const fetch = vi.fn(async () => res({ status: 200 }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    await store.blobGet('t/x');
    expect((fetch.mock.calls[0][1] as any).headers['openom-auth']).toBeUndefined();
  });

  it('on a 401 does EXACTLY ONE forced-refresh retry, then succeeds', async () => {
    const fetch = vi.fn(async () => (fetch.mock.calls.length === 1 ? res({ status: 401 }) : res({ status: 200, body: new Uint8Array([5]) })));
    const auth = { getAccessToken: vi.fn(async ({ forceRefresh } = {} as any) => (forceRefresh ? 'fresh' : 'stale')) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const bytes = await store.blobGet('t/x');
    expect(Array.from(bytes!)).toEqual([5]);
    // First attempt stale, retry forced-refresh.
    expect(auth.getAccessToken).toHaveBeenNthCalledWith(1, { forceRefresh: false });
    expect(auth.getAccessToken).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect((fetch.mock.calls[1][1] as any).headers['openom-auth']).toBe('Bearer fresh');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('a persistent 401 surfaces an auth_required AppError after one retry — never loops', async () => {
    const fetch = vi.fn(async () => res({ status: 401, text: 'nope' }));
    const auth = { getAccessToken: vi.fn(async () => 'tok') };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const err = await store.blobGet('t/x').catch((e: any) => e);
    expect(err.code).toBe('auth_required'); // #send throws AuthError; the blob channel normalizes it to an AppError
    expect(fetch).toHaveBeenCalledTimes(2); // initial + one forced-refresh retry, no more
  });

  it('a 401 with no auth seam surfaces an auth_required AppError without a retry', async () => {
    const fetch = vi.fn(async () => res({ status: 401 }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    const err = await store.blobGet('t/x').catch((e: any) => e);
    expect(err.code).toBe('auth_required');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('the 401 retry also protects a PUT (keyring publish path)', async () => {
    const queue = [res({ status: 401 }), jsonRes({ json: { revision: 2 } })];
    const fetch = vi.fn(async () => queue.shift());
    const auth = { getAccessToken: vi.fn(async ({ forceRefresh } = {} as any) => (forceRefresh ? 'fresh' : 'stale')) };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const out = await store.putKeyring('t', new Uint8Array([1, 2]));
    expect(out).toEqual({ revision: 2 });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('caps reports remote + conditional + durable', () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res() });
    expect(store.caps()).toEqual({ remote: true, conditionalWrites: true, durable: true });
  });

  it('list and delete stay unsupported', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => res({ status: 404 }) });
    await expect(store.list()).rejects.toThrow();
    await expect(store.delete()).rejects.toThrow();
  });
});

describe('RemoteStore membership summary (/access)', () => {
  // A JSON Response stand-in (the base `res` helper is bytes-only).
  const jres = ({ status = 200, json = {}, text = '' } = {}) => ({
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    json: async () => json,
    text: async () => text,
  });

  it('getAccess maps the server shape and returns null on 404', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ json: { members: [{ member_id: 'owner', role: 1 }], generation: 3, basis: ['op:a'] } }),
    });
    expect(await store.getAccess('t')).toEqual({
      members: [{ memberId: 'owner', role: 1 }],
      generation: 3,
      basis: ['op:a'],
    });
    const s404 = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ status: 404 }) });
    expect(await s404.getAccess('t')).toBeNull();
  });

  it('getAccess defaults generation to null and basis to [] when absent (chain, never summary-pushed)', async () => {
    const store = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ json: { members: [] } }) });
    expect(await store.getAccess('t')).toEqual({ members: [], generation: null, basis: [] });
  });

  it('putAccess sends the snake_case body + CAS generation and returns {generation, unchanged}', async () => {
    const fetch = vi.fn(async () => jres({ json: { generation: 4 } }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch });
    const out = await store.putAccess('t', {
      basis: ['op:b'],
      expectedGeneration: 3,
      members: [
        { memberId: 'owner', role: 1 },
        { memberId: 'bob', role: 4 },
      ],
    });
    expect(out).toEqual({ generation: 4, unchanged: false });
    const init = fetch.mock.calls[0][1] as any;
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({
      basis: ['op:b'],
      expected_generation: 3,
      members: [
        { member_id: 'owner', role: 1 },
        { member_id: 'bob', role: 4 },
      ],
    });
  });

  it('putAccess surfaces `unchanged`, and throws ConflictError on 409', async () => {
    const ok = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ json: { generation: 5, unchanged: true } }) });
    expect(await ok.putAccess('t', { basis: [], expectedGeneration: 5, members: [] })).toEqual({
      generation: 5,
      unchanged: true,
    });
    const conflict = new RemoteStore({ baseUrl: 'http://x', fetch: async () => jres({ status: 409 }) });
    await expect(conflict.putAccess('t', { basis: [], expectedGeneration: 1, members: [] })).rejects.toBeInstanceOf(
      ConflictError,
    );
  });
});

describe('RemoteStore account surface (/register, /me, /account/keystore)', () => {
  const jres = ({ status = 200, json = {} as any, etag = '"account-v1"' } = {}) => ({
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name: string) => (name.toLowerCase() === 'etag' ? etag : null) },
    json: async () => json,
    text: async () => JSON.stringify(json),
  });
  const problem = (status: number, code: keyof typeof ERROR_CODES, args?: Record<string, unknown>) => ({
    type: `/errors/${code}`,
    title: ERROR_CODES[code].title,
    status,
    code,
    detail: 'safe detail',
    ...(args ? { args } : {}),
  });

  it('register sends the snake_case PoP body and returns { memberId }', async () => {
    const fetch = vi.fn(async () => jres({ json: { member_id: 'mid-1' } }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth: async () => 'jwt' });
    const out = await store.register({
      memberId: 'mid-1',
      authorPublicKey: new Uint8Array([1, 2, 3]),
      signature: new Uint8Array([4, 5]),
      ts: 1000,
    }, { accessToken: 'pinned-jwt' });
    expect(out).toEqual({ memberId: 'mid-1' });
    expect(fetch.mock.calls[0][0]).toBe('http://x/v1/register');
    const init = fetch.mock.calls[0][1] as any;
    expect(init.method).toBe('POST');
    expect(init.headers['openom-auth']).toBe('Bearer pinned-jwt');
    expect(JSON.parse(init.body)).toEqual({
      member_id: 'mid-1',
      author_pubkey: 'AQID', // base64([1,2,3])
      signature: 'BAU=', // base64([4,5])
      ts: 1000,
    });
  });

  it('register does NOT auth-retry a 401 PoP failure — it maps the body code, not auth_required', async () => {
    const fetch = vi.fn(async () => jres({
      status: 401,
      json: problem(401, 'stale_timestamp', { server_time: 1_700_000_000 }),
    }));
    const auth = { getAccessToken: vi.fn(async () => 'jwt') };
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth });
    const err = await store
      .register(
        { memberId: 'm', authorPublicKey: new Uint8Array([1]), signature: new Uint8Array([2]), ts: 1 },
        { accessToken: 'pinned-jwt' },
      )
      .catch((e: any) => e);
    expect(err.code).toBe('stale_timestamp');
    expect(err.args).toEqual({ server_time: 1_700_000_000 });
    expect(fetch).toHaveBeenCalledTimes(1); // NO forced-refresh retry, despite the seam being present
    expect(auth.getAccessToken).not.toHaveBeenCalled();
  });

  it.each([
    [400, 'invalid_request'],
    [400, 'member_id_mismatch'],
    [401, 'bad_signature'],
  ] as const)('register maps %s %s through the shared problem registry', async (status, code) => {
    expect(ERROR_CODES[code]).toBeDefined();
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ status, json: problem(status, code) }),
      auth: async () => 'jwt',
    });
    const error = await store
      .register(
        { memberId: 'm', authorPublicKey: new Uint8Array([1]), signature: new Uint8Array([2]), ts: 1 },
        { accessToken: 'pinned-jwt' },
      )
      .catch((caught: any) => caught);
    expect(error.code).toBe(code);
  });

  it('register maps a 409 to identity_conflict', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ status: 409, json: problem(409, 'identity_conflict') }),
      auth: async () => 'jwt',
    });
    const err = await store
      .register(
        { memberId: 'm', authorPublicKey: new Uint8Array([1]), signature: new Uint8Array([2]), ts: 1 },
        { accessToken: 'pinned-jwt' },
      )
      .catch((e: any) => e);
    expect(err.code).toBe('identity_conflict');
  });

  it('me maps the shape and decodes the keystore blob', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ json: { member_id: 'm', keystore: 'CQk=', generation: 2 } }),
      auth: async () => 'jwt',
    });
    const out = await store.me();
    expect(out.memberId).toBe('m');
    expect(Array.from(out.keystore!)).toEqual([9, 9]);
    expect(out.generation).toBe(2);
    expect(out.etag).toBe('"account-v1"');
  });

  it('me returns a null keystore when the server has no backup', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ json: { member_id: 'm', keystore: null, generation: 0 } }),
      auth: async () => 'jwt',
    });
    expect(await store.me()).toEqual({
      memberId: 'm', keystore: null, generation: 0, etag: '"account-v1"',
    });
  });

  it('getKeystore decodes the blob, and throws unregistered on a 403', async () => {
    const ok = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ json: { keystore: 'CQk=', generation: 3 } }),
      auth: async () => 'jwt',
    });
    const got = await ok.getKeystore();
    expect(Array.from(got.keystore!)).toEqual([9, 9]);
    expect(got.generation).toBe(3);
    expect(got.etag).toBe('"account-v1"');

    const unreg = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ status: 403, json: problem(403, 'unregistered') }),
      auth: async () => 'jwt',
    });
    const err = await unreg.getKeystore().catch((e: any) => e);
    expect(err.code).toBe('unregistered');
  });

  it('putKeystore sends { keystore, generation } and returns the accepted generation', async () => {
    const fetch = vi.fn(async () => jres({ json: { generation: 5 } }));
    const store = new RemoteStore({ baseUrl: 'http://x', fetch, auth: async () => 'jwt' });
    const out = await store.putKeystore(new Uint8Array([9, 9]), 5, {
      etag: '"account-v0"', accessToken: 'pinned-jwt',
    });
    expect(out).toEqual({ generation: 5, etag: '"account-v1"' });
    expect(fetch.mock.calls[0][0]).toBe('http://x/v1/account/keystore');
    const init = fetch.mock.calls[0][1] as any;
    expect(init.method).toBe('PUT');
    expect(init.headers['if-match']).toBe('"account-v0"');
    expect(init.headers['openom-auth']).toBe('Bearer pinned-jwt');
    expect(JSON.parse(init.body)).toEqual({ keystore: 'CQk=', generation: 5 });
  });

  it('putKeystore maps a 409 to generation_rollback', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({ status: 409, json: problem(409, 'generation_rollback') }),
      auth: async () => 'jwt',
    });
    const err = await store
      .putKeystore(new Uint8Array([1]), 1, { etag: '"account-v0"' })
      .catch((e: any) => e);
    expect(err.code).toBe('generation_rollback');
  });

  it('putKeystore preserves the account-specific 412 reconciliation code', async () => {
    const store = new RemoteStore({
      baseUrl: 'http://x',
      fetch: async () => jres({
        status: 412, json: problem(412, 'account_backup_precondition_failed'),
      }),
      auth: async () => 'jwt',
    });
    const error = await store
      .putKeystore(new Uint8Array([1]), 1, { etag: '"stale"' })
      .catch((caught: any) => caught);
    expect(error.code).toBe('account_backup_precondition_failed');
    expect(error.httpStatus).toBe(412);
  });
});
