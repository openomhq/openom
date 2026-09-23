import { describe, expect, it, vi } from 'vitest';
import { AuthSessionCoordinator } from '../app/src/core/authSessionStore.js';
import { makeError } from '../app/src/core/errorModel.js';
import { SupabaseAuth } from '../app/src/core/session.js';

const ISSUER = 'https://project.supabase.co/auth/v1';

function jwt(subject: string, label = 'token', issuer = ISSUER) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'ES256', kid: label })}.${encode({ iss: issuer, sub: subject })}.signature`;
}

const tokens = ({
  subject = 'subject-a',
  accessToken = jwt(subject),
  refreshToken = 'refresh-a',
  expiresAt = 2_000_000_000,
} = {}) => ({ accessToken, refreshToken, expiresAt });

class MemoryStorage {
  values = new Map<string, string>();
  failReads = false;
  failWrites = false;
  writes: string[] = [];

  getItem(key: string) {
    if (this.failReads) throw new Error('storage read denied');
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    if (this.failWrites) throw new Error('storage write denied');
    this.writes.push(value);
    this.values.set(key, value);
  }
}

class SerialLocks {
  tail = Promise.resolve<unknown>(undefined);
  calls: string[] = [];

  request(name: string, _options: unknown, operation: () => unknown) {
    this.calls.push(name);
    const result = this.tail.then(operation, operation);
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

class FakeBroadcastChannel {
  static channels = new Map<string, Set<FakeBroadcastChannel>>();
  listener: ((event: { data: unknown }) => void) | null = null;

  constructor(readonly name: string) {
    const channels = FakeBroadcastChannel.channels.get(name) ?? new Set();
    channels.add(this);
    FakeBroadcastChannel.channels.set(name, channels);
  }

  addEventListener(type: string, listener: (event: { data: unknown }) => void) {
    if (type === 'message') this.listener = listener;
  }

  postMessage(data: unknown) {
    for (const channel of FakeBroadcastChannel.channels.get(this.name) ?? []) {
      if (channel !== this) queueMicrotask(() => channel.listener?.({ data }));
    }
  }

  close() {
    FakeBroadcastChannel.channels.get(this.name)?.delete(this);
  }
}

function fakeClient(overrides = {}) {
  return {
    signInWithPassword: vi.fn(async () => tokens()),
    refresh: vi.fn(async () => tokens({ accessToken: jwt('subject-a', 'refreshed'), refreshToken: 'refresh-b' })),
    signOut: vi.fn(async () => {}),
    ...overrides,
  };
}

function coordinator(storage = new MemoryStorage(), options = {}) {
  return new AuthSessionCoordinator('project', {
    storage,
    locks: null,
    broadcastFactory: null,
    ...options,
  });
}

async function seedActive(store: AuthSessionCoordinator, refreshToken = 'refresh-a', subject = 'subject-a') {
  return store.runExclusive(null, (transaction) => transaction.commit({
    state: 'active',
    refreshToken,
    issuer: ISSUER,
    subject,
  }).record);
}

describe('SupabaseAuth rotating session', () => {
  it('starts signed out when no persisted refresh record exists', async () => {
    const auth = new SupabaseAuth(fakeClient(), { store: coordinator() });
    expect(auth.subject()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'auth_required' });
  });

  it('persists a validated sign-in before publishing the authenticated subject', async () => {
    const storage = new MemoryStorage();
    const store = coordinator(storage);
    const client = fakeClient();
    const auth = new SupabaseAuth(client, { store });
    const observed: Array<{ subject: string | null, persisted: boolean }> = [];
    auth.onChange(() => observed.push({ subject: auth.subject(), persisted: store.read()?.state === 'active' }));

    await auth.signIn({ email: 'person@example.test', password: 'secret' });

    expect(observed).toEqual([{ subject: 'subject-a', persisted: true }]);
    expect(store.read()).toMatchObject({
      version: 1,
      revision: 1,
      state: 'active',
      refreshToken: 'refresh-a',
      issuer: ISSUER,
      subject: 'subject-a',
    });
    expect(await auth.getAccessToken()).toBe(jwt('subject-a'));
    expect(client.refresh).not.toHaveBeenCalled();
  });

  it('restores the subject synchronously and lazily refreshes after reload', async () => {
    const storage = new MemoryStorage();
    const firstStore = coordinator(storage);
    const first = new SupabaseAuth(fakeClient(), { store: firstStore });
    await first.signIn({ email: 'person@example.test', password: 'secret' });
    first.dispose();

    const client = fakeClient();
    const restored = new SupabaseAuth(client, { store: coordinator(storage) });
    expect(restored.subject()).toBe('subject-a');
    await expect(restored.getAccessToken()).resolves.toBe(jwt('subject-a', 'refreshed'));
    expect(client.refresh).toHaveBeenCalledWith('refresh-a');
  });

  it('refreshes near expiry or when forced, and commits rotation before returning', async () => {
    let now = 1_700_000_000_000;
    const storage = new MemoryStorage();
    const client = fakeClient({
      signInWithPassword: vi.fn(async () => tokens({ expiresAt: now / 1_000 + 30 })),
    });
    const store = coordinator(storage);
    const auth = new SupabaseAuth(client, { store, now: () => now, refreshMarginMs: 60_000 });
    await auth.signIn({ email: 'person@example.test', password: 'secret' });

    await expect(auth.getAccessToken()).resolves.toBe(jwt('subject-a', 'refreshed'));
    expect(client.refresh).toHaveBeenCalledWith('refresh-a');
    expect(store.read()).toMatchObject({ refreshToken: 'refresh-b', revision: 2 });

    client.refresh.mockResolvedValueOnce(tokens({
      accessToken: jwt('subject-a', 'forced'),
      refreshToken: 'refresh-c',
    }));
    await expect(auth.getAccessToken({ forceRefresh: true })).resolves.toBe(jwt('subject-a', 'forced'));
    expect(store.read()).toMatchObject({ refreshToken: 'refresh-c', revision: 3 });
  });

  it('coalesces simultaneous same-tab refresh callers', async () => {
    const store = coordinator();
    await seedActive(store);
    let release!: (value: ReturnType<typeof tokens>) => void;
    const pending = new Promise<ReturnType<typeof tokens>>((resolve) => { release = resolve; });
    const client = fakeClient({ refresh: vi.fn(() => pending) });
    const auth = new SupabaseAuth(client, { store });

    const first = auth.getAccessToken();
    const second = auth.getAccessToken({ forceRefresh: true });
    await Promise.resolve();
    expect(client.refresh).toHaveBeenCalledTimes(1);
    release(tokens({ accessToken: jwt('subject-a', 'one-flight'), refreshToken: 'refresh-b' }));
    await expect(Promise.all([first, second])).resolves.toEqual([
      jwt('subject-a', 'one-flight'),
      jwt('subject-a', 'one-flight'),
    ]);
  });

  it('continues in memory when browser storage denies writes', async () => {
    const storage = new MemoryStorage();
    storage.failWrites = true;
    const client = fakeClient();
    const auth = new SupabaseAuth(client, { store: coordinator(storage) });

    await auth.signIn({ email: 'person@example.test', password: 'secret' });
    expect(auth.subject()).toBe('subject-a');
    expect(await auth.getAccessToken()).toBe(jwt('subject-a'));
    await expect(auth.getAccessToken({ forceRefresh: true })).resolves.toBe(jwt('subject-a', 'refreshed'));
    expect(client.refresh).toHaveBeenCalledWith('refresh-a');
    expect(storage.values.size).toBe(0);
  });

  it('retains the last session and refresh record through network failure', async () => {
    const storage = new MemoryStorage();
    const client = fakeClient();
    const store = coordinator(storage);
    const auth = new SupabaseAuth(client, { store });
    await auth.signIn({ email: 'person@example.test', password: 'secret' });
    client.refresh.mockRejectedValueOnce(makeError('request_failed', { cause: 'offline' }));

    await expect(auth.getAccessToken({ forceRefresh: true })).rejects.toMatchObject({ code: 'request_failed' });
    expect(auth.subject()).toBe('subject-a');
    expect(store.read()).toMatchObject({ state: 'active', refreshToken: 'refresh-a' });
    await expect(auth.getAccessToken()).resolves.toBe(jwt('subject-a'));
  });

  it('rereads storage before a definitive rejection and persists an expired tombstone', async () => {
    const storage = new MemoryStorage();
    const store = coordinator(storage);
    await seedActive(store);
    const client = fakeClient({
      refresh: vi.fn(async () => { throw makeError('session_expired'); }),
    });
    const auth = new SupabaseAuth(client, { store });
    const changed = vi.fn();
    auth.onChange(changed);

    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'session_expired' });
    expect(store.read()).toEqual({ version: 1, revision: 2, state: 'expired' });
    expect(auth.subject()).toBeNull();
    expect(changed).toHaveBeenCalledTimes(1);
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'session_expired' });
    expect(client.refresh).toHaveBeenCalledTimes(1);
  });

  it('retries once with a newer persisted rotation instead of clearing it', async () => {
    const storage = new MemoryStorage();
    const store = coordinator(storage);
    await seedActive(store, 'refresh-old');
    const refresh = vi.fn(async (refreshToken: string) => {
      if (refreshToken === 'refresh-old') {
        const [key, encoded] = [...storage.values.entries()][0];
        const record = JSON.parse(encoded);
        storage.values.set(key, JSON.stringify({ ...record, revision: 2, refreshToken: 'refresh-newer' }));
        throw makeError('session_expired');
      }
      return tokens({ accessToken: jwt('subject-a', 'retried'), refreshToken: 'refresh-final' });
    });
    const auth = new SupabaseAuth(fakeClient({ refresh }), { store });

    await expect(auth.getAccessToken()).resolves.toBe(jwt('subject-a', 'retried'));
    expect(refresh.mock.calls.map(([value]) => value)).toEqual(['refresh-old', 'refresh-newer']);
    expect(store.read()).toMatchObject({ revision: 3, refreshToken: 'refresh-final' });
  });

  it('recovers a lost refresh response by retrying the persisted parent after reload', async () => {
    const storage = new MemoryStorage();
    const firstStore = coordinator(storage);
    await seedActive(firstStore, 'refresh-parent');
    const firstClient = fakeClient({
      refresh: vi.fn(async () => { throw makeError('request_failed', { cause: 'response lost' }); }),
    });
    const first = new SupabaseAuth(firstClient, { store: firstStore });
    await expect(first.getAccessToken()).rejects.toMatchObject({ code: 'request_failed' });
    expect(firstStore.read()).toMatchObject({ refreshToken: 'refresh-parent' });
    first.dispose();

    const secondClient = fakeClient({
      refresh: vi.fn(async () => tokens({
        accessToken: jwt('subject-a', 'recovered'),
        refreshToken: 'refresh-active',
      })),
    });
    const restored = new SupabaseAuth(secondClient, { store: coordinator(storage) });
    await expect(restored.getAccessToken()).resolves.toBe(jwt('subject-a', 'recovered'));
    expect(secondClient.refresh).toHaveBeenCalledWith('refresh-parent');
  });

  it('fails closed when refresh changes issuer or subject', async () => {
    const store = coordinator();
    await seedActive(store);
    const client = fakeClient({
      refresh: vi.fn(async () => tokens({
        subject: 'subject-b',
        accessToken: jwt('subject-b', 'switched'),
        refreshToken: 'refresh-b',
      })),
    });
    const auth = new SupabaseAuth(client, { store });

    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'session_expired' });
    expect(store.read()).toMatchObject({ state: 'expired' });
    expect(auth.subject()).toBeNull();
  });

  it('allows explicit sign-in to replace the active provider identity', async () => {
    const client = fakeClient();
    const store = coordinator();
    const auth = new SupabaseAuth(client, { store });
    await auth.signIn({ email: 'a@example.test', password: 'secret' });
    client.signInWithPassword.mockResolvedValueOnce(tokens({
      subject: 'subject-b',
      accessToken: jwt('subject-b', 'account-b'),
      refreshToken: 'refresh-b',
    }));

    await auth.signIn({ email: 'b@example.test', password: 'secret' });
    expect(auth.subject()).toBe('subject-b');
    expect(store.read()).toMatchObject({ revision: 2, subject: 'subject-b', refreshToken: 'refresh-b' });
  });

  it('pins registration claims to the exact returned access token', async () => {
    const client = fakeClient();
    const auth = new SupabaseAuth(client, { store: coordinator() });
    await auth.signIn({ email: 'person@example.test', password: 'secret' });

    const attempt = await auth.registrationAttempt();
    expect(attempt).toEqual({ accessToken: jwt('subject-a'), issuer: ISSUER, subject: 'subject-a' });

    client.refresh.mockResolvedValueOnce(tokens({
      accessToken: jwt('subject-a', 'registration-refresh'),
      refreshToken: 'refresh-b',
    }));
    const refreshed = await auth.registrationAttempt({ forceRefresh: true });
    expect(refreshed).toEqual({
      accessToken: jwt('subject-a', 'registration-refresh'),
      issuer: ISSUER,
      subject: 'subject-a',
    });
  });

  it('clears local custody on logout even when remote revocation fails', async () => {
    const store = coordinator();
    const client = fakeClient({
      signOut: vi.fn(async () => { throw makeError('request_failed', { cause: 'offline' }); }),
    });
    const auth = new SupabaseAuth(client, { store });
    await auth.signIn({ email: 'person@example.test', password: 'secret' });

    await expect(auth.signOut()).rejects.toMatchObject({ code: 'request_failed' });
    expect(client.signOut).toHaveBeenCalledWith(jwt('subject-a'));
    expect(store.read()).toEqual({ version: 1, revision: 2, state: 'signed_out' });
    expect(auth.subject()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'auth_required' });
  });

  it('retries logout against a concurrently selected provider identity', async () => {
    const store = coordinator();
    const client = fakeClient({
      refresh: vi.fn(async (refreshToken: string) => {
        expect(refreshToken).toBe('refresh-b');
        return tokens({
          subject: 'subject-b',
          accessToken: jwt('subject-b', 'logout-b'),
          refreshToken: 'refresh-c',
        });
      }),
    });
    const auth = new SupabaseAuth(client, { store });
    await auth.signIn({ email: 'a@example.test', password: 'secret' });

    const logout = auth.signOut();
    await store.runExclusive(store.read(), (transaction) => transaction.commit({
      state: 'active',
      refreshToken: 'refresh-b',
      issuer: ISSUER,
      subject: 'subject-b',
    }));
    await logout;

    expect(client.signOut).toHaveBeenCalledTimes(1);
    expect(client.signOut).toHaveBeenCalledWith(jwt('subject-b', 'logout-b'));
    expect(store.read()).toMatchObject({ state: 'signed_out' });
  });

  it('ignores malformed persisted custody', async () => {
    const storage = new MemoryStorage();
    storage.values.set('openom.auth.session.v1.project', '{"version":1,"refreshToken":"partial"}');
    const client = fakeClient();
    const auth = new SupabaseAuth(client, { store: coordinator(storage) });
    expect(auth.subject()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: 'auth_required' });
    expect(client.refresh).not.toHaveBeenCalled();
  });
});

describe('SupabaseAuth cross-tab coordination', () => {
  it('serializes rotations, adopts peer revisions, and propagates sign-out', async () => {
    FakeBroadcastChannel.channels.clear();
    const storage = new MemoryStorage();
    const locks = new SerialLocks();
    const makeStore = () => coordinator(storage, {
      locks,
      broadcastFactory: FakeBroadcastChannel as unknown as typeof BroadcastChannel,
    });
    const rotations: string[] = [];
    const client = fakeClient({
      refresh: vi.fn(async (refreshToken: string) => {
        rotations.push(refreshToken);
        const next = refreshToken === 'refresh-a' ? 'refresh-b' : 'refresh-c';
        return tokens({ accessToken: jwt('subject-a', next), refreshToken: next });
      }),
    });
    const first = new SupabaseAuth(client, { store: makeStore() });
    const second = new SupabaseAuth(client, { store: makeStore() });
    const secondChanges = vi.fn();
    second.onChange(secondChanges);

    await first.signIn({ email: 'person@example.test', password: 'secret' });
    await vi.waitFor(() => expect(second.subject()).toBe('subject-a'));

    await Promise.all([
      first.getAccessToken({ forceRefresh: true }),
      second.getAccessToken({ forceRefresh: true }),
    ]);
    expect(rotations).toEqual(['refresh-a', 'refresh-b']);

    await first.signOut();
    await vi.waitFor(() => expect(second.subject()).toBeNull());
    expect(secondChanges).toHaveBeenCalled();
    expect(locks.calls.every((name) => name === 'openom.auth.session.project')).toBe(true);
  });
});
