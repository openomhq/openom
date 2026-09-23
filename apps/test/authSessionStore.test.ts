import { describe, expect, it, vi } from 'vitest';
import {
  AuthSessionCoordinator,
  decodeAuthSessionRecord,
} from '../app/src/core/authSessionStore.js';

class MemoryStorage {
  values = new Map<string, string>();
  failReads = false;
  failWrites = false;

  getItem(key: string) {
    if (this.failReads) throw new Error('storage read denied');
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    if (this.failWrites) throw new Error('storage write denied');
    this.values.set(key, value);
  }
}

class FakeBroadcastChannel {
  static channels = new Map<string, Set<FakeBroadcastChannel>>();
  listener: ((event: { data: unknown }) => void) | null = null;
  messages: unknown[] = [];

  constructor(readonly name: string) {
    const channels = FakeBroadcastChannel.channels.get(name) ?? new Set();
    channels.add(this);
    FakeBroadcastChannel.channels.set(name, channels);
  }

  addEventListener(type: string, listener: (event: { data: unknown }) => void) {
    if (type === 'message') this.listener = listener;
  }

  postMessage(data: unknown) {
    this.messages.push(data);
    for (const channel of FakeBroadcastChannel.channels.get(this.name) ?? []) {
      if (channel !== this) channel.listener?.({ data });
    }
  }

  close() {
    FakeBroadcastChannel.channels.get(this.name)?.delete(this);
  }
}

const active = (refreshToken = 'refresh-a') => ({
  state: 'active' as const,
  refreshToken,
  issuer: 'https://issuer.example/auth/v1',
  subject: 'provider-subject',
});

describe('AuthSessionCoordinator', () => {
  it('writes and verifies a versioned active record', async () => {
    const storage = new MemoryStorage();
    const coordinator = new AuthSessionCoordinator('project', {
      storage,
      locks: null,
      broadcastFactory: null,
    });
    const committed = await coordinator.runExclusive(null, (transaction) => transaction.commit(active()));

    expect(committed.persisted).toBe(true);
    expect(committed.record).toEqual({ version: 1, revision: 1, ...active() });
    expect(coordinator.read()).toEqual(committed.record);
  });

  it('persists tombstones so stale tabs cannot resurrect a signed-out or expired session', async () => {
    const storage = new MemoryStorage();
    const coordinator = new AuthSessionCoordinator('project', { storage, locks: null, broadcastFactory: null });
    const first = await coordinator.runExclusive(null, (transaction) => transaction.commit(active()));
    const signedOut = await coordinator.runExclusive(first.record, (transaction) => transaction.commit({
      state: 'signed_out',
    }));
    const expired = await coordinator.runExclusive(first.record, (transaction) => {
      expect(transaction.record()).toEqual(signedOut.record);
      return transaction.commit({ state: 'expired' });
    });

    expect(signedOut.record).toEqual({ version: 1, revision: 2, state: 'signed_out' });
    expect(expired.record).toEqual({ version: 1, revision: 3, state: 'expired' });
  });

  it('serializes local operations through the project Web Lock and promise tail', async () => {
    const storage = new MemoryStorage();
    const events: string[] = [];
    const locks = {
      request: vi.fn(async (name: string, options: unknown, operation: () => unknown) => {
        events.push(`${name}:${JSON.stringify(options)}`);
        return operation();
      }),
    };
    const coordinator = new AuthSessionCoordinator('https://project.example', {
      storage,
      locks,
      broadcastFactory: null,
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = coordinator.runExclusive(null, async (transaction) => {
      events.push('first-start');
      await gate;
      transaction.commit(active());
      events.push('first-end');
    });
    const second = coordinator.runExclusive(null, (transaction) => {
      events.push('second-start');
      expect(transaction.record()?.revision).toBe(1);
    });
    await Promise.resolve();
    expect(events).not.toContain('second-start');
    release();
    await Promise.all([first, second]);

    expect(events.indexOf('first-end')).toBeLessThan(events.indexOf('second-start'));
    expect(locks.request).toHaveBeenCalledTimes(2);
    expect(events[0]).toBe('openom.auth.session.https://project.example:{"mode":"exclusive"}');
  });

  it('keeps a validated volatile record when browser storage is unavailable', async () => {
    const storage = new MemoryStorage();
    storage.failWrites = true;
    const coordinator = new AuthSessionCoordinator('project', { storage, locks: null, broadcastFactory: null });
    const result = await coordinator.runExclusive(null, (transaction) => transaction.commit(active()));

    expect(result.persisted).toBe(false);
    expect(result.record).toEqual({ version: 1, revision: 1, ...active() });
    expect(coordinator.read()).toBeNull();
  });

  it('treats persisted peer state as authoritative over a higher volatile fallback', async () => {
    const storage = new MemoryStorage();
    const coordinator = new AuthSessionCoordinator('project', { storage, locks: null, broadcastFactory: null });
    const persisted = await coordinator.runExclusive(null, (transaction) => transaction.commit({
      state: 'signed_out',
    }).record);
    const volatile = {
      version: 1 as const,
      revision: persisted.revision + 10,
      ...active('volatile-refresh'),
    };

    await coordinator.runExclusive(volatile, (transaction) => {
      expect(transaction.record()).toEqual(persisted);
    });
  });

  it('broadcasts only the committed revision, never tokens or identity hints', async () => {
    FakeBroadcastChannel.channels.clear();
    const storage = new MemoryStorage();
    const first = new AuthSessionCoordinator('shared', {
      storage,
      locks: null,
      broadcastFactory: FakeBroadcastChannel as unknown as typeof BroadcastChannel,
    });
    const second = new AuthSessionCoordinator('shared', {
      storage,
      locks: null,
      broadcastFactory: FakeBroadcastChannel as unknown as typeof BroadcastChannel,
    });
    const revisions: number[] = [];
    second.onRevision((revision) => revisions.push(revision));

    await first.runExclusive(null, (transaction) => transaction.commit(active('sensitive-refresh-token')));
    expect(revisions).toEqual([1]);
    const channels = [...FakeBroadcastChannel.channels.values()].flatMap((entries) => [...entries]);
    expect(channels.flatMap((channel) => channel.messages)).toEqual([{ revision: 1 }]);
    expect(JSON.stringify(channels.flatMap((channel) => channel.messages))).not.toContain('sensitive');
    first.close();
    second.close();
  });

  it('ignores malformed, partial, or unversioned persisted records', () => {
    expect(decodeAuthSessionRecord(null)).toBeNull();
    expect(decodeAuthSessionRecord({ version: 1, revision: 0, ...active() })).toBeNull();
    expect(decodeAuthSessionRecord({ version: 2, revision: 1, ...active() })).toBeNull();
    expect(decodeAuthSessionRecord({ version: 1, revision: 1, state: 'active' })).toBeNull();
    expect(decodeAuthSessionRecord({ version: 1, revision: 1, state: 'other' })).toBeNull();
  });
});
