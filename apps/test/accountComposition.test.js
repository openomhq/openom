import { describe, expect, it, vi } from 'vitest';
import { composeAccountSession } from '../app/src/core/accountComposition.js';

function core() {
  return {
    accountStatus: vi.fn(async () => 'none'),
    accountSyncState: vi.fn(async () => ({ record: null, storagePersistence: 'granted' })),
  };
}

function authBackend() {
  let subject = null;
  const subscribers = new Set();
  return {
    subject: () => subject,
    registrationAttempt: vi.fn(),
    getAccessToken: vi.fn(),
    onChange(callback) {
      subscribers.add(callback);
      return () => subscribers.delete(callback);
    },
    capabilities: () => ({ canRegister: false, canLogin: false, sync: true }),
    setSubject(next) {
      subject = next;
      for (const callback of subscribers) callback();
    },
    dispose: vi.fn(() => subscribers.clear()),
  };
}

describe('account composition', () => {
  it('constructs and attaches the sole facade before exposing dependencies', async () => {
    const backend = authBackend();
    const remote = { me: vi.fn(), register: vi.fn(), putKeystore: vi.fn() };
    const createRemote = vi.fn(() => remote);
    const composition = await composeAccountSession(core(), {
      createAuth: () => backend,
      createRemote,
    });

    expect(composition.account.state().auth).toBe('signedOut');
    expect(createRemote).toHaveBeenCalledWith(composition.auth);
    backend.setSubject('provider-subject');
    expect(composition.account.state().auth).toBe('signedIn');

    composition.dispose();
    expect(backend.dispose).toHaveBeenCalledTimes(1);
  });

  it('disposes partial composition when provider construction fails', async () => {
    await expect(composeAccountSession(core(), {
      createAuth: () => { throw new Error('provider unavailable'); },
    })).rejects.toThrow(/provider unavailable/);
  });
});
