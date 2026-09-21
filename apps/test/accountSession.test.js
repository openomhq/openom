import { describe, expect, it, vi } from 'vitest';
import { AccountSession } from '../app/src/core/accountSession.js';

const identity = (memberId) => ({
  memberId,
  authorPublicKey: new Uint8Array([1]),
  hpkePublicKey: new Uint8Array([2]),
});

function backend(overrides = {}) {
  return {
    accountStatus: vi.fn(async () => 'none'),
    accountCreate: vi.fn(async () => ({ ...identity('member-created'), recoveryCode: 'recovery' })),
    accountUnlock: vi.fn(async () => identity('member-unlocked')),
    accountRecover: vi.fn(async () => ({ recoveryCode: 'next-recovery', generation: 2 })),
    accountChangePassphrase: vi.fn(async () => ({ generation: 1 })),
    accountRotateRoot: vi.fn(async () => ({ recoveryCode: 'rotated', generation: 2 })),
    accountRegisterProof: vi.fn(async () => new Uint8Array(64)),
    accountPublicIdentity: vi.fn(async () => identity('member-public')),
    accountLock: vi.fn(async () => {}),
    ...overrides,
  };
}

describe('AccountSession', () => {
  it('initializes from host custody and loads identity only for an unlocked account', async () => {
    const lockedCore = backend({ accountStatus: vi.fn(async () => 'locked') });
    const locked = new AccountSession(lockedCore);
    await expect(locked.initialize()).resolves.toEqual({ account: 'locked' });
    expect(locked.memberId()).toBeNull();
    expect(lockedCore.accountPublicIdentity).not.toHaveBeenCalled();

    const unlockedCore = backend({ accountStatus: vi.fn(async () => 'unlocked') });
    const unlocked = new AccountSession(unlockedCore);
    await expect(unlocked.initialize()).resolves.toEqual({ account: 'unlocked', memberId: 'member-public' });
  });

  it('takes application identity only from account-core results', async () => {
    const core = backend();
    const session = new AccountSession(core);
    await session.initialize();
    await session.createAccount('passphrase');
    expect(session.memberId()).toBe('member-created');
    await session.unlock('passphrase');
    expect(session.memberId()).toBe('member-unlocked');
  });

  it('recovers identity from the resident account when the host returns custody metadata only', async () => {
    const core = backend();
    const session = new AccountSession(core);
    const recovered = await session.recover('old-code', 'new-passphrase');
    expect(core.accountRecover).toHaveBeenCalledWith({ recoveryCode: 'old-code', newPassphrase: 'new-passphrase' });
    expect(recovered.memberId).toBe('member-public');
    expect(session.state()).toEqual({ account: 'unlocked', memberId: 'member-public' });
  });

  it('locks host custody before clearing the observable identity', async () => {
    const calls = [];
    const core = backend({
      accountUnlock: vi.fn(async () => identity('member-account')),
      accountLock: vi.fn(async () => { calls.push('host'); }),
    });
    const session = new AccountSession(core);
    const changes = [];
    session.onChange((state) => { calls.push('change'); changes.push(state); });
    await session.unlock('passphrase');
    calls.length = 0;
    await session.lock();
    expect(calls).toEqual(['host', 'change']);
    expect(changes.at(-1)).toEqual({ account: 'locked' });
    expect(session.memberId()).toBeNull();
  });

  it('delegates credential and registration operations without changing identity', async () => {
    const core = backend();
    const session = new AccountSession(core);
    await session.unlock('passphrase');
    await session.changePassphrase('passphrase', 'replacement');
    await session.rotateRoot('replacement');
    await session.registerProof('issuer', 'provider-subject', 123);
    expect(session.memberId()).toBe('member-unlocked');
    expect(core.accountChangePassphrase).toHaveBeenCalledWith({ current: 'passphrase', next: 'replacement' });
    expect(core.accountRotateRoot).toHaveBeenCalledWith({ passphrase: 'replacement' });
    expect(core.accountRegisterProof).toHaveBeenCalledWith({
      issuer: 'issuer', subject: 'provider-subject', timestamp: 123,
    });
  });

  it('rejects an invalid backend state and requires a backend', async () => {
    expect(() => new AccountSession(null)).toThrow('needs an app-core account backend');
    const session = new AccountSession(backend({ accountStatus: vi.fn(async () => 'mystery') }));
    await expect(session.initialize()).rejects.toThrow('unknown account state');
  });
});
