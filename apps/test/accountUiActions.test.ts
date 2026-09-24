import { describe, expect, it, vi } from 'vitest';
import { AccountUiActions } from '../app/src/core/accountUiActions.js';

function accountState(overrides = {}) {
  return {
    auth: 'signedIn',
    account: 'unlocked',
    binding: 'unbound',
    syncDisposition: 'remote',
    pending: new Set(),
    conflict: null,
    retainedIdentities: [],
    storagePersistence: 'granted',
    ...overrides,
  };
}

function fixture({ signUpResult = { status: 'signedIn' }, probe, state } = {}) {
  const currentState = state ?? accountState();
  const remoteProbe = probe ?? { status: 'unregistered', attempt: {}, remote: null };
  const account = {
    state: vi.fn(() => currentState),
    probe: vi.fn(async () => remoteProbe),
    enableSync: vi.fn(async () => currentState),
  };
  const auth = {
    signUp: vi.fn(async () => signUpResult),
    signIn: vi.fn(async () => {}),
    signOut: vi.fn(async () => {}),
  };
  const changes = vi.fn();
  const logError = vi.fn((_operation, error) => error);
  const actions = new AccountUiActions({
    account,
    auth,
    onChange: changes,
    errorText: (error) => `safe:${error.code ?? 'unknown'}`,
    logError,
  });
  return { account, actions, auth, changes, logError };
}

describe('AccountUiActions', () => {
  it('routes signed-in users from a post-auth remote probe', async () => {
    const restore = fixture({
      state: accountState({
        account: 'none',
        conflict: { code: 'identity_conflict', reason: 'remote_restore_available' },
      }),
      probe: {
        status: 'registered',
        attempt: {},
        remote: { memberId: 'remote', keystore: new Uint8Array([1]), generation: 1, etag: 'etag' },
      },
    });
    await restore.actions.signIn({ email: 'person@example.test', password: 'secret' });
    expect(restore.account.probe).toHaveBeenCalledTimes(1);
    expect(restore.actions.state()).toMatchObject({ screen: 'restore', busy: null, error: '' });

    const conflict = fixture({ state: accountState({ conflict: { code: 'identity_conflict', reason: 'mismatch' } }) });
    await conflict.actions.signIn({ email: 'person@example.test', password: 'secret' });
    expect(conflict.actions.state().screen).toBe('conflict');
  });

  it('parks confirmation-required sign-up without probing or claiming a session', async () => {
    const { account, actions } = fixture({ signUpResult: { status: 'confirmationRequired' } });
    await expect(actions.signUp({ email: 'new@example.test', password: 'secret' }))
      .resolves.toEqual({ status: 'confirmationRequired' });
    expect(account.probe).not.toHaveBeenCalled();
    expect(actions.state()).toMatchObject({
      screen: 'confirmationRequired',
      notice: 'confirmationRequired',
      busy: null,
      discovery: 'unknown',
    });
  });

  it('probes after immediate-session sign-up and serializes interactive operations', async () => {
    let release;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const { actions, auth, account } = fixture();
    auth.signUp.mockImplementationOnce(async () => {
      await pending;
      return { status: 'signedIn' };
    });

    const first = actions.signUp({ email: 'new@example.test', password: 'secret' });
    expect(actions.state().busy).toBe('signUp');
    await expect(actions.signIn({ email: 'other@example.test', password: 'secret' })).resolves.toBeNull();
    expect(auth.signIn).not.toHaveBeenCalled();
    release();
    await first;

    expect(account.probe).toHaveBeenCalledTimes(1);
    expect(actions.state()).toMatchObject({ screen: 'overview', busy: null, notice: null });
  });

  it('maps failures through the registry adapter and never exposes raw errors as state', async () => {
    const failure = { code: 'sign_in_failed', message: 'provider detail' };
    const { actions, auth, logError } = fixture();
    auth.signIn.mockRejectedValueOnce(failure);

    await expect(actions.signIn({ email: 'person@example.test', password: 'wrong' })).resolves.toBeNull();
    expect(logError).toHaveBeenCalledWith('signIn', failure);
    expect(actions.state()).toMatchObject({ busy: null, error: 'safe:sign_in_failed' });
    expect(JSON.stringify(actions.state())).not.toContain('provider detail');
  });

  it('surfaces enable-sync conflicts and resets route state on sign-out', async () => {
    const conflictState = accountState({ conflict: { code: 'identity_conflict', reason: 'mismatch' } });
    const fixtureValue = fixture({ state: conflictState });
    await fixtureValue.actions.enableSync();
    expect(fixtureValue.actions.state().screen).toBe('conflict');

    await fixtureValue.actions.signOut();
    expect(fixtureValue.auth.signOut).toHaveBeenCalledTimes(1);
    expect(fixtureValue.actions.state()).toMatchObject({
      screen: 'overview', discovery: 'unknown', notice: null,
    });
  });

  it('validates routes and supports an independently mounted closed state', () => {
    const { actions } = fixture();
    actions.show('signUp');
    expect(actions.state().screen).toBe('signUp');
    actions.close();
    expect(actions.state()).toMatchObject({ screen: null, error: '', notice: null });
    expect(() => actions.show('unknown')).toThrow('unknown account UI screen');
  });
});
