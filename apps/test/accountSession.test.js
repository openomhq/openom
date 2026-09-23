import { afterEach, describe, expect, it, vi } from 'vitest';
import { AccountSession, classifyAccountBindingState } from '../app/src/core/accountSession.js';
import { makeError } from '../app/src/core/errorModel.js';

const identity = (memberId = 'member-local') => ({
  memberId,
  authorPublicKey: new Uint8Array([1]),
  hpkePublicKey: new Uint8Array([2]),
});

const version = (generation = 1, byte = 7) => ({
  generation,
  blobHash: new Uint8Array(32).fill(byte),
});

function record(memberId = 'member-local', overrides = {}) {
  return {
    revision: 1,
    identity: {
      memberId,
      version: version(),
      floor: 1,
      effectiveFloor: 1,
    },
    binding: null,
    acknowledgedBackup: null,
    pendingBackup: null,
    retainedIdentities: [],
    ...overrides,
  };
}

function backend({ account = 'unlocked', initialRecord = record(), overrides = {} } = {}) {
  let syncRecord = initialRecord;
  const syncState = () => ({ record: syncRecord, storagePersistence: 'granted' });
  const core = {
    accountStatus: vi.fn(async () => account),
    accountCreate: vi.fn(async () => ({ ...identity('member-created'), recoveryCode: 'recovery' })),
    accountUnlock: vi.fn(async () => identity()),
    accountRecover: vi.fn(async () => ({ recoveryCode: 'next-recovery', generation: 2 })),
    accountChangePassphrase: vi.fn(async () => ({ generation: 1 })),
    accountRotateRoot: vi.fn(async () => ({ recoveryCode: 'rotated', generation: 2 })),
    accountRegisterProof: vi.fn(async () => new Uint8Array([8, 9])),
    accountPublicIdentity: vi.fn(async () => identity(syncRecord?.identity.memberId ?? 'member-local')),
    accountLock: vi.fn(async () => {}),
    accountSnapshot: vi.fn(async () => ({
      ...identity(syncRecord.identity.memberId),
      keystore: new Uint8Array([4, 5]),
      generation: syncRecord.identity.version.generation,
      blobHash: syncRecord.identity.version.blobHash,
    })),
    accountSyncState: vi.fn(async () => syncState()),
    accountConfirmBinding: vi.fn(async (binding) => {
      syncRecord = {
        ...syncRecord, revision: syncRecord.revision + 1, binding,
        acknowledgedBackup: null, pendingBackup: null,
      };
      return syncState();
    }),
    accountStageBackup: vi.fn(async ({ kind, binding }) => {
      if (syncRecord.pendingBackup?.kind === 'revoke' && kind === 'backup') return syncState();
      syncRecord = {
        ...syncRecord,
        revision: syncRecord.revision + 1,
        pendingBackup: { kind, version: syncRecord.identity.version, binding },
      };
      return syncState();
    }),
    accountAcknowledgeBackup: vi.fn(async ({ expected, checkpoint }) => {
      const cleared = syncRecord.pendingBackup === expected;
      if (cleared) {
        syncRecord = {
          ...syncRecord, revision: syncRecord.revision + 1,
          acknowledgedBackup: checkpoint, pendingBackup: null,
        };
      }
      return { cleared, ...syncState() };
    }),
    accountAdoptCandidate: vi.fn(async ({ expectedMemberId, credential, binding, checkpoint }) => {
      const previous = syncRecord;
      const recovered = typeof credential?.recoveryCode === 'string';
      const adoptedVersion = recovered
        ? version(checkpoint.version.generation + 1, 11)
        : checkpoint.version;
      syncRecord = record(expectedMemberId, {
        revision: (previous?.revision ?? 0) + 1,
        identity: {
          memberId: expectedMemberId,
          version: adoptedVersion,
          floor: adoptedVersion.generation,
          effectiveFloor: adoptedVersion.generation,
        },
        retainedIdentities: previous && previous.identity.memberId !== expectedMemberId
          ? [previous.identity, ...(previous.retainedIdentities ?? [])]
          : (previous?.retainedIdentities ?? []),
        binding,
        acknowledgedBackup: checkpoint,
        pendingBackup: recovered ? { kind: 'revoke', version: adoptedVersion, binding } : null,
      });
      return {
        ...identity(expectedMemberId),
        generation: adoptedVersion.generation,
        blobHash: adoptedVersion.blobHash,
        recoveryCode: recovered ? 'new-recovery' : '',
      };
    }),
    ...overrides,
  };
  return core;
}

function auth(attempts = [{ accessToken: 'token-1', issuer: 'https://issuer', subject: 'provider-sub' }]) {
  let signedIn = true;
  const subscribers = new Set();
  let index = 0;
  return {
    subject: vi.fn(() => (signedIn ? attempts[Math.min(index, attempts.length - 1)].subject : null)),
    registrationAttempt: vi.fn(async () => attempts[Math.min(index++, attempts.length - 1)]),
    onChange(callback) {
      subscribers.add(callback);
      return () => subscribers.delete(callback);
    },
    setSignedIn(next) {
      signedIn = next;
      for (const callback of subscribers) callback();
    },
  };
}

function unregistered() {
  return makeError('unregistered', { httpStatus: 403 });
}

function stateShape(overrides = {}) {
  return {
    auth: 'signedOut',
    account: 'none',
    binding: 'unbound',
    syncDisposition: 'remote',
    pending: new Set(),
    conflict: null,
    retainedIdentities: [],
    storagePersistence: 'granted',
    ...overrides,
  };
}

afterEach(() => vi.useRealTimers());

describe('AccountSession default-deny identity classification', () => {
  const attempt = { issuer: 'https://issuer', subject: 'provider-sub' };
  const binding = { ...attempt, memberId: 'member-local' };
  const unbound = record();
  const bound = record('member-local', { binding });
  const noBackup = (memberId) => ({ memberId, keystore: null });
  const withBackup = (memberId) => ({ memberId, keystore: new Uint8Array([1]) });
  const cases = [
    ['none / unregistered', null, null, { action: 'none' }],
    ['none / bound without backup', null, noBackup('member-remote'), {
      action: 'conflict', reason: 'remote_identity_without_backup',
    }],
    ['none / bound with backup', null, withBackup('member-remote'), {
      action: 'conflict', reason: 'remote_restore_available',
    }],
    ['unbound / unregistered', unbound, null, { action: 'register' }],
    ['unbound / same without backup', unbound, noBackup('member-local'), { action: 'reconcile' }],
    ['unbound / different without backup', unbound, noBackup('member-remote'), {
      action: 'conflict', reason: 'local_remote_identity_mismatch', restoreAvailable: false,
    }],
    ['unbound / same with backup', unbound, withBackup('member-local'), { action: 'reconcile' }],
    ['unbound / different with backup', unbound, withBackup('member-remote'), {
      action: 'conflict', reason: 'local_remote_identity_mismatch', restoreAvailable: true,
    }],
    ['bound / unregistered', bound, null, {
      action: 'conflict', reason: 'registration_preconditions_ambiguous',
    }],
    ['bound / same without backup', bound, noBackup('member-local'), { action: 'reconcile' }],
    ['bound / different without backup', bound, noBackup('member-remote'), {
      action: 'conflict', reason: 'local_remote_identity_mismatch', restoreAvailable: false,
    }],
    ['bound / same with backup', bound, withBackup('member-local'), { action: 'reconcile' }],
    ['bound / different with backup', bound, withBackup('member-remote'), {
      action: 'conflict', reason: 'local_remote_identity_mismatch', restoreAvailable: true,
    }],
  ];

  it.each(cases)('%s', (_name, local, remote, expected) => {
    expect(classifyAccountBindingState({ record: local, attempt, remote })).toEqual(expected);
  });

  it('denies a persisted binding belonging to another provider subject', () => {
    expect(classifyAccountBindingState({
      record: bound,
      attempt: { issuer: attempt.issuer, subject: 'other-subject' },
      remote: withBackup('member-local'),
    })).toEqual({ action: 'conflict', reason: 'local_auth_binding_mismatch' });
  });
});

describe('AccountSession local custody and observable axes', () => {
  it('initializes custody and keeps provider auth independent', async () => {
    const core = backend();
    const session = new AccountSession(core);
    await expect(session.initialize()).resolves.toEqual(stateShape({
      account: 'unlocked', memberId: 'member-local',
    }));

    const provider = auth();
    session.attachSync({ auth: provider, remote: null });
    expect(session.state()).toEqual(stateShape({
      auth: 'signedIn', account: 'unlocked', memberId: 'member-local',
    }));
    provider.setSignedIn(false);
    expect(session.state()).toEqual(stateShape({
      auth: 'signedOut', account: 'unlocked', memberId: 'member-local',
    }));
  });

  it('locks host custody before clearing observable identity', async () => {
    const calls = [];
    const core = backend({ overrides: { accountLock: vi.fn(async () => { calls.push('host'); }) } });
    const session = new AccountSession(core);
    await session.initialize();
    session.onChange(() => calls.push('change'));
    await session.lock();
    expect(calls).toEqual(['host', 'change']);
    expect(session.memberId()).toBeNull();
    expect(session.state()).toEqual(stateShape({ account: 'locked' }));
  });

  it('refreshes local sync metadata after credential operations', async () => {
    const core = backend();
    const session = new AccountSession(core);
    await session.initialize();
    await session.changePassphrase('old', 'new');
    await session.rotateRoot('new');
    expect(core.accountSyncState).toHaveBeenCalledTimes(3);
    expect(core.accountChangePassphrase).toHaveBeenCalledWith({ current: 'old', next: 'new' });
  });

  it('rejects invalid construction and host states', async () => {
    expect(() => new AccountSession(null)).toThrow('needs an app-core account backend');
    const session = new AccountSession(backend({ account: 'mystery' }));
    await expect(session.initialize()).rejects.toThrow('unknown account state');
  });
});

describe('AccountSession registration and backup coordinator', () => {
  it('refreshes and repeats the mandatory probe when its pinned token expired', async () => {
    const attempts = [
      { accessToken: 'expired-token', issuer: 'https://issuer', subject: 'provider-sub' },
      { accessToken: 'fresh-token', issuer: 'https://issuer', subject: 'provider-sub' },
    ];
    const provider = auth(attempts);
    const remote = {
      me: vi.fn(async ({ accessToken }) => {
        if (accessToken === 'expired-token') throw makeError('auth_required', { httpStatus: 401 });
        throw unregistered();
      }),
      register: vi.fn(),
      putKeystore: vi.fn(),
    };
    const session = new AccountSession(backend());
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await expect(session.probe()).resolves.toMatchObject({ status: 'unregistered' });

    expect(provider.registrationAttempt).toHaveBeenNthCalledWith(1, { forceRefresh: false });
    expect(provider.registrationAttempt).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect(remote.me).toHaveBeenCalledTimes(2);
    expect(session.state().auth).toBe('signedIn');
  });

  it('probes first, pins exact claims and token, then persists registration before backup', async () => {
    const core = backend();
    const provider = auth();
    const calls = [];
    let registered = false;
    const remote = {
      me: vi.fn(async ({ accessToken }) => {
        calls.push(`me:${accessToken}`);
        if (!registered) throw unregistered();
        return {
          memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"',
        };
      }),
      register: vi.fn(async (proof, options) => {
        calls.push(`register:${options.accessToken}`);
        registered = true;
        return { memberId: proof.memberId };
      }),
      putKeystore: vi.fn(async (_bytes, generation, options) => {
        calls.push(`backup:${options.accessToken}:${options.etag}`);
        return { generation, etag: '"stored"' };
      }),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await session.enableSync();

    expect(calls).toEqual([
      'me:token-1', 'register:token-1', 'me:token-1', 'me:token-1', 'backup:token-1:"empty"',
    ]);
    expect(core.accountRegisterProof).toHaveBeenCalledWith(expect.objectContaining({
      issuer: 'https://issuer', subject: 'provider-sub',
    }));
    expect(core.accountConfirmBinding.mock.invocationCallOrder[0])
      .toBeLessThan(core.accountStageBackup.mock.invocationCallOrder[0]);
    expect(session.state()).toEqual(stateShape({
      auth: 'signedIn', account: 'unlocked', binding: 'backedUp', memberId: 'member-local',
    }));
  });

  it('re-signs exactly once from bounded explicit server time', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-23T12:00:00Z'));
    const now = Math.floor(Date.now() / 1000);
    const core = backend();
    const provider = auth();
    let registered = false;
    const remote = {
      me: vi.fn(async () => {
        if (!registered) throw unregistered();
        return { memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"' };
      }),
      register: vi.fn(async ({ memberId }) => {
        if (remote.register.mock.calls.length === 1) {
          throw makeError('stale_timestamp', { args: { server_time: now + 120 } });
        }
        registered = true;
        return { memberId };
      }),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await session.register();

    expect(remote.register).toHaveBeenCalledTimes(2);
    expect(core.accountRegisterProof).toHaveBeenNthCalledWith(1, {
      issuer: 'https://issuer', subject: 'provider-sub', timestamp: now,
    });
    expect(core.accountRegisterProof).toHaveBeenNthCalledWith(2, {
      issuer: 'https://issuer', subject: 'provider-sub', timestamp: now + 120,
    });
  });

  it('restarts probe, claims, and proof when the pinned token expires', async () => {
    const attempts = [
      { accessToken: 'expired-token', issuer: 'https://issuer', subject: 'provider-sub' },
      { accessToken: 'fresh-token', issuer: 'https://issuer', subject: 'provider-sub' },
    ];
    const provider = auth(attempts);
    const core = backend();
    let registered = false;
    const remote = {
      me: vi.fn(async () => {
        if (!registered) throw unregistered();
        return { memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"' };
      }),
      register: vi.fn(async ({ memberId }, { accessToken }) => {
        if (accessToken === 'expired-token') throw makeError('auth_required', { httpStatus: 401 });
        registered = true;
        return { memberId };
      }),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await session.register();

    expect(provider.registrationAttempt).toHaveBeenNthCalledWith(1, { forceRefresh: false });
    expect(provider.registrationAttempt).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect(core.accountRegisterProof).toHaveBeenCalledTimes(2);
  });

  it('resumes a partial enableSync from durable binding and pending backup', async () => {
    const core = backend();
    const provider = auth();
    let registered = false;
    let failBackup = true;
    const remote = {
      me: vi.fn(async () => {
        if (!registered) throw unregistered();
        return { memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"' };
      }),
      register: vi.fn(async ({ memberId }) => {
        registered = true;
        return { memberId };
      }),
      putKeystore: vi.fn(async (_bytes, generation) => {
        if (failBackup) throw makeError('unavailable', { httpStatus: 503 });
        return { generation, etag: '"stored"' };
      }),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await expect(session.enableSync()).rejects.toMatchObject({ code: 'unavailable' });
    expect(session.state().binding).toBe('bound');
    expect(session.state().pending).toEqual(new Set(['backup']));
    failBackup = false;
    await session.enableSync();

    expect(remote.register).toHaveBeenCalledTimes(1);
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().binding).toBe('backedUp');
  });

  it('never auto-registers a different remote identity', async () => {
    const core = backend();
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-remote', keystore: new Uint8Array([9]), generation: 2, etag: '"remote"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.enableSync()).rejects.toMatchObject({ code: 'identity_conflict' });
    expect(remote.register).not.toHaveBeenCalled();
    expect(session.state().binding).toBe('unbound');
    expect(session.state().conflict).toMatchObject({
      code: 'identity_conflict', reason: 'local_remote_identity_mismatch',
    });
  });

  it('does not overwrite an unverified remote backup for the same identity', async () => {
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const core = backend({ initialRecord: record('member-local', { binding }) });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore: new Uint8Array([99]), generation: 1, etag: '"other-wrap"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.enableSync()).rejects.toMatchObject({ code: 'account_backup_precondition_failed' });

    expect(remote.putKeystore).not.toHaveBeenCalled();
    expect(session.state().binding).toBe('bound');
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().conflict).toEqual({
      code: 'account_backup_precondition_failed',
      reason: 'remote_backup_requires_verification',
      localGeneration: 1,
      remoteGeneration: 1,
      remoteEtag: '"other-wrap"',
    });
  });

  it('retains pending backup and exposes reconciliation after a stale ETag', async () => {
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const core = backend({ initialRecord: record('member-local', { binding }) });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore: null, generation: 0, etag: '"stale"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(async () => {
        throw makeError('account_backup_precondition_failed', { httpStatus: 412 });
      }),
      getKeystore: vi.fn(async () => ({
        keystore: new Uint8Array([8]), generation: 2, etag: '"current"',
      })),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.backup()).rejects.toMatchObject({ code: 'account_backup_precondition_failed' });

    expect(session.state().pending).toEqual(new Set(['backup']));
    expect(session.state().conflict).toEqual({
      code: 'account_backup_precondition_failed',
      reason: 'backup_reconciliation_required',
      localGeneration: 1,
      remoteGeneration: 2,
      remoteEtag: '"current"',
    });
  });

  it('bounds retries when another context keeps changing the staged account snapshot', async () => {
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const core = backend({
      initialRecord: record('member-local', { binding }),
      overrides: {
        accountSnapshot: vi.fn(async () => ({
          ...identity(), keystore: new Uint8Array([4]), generation: 1, blobHash: new Uint8Array(32).fill(9),
        })),
      },
    });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.backup()).rejects.toMatchObject({ code: 'version_conflict' });

    expect(core.accountStageBackup).toHaveBeenCalledTimes(2);
    expect(remote.putKeystore).not.toHaveBeenCalled();
    expect(session.state().pending).toEqual(new Set(['backup']));
  });

  it('does not acknowledge a backup after the authenticated subject switches', async () => {
    let subject = 'provider-sub';
    const subscribers = new Set();
    const provider = {
      subject: vi.fn(() => subject),
      registrationAttempt: vi.fn(async () => ({
        accessToken: 'token-1', issuer: 'https://issuer', subject: 'provider-sub',
      })),
      onChange(callback) {
        subscribers.add(callback);
        return () => subscribers.delete(callback);
      },
      switchSubject(next) {
        subject = next;
        for (const callback of subscribers) callback();
      },
    };
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const core = backend({ initialRecord: record('member-local', { binding }) });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(async (_bytes, generation) => {
        provider.switchSubject('another-subject');
        return { generation, etag: '"stored"' };
      }),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await expect(session.backup()).rejects.toMatchObject({ code: 'identity_conflict' });

    expect(core.accountAcknowledgeBackup).not.toHaveBeenCalled();
    expect(session.state().pending).toEqual(new Set(['backup']));
    expect(session.state().conflict).toMatchObject({
      code: 'identity_conflict', reason: 'auth_identity_changed_during_operation',
    });
  });

  it('stops after one stale-timestamp re-sign and clears volatile register state', async () => {
    const now = Math.floor(Date.now() / 1000);
    const remote = {
      me: vi.fn(async () => { throw unregistered(); }),
      register: vi.fn(async () => {
        throw makeError('stale_timestamp', { args: { server_time: now + 30 } });
      }),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend());
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.register()).rejects.toMatchObject({ code: 'stale_timestamp' });

    expect(remote.register).toHaveBeenCalledTimes(2);
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().auth).toBe('signedIn');
  });

  it('stops after one expired-token restart and clears volatile register state', async () => {
    const provider = auth();
    const remote = {
      me: vi.fn(async () => { throw unregistered(); }),
      register: vi.fn(async () => { throw makeError('auth_required', { httpStatus: 401 }); }),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend());
    await session.initialize();
    session.attachSync({ auth: provider, remote });

    await expect(session.register()).rejects.toMatchObject({ code: 'auth_required' });

    expect(remote.register).toHaveBeenCalledTimes(2);
    expect(provider.registrationAttempt).toHaveBeenLastCalledWith({ forceRefresh: true });
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().auth).toBe('expired');
  });

  it('retains a newer pending operation when an older successful PUT loses the compare-clear race', async () => {
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const newerVersion = version(2, 9);
    const newerPending = { kind: 'revoke', version: newerVersion, binding };
    const newerRecord = record('member-local', {
      revision: 4,
      identity: {
        memberId: 'member-local', version: newerVersion, floor: 2, effectiveFloor: 2,
      },
      binding,
      pendingBackup: newerPending,
    });
    const core = backend({
      initialRecord: record('member-local', { binding }),
      overrides: {
        accountAcknowledgeBackup: vi.fn(async () => ({
          cleared: false, record: newerRecord, storagePersistence: 'granted',
        })),
      },
    });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(async (_bytes, generation) => ({ generation, etag: '"stored-old"' })),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await session.backup();

    expect(session.state().pending).toEqual(new Set(['revoke']));
    expect(session.state().binding).toBe('bound');
    expect(session.state().conflict).toBeNull();
  });

  it('surfaces a matching persisted binding as ambiguous when the server is unregistered', async () => {
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const remote = {
      me: vi.fn(async () => { throw unregistered(); }),
      register: vi.fn(),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend({ initialRecord: record('member-local', { binding }) }));
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.enableSync()).rejects.toMatchObject({ code: 'identity_conflict' });

    expect(remote.register).not.toHaveBeenCalled();
    expect(session.state().conflict).toMatchObject({
      code: 'identity_conflict', reason: 'registration_preconditions_ambiguous',
    });
  });

  it('recognizes an exact remote backup as the local identity backup', async () => {
    const keystore = new Uint8Array([4, 5]);
    const blobHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keystore));
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const local = record('member-local', {
      identity: {
        memberId: 'member-local', version: { generation: 1, blobHash }, floor: 1, effectiveFloor: 1,
      },
      binding,
    });
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local', keystore, generation: 1, etag: '"stored"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend({ initialRecord: local }));
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await session.probe();

    expect(session.state().binding).toBe('backedUp');
    expect(session.state().conflict).toBeNull();
    expect(remote.putKeystore).not.toHaveBeenCalled();
  });

  it('resumes a durable backup after the server stored a response the client never received', async () => {
    const keystore = new Uint8Array([4, 5]);
    const blobHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keystore));
    const binding = { issuer: 'https://issuer', subject: 'provider-sub', memberId: 'member-local' };
    const local = record('member-local', {
      identity: {
        memberId: 'member-local', version: { generation: 1, blobHash }, floor: 1, effectiveFloor: 1,
      },
      binding,
    });
    let stored = null;
    let loseResponse = true;
    const remote = {
      me: vi.fn(async () => ({
        memberId: 'member-local',
        keystore: stored?.keystore ?? null,
        generation: stored?.generation ?? 0,
        etag: stored?.etag ?? '"empty"',
      })),
      register: vi.fn(),
      putKeystore: vi.fn(async (bytes, generation) => {
        stored = { keystore: bytes.slice(), generation, etag: '"stored"' };
        if (loseResponse) {
          loseResponse = false;
          throw makeError('request_failed');
        }
        return { generation, etag: stored.etag };
      }),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend({ initialRecord: local }));
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.backup()).rejects.toMatchObject({ code: 'request_failed' });
    expect(session.state().pending).toEqual(new Set(['backup']));

    await session.enableSync();

    expect(remote.putKeystore).toHaveBeenCalledTimes(2);
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().binding).toBe('backedUp');
  });

  it('coalesces simultaneous enableSync callers into one register-and-backup operation', async () => {
    let registered = false;
    const remote = {
      me: vi.fn(async () => {
        if (!registered) throw unregistered();
        return { memberId: 'member-local', keystore: null, generation: 0, etag: '"empty"' };
      }),
      register: vi.fn(async ({ memberId }) => {
        registered = true;
        return { memberId };
      }),
      putKeystore: vi.fn(async (_bytes, generation) => ({ generation, etag: '"stored"' })),
      getKeystore: vi.fn(),
    };
    const session = new AccountSession(backend());
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    const first = session.enableSync();
    const second = session.enableSync();
    expect(second).toBe(first);
    await Promise.all([first, second]);

    expect(remote.register).toHaveBeenCalledTimes(1);
    expect(remote.putKeystore).toHaveBeenCalledTimes(1);
    expect(session.state().binding).toBe('backedUp');
  });
});

describe('AccountSession remote restore and conflict decisions', () => {
  const remoteBackup = (overrides = {}) => ({
    memberId: 'member-remote',
    keystore: new Uint8Array([8, 8]),
    generation: 1,
    etag: '"remote-v1"',
    ...overrides,
  });

  it('restores a bound backup into an empty profile without rotating it', async () => {
    const core = backend({ account: 'none', initialRecord: null });
    const remote = {
      me: vi.fn(async () => remoteBackup()),
      register: vi.fn(),
      putKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.restore({ passphrase: 'remote passphrase' })).resolves.toEqual({
      memberId: 'member-remote',
    });

    expect(core.accountAdoptCandidate).toHaveBeenCalledWith(expect.objectContaining({
      expectedMemberId: 'member-remote',
      credential: { passphrase: 'remote passphrase' },
    }));
    expect(remote.putKeystore).not.toHaveBeenCalled();
    expect(session.state()).toMatchObject({
      account: 'unlocked', memberId: 'member-remote', binding: 'backedUp', conflict: null,
    });
  });

  it('preserves credential-verification errors without mutating empty custody', async () => {
    const core = backend({
      account: 'none',
      initialRecord: null,
      overrides: {
        accountAdoptCandidate: vi.fn(async () => { throw makeError('wrong_passphrase'); }),
      },
    });
    const remote = {
      me: vi.fn(async () => remoteBackup()),
      register: vi.fn(),
      putKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.restore({ passphrase: 'wrong' }))
      .rejects.toMatchObject({ code: 'wrong_passphrase' });
    expect(session.state().account).toBe('none');
    expect(session.memberId()).toBeNull();
    expect(remote.putKeystore).not.toHaveBeenCalled();
  });

  it('requires explicit adoption and retains displaced local custody', async () => {
    const core = backend();
    const remote = {
      me: vi.fn(async () => remoteBackup()),
      register: vi.fn(),
      putKeystore: vi.fn(),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });

    await expect(session.restore({ passphrase: 'remote passphrase' }))
      .rejects.toMatchObject({ code: 'identity_conflict' });
    expect(core.accountAdoptCandidate).not.toHaveBeenCalled();

    await session.adoptRemoteIdentity({ passphrase: 'remote passphrase' });

    expect(session.memberId()).toBe('member-remote');
    expect(session.state().retainedIdentities).toEqual([
      { memberId: 'member-local', generation: 1, floor: 1 },
    ]);
  });

  it('resumes a pending recovery rotation without rotating the remote blob twice', async () => {
    const core = backend({ account: 'none', initialRecord: null });
    let uploadAttempts = 0;
    const remoteState = remoteBackup();
    const remote = {
      me: vi.fn(async () => ({ ...remoteState })),
      register: vi.fn(),
      putKeystore: vi.fn(async (keystore, generation) => {
        uploadAttempts += 1;
        if (uploadAttempts === 1) throw makeError('request_failed');
        remoteState.keystore = keystore;
        remoteState.generation = generation;
        remoteState.etag = '"remote-v2"';
        return { generation, etag: remoteState.etag };
      }),
    };
    const session = new AccountSession(core);
    await session.initialize();
    session.attachSync({ auth: auth(), remote });
    const credential = { recoveryCode: 'old-recovery', newPassphrase: 'replacement passphrase' };

    await expect(session.restore(credential)).resolves.toEqual({
      memberId: 'member-remote',
      recoveryCode: 'new-recovery',
      pending: true,
      uploadError: 'request_failed',
    });
    expect(session.state().pending).toEqual(new Set(['revoke']));

    await expect(session.restore(credential)).resolves.toEqual({
      memberId: 'member-remote', pending: false, resumed: true,
    });
    expect(core.accountAdoptCandidate).toHaveBeenCalledTimes(1);
    expect(remote.putKeystore).toHaveBeenCalledTimes(2);
    expect(session.state().pending).toEqual(new Set());
    expect(session.state().binding).toBe('backedUp');
  });

  it('scopes keepLocalOffline to the current authenticated subject', async () => {
    const provider = auth([
      { accessToken: 'token-1', issuer: 'https://issuer', subject: 'provider-sub' },
    ]);
    const remote = {
      me: vi.fn(async () => remoteBackup()),
      register: vi.fn(),
      putKeystore: vi.fn(),
    };
    const session = new AccountSession(backend());
    await session.initialize();
    session.attachSync({ auth: provider, remote });
    await session.probe();

    await session.keepLocalOffline();
    expect(session.state()).toMatchObject({ syncDisposition: 'localOnly', conflict: null });

    provider.setSignedIn(false);
    expect(session.state().syncDisposition).toBe('remote');
  });
});
