import { afterEach, describe, expect, it } from 'vitest';
import { invokeNative } from '../app/src/core/nativeHost.js';

const previousTauri = Reflect.get(globalThis, '__TAURI__');

function respondWith(value) {
  Reflect.set(globalThis, '__TAURI__', {
    core: { invoke: async () => value },
  });
}

afterEach(() => {
  if (previousTauri === undefined) Reflect.deleteProperty(globalThis, '__TAURI__');
  else Reflect.set(globalThis, '__TAURI__', previousTauri);
});

describe('native host boundary', () => {
  it('narrows account identity bytes into the shared runtime shape', async () => {
    respondWith({
      memberId: 'member-1',
      authorPublicKey: [1, 2, 3],
      hpkePublicKey: [4, 5, 6],
    });

    const identity = await invokeNative('account_unlock', { passphrase: 'passphrase' });

    expect(identity.memberId).toBe('member-1');
    expect(identity.authorPublicKey).toEqual(new Uint8Array([1, 2, 3]));
    expect(identity.hpkePublicKey).toEqual(new Uint8Array([4, 5, 6]));
  });

  it('rejects malformed host output before it reaches orchestration', async () => {
    respondWith({ recoveryCode: 'code', generation: Number.POSITIVE_INFINITY });

    await expect(invokeNative('account_create', { passphrase: 'passphrase' }))
      .rejects.toThrow('native host returned malformed account generation');
  });

  it('normalizes native sync coverage into the worker transport contract', async () => {
    respondWith({
      uploads: [{ key: 'doc/snapshot', bytes: [7, 8], pointer: true }],
      folded: 2,
      covered: { aabb: 3 },
    });

    const result = await invokeNative('core_sync', {
      doc: 'doc', remote: [], present: [], compactK: 8,
    });

    expect(result.uploads[0].bytes).toEqual(new Uint8Array([7, 8]));
    expect(result.covered).toBe('{"aabb":3}');
  });

  it('rejects malformed byte arrays instead of truncating them', async () => {
    respondWith([256]);

    await expect(invokeNative('account_register_proof', {
      issuer: 'issuer', subject: 'subject', timestamp: 1,
    })).rejects.toThrow('native host returned malformed registration proof');
  });

  it('narrows DAG reconciliation outcomes and rejects unknown variants', async () => {
    respondWith('localAhead');
    await expect(invokeNative('core_sync_dag_anchor', {
      doc: 'doc', treeId: [1], anchor: [2],
    })).resolves.toBe('localAhead');

    respondWith('serverWins');
    await expect(invokeNative('core_sync_dag_anchor', {
      doc: 'doc', treeId: [1], anchor: [2],
    })).rejects.toThrow('native host returned malformed DAG keyring sync outcome');
  });
});
