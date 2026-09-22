import { describe, expect, it, vi } from 'vitest';
import { createAccountRecord, replaceAccountIdentity } from '../app/src/core/accountRecord.js';
import { AccountRecordCoordinator } from '../app/src/core/accountRecordStore.js';

async function snapshot(keystore = new Uint8Array([1, 2, 3])) {
  return {
    memberId: 'member-a',
    keystore,
    generation: 3,
    blobHash: new Uint8Array(await crypto.subtle.digest('SHA-256', keystore)),
  };
}

async function record(revision = 1) {
  let current = await createAccountRecord(await snapshot());
  while (current.revision < revision) {
    current = await replaceAccountIdentity(current, await snapshot(new Uint8Array([1, 2, 3, current.revision])));
  }
  return current;
}

class MemorySnapshots {
  row = null;
  writes = 0;

  async readSnapshot() {
    return this.row && { bytes: new Uint8Array(this.row.bytes), version: this.row.version };
  }

  async putSnapshot(_key, bytes, expected) {
    const found = this.row?.version ?? null;
    if (expected !== found) throw new Error(`conflict: expected ${expected}, found ${found}`);
    this.writes += 1;
    const version = `opaque-${this.writes}`;
    this.row = { bytes: new Uint8Array(bytes), version };
    return version;
  }
}

describe('AccountRecordCoordinator', () => {
  it('serializes local operations and commits through the profile Web Lock', async () => {
    const store = new MemorySnapshots();
    const calls = [];
    const locks = {
      request: vi.fn(async (name, options, operation) => {
        calls.push([name, options]);
        return operation();
      }),
    };
    const coordinator = new AccountRecordCoordinator(store, { profile: 'p1', locks });
    let release;
    const gate = new Promise((resolve) => { release = resolve; });

    const first = coordinator.runExclusive(async (tx) => {
      calls.push('first-start');
      await gate;
      await tx.commit(await record());
      calls.push('first-end');
    });
    const second = coordinator.runExclusive(async (tx) => {
      calls.push('second-start');
      expect(tx.record().revision).toBe(1);
    });
    await Promise.resolve();
    expect(calls).not.toContain('second-start');
    release();
    await Promise.all([first, second]);

    expect(calls.indexOf('first-end')).toBeLessThan(calls.indexOf('second-start'));
    expect(locks.request).toHaveBeenCalledTimes(2);
    expect(calls[0]).toEqual(['openom.account.record.p1', { mode: 'exclusive' }]);
  });

  it('keeps the storage CAS token opaque and rejects a stale writer', async () => {
    const store = new MemorySnapshots();
    const coordinator = new AccountRecordCoordinator(store, { locks: null });
    await coordinator.runExclusive(async (tx) => tx.commit(await record()));

    await expect(coordinator.runExclusive(async (tx) => {
      store.row.version = 'won-by-another-context';
      await tx.commit(await record(2));
    })).rejects.toThrow('conflict');
    expect((await coordinator.read()).revision).toBe(1);
  });

  it('rejects skipped revisions before writing', async () => {
    const store = new MemorySnapshots();
    const coordinator = new AccountRecordCoordinator(store, { locks: null });

    await expect(coordinator.runExclusive(async (tx) => tx.commit(await record(2))))
      .rejects.toThrow('not the next revision');
    expect(store.writes).toBe(0);
  });

  it('requires an exact read-back before reporting a commit', async () => {
    const store = new MemorySnapshots();
    const originalRead = store.readSnapshot.bind(store);
    let corruptReadBack = false;
    store.readSnapshot = async () => {
      const saved = await originalRead();
      if (!saved || !corruptReadBack) return saved;
      const bytes = new Uint8Array(saved.bytes);
      bytes[0] ^= 1;
      return { ...saved, bytes };
    };
    const coordinator = new AccountRecordCoordinator(store, { locks: null });

    await expect(coordinator.runExclusive(async (tx) => {
      corruptReadBack = true;
      await tx.commit(await record());
    })).rejects.toThrow('persistence verification failed');
  });

  it('reports persistent-storage support without making denial fatal', async () => {
    const store = new MemorySnapshots();
    const granted = new AccountRecordCoordinator(store, {
      storageManager: { persist: vi.fn(async () => true) },
    });
    const denied = new AccountRecordCoordinator(store, {
      storageManager: { persist: vi.fn(async () => false) },
    });
    const unavailable = new AccountRecordCoordinator(store, { storageManager: null });

    await expect(granted.requestPersistentStorage()).resolves.toBe('granted');
    await expect(denied.requestPersistentStorage()).resolves.toBe('denied');
    await expect(unavailable.requestPersistentStorage()).resolves.toBe('unavailable');
  });
});
