import {
  decodeAccountRecord,
  encodeAccountRecord,
  validateAccountRecord,
} from './accountRecord.js';

const ACCOUNT_KEY_PREFIX = 'profile::account::';
const ACCOUNT_LOCK_PREFIX = 'openom.account.record.';

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

class AccountRecordTransaction {
  #store;
  #key;
  #snapshot;
  #record;
  #committed = false;
  #onCommit;

  constructor(store, key, snapshot, record, onCommit) {
    this.#store = store;
    this.#key = key;
    this.#snapshot = snapshot;
    this.#record = record;
    this.#onCommit = onCommit;
  }

  record() {
    return this.#record;
  }

  async commit(next) {
    if (this.#committed) throw new Error('account record transaction already committed');
    await validateAccountRecord(next);
    const expectedRevision = this.#record?.revision ?? 0;
    if (next.revision !== expectedRevision + 1) {
      throw new Error('account record revision is not the next revision');
    }

    const encoded = await encodeAccountRecord(next);
    const storageVersion = await this.#store.putSnapshot(
      this.#key,
      encoded,
      this.#snapshot?.version ?? null,
    );
    const saved = await this.#store.readSnapshot(this.#key);
    if (!saved || saved.version !== storageVersion || !sameBytes(saved.bytes, encoded)) {
      throw new Error('account persistence verification failed');
    }

    const verified = await decodeAccountRecord(saved.bytes);
    if (verified.revision !== next.revision) {
      throw new Error('account persistence revision verification failed');
    }
    this.#committed = true;
    this.#snapshot = saved;
    this.#record = verified;
    this.#onCommit(verified.revision);
    return verified;
  }
}

/**
 * Serializes the complete browser account-record protocol. The portable record revision is checked inside
 * the encoded value; the snapshot version remains an opaque storage-only CAS token.
 */
export class AccountRecordCoordinator {
  #store;
  #key;
  #lockName;
  #locks;
  #storageManager;
  #channel;
  #revisionSubscribers = new Set();
  #tail = Promise.resolve();

  constructor(store, {
    profile = 'default',
    locks = globalThis.navigator?.locks ?? null,
    storageManager = globalThis.navigator?.storage ?? null,
    broadcastFactory = null,
  } = {}) {
    if (!store?.readSnapshot || !store?.putSnapshot) {
      throw new Error('AccountRecordCoordinator needs a conditional snapshot store');
    }
    this.#store = store;
    this.#key = `${ACCOUNT_KEY_PREFIX}${profile}`;
    this.#lockName = `${ACCOUNT_LOCK_PREFIX}${profile}`;
    this.#locks = locks;
    this.#storageManager = storageManager;
    if (broadcastFactory) {
      try {
        this.#channel = new broadcastFactory(`${ACCOUNT_LOCK_PREFIX}${profile}.changes`);
        this.#channel.addEventListener('message', (event) => this.#receiveRevision(event.data));
      } catch {
        this.#channel = null;
      }
    }
  }

  async read() {
    const snapshot = await this.#store.readSnapshot(this.#key);
    return snapshot ? decodeAccountRecord(snapshot.bytes) : null;
  }

  runExclusive(operation) {
    if (typeof operation !== 'function') throw new Error('account record operation must be a function');
    const run = () => this.#withCrossContextLock(async () => {
      const snapshot = await this.#store.readSnapshot(this.#key);
      const record = snapshot ? await decodeAccountRecord(snapshot.bytes) : null;
      return operation(new AccountRecordTransaction(
        this.#store,
        this.#key,
        snapshot,
        record,
        (revision) => this.#publishRevision(revision),
      ));
    });
    const result = this.#tail.then(run, run);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async requestPersistentStorage() {
    if (typeof this.#storageManager?.persist !== 'function') return 'unavailable';
    try {
      return await this.#storageManager.persist() ? 'granted' : 'denied';
    } catch {
      return 'denied';
    }
  }

  async persistentStorageStatus() {
    if (typeof this.#storageManager?.persisted !== 'function') return 'unavailable';
    try {
      return await this.#storageManager.persisted() ? 'granted' : 'denied';
    } catch {
      return 'denied';
    }
  }

  onRevision(callback) {
    if (typeof callback !== 'function') throw new Error('revision subscriber must be a function');
    this.#revisionSubscribers.add(callback);
    return () => this.#revisionSubscribers.delete(callback);
  }

  close() {
    this.#revisionSubscribers.clear();
    this.#channel?.close();
    this.#channel = null;
  }

  #withCrossContextLock(operation) {
    if (typeof this.#locks?.request === 'function') {
      return this.#locks.request(this.#lockName, { mode: 'exclusive' }, operation);
    }
    return operation();
  }

  #publishRevision(revision) {
    try {
      this.#channel?.postMessage({ revision });
    } catch {
      // IndexedDB is authoritative; a later operation still refreshes under the profile lock.
    }
  }

  #receiveRevision(message) {
    const revision = message?.revision;
    if (!Number.isSafeInteger(revision) || revision <= 0) return;
    for (const callback of this.#revisionSubscribers) {
      try {
        callback(revision);
      } catch {
        // A subscriber cannot break invalidation for the remaining contexts.
      }
    }
  }
}
