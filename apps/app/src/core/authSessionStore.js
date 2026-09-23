// Browser persistence and cross-tab serialization for provider refresh-token custody.
//
// The stored record contains the rotating refresh token and continuity hints, never an access token.
// Broadcast messages contain only a revision; peers reread storage under the same project-scoped lock.
const RECORD_VERSION = 1;
const STORAGE_PREFIX = 'openom.auth.session.v1.';
const LOCK_PREFIX = 'openom.auth.session.';

/** @typedef {{ readonly state: 'active', readonly refreshToken: string, readonly issuer: string, readonly subject: string }} ActiveAuthState */
/** @typedef {{ readonly state: 'signed_out'|'expired' }} InactiveAuthState */
/** @typedef {ActiveAuthState|InactiveAuthState} AuthRecordState */
/** @typedef {{ readonly version: 1, readonly revision: number } & AuthRecordState} AuthSessionRecord */
/** @typedef {{ getItem(key: string): string|null, setItem(key: string, value: string): void }} StorageLike */
/** @typedef {{ request: <Result>(name: string, options: { mode: 'exclusive' }, operation: () => Result|PromiseLike<Result>) => Promise<Result> }} LockManagerLike */
/** @typedef {new(name: string) => BroadcastChannel} BroadcastChannelFactory */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** @param {unknown} value @returns {AuthSessionRecord|null} */
export function decodeAuthSessionRecord(value) {
  if (!isRecord(value)
    || value.version !== RECORD_VERSION
    || typeof value.revision !== 'number'
    || !Number.isSafeInteger(value.revision)
    || value.revision <= 0) return null;

  if (value.state === 'active'
    && typeof value.refreshToken === 'string' && value.refreshToken.length > 0
    && typeof value.issuer === 'string' && value.issuer.length > 0
    && typeof value.subject === 'string' && value.subject.length > 0) {
    return {
      version: RECORD_VERSION,
      revision: value.revision,
      state: 'active',
      refreshToken: value.refreshToken,
      issuer: value.issuer,
      subject: value.subject,
    };
  }
  if (value.state === 'signed_out' || value.state === 'expired') {
    return { version: RECORD_VERSION, revision: value.revision, state: value.state };
  }
  return null;
}

/** @param {AuthSessionRecord|null} stored @param {AuthSessionRecord|null} fallback */
function newest(stored, fallback) {
  // A persisted peer tombstone must beat a higher volatile revision from a storage-denied tab; otherwise
  // that tab could resurrect a session after another tab signed out. A fallback is used only when storage
  // has no valid record at all.
  return stored ?? fallback;
}

function browserStorage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export class AuthSessionTransaction {
  /** @type {StorageLike|null} */ #storage;
  /** @type {string} */ #key;
  /** @type {AuthSessionRecord|null} */ #record;
  /** @type {(revision: number) => void} */ #onCommit;
  #committed = false;

  /**
   * @param {StorageLike|null} storage
   * @param {string} key
   * @param {AuthSessionRecord|null} record
   * @param {(revision: number) => void} onCommit
   */
  constructor(storage, key, record, onCommit) {
    this.#storage = storage;
    this.#key = key;
    this.#record = record;
    this.#onCommit = onCommit;
  }

  record() {
    return this.#record;
  }

  /** @param {AuthRecordState} state @returns {{ record: AuthSessionRecord, persisted: boolean }} */
  commit(state) {
    if (this.#committed) throw new Error('auth session transaction already committed');
    if (!isRecord(state)
      || (state.state !== 'signed_out' && state.state !== 'expired' && state.state !== 'active')) {
      throw new Error('invalid auth session state');
    }
    const revision = (this.#record?.revision ?? 0) + 1;
    if (!Number.isSafeInteger(revision)) throw new Error('auth session revision exhausted');
    const record = decodeAuthSessionRecord({ version: RECORD_VERSION, revision, ...state });
    if (!record) throw new Error('invalid auth session state');
    this.#record = record;
    this.#committed = true;

    if (!this.#storage) return { record, persisted: false };
    try {
      const encoded = JSON.stringify(record);
      this.#storage.setItem(this.#key, encoded);
      const readBack = this.#storage.getItem(this.#key);
      if (readBack !== encoded) return { record, persisted: false };
      const verified = decodeAuthSessionRecord(JSON.parse(readBack));
      if (!verified || verified.revision !== revision) return { record, persisted: false };
      this.#onCommit(revision);
      return { record: verified, persisted: true };
    } catch {
      return { record, persisted: false };
    }
  }
}

export class AuthSessionCoordinator {
  /** @type {StorageLike|null} */ #storage;
  /** @type {string} */ #key;
  /** @type {string} */ #lockName;
  /** @type {LockManagerLike|null} */ #locks;
  /** @type {BroadcastChannel|null} */ #channel = null;
  /** @type {Set<(revision: number) => void>} */ #revisionSubscribers = new Set();
  /** @type {Promise<void>} */ #tail = Promise.resolve();

  /**
   * @param {string} scope
   * @param {{ storage?: StorageLike|null, locks?: LockManagerLike|null, broadcastFactory?: BroadcastChannelFactory|null }} [options]
   */
  constructor(scope, {
    storage = browserStorage(),
    locks = globalThis.navigator?.locks ?? null,
    broadcastFactory = globalThis.BroadcastChannel ?? null,
  } = {}) {
    if (typeof scope !== 'string' || scope.length === 0) {
      throw new Error('AuthSessionCoordinator requires a project scope');
    }
    this.#storage = storage;
    this.#key = `${STORAGE_PREFIX}${encodeURIComponent(scope)}`;
    this.#lockName = `${LOCK_PREFIX}${scope}`;
    this.#locks = locks;
    if (broadcastFactory) {
      try {
        this.#channel = new broadcastFactory(`${this.#lockName}.changes`);
        this.#channel.addEventListener('message', (event) => this.#receiveRevision(event.data));
      } catch {
        this.#channel = null;
      }
    }
  }

  read() {
    if (!this.#storage) return null;
    try {
      const encoded = this.#storage.getItem(this.#key);
      return encoded ? decodeAuthSessionRecord(JSON.parse(encoded)) : null;
    } catch {
      return null;
    }
  }

  /**
   * @template Result
   * @param {AuthSessionRecord|null} fallback
   * @param {(transaction: AuthSessionTransaction) => Result|PromiseLike<Result>} operation
   * @returns {Promise<Awaited<Result>>}
   */
  runExclusive(fallback, operation) {
    if (typeof operation !== 'function') throw new Error('auth session operation must be a function');
    const run = () => this.#withCrossContextLock(() => operation(new AuthSessionTransaction(
      this.#storage,
      this.#key,
      newest(this.read(), fallback),
      (revision) => this.#publishRevision(revision),
    )));
    const result = this.#tail.then(run, run);
    this.#tail = result.then(() => undefined, () => undefined);
    return /** @type {Promise<Awaited<Result>>} */ (result);
  }

  /** @param {(revision: number) => void} callback */
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

  /** @template Result @param {() => Result|PromiseLike<Result>} operation @returns {Promise<Result>} */
  #withCrossContextLock(operation) {
    if (typeof this.#locks?.request === 'function') {
      return this.#locks.request(this.#lockName, { mode: 'exclusive' }, operation);
    }
    return Promise.resolve(operation());
  }

  /** @param {number} revision */
  #publishRevision(revision) {
    try {
      this.#channel?.postMessage({ revision });
    } catch {
      // Storage remains authoritative; a later operation still rereads it under the project lock.
    }
  }

  /** @param {unknown} message */
  #receiveRevision(message) {
    const revision = isRecord(message) ? message.revision : null;
    if (typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision <= 0) return;
    for (const callback of this.#revisionSubscribers) {
      try {
        callback(revision);
      } catch {
        // One subscriber cannot block invalidation for the remaining contexts.
      }
    }
  }
}
