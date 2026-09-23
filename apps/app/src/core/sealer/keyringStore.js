// Where a tree's keyring lives on the device. The keyring is not secret (only wrapped material + a
// signature), so plain durable storage is fine; it is the source of truth for unlocking AND — since the
// launch gate (§B3) — for verifying a landed entry against the keyring revision that governed it. So the
// store RETAINS EVERY revision (not just the head): a peer's delta stamped at an older revision is verified
// against the keyring AT that revision, which the client walked + trusts.
//
// Interface (async):
//   saveHead(treeKey, engine, bytes)    // the current UNLOCK anchor + its engine tag (both engines; OPE-278)
//   loadHead(treeKey) -> {engine,bytes}|null
//   load(treeKey) -> bytes|null         // the head record's anchor — a convenience over loadHead()
//   save(treeKey, revision, bytes)      // CHAIN retention: persist one verified revision (§B3)
//   at(treeKey, revision) -> bytes|null // a specific retained revision (the governing keyring, chain-only)
//   head(treeKey) -> {revision, bytes}|null   // the highest retained revision (chain-only)
//
// The head record is the engine-neutral unlock anchor (the dag has no revisions — its anchor is one blob).
// The per-revision retention is CHAIN-ONLY: the §B3 verify composer reads `at(revision)` for the keyring
// that governed a landed entry. Kept in its own IndexedDB database so it never entangles with the
// snapshot/update store's versioning.

/** @typedef {import('../types/domain.js').DocId} DocId */
/** @typedef {import('../types/domain.js').KeyringBytes} KeyringBytes */
/** @typedef {import('../types/domain.js').KeyringEngine} KeyringEngine */
/** @typedef {import('../types/domain.js').KeyringRevision} KeyringRevision */
/** @typedef {{ engine: KeyringEngine, bytes: KeyringBytes }} KeyringHead */
/** @typedef {{ revision: KeyringRevision, bytes: KeyringBytes }} RetainedKeyring */
/** @typedef {{
 * saveHead: (treeKey: DocId, engine: KeyringEngine, bytes: KeyringBytes) => Promise<void>,
 * loadHead: (treeKey: DocId) => Promise<KeyringHead|null>,
 * load: (treeKey: DocId) => Promise<KeyringBytes|null>,
 * save: (treeKey: DocId, revision: KeyringRevision, bytes: KeyringBytes) => Promise<void>,
 * at: (treeKey: DocId, revision: KeyringRevision) => Promise<KeyringBytes|null>,
 * head: (treeKey: DocId) => Promise<RetainedKeyring|null>,
 * }} KeyringStore */

const DB = 'openom-keyrings';
const STORE = 'keyrings';
/** @param {DocId} treeKey */
const HEAD = (treeKey) => `${treeKey}::head`; // pointer record: the max retained revision (chain retention)
/** @param {DocId} treeKey */
const HEADREC = (treeKey) => `${treeKey}::headrec`; // the current head record: { engine, bytes }
/** @param {DocId} treeKey @param {KeyringRevision} revision */
const REV = (treeKey, revision) => `${treeKey}::r${revision}`;

/** @returns {Promise<IDBDatabase>} */
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** @param {IDBDatabase} db @param {IDBTransactionMode} mode @returns {IDBObjectStore} */
function tx(db, mode) {
  return db.transaction(STORE, mode).objectStore(STORE);
}

/** @template Value @param {IDBObjectStore} store @param {IDBValidKey} key @returns {Promise<Value|undefined>} */
function get(store, key) {
  return new Promise((res, rej) => {
    const r = store.get(key);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
/** @param {IDBObjectStore} store @param {unknown} value @param {IDBValidKey} key @returns {Promise<void>} */
function put(store, value, key) {
  return new Promise((res, rej) => {
    const r = store.put(value, key);
    r.onsuccess = () => res();
    r.onerror = () => rej(r.error);
  });
}

/** The durable browser keyring store (IndexedDB), retaining every revision. */
export function indexedDbKeyringStore() {
  /** @type {Promise<IDBDatabase>|null} */
  let dbPromise = null;
  const db = () => (dbPromise ??= openDb());
  return {
    /** @param {DocId} treeKey @param {KeyringEngine} engine @param {KeyringBytes} bytes */
    async saveHead(treeKey, engine, bytes) {
      await put(tx(await db(), 'readwrite'), { engine, bytes: Array.from(bytes) }, HEADREC(treeKey));
    },
    /** @param {DocId} treeKey @returns {Promise<KeyringHead|null>} */
    async loadHead(treeKey) {
      const rec = await get(/** @type {IDBObjectStore} */ (tx(await db(), 'readonly')), HEADREC(treeKey));
      if (rec == null) return null;
      if (typeof rec !== 'object' || rec === null) throw new TypeError('invalid keyring head record');
      const value = /** @type {Record<string, unknown>} */ (rec);
      if ((value.engine !== 'chain' && value.engine !== 'dag') || !isByteArray(value.bytes)) {
        throw new TypeError('invalid keyring head record');
      }
      return { engine: value.engine, bytes: /** @type {KeyringBytes} */ (new Uint8Array(value.bytes)) };
    },
    /** @param {DocId} treeKey @returns {Promise<KeyringBytes|null>} */
    async load(treeKey) {
      return (await this.loadHead(treeKey))?.bytes ?? null;
    },
    /** @param {DocId} treeKey @param {KeyringRevision} revision @param {KeyringBytes} bytes */
    async save(treeKey, revision, bytes) {
      const store = tx(await db(), 'readwrite');
      await put(store, Array.from(bytes), REV(treeKey, revision));
      const curHead = await get(/** @type {IDBObjectStore} */ (store), HEAD(treeKey));
      if (curHead != null && (typeof curHead !== 'number' || !Number.isSafeInteger(curHead) || curHead < 0)) {
        throw new TypeError('invalid keyring revision pointer');
      }
      if (curHead == null || revision > curHead) await put(store, revision, HEAD(treeKey));
    },
    /** @param {DocId} treeKey @param {KeyringRevision} revision @returns {Promise<KeyringBytes|null>} */
    async at(treeKey, revision) {
      const row = await get(tx(await db(), 'readonly'), REV(treeKey, revision));
      if (row == null) return null;
      if (!isByteArray(row)) throw new TypeError('invalid retained keyring bytes');
      return /** @type {KeyringBytes} */ (new Uint8Array(row));
    },
    /** @param {DocId} treeKey @returns {Promise<RetainedKeyring|null>} */
    async head(treeKey) {
      const store = tx(await db(), 'readonly');
      const rev = await get(store, HEAD(treeKey));
      if (rev == null) return null;
      if (typeof rev !== 'number' || !Number.isSafeInteger(rev) || rev < 0) throw new TypeError('invalid keyring revision pointer');
      const revision = /** @type {KeyringRevision} */ (rev);
      const row = await get(store, REV(treeKey, revision));
      if (row == null) return null;
      if (!isByteArray(row)) throw new TypeError('invalid retained keyring bytes');
      return { revision, bytes: /** @type {KeyringBytes} */ (new Uint8Array(row)) };
    },
  };
}

/** In-memory keyring store (tests, or environments without IndexedDB), retaining every revision. */
export function memoryKeyringStore() {
  /** @type {Map<DocId, Map<KeyringRevision, KeyringBytes>>} */
  const trees = new Map(); // treeKey -> Map(revision -> bytes)   (chain retention)
  /** @type {Map<DocId, KeyringHead>} */
  const heads = new Map(); // treeKey -> { engine, bytes }        (the unlock head record)
  /** @param {DocId} k */
  const forTree = (k) => {
    let t = trees.get(k);
    if (!t) trees.set(k, (t = new Map()));
    return t;
  };
  /** @param {DocId} treeKey @returns {RetainedKeyring|null} */
  const headOf = (treeKey) => {
    const t = trees.get(treeKey);
    if (!t || t.size === 0) return null;
    let max = -1;
    for (const r of t.keys()) if (r > max) max = r;
    const revision = /** @type {KeyringRevision} */ (max);
    const bytes = t.get(revision);
    return bytes ? { revision, bytes } : null;
  };
  return {
    /** @param {DocId} treeKey @param {KeyringEngine} engine @param {KeyringBytes} bytes */
    async saveHead(treeKey, engine, bytes) {
      heads.set(treeKey, { engine, bytes });
    },
    /** @param {DocId} treeKey @returns {Promise<KeyringHead|null>} */
    async loadHead(treeKey) {
      return heads.get(treeKey) ?? null;
    },
    /** @param {DocId} treeKey @returns {Promise<KeyringBytes|null>} */
    async load(treeKey) {
      return heads.get(treeKey)?.bytes ?? null;
    },
    /** @param {DocId} treeKey @param {KeyringRevision} revision @param {KeyringBytes} bytes */
    async save(treeKey, revision, bytes) {
      forTree(treeKey).set(revision, bytes);
    },
    /** @param {DocId} treeKey @param {KeyringRevision} revision @returns {Promise<KeyringBytes|null>} */
    async at(treeKey, revision) {
      return trees.get(treeKey)?.get(revision) ?? null;
    },
    /** @param {DocId} treeKey @returns {Promise<RetainedKeyring|null>} */
    async head(treeKey) {
      return headOf(treeKey);
    },
  };
}

/** @param {unknown} value @returns {value is number[]} */
function isByteArray(value) {
  return Array.isArray(value) && value.every((byte) => typeof byte === 'number' &&
    Number.isInteger(byte) && byte >= 0 && byte <= 255);
}
