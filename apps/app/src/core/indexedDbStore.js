// DocStore mit IndexedDB. Gleiche Semantik wie MemoryStore und TauriStore —
// nur bleibt hier etwas liegen, wenn der Browser den Tab verwirft.
//
// Warum ueberhaupt: mobile Browser raeumen Hintergrund-Tabs schon nach Minuten
// ab. Ohne Speicher verliert jemand seinen Baum, waehrend er kurz in eine
// andere App wechselt — und merkt es erst danach.
//
// Spaeter mit S3 wird daraus die Offline-Kopie und die Warteschlange fuer noch
// nicht hochgeladene Aenderungen: dieselbe Schnittstelle, andere Rolle.

import { ConflictError } from './store.js';

/** @typedef {{ doc: string, bytes: number[], version: string, counter: number }} SnapshotRow */
/** @typedef {{ doc: string, update: Uint8Array, seq: number }} UpdateRow */
/** @typedef {{ doc: string, key: string, bytes: number[] }} BlobRow */

const DB = 'openom';
const VERSION = 2;
const SNAPSHOTS = 'snapshots';
const UPDATES = 'updates';
// The durable mirror of the core's local BlobStore: opaque (doc, key) → bytes objects. The app-core core owns
// the keyspace; this just persists whatever `export()` hands it and replays it into `import()` on reload.
const BLOBS = 'blobs';

/** @returns {Promise<IDBDatabase>} */
function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(SNAPSHOTS)) db.createObjectStore(SNAPSHOTS, { keyPath: 'doc' });
      if (!db.objectStoreNames.contains(UPDATES)) {
        // Fortlaufender Schluessel: der Log ist eine Reihenfolge, kein Satz.
        const s = db.createObjectStore(UPDATES, { keyPath: 'seq', autoIncrement: true });
        s.createIndex('doc', 'doc');
      }
      if (!db.objectStoreNames.contains(BLOBS)) {
        // Keyed by the composite [doc, key]; indexed by doc so a whole document's objects load in one range.
        const b = db.createObjectStore(BLOBS, { keyPath: ['doc', 'key'] });
        b.createIndex('doc', 'doc');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** @param {IDBTransaction} tx @returns {Promise<void>} */
const done = (tx) => new Promise((resolve, reject) => {
  tx.oncomplete = () => resolve();
  tx.onerror = () => reject(tx.error);
  tx.onabort = () => reject(tx.error);
});

/** @template Value @param {IDBRequest<Value>} req @returns {Promise<Value>} */
const ask = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

export class IndexedDbStore {
  /** @type {IDBDatabase|null} */
  #db = null;

  caps() {
    return { remote: false, conditionalWrites: true, durable: true };
  }

  async #handle() {
    if (!this.#db) this.#db = await open();
    return this.#db;
  }

  /** @param {string[]} names @param {IDBTransactionMode} mode @returns {Promise<IDBTransaction>} */
  async #tx(names, mode) {
    const db = await this.#handle();
    return db.transaction(names, mode);
  }

  /** @returns {Promise<string[]>} */
  async list() {
    const tx = await this.#tx([SNAPSHOTS, UPDATES], 'readonly');
    const snapshotKeys = await ask(tx.objectStore(SNAPSHOTS).getAllKeys());
    const docs = new Set(snapshotKeys.filter((key) => typeof key === 'string'));
    /** @type {unknown[]} */
    const rows = await ask(tx.objectStore(UPDATES).getAll());
    for (const value of rows) {
      if (isUpdateRow(value)) docs.add(value.doc);
    }
    return [...docs];
  }

  /** @param {string} doc @returns {Promise<{bytes: Uint8Array, version: string}|null>} */
  async readSnapshot(doc) {
    const tx = await this.#tx([SNAPSHOTS], 'readonly');
    const row = await ask(tx.objectStore(SNAPSHOTS).get(doc));
    if (row != null && !isSnapshotRow(row)) throw new TypeError('invalid IndexedDB snapshot row');
    return row ? { bytes: new Uint8Array(row.bytes), version: row.version } : null;
  }

  /** @param {string} doc @param {number|null|undefined} [since] @returns {Promise<{updates: Uint8Array[], cursor: number}>} */
  async readUpdates(doc, since) {
    const tx = await this.#tx([UPDATES], 'readonly');
    /** @type {unknown[]} */
    const values = await ask(tx.objectStore(UPDATES).index('doc').getAll(doc));
    if (!values.every(isUpdateRow)) throw new TypeError('invalid IndexedDB update row');
    const rows = /** @type {UpdateRow[]} */ (values);
    // Nach seq sortiert: der Index gibt die Reihenfolge nicht zu.
    rows.sort((a, b) => a.seq - b.seq);
    const from = since ?? 0;
    return { updates: rows.slice(from).map((r) => r.update), cursor: rows.length };
  }

  /** @param {string} doc @param {Uint8Array[]} updates @returns {Promise<number>} */
  async append(doc, updates) {
    const tx = await this.#tx([UPDATES], 'readwrite');
    const store = tx.objectStore(UPDATES);
    for (const update of updates) store.add({ doc, update });
    await done(tx);
    const { cursor } = await this.readUpdates(doc, null);
    return cursor;
  }

  /** @param {string} doc @param {Uint8Array} bytes @param {string|null} [expected] @returns {Promise<string>} */
  async putSnapshot(doc, bytes, expected = null) {
    const tx = await this.#tx([SNAPSHOTS], 'readwrite');
    const store = tx.objectStore(SNAPSHOTS);
    const prev = await ask(store.get(doc));
    const found = prev?.version ?? null;
    // Bedingtes Schreiben in derselben Transaktion wie das Lesen — sonst
    // koennten zwei Tabs desselben Browsers einander ueberschreiben.
    if (found !== expected) { tx.abort(); throw new ConflictError(expected, found); }
    const counter = (prev?.counter ?? 0) + 1;
    store.put({ doc, bytes: Array.from(bytes), version: 'v' + counter, counter });
    await done(tx);
    return 'v' + counter;
  }

  // Load every persisted object for a doc as [{ key, bytes }] — fed straight into the core's `import`.
  /** @param {string} doc @returns {Promise<{key: string, bytes: Uint8Array}[]>} */
  async readBlobs(doc) {
    const tx = await this.#tx([BLOBS], 'readonly');
    /** @type {unknown[]} */
    const values = await ask(tx.objectStore(BLOBS).index('doc').getAll(doc));
    if (!values.every(isBlobRow)) throw new TypeError('invalid IndexedDB blob row');
    const rows = /** @type {BlobRow[]} */ (values);
    return rows.map((r) => ({ key: r.key, bytes: new Uint8Array(r.bytes) }));
  }

  // Persist a batch of the core's objects (from `export()`). Idempotent: immutable log objects re-put
  // identically; pointer objects (heads/snapshot) overwrite. `objects` is [{ key, bytes }] (a `pointer` flag,
  // if present, is ignored here — durability keeps every object regardless).
  /** @param {string} doc @param {{key: string, bytes: Uint8Array}[]} objects @returns {Promise<void>} */
  async putBlobs(doc, objects) {
    if (!objects.length) return;
    const tx = await this.#tx([BLOBS], 'readwrite');
    const store = tx.objectStore(BLOBS);
    for (const { key, bytes } of objects) store.put({ doc, key, bytes: Array.from(bytes) });
    await done(tx);
  }

  /** @param {string} doc @returns {Promise<void>} */
  async delete(doc) {
    const tx = await this.#tx([SNAPSHOTS, UPDATES, BLOBS], 'readwrite');
    tx.objectStore(SNAPSHOTS).delete(doc);
    const updIndex = tx.objectStore(UPDATES).index('doc');
    for (const key of await ask(updIndex.getAllKeys(doc))) tx.objectStore(UPDATES).delete(key);
    const blobIndex = tx.objectStore(BLOBS).index('doc');
    for (const key of await ask(blobIndex.getAllKeys(doc))) tx.objectStore(BLOBS).delete(key);
    await done(tx);
  }
}

/** @param {unknown} value @returns {value is SnapshotRow} */
function isSnapshotRow(value) {
  if (typeof value !== 'object' || value === null) return false;
  const row = /** @type {Record<string, unknown>} */ (value);
  return typeof row.doc === 'string' && Array.isArray(row.bytes) &&
    row.bytes.every(isByte) && typeof row.version === 'string' &&
    typeof row.counter === 'number' && Number.isSafeInteger(row.counter);
}

/** @param {unknown} value @returns {value is UpdateRow} */
function isUpdateRow(value) {
  if (typeof value !== 'object' || value === null) return false;
  const row = /** @type {Record<string, unknown>} */ (value);
  return typeof row.doc === 'string' && row.update instanceof Uint8Array &&
    typeof row.seq === 'number' && Number.isSafeInteger(row.seq);
}

/** @param {unknown} value @returns {value is BlobRow} */
function isBlobRow(value) {
  if (typeof value !== 'object' || value === null) return false;
  const row = /** @type {Record<string, unknown>} */ (value);
  return typeof row.doc === 'string' && typeof row.key === 'string' &&
    Array.isArray(row.bytes) && row.bytes.every(isByte);
}

/** @param {unknown} value @returns {value is number} */
function isByte(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 255;
}

/** Steht IndexedDB zur Verfuegung? Im privaten Modus mancher Browser nicht. */
export async function indexedDbUsable() {
  if (typeof indexedDB === 'undefined') return false;
  try {
    const db = await open();
    db.close();
    return true;
  } catch {
    return false;
  }
}
