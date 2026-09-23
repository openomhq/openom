// DocStore: Persistenz opaker Bytes. Zwei Implementierungen mit identischer
// Semantik — die Speicher-Variante für den Browser, die Tauri-Variante
// spricht rusqlite über genau zwei Kommandos.

/** @typedef {{ remote: boolean, conditionalWrites: boolean, durable: boolean }} StoreCapabilities */
/** @typedef {{ bytes: Uint8Array, version: string|null }} StoreSnapshot */
/** @typedef {{ updates: Uint8Array[], cursor: number }} StoreUpdates */
/** @typedef {{ store: DocStore, kind: string }} StoreSelection */
/** @typedef {string} StoreDocId */
/** @typedef {{ remote: boolean, conditional_writes: boolean, durable: boolean }} NativeStoreCapabilities */
/** @typedef {{ bytes: number[], version: string }} NativeSnapshot */
/** @typedef {{ caps: NativeStoreCapabilities, snapshot: NativeSnapshot|null, updates: number[][], cursor: number }} NativeStoreRead */
/** @typedef {(command: string, args?: object) => Promise<unknown>} StoreInvoke */
/** @typedef {{
 * caps: () => StoreCapabilities,
 * list: () => Promise<StoreDocId[]>,
 * readSnapshot: (id: StoreDocId) => Promise<StoreSnapshot|null>,
 * readUpdates: (id: StoreDocId, since?: number|null) => Promise<StoreUpdates>,
 * append: (id: StoreDocId, updates: Uint8Array[]) => Promise<number>,
 * putSnapshot: (id: StoreDocId, bytes: Uint8Array, expected?: string|null) => Promise<string>,
 * delete: (id: StoreDocId) => Promise<void>,
 * }} DocStore */

export class ConflictError extends Error {
  /** @param {string|null} expected @param {string|null} found */
  constructor(expected, found) {
    super(`version conflict: expected ${expected}, found ${found}`);
    this.name = 'ConflictError';
    this.expected = expected;
    this.found = found;
  }
}

// A 401 from the remote that survived one forced-refresh retry: the AuthSession could not
// produce a token the server accepts (expired/rotated/revoked identity). Distinct from a
// ConflictError (retry with a fresh CAS) and a bare network Error (retry the same request) —
// the composition root reacts by re-gating / signing out, never by looping the request.
export class AuthError extends Error {
  constructor(detail = '') {
    super(`authentication failed${detail ? `: ${detail}` : ''}`);
    this.name = 'AuthError';
    this.status = 401;
  }
}

export class MemoryStore {
  /** @type {Map<StoreDocId, { snapshot: Uint8Array|null, version: string|null, log: Uint8Array[], counter: number }>} */
  #docs = new Map();

  caps() {
    return { remote: false, conditionalWrites: true, durable: false };
  }

  /** @param {StoreDocId} id */
  #doc(id) {
    if (!this.#docs.has(id)) this.#docs.set(id, { snapshot: null, version: null, log: [], counter: 0 });
    const doc = this.#docs.get(id);
    if (!doc) throw new Error('document initialization failed');
    return doc;
  }

  async list() {
    return [...this.#docs.keys()];
  }

  /** @param {StoreDocId} id @returns {Promise<StoreSnapshot|null>} */
  async readSnapshot(id) {
    const d = this.#doc(id);
    return d.snapshot ? { bytes: d.snapshot, version: d.version } : null;
  }

  /** @param {StoreDocId} id @param {number|null} [since] @returns {Promise<StoreUpdates>} */
  async readUpdates(id, since) {
    const d = this.#doc(id);
    const from = since ?? 0;
    return { updates: d.log.slice(from), cursor: d.log.length };
  }

  /** @param {StoreDocId} id @param {Uint8Array[]} updates @returns {Promise<number>} */
  async append(id, updates) {
    const d = this.#doc(id);
    d.log.push(...updates);
    d.counter = d.log.length;
    return d.counter;
  }

  /** @param {StoreDocId} id @param {Uint8Array} bytes @param {string|null} [expected] @returns {Promise<string>} */
  async putSnapshot(id, bytes, expected = null) {
    const d = this.#doc(id);
    if (d.version !== expected) throw new ConflictError(expected, d.version);
    d.counter += 1;
    d.snapshot = bytes;
    d.version = 'v' + d.counter;
    return d.version;
  }

  /** @param {StoreDocId} id @returns {Promise<void>} */
  async delete(id) {
    this.#docs.delete(id);
  }
}

export class TauriStore {
  /** @type {StoreInvoke} */
  #invoke;
  /** @type {StoreCapabilities} */
  #caps = { remote: false, conditionalWrites: true, durable: false };

  /** @param {StoreInvoke} invoke */
  constructor(invoke) {
    this.#invoke = invoke;
  }

  caps() {
    return this.#caps;
  }

  /** @returns {Promise<StoreDocId[]>} */
  async list() {
    const result = await this.#invoke('store_list');
    if (!Array.isArray(result) || !result.every((item) => typeof item === 'string')) {
      throw new TypeError('store_list returned invalid document ids');
    }
    return /** @type {StoreDocId[]} */ (result);
  }

  /** @param {StoreDocId} doc @param {number|null} since */
  async #read(doc, since) {
    const value = await this.#invoke('store_read', { doc, since: since ?? null });
    if (!isNativeStoreRead(value)) throw new TypeError('store_read returned an invalid response');
    const res = value;
    this.#caps = { remote: res.caps.remote, conditionalWrites: res.caps.conditional_writes, durable: res.caps.durable };
    return res;
  }

  /** @param {StoreDocId} doc @returns {Promise<StoreSnapshot|null>} */
  async readSnapshot(doc) {
    const res = await this.#read(doc, null);
    return res.snapshot ? { bytes: new Uint8Array(res.snapshot.bytes), version: res.snapshot.version } : null;
  }

  /** @param {StoreDocId} doc @param {number|null|undefined} [since] @returns {Promise<StoreUpdates>} */
  async readUpdates(doc, since) {
    const res = await this.#read(doc, since ?? null);
    // Rust returns each update as a JSON number array; hand back Uint8Arrays like the other stores.
    return { updates: res.updates.map((u) => new Uint8Array(u)), cursor: res.cursor };
  }

  /** @param {StoreDocId} doc @param {Uint8Array[]} updates @returns {Promise<number>} */
  async append(doc, updates) {
    // Each update is a raw envelope Uint8Array; serde decodes Vec<Vec<u8>> from number arrays,
    // never from a Uint8Array (which JSON-stringifies to an index-keyed object).
    const encoded = updates.map((u) => Array.from(u));
    const result = await this.#invoke('store_append', { args: { doc, updates: encoded } });
    if (typeof result !== 'number') throw new TypeError('store_append returned an invalid cursor');
    return result;
  }

  /** @param {StoreDocId} doc @param {Uint8Array} bytes @param {string|null} [expected] @returns {Promise<string>} */
  async putSnapshot(doc, bytes, expected = null) {
    try {
      const result = await this.#invoke('store_put_snapshot', { doc, bytes: Array.from(bytes), expected });
      if (typeof result !== 'string') throw new TypeError('store_put_snapshot returned an invalid version');
      return result;
    } catch (e) {
      if (String(e).includes('version conflict')) throw new ConflictError(expected, null);
      throw e;
    }
  }

  /** @param {StoreDocId} doc @returns {Promise<void>} */
  async delete(doc) {
    await this.#invoke('store_delete', { doc });
  }
}

/** @param {unknown} value @returns {value is NativeStoreRead} */
function isNativeStoreRead(value) {
  if (typeof value !== 'object' || value === null) return false;
  const read = /** @type {Record<string, unknown>} */ (value);
  const caps = read.caps;
  const snapshot = read.snapshot;
  const updates = read.updates;
  return typeof caps === 'object' && caps !== null &&
    typeof /** @type {Record<string, unknown>} */ (caps).remote === 'boolean' &&
    typeof /** @type {Record<string, unknown>} */ (caps).conditional_writes === 'boolean' &&
    typeof /** @type {Record<string, unknown>} */ (caps).durable === 'boolean' &&
    (snapshot === null || (typeof snapshot === 'object' && snapshot !== null &&
      Array.isArray(/** @type {Record<string, unknown>} */ (snapshot).bytes) &&
      /** @type {number[]} */ (/** @type {Record<string, unknown>} */ (snapshot).bytes).every(isByte) &&
      typeof /** @type {Record<string, unknown>} */ (snapshot).version === 'string')) &&
    Array.isArray(updates) && updates.every((row) => Array.isArray(row) && row.every(isByte)) &&
    typeof read.cursor === 'number' && Number.isSafeInteger(read.cursor);
}

/** @param {unknown} value @returns {value is number} */
function isByte(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 255;
}

/**
 * Waehlt den Anbieter: Rust in Tauri, sonst IndexedDB im Browser, sonst
 * Speicher. Die Reihenfolge ist die Rangfolge der Haltbarkeit — und weil alle
 * drei dieselbe Schnittstelle haben, merkt die Oberflaeche nichts davon.
 *
 * Asynchron, weil sich nur durch Oeffnen herausfindet, ob IndexedDB wirklich
 * benutzbar ist: im privaten Modus mancher Browser gibt es das Objekt, aber
 * jeder Zugriff scheitert.
 */
/** @returns {Promise<StoreSelection>} */
export async function createStore() {
  const host = Reflect.get(globalThis, '__TAURI__');
  const core = typeof host === 'object' && host !== null ? Reflect.get(host, 'core') : null;
  const invoke = typeof core === 'object' && core !== null ? Reflect.get(core, 'invoke') : null;
  if (typeof invoke === 'function') return { store: new TauriStore(invoke), kind: 'sqlite (rust)' };
  const { IndexedDbStore, indexedDbUsable } = await import('./indexedDbStore.js');
  if (await indexedDbUsable()) return { store: new IndexedDbStore(), kind: 'indexeddb (browser)' };
  return { store: new MemoryStore(), kind: 'memory (browser)' };
}
