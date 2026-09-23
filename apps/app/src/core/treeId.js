// Per-account selected-tree identity — the ONE id, in its two encodings.
//
// The server binds the 16-byte tree id carried INSIDE every signed/sealed payload to the raw
// bytes of the URL's UUID (openom/src/{trees,log,keyring}.rs). So the sealer's scope id and the
// server's resource id are not two ids to reconcile — they are one identity: 16 random bytes
// (the seam id, minted once at provision), whose UUID-string form `treeIdToUuid(bytes)` is the
// URL id, the local doc/keyring key, and the SyncController docId all at once.
//
// The keyring's own tree binding is the ULTIMATE source of truth (any device that legitimately
// holds the keyring already knows the tree's id). This localStorage entry is only a cache so the
// post-account-unlock path knows which keyring to decrypt — it is seeded at provision and is
// re-derivable from the keyring head. Its key is the durable AccountSession member ID, never the
// provider-auth subject.
//
// The mint is serialized across tabs (navigator.locks): two tabs of one account both seeing "no id
// yet" at a first provision would otherwise each mint a different id and split the account's one
// tree across two server rows (cas_create accepts both — nothing reconciles them afterwards).

import { treeIdToUuid } from './keyringPublish.js';

/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').TreeId} TreeId */
/** @typedef {import('./types/domain.js').TreeUuid} TreeUuid */
/** @typedef {import('./types/contracts.js').TreeIdentity} TreeIdentity */
/** @typedef {{ getItem(key: string): string | null, setItem(key: string, value: string): void }} TreeIdentityStorage */
/** @typedef {{ request<T>(name: string, callback: () => Promise<T> | T): Promise<T> }} TreeIdentityLocks */

/** @param {MemberId} accountMemberId */
const key = (accountMemberId) => `openom.tree.${accountMemberId}`;

/** @returns {TreeIdentityStorage} */
function defaultStorage() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem('__treeid_probe__');
      return localStorage;
    }
  } catch {
    /* private mode / Node — fall through */
  }
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? (m.get(k) ?? null) : null),
    setItem: (k, v) => { m.set(k, v); },
  };
}

const b64 = {
  /** @param {TreeId} bytes */
  enc: (bytes) => btoa(String.fromCharCode(...bytes)),
  /** @param {string} s @returns {TreeId} */
  dec: (s) => /** @type {TreeId} */ (Uint8Array.from(atob(s), (c) => c.charCodeAt(0))),
};

/** @param {TreeIdentityStorage} storage @param {MemberId} accountMemberId @returns {TreeIdentity | null} */
function read(storage, accountMemberId) {
  try {
    const raw = storage.getItem(key(accountMemberId));
    if (!raw) return null;
    const parsed = /** @type {unknown} */ (JSON.parse(raw));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const { seam, uuid } = /** @type {{ seam?: unknown, uuid?: unknown }} */ (parsed);
    if (typeof seam !== 'string') return null;
    const bytes = b64.dec(seam);
    if (bytes.length !== 16 || typeof uuid !== 'string') return null;
    return { bytes, uuid: /** @type {TreeUuid} */ (uuid) };
  } catch {
    return null;
  }
}

/** @param {TreeIdentityStorage} storage @param {MemberId} accountMemberId @param {TreeId} bytes @param {TreeUuid} uuid */
function write(storage, accountMemberId, bytes, uuid) {
  try {
    storage.setItem(key(accountMemberId), JSON.stringify({ seam: b64.enc(bytes), uuid }));
  } catch {
    /* best effort — the caller still holds the freshly-minted identity for this session */
  }
}

/**
 * The account's already-minted selected-tree identity, or null if none exists yet (not provisioned).
 * Synchronous — called only after account unlock has supplied the durable member ID.
 * @param {MemberId | null | undefined} accountMemberId
 * @param {{ storage?: TreeIdentityStorage }} [options]
 * @returns {TreeIdentity | null}
 */
export function readTreeIdentity(accountMemberId, { storage = defaultStorage() } = {}) {
  if (!accountMemberId) return null;
  return read(storage, accountMemberId);
}

/**
 * Mint-or-read the account's tree identity, serialized across tabs so concurrent first-provisions
 * converge on ONE identity. Call at provision; `readTreeIdentity` suffices at unlock.
 * @param {MemberId} accountMemberId
 * @param {{ storage?: TreeIdentityStorage, makeBytes?: () => TreeId, locks?: TreeIdentityLocks | null }} [options]
 * @returns {Promise<TreeIdentity>}
 */
export async function ensureTreeIdentity(
  accountMemberId,
  {
    storage = defaultStorage(),
    makeBytes = () => /** @type {TreeId} */ (crypto.getRandomValues(new Uint8Array(16))),
    locks = typeof navigator !== 'undefined' ? navigator.locks : null,
  } = {},
) {
  if (!accountMemberId) throw new Error('ensureTreeIdentity needs an account member ID');
  const existing = read(storage, accountMemberId);
  if (existing) return existing;

  // Mint under a per-account cross-tab lock; re-read inside it so a tab that lost the race adopts
  // the winner's id rather than minting a second one.
  const mint = () => {
    const again = read(storage, accountMemberId);
    if (again) return again;
    const bytes = makeBytes();
    if (bytes.length !== 16) throw new Error('tree seam id must be 16 bytes');
    const uuid = treeIdToUuid(bytes);
    write(storage, accountMemberId, bytes, uuid);
    return { bytes, uuid };
  };
  if (locks?.request) return locks.request(`openom.tree.mint.${accountMemberId}`, mint);
  return mint(); // no navigator.locks (tests / older browsers): best-effort, single-tab-safe
}

/**
 * Seed an account's tree identity from an invite: the invitee ADOPTS the owner's tree id (learned from the
 * link) rather than minting a fresh one — without this, `ensureTreeIdentity` would mint a random tree and
 * account would never sync the owner's. Idempotent; a conflicting existing identity for this account is
 * a bug and is surfaced. (V1 is one selected tree per account; the multi-tree registry is separate future work.)
 * @param {MemberId} accountMemberId
 * @param {TreeIdentity} identity
 * @param {{ storage?: TreeIdentityStorage }} [options]
 * @returns {TreeIdentity}
 */
export function seedTreeIdentity(accountMemberId, { bytes, uuid }, { storage = defaultStorage() } = {}) {
  if (!accountMemberId) throw new Error('seedTreeIdentity needs an account member ID');
  if (!bytes || bytes.length !== 16 || !uuid) throw new Error('seedTreeIdentity needs { bytes(16 B), uuid }');
  const existing = read(storage, accountMemberId);
  if (existing && existing.uuid !== uuid) {
    throw new Error('seedTreeIdentity: this account already holds a different tree identity');
  }
  write(storage, accountMemberId, bytes, uuid);
  return { bytes, uuid };
}
