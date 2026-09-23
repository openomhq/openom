// The two-channel invite crypto for Mode A sharing — invite model v3 (plan/sharing/design.invite-model-v3.md).
// Pure WebCrypto, no server, no wasm. The security boundary:
//   * `s` (the 32-byte link secret) is the ONLY out-of-band field. It is HKDF-split into DOMAIN-SEPARATED subkeys
//     `s_mac_claim` and `s_mac_meta`, so a tag valid in one direction can NEVER verify in the other (no
//     cross-protocol confusion, regardless of future field shapes). The server never sees `s` or either subkey.
//   * META MAC (owner → invitee, `s_mac_meta`): authenticates uuid/role/engine/pin — the metadata the joiner
//     fetches from the untrusted server. The server lacks `s`, so it serves the real metadata or fails verify;
//     it can never forge or substitute (equivalent to putting the pin in the link, just shorter).
//   * CLAIM MAC (invitee → owner, `s_mac_claim`): authenticates the invitee's keys + role/tree/invite. The owner
//     admits from a LOCAL mint record and verifies this MAC — role/uuid/inviteId come from the RECORD, never the
//     server/claim.
//   * a leaked link is a bearer token (a stated, family-app-acceptable decision).
// This module is engine-AGNOSTIC: `pin` is opaque bytes the worker packs per engine; invite.js only carries it
// and MACs over it. Everything is async (crypto.subtle) and injectable (`subtle`, `makeBytes`, `now`) for tests.

/** @typedef {import('./types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('./types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('./types/domain.js').InviteId} InviteId */
/** @typedef {import('./types/domain.js').InviteLink} InviteLink */
/** @typedef {import('./types/domain.js').InviteMacBytes} InviteMacBytes */
/** @typedef {import('./types/domain.js').InvitePinBytes} InvitePinBytes */
/** @typedef {import('./types/domain.js').KeyringEngine} KeyringEngine */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').MemberRole} MemberRole */
/** @typedef {import('./types/domain.js').TreeUuid} TreeUuid */
/** @typedef {import('./types/appCoreApi.js').InviteClaim} InviteClaim */
/** @typedef {import('./types/appCoreApi.js').PendingInvite} PendingInvite */

/** @typedef {{ readonly memberId: MemberId, readonly authorPublicKey: AuthorPublicKeyBytes }} InviteSigner */
/** @typedef {{ readonly memberId: MemberId, readonly role: number }} SummaryMember */
/** @typedef {{
 *   readonly inviteId: InviteId,
 *   readonly uuid: TreeUuid,
 *   readonly role: MemberRole,
 *   readonly engine: KeyringEngine,
 *   readonly sMacClaim: Uint8Array,
 *   readonly expiry: number,
 *   readonly recipientPin: string | null,
 * }} InviteMintRecord */
/** @typedef {{
 *   readonly uuid: TreeUuid,
 *   readonly role: MemberRole,
 *   readonly engine: KeyringEngine,
 *   readonly pin: InvitePinBytes,
 * }} VerifiedInviteMeta */

const enc = new TextEncoder();

const b64u = {
  /** @param {Uint8Array} b */
  enc: (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  /** @param {string} s */
  dec: (s) => {
    const t = s.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
  },
};

/** @param {string | Uint8Array} x */
function bytesOf(x) {
  return typeof x === 'string' ? enc.encode(x) : x;
}

// Unambiguous concatenation: each field prefixed by its u32-BE byte length.
/** @param {...(string | Uint8Array)} parts */
function framed(...parts) {
  const bufs = parts.map(bytesOf);
  const out = new Uint8Array(bufs.reduce((n, b) => n + 4 + b.length, 0));
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const b of bufs) {
    dv.setUint32(off, b.length, false);
    off += 4;
    out.set(b, off);
    off += b.length;
  }
  return out;
}

/** @param {Uint8Array} a @param {Uint8Array} b */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** @param {Uint8Array} value @returns {Uint8Array<ArrayBuffer>} */
function cryptoBytes(value) {
  return Uint8Array.from(value);
}

// Domain-separated MAC subkeys — the two directions can never be confused (crypto review).
const CLAIM_INFO = 'openom:invite:mac:claim';
const META_INFO = 'openom:invite:mac:meta';

/** @param {SubtleCrypto} subtle @param {Uint8Array} ikm @param {string} info */
async function hkdf(subtle, ikm, info) {
  const key = await subtle.importKey('raw', cryptoBytes(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/** @param {SubtleCrypto} subtle @param {Uint8Array} keyBytes @param {Uint8Array} data */
async function hmac(subtle, keyBytes, data) {
  const key = await subtle.importKey('raw', cryptoBytes(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, cryptoBytes(data)));
}

/** @param {SubtleCrypto} subtle @param {Uint8Array} data */
async function sha256(subtle, data) {
  return new Uint8Array(await subtle.digest('SHA-256', cryptoBytes(data)));
}

// The invitee's key claim, MAC'd under s_mac_claim: binds invite/tree/role/account/keys.
/**
 * @param {SubtleCrypto} subtle
 * @param {Uint8Array} sMacClaim
 * @param {{ inviteId: InviteId, uuid: TreeUuid, role: MemberRole, memberId: MemberId,
 *   hpkePublicKey: HpkePublicKeyBytes, authorPublicKey: AuthorPublicKeyBytes }} claim
 */
async function claimTag(subtle, sMacClaim, { inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey }) {
  return hmac(subtle, sMacClaim, framed(inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey));
}

// The owner's metadata MAC under s_mac_meta: binds invite/tree/role/engine/pin so the server can't tamper.
/**
 * @param {SubtleCrypto} subtle
 * @param {Uint8Array} sMacMeta
 * @param {{ inviteId: InviteId, uuid: TreeUuid, role: MemberRole, engine: KeyringEngine,
 *   pin: InvitePinBytes }} meta
 */
async function metaTag(subtle, sMacMeta, { inviteId, uuid, role, engine, pin }) {
  return hmac(subtle, sMacMeta, framed(inviteId, uuid, role, engine, pin));
}

/**
 * Canonical fingerprint of a tree's signer set: SHA-256 over the signers SORTED by member id, each as
 * framed(member_id ‖ author_public), base64url. Used by the OWNER's admit-time anti-substitution gate (compare
 * the current signer set against the mint-time one) — NOT part of the authenticated pin (kh already covers it).
 * @param {ReadonlyArray<InviteSigner>} signers
 * @param {{ subtle?: SubtleCrypto }} [options]
 */
export async function fingerprintSigners(signers, { subtle = crypto.subtle } = {}) {
  const sorted = [...signers].sort((a, b) => (a.memberId < b.memberId ? -1 : a.memberId > b.memberId ? 1 : 0));
  const parts = sorted.map((s) => framed(s.memberId, s.authorPublicKey));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const cat = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { cat.set(p, off); off += p.length; }
  return b64u.enc(await sha256(subtle, cat));
}

/**
 * The tree's SIGNER set (owner + co-owners = role ≤ 2) as a sorted memberId list, from the engine-agnostic keyring
 * summary `[{memberId, role}]`. Recorded at mint for the admit-time anti-substitution gate. Engine-agnostic (the
 * summary works for chain AND dag).
 * @param {ReadonlyArray<SummaryMember>} members
 * @returns {MemberId[]}
 */
export function signerIds(members) {
  return (members ?? []).filter((m) => m.role <= 2).map((m) => m.memberId).sort();
}

/**
 * The admit-time ANTI-SUBSTITUTION check: is every signer present at MINT still a signer NOW? REMOVAL-ONLY — a
 * signer removed or demoted since mint fails (e.g. a co-owner about to be kicked pre-minted an invite for
 * themselves, then it's admitted after their removal), so the stale invite is refused. ADDING a signer since mint
 * is TOLERATED (it enables no stale-invite attack — the invite admits the claimant at the recorded role, not the
 * new signer). Subset check, not equality.
 * @param {ReadonlyArray<MemberId>} mintSignerIds  the sorted signer list recorded at mint (`signerIds` output)
 * @param {ReadonlyArray<SummaryMember>} currentMembers  the CURRENT keyring summary members
 */
export function signersRetained(mintSignerIds, currentMembers) {
  const now = new Set((currentMembers ?? []).filter((m) => m.role <= 2).map((m) => m.memberId));
  return (mintSignerIds ?? []).every((id) => now.has(id));
}

/**
 * Owner: mint an invite. `pin` is OPAQUE engine-specific bytes the caller (the worker) produced (chain: rev‖kh;
 * dag: dagAnchorPin). Returns the short shareable `link` (`#invite=<id>&s=<s>` — only `s` is out-of-band), the
 * `pending` payload for the server (the authenticated metadata, NO secret), and the LOCAL `record` (holds
 * `s_mac_claim` for admit — the caller augments it with the mint-time signer set for the admit gate).
 * @param {{ uuid: TreeUuid, role: MemberRole, engine: KeyringEngine, pin: InvitePinBytes, recipientPin?: string|null,
 *   ttlMs?: number, base?: string, now?: number, subtle?: SubtleCrypto, makeBytes?: (n:number)=>Uint8Array }} o
 * @returns {Promise<{
 *   inviteId: InviteId,
 *   link: InviteLink,
 *   pending: PendingInvite,
 *   record: InviteMintRecord,
 * }>}
 */
export async function mint({
  uuid,
  role,
  engine,
  pin,
  recipientPin = null,
  ttlMs = 7 * 24 * 3600 * 1000,
  base = 'https://openom.app',
  now = Date.now(),
  subtle = crypto.subtle,
  makeBytes = (n) => crypto.getRandomValues(new Uint8Array(n)),
}) {
  if (engine !== 'chain' && engine !== 'dag') throw new Error("mint: engine must be 'chain' or 'dag'");
  if (!(pin instanceof Uint8Array) || pin.length === 0) throw new Error('mint: pin must be non-empty bytes');
  const s = makeBytes(32);
  const sMacClaim = await hkdf(subtle, s, CLAIM_INFO);
  const sMacMeta = await hkdf(subtle, s, META_INFO);
  const inviteId = /** @type {InviteId} */ (b64u.enc(makeBytes(16)));
  const expiry = now + ttlMs;
  const metaMac = await metaTag(subtle, sMacMeta, { inviteId, uuid, role, engine, pin });
  const q = `invite=${encodeURIComponent(inviteId)}&s=${b64u.enc(s)}`;
  return {
    inviteId,
    link: /** @type {InviteLink} */ (`${base}/join#${q}`),
    // To the server (the authenticated metadata + spam control). `pin`/`metaMac` are bytes; the transport b64s them.
    pending: {
      inviteId, uuid, role, engine, pin,
      metaMac: /** @type {InviteMacBytes} */ (metaMac),
      recipientPin,
      expiry,
    },
    // LOCAL only — admit reads this. `s_mac_claim` verifies the claimant's MAC; the caller adds the signer set.
    record: { inviteId, uuid, role, engine, sMacClaim, expiry, recipientPin },
  };
}

/**
 * Invitee: parse the short invite link's fragment → `{ inviteId, s }`. Throws on a malformed link.
 * @param {string} url
 * @returns {{ inviteId: InviteId, s: Uint8Array }}
 */
export function parseLink(url) {
  const frag = url.includes('#') ? url.slice(url.indexOf('#') + 1) : '';
  const p = new URLSearchParams(frag);
  const inviteId = p.get('invite');
  const sB64 = p.get('s');
  if (!inviteId || !sB64) throw new Error('invalid invite link');
  return { inviteId: /** @type {InviteId} */ (inviteId), s: b64u.dec(sB64) };
}

/**
 * Invitee: verify the server-fetched metadata's MAC with `s_mac_meta` (from the link's `s`). UNCONDITIONAL and
 * fail-closed — ANY missing field throws, never an "if present, check; else proceed" fallback (there is no
 * redundant channel behind `meta_mac`). Returns the trusted `{ uuid, role, engine, pin }` on success; throws on
 * a mismatch or a missing field.
 * @param {{ s: Uint8Array, inviteId: InviteId, uuid: TreeUuid, role: MemberRole, engine: KeyringEngine,
 *   pin: InvitePinBytes, metaMac: InviteMacBytes }} m
 * @param {{ subtle?: SubtleCrypto }} [options]
 * @returns {Promise<VerifiedInviteMeta>}
 */
export async function verifyMeta({ s, inviteId, uuid, role, engine, pin, metaMac }, { subtle = crypto.subtle } = {}) {
  if (!s || !inviteId || !uuid || !role || !engine || !(pin instanceof Uint8Array) || !(metaMac instanceof Uint8Array)) {
    throw new Error('invite meta: missing or malformed field');
  }
  const sMacMeta = await hkdf(subtle, s, META_INFO);
  const expected = await metaTag(subtle, sMacMeta, { inviteId, uuid, role, engine, pin });
  if (!timingSafeEqual(expected, metaMac)) throw new Error('invite meta MAC mismatch');
  return { uuid, role, engine, pin };
}

/**
 * Invitee: build the claim to submit to the server, MAC'd with `s_mac_claim` over its own keys. `s` comes from
 * the parsed link; `uuid`/`role` from the VERIFIED meta; `inviteId` from the link.
 * @param {{ s: Uint8Array, inviteId: InviteId, uuid: TreeUuid, role: MemberRole, memberId: MemberId,
 *   hpkePublicKey: HpkePublicKeyBytes, authorPublicKey: AuthorPublicKeyBytes }} input
 * @param {{ subtle?: SubtleCrypto }} [options]
 * @returns {Promise<InviteClaim>}
 */
export async function claim({ s, inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey }, { subtle = crypto.subtle } = {}) {
  const sMacClaim = await hkdf(subtle, s, CLAIM_INFO);
  const tag = await claimTag(subtle, sMacClaim, { inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey });
  return {
    inviteId, memberId, hpkePublicKey, authorPublicKey,
    tag: /** @type {InviteMacBytes} */ (tag),
  };
}

/**
 * Owner: verify a claim's MAC against the LOCAL mint record. role/uuid/inviteId come from the RECORD, never the
 * claim — so a tampered claim (or a lying server) fails to match and is rejected.
 * @param {InviteMintRecord} record
 * @param {InviteClaim} claim
 * @param {{ subtle?: SubtleCrypto }} [options]
 * @returns {Promise<boolean>}
 */
export async function verifyClaim(record, claim, { subtle = crypto.subtle } = {}) {
  const expected = await claimTag(subtle, record.sMacClaim, {
    inviteId: record.inviteId,
    uuid: record.uuid,
    role: record.role,
    memberId: claim.memberId,
    hpkePublicKey: claim.hpkePublicKey,
    authorPublicKey: claim.authorPublicKey,
  });
  return timingSafeEqual(expected, claim.tag);
}

export const _internal = { framed, b64u, timingSafeEqual, CLAIM_INFO, META_INFO };
