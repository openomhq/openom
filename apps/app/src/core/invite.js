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

const enc = new TextEncoder();

const b64u = {
  enc: (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => {
    const t = s.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
  },
};

function bytesOf(x) {
  return typeof x === 'string' ? enc.encode(x) : x;
}

// Unambiguous concatenation: each field prefixed by its u32-BE byte length.
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

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Domain-separated MAC subkeys — the two directions can never be confused (crypto review).
const CLAIM_INFO = 'openom:invite:mac:claim';
const META_INFO = 'openom:invite:mac:meta';

async function hkdf(subtle, ikm, info) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function hmac(subtle, keyBytes, data) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, data));
}

async function sha256(subtle, data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

// The invitee's key claim, MAC'd under s_mac_claim: binds invite/tree/role/account/keys.
async function claimTag(subtle, sMacClaim, { inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey }) {
  return hmac(subtle, sMacClaim, framed(inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey));
}

// The owner's metadata MAC under s_mac_meta: binds invite/tree/role/engine/pin so the server can't tamper.
async function metaTag(subtle, sMacMeta, { inviteId, uuid, role, engine, pin }) {
  return hmac(subtle, sMacMeta, framed(inviteId, uuid, role, engine, pin));
}

/**
 * Canonical fingerprint of a tree's signer set: SHA-256 over the signers SORTED by member id, each as
 * framed(member_id ‖ author_public), base64url. Used by the OWNER's admit-time anti-substitution gate (compare
 * the current signer set against the mint-time one) — NOT part of the authenticated pin (kh already covers it).
 * @param {{memberId: string, authorPublicKey: Uint8Array}[]} signers
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
 * Owner: mint an invite. `pin` is OPAQUE engine-specific bytes the caller (the worker) produced (chain: rev‖kh;
 * dag: dagAnchorPin). Returns the short shareable `link` (`#invite=<id>&s=<s>` — only `s` is out-of-band), the
 * `pending` payload for the server (the authenticated metadata, NO secret), and the LOCAL `record` (holds
 * `s_mac_claim` for admit — the caller augments it with the mint-time signer set for the admit gate).
 * @param {{ uuid: string, role: string, engine: string, pin: Uint8Array, recipientPin?: string|null,
 *   ttlMs?: number, base?: string, now?: number, subtle?: SubtleCrypto, makeBytes?: (n:number)=>Uint8Array }} o
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
  const inviteId = b64u.enc(makeBytes(16));
  const expiry = now + ttlMs;
  const metaMac = await metaTag(subtle, sMacMeta, { inviteId, uuid, role, engine, pin });
  const q = `invite=${encodeURIComponent(inviteId)}&s=${b64u.enc(s)}`;
  return {
    inviteId,
    link: `${base}/join#${q}`,
    // To the server (the authenticated metadata + spam control). `pin`/`metaMac` are bytes; the transport b64s them.
    pending: { inviteId, uuid, role, engine, pin, metaMac, recipientPin, expiry },
    // LOCAL only — admit reads this. `s_mac_claim` verifies the claimant's MAC; the caller adds the signer set.
    record: { inviteId, uuid, role, engine, sMacClaim, expiry, recipientPin },
  };
}

/** Invitee: parse the short invite link's fragment → `{ inviteId, s }`. Throws on a malformed link. */
export function parseLink(url) {
  const frag = url.includes('#') ? url.slice(url.indexOf('#') + 1) : '';
  const p = new URLSearchParams(frag);
  const inviteId = p.get('invite');
  const sB64 = p.get('s');
  if (!inviteId || !sB64) throw new Error('invalid invite link');
  return { inviteId, s: b64u.dec(sB64) };
}

/**
 * Invitee: verify the server-fetched metadata's MAC with `s_mac_meta` (from the link's `s`). UNCONDITIONAL and
 * fail-closed — ANY missing field throws, never an "if present, check; else proceed" fallback (there is no
 * redundant channel behind `meta_mac`). Returns the trusted `{ uuid, role, engine, pin }` on success; throws on
 * a mismatch or a missing field.
 * @param {{ s: Uint8Array, inviteId: string, uuid: string, role: string, engine: string,
 *   pin: Uint8Array, metaMac: Uint8Array }} m
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
 */
export async function claim({ s, inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey }, { subtle = crypto.subtle } = {}) {
  const sMacClaim = await hkdf(subtle, s, CLAIM_INFO);
  const tag = await claimTag(subtle, sMacClaim, { inviteId, uuid, role, memberId, hpkePublicKey, authorPublicKey });
  return { inviteId, memberId, hpkePublicKey, authorPublicKey, tag };
}

/**
 * Owner: verify a claim's MAC against the LOCAL mint record. role/uuid/inviteId come from the RECORD, never the
 * claim — so a tampered claim (or a lying server) fails to match and is rejected.
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
