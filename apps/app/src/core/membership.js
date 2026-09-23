// App-level Mode A membership orchestration (invite model v3) — the coherent invite / admit / join API the
// members-UI (OPE-10/416) binds to. It sits ABOVE the built crypto (worker `inviteMember`/`admitMember`/
// `provisionMember`/`joinAsMember` + the two-channel MACs in invite.js) and the server routes (`/invites`,
// `/invites/{id}/meta`, `/keyring`), wiring them into design.invite-model-v3.md's short-link flow.
//
//   * OWNER:  inviteMember → (deliver link OOB) → pendingInvites → admitMember (marks the row admitted, never
//     deletes — the joiner still needs /meta to finish).
//   * INVITEE: joinTree = submitJoinClaim (fetch+verify meta, provision, PERSIST the join context, claim) →
//     completeJoin (join off the VERIFIED engine/pin; terminal-state aware). The context is persisted BEFORE the
//     claim and keyed by invite_id, so a restart RESUMES rather than re-provisioning (which would mint different
//     keys → admitted to a keyring it can't unlock — Fable Finding 2).
//
// Engine-agnostic: the opaque `pin` flows through untouched; only the worker interprets it per the verified
// engine. Every function takes explicit deps for unit-testing with a server double + a stubbed worker.

import { parseLink, verifyMeta, claim as buildClaim } from './invite.js';
import { uuidToTreeId } from './keyringPublish.js';
import { seedTreeIdentity } from './treeId.js';

/** @typedef {import('./types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('./types/domain.js').DocId} DocId */
/** @typedef {import('./types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('./types/domain.js').InviteId} InviteId */
/** @typedef {import('./types/domain.js').InviteLink} InviteLink */
/** @typedef {import('./types/domain.js').InviteMacBytes} InviteMacBytes */
/** @typedef {import('./types/domain.js').InvitePinBytes} InvitePinBytes */
/** @typedef {import('./types/domain.js').KeyringEngine} KeyringEngine */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').MemberRole} MemberRole */
/** @typedef {import('./types/domain.js').Passphrase} Passphrase */
/** @typedef {import('./types/domain.js').TreeId} TreeId */
/** @typedef {import('./types/domain.js').TreeUuid} TreeUuid */
/** @typedef {import('./types/appCoreApi.js').AppCoreService} AppCoreService */
/** @typedef {import('./types/appCoreApi.js').InviteClaim} InviteClaim */
/** @typedef {import('./types/appCoreApi.js').PendingInvite} PendingInvite */
/** @typedef {{ getItem(key: string): string | null, setItem(key: string, value: string): void,
 *   removeItem(key: string): void }} JoinStorage */
/** @typedef {{ inviteId: InviteId, s: Uint8Array, docId: DocId, treeId: TreeId, uuid: TreeUuid,
 *   role: MemberRole, engine: KeyringEngine, pin: InvitePinBytes, memberId: MemberId,
 *   selfMemberId: MemberId }} StoredJoinContext */
/** @typedef {{ inviteId: string, s: number[], docId: string, treeId: number[], uuid: string,
 *   role: MemberRole, engine: KeyringEngine, pin: number[], memberId: string,
 *   selfMemberId: string }} SerializedJoinContext */
/** @typedef {StoredJoinContext & { passphrase: Passphrase }} JoinContext */
/** @typedef {Pick<AppCoreService, 'inviteMember' | 'admitMember' | 'provisionMember' | 'joinAsMember'>} JoinWorker */
/** @typedef {{
 *   createInvite(docId: DocId, pending: PendingInvite): Promise<unknown>,
 *   listInvites(docId: DocId): Promise<ReadonlyArray<PendingInviteRecord>>,
 *   getInviteMeta(inviteId: InviteId): Promise<unknown>,
 *   admitInvite(inviteId: InviteId): Promise<void>,
 *   claimInvite(claim: InviteClaim): Promise<void>,
 * }} InviteRemote */
/** @typedef {{ inviteId: InviteId, role: MemberRole, recipientPin: string | null, expiry: number,
 *   status: string, claim: InviteClaim | null }} PendingInviteRecord */
/** @typedef {{ worker: JoinWorker, remote: InviteRemote, storage?: JoinStorage,
 *   attachTransport?: (docId: DocId) => Promise<void> }} MembershipDeps */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** @param {unknown} value @returns {value is MemberRole} */
function isMemberRole(value) {
  return value === 'owner' || value === 'co-owner' || value === 'maintainer'
    || value === 'editor' || value === 'viewer';
}

/** @param {unknown} value @returns {value is KeyringEngine} */
function isKeyringEngine(value) {
  return value === 'chain' || value === 'dag';
}

/** @param {unknown} value @returns {value is number[]} */
function isByteArray(value) {
  return Array.isArray(value) && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
}

/**
 * A normal, expected pre-admit condition (NOT an error): the invitee has claimed but the owner hasn't admitted
 * yet, so the keyring isn't readable. The UI shows "waiting for approval" and polls `completeJoin(deps,
 * err.context)`. `context` carries everything a retry needs — no re-provision, no re-claim.
 */
export class WaitingForApproval extends Error {
  /** @param {JoinContext} context */
  constructor(context) {
    super('waiting for the owner to approve this join');
    this.name = 'WaitingForApproval';
    this.context = context;
  }
}

/** A TERMINAL condition: the invite is gone (canceled/expired) or unusable — the UI must ask for a NEW invite,
 *  not keep waiting. */
export class InviteUnavailable extends Error {
  /** @param {string} reason */
  constructor(reason) {
    super(reason);
    this.name = 'InviteUnavailable';
  }
}

// The keyring isn't readable yet because our ACL entry hasn't landed: the server 403s a non-member's keyring GET
// (→ access_denied), or serves an empty history (→ JoinError 'no keyring history'). Either is the pre-admit state.
/** @param {unknown} error */
function isNotYetAdmitted(error) {
  if (!isRecord(error)) return false;
  if (error.code === 'access_denied' || error.httpStatus === 403) return true;
  return error.name === 'JoinError' && typeof error.message === 'string'
    && /no keyring history/i.test(error.message);
}

// --- durable invitee join context (survives a restart; keyed by invite_id) -------------------------------------
/** @param {Pick<MembershipDeps, 'storage'>} deps @returns {JoinStorage | null} */
const storageOf = (deps) => deps.storage ?? (typeof localStorage !== 'undefined' ? localStorage : null);
/** @param {InviteId} inviteId */
const JOIN_KEY = (inviteId) => `openom:join-ctx:${inviteId}`;

/** @param {JoinStorage | null} storage @param {StoredJoinContext} ctx */
function saveJoinContext(storage, ctx) {
  if (!storage) return;
  // The passphrase is NEVER persisted — the UI re-supplies it on resume (it must match the provisioning one).
  try {
    storage.setItem(JOIN_KEY(ctx.inviteId), JSON.stringify({
      ...ctx,
      s: Array.from(ctx.s),
      treeId: Array.from(ctx.treeId),
      pin: Array.from(ctx.pin),
    }));
  } catch { /* no storage */ }
}

/** @param {unknown} value @returns {value is SerializedJoinContext} */
function isStoredJoinContext(value) {
  if (!isRecord(value)) return false;
  return typeof value.inviteId === 'string'
    && isByteArray(value.s)
    && typeof value.docId === 'string'
    && isByteArray(value.treeId)
    && typeof value.uuid === 'string'
    && isMemberRole(value.role)
    && isKeyringEngine(value.engine)
    && isByteArray(value.pin)
    && typeof value.memberId === 'string'
    && typeof value.selfMemberId === 'string';
}

/** @param {JoinStorage | null} storage @param {InviteId} inviteId @returns {StoredJoinContext | null} */
function loadJoinContext(storage, inviteId) {
  if (!storage) return null;
  let raw;
  try { raw = storage.getItem(JOIN_KEY(inviteId)); } catch { return null; }
  if (!raw) return null;
  try {
    const parsed = /** @type {unknown} */ (JSON.parse(raw));
    if (!isStoredJoinContext(parsed)) return null;
    return {
      inviteId: /** @type {InviteId} */ (parsed.inviteId),
      s: Uint8Array.from(parsed.s),
      docId: /** @type {DocId} */ (parsed.docId),
      treeId: /** @type {TreeId} */ (Uint8Array.from(parsed.treeId)),
      uuid: /** @type {TreeUuid} */ (parsed.uuid),
      role: parsed.role,
      engine: parsed.engine,
      pin: /** @type {InvitePinBytes} */ (Uint8Array.from(parsed.pin)),
      memberId: /** @type {MemberId} */ (parsed.memberId),
      selfMemberId: /** @type {MemberId} */ (parsed.selfMemberId),
    };
  } catch {
    return null;
  }
}

/** @param {JoinStorage | null} storage @param {InviteId} inviteId */
function clearJoinContext(storage, inviteId) {
  try { storage?.removeItem(JOIN_KEY(inviteId)); } catch { /* best-effort */ }
}

/**
 * OWNER: mint a share invite for the active tree and register it. Returns `{ inviteId, link }` — deliver `link`
 * (short: `#invite=<id>&s=<s>`) out of band. The `s_mac_claim` mint record is stored durably inside the worker.
 * @param {Pick<MembershipDeps, 'worker' | 'remote'>} deps
 * @param {{docId:DocId, treeId:TreeId, role:MemberRole, recipientPin?:string|null, ttlMs?:number, base?:string}} o
 */
export async function inviteMember({ worker, remote }, { docId, treeId, role, recipientPin = null, ttlMs, base }) {
  void treeId;
  const minted = await worker.inviteMember(docId, {
    role,
    recipientPin,
    ...(ttlMs === undefined ? {} : { ttlMs }),
    ...(base === undefined ? {} : { base }),
  });
  await remote.createInvite(docId, minted.pending);
  return { inviteId: minted.inviteId, link: minted.link };
}

/** OWNER: list this tree's pending invites + any submitted claims (each ready-to-admit item has a `claim`). */
/** @param {Pick<MembershipDeps, 'remote'>} deps @param {{ docId: DocId }} options */
export async function pendingInvites({ remote }, { docId }) {
  return remote.listInvites(docId);
}

/**
 * OWNER: admit a claimed invite. The worker verifies the claim's MAC + the anti-substitution admit gate, then
 * `addMember`s at the record's role. On success the server invite is MARKED ADMITTED (not deleted — the joiner
 * still needs `/meta` to complete). `claim` is the object from `pendingInvites`.
 * @param {Pick<MembershipDeps, 'worker' | 'remote'>} deps
 * @param {{docId:DocId, treeId:TreeId, ownerMemberId:MemberId, passphrase:Passphrase, inviteId:InviteId, claim:InviteClaim}} o
 */
export async function admitMember({ worker, remote }, { docId, treeId, ownerMemberId, passphrase, inviteId, claim }) {
  await worker.admitMember(docId, { passphrase, treeId, ownerMemberId, inviteId, claim });
  await remote.admitInvite(inviteId); // mark admitted; a scheduled sweep GCs it at expiry
}

/**
 * INVITEE step 1: parse the link, fetch + VERIFY the server metadata, mint this account's identity, seed the tree
 * identity, PERSIST the join context, then submit the claim. Returns the `joinContext` `completeJoin` needs. A
 * restart after this RESUMES from the persisted context (skips re-provision/re-claim). Throws `InviteUnavailable`
 * if the invite is gone/expired.
 * @param {MembershipDeps} deps
 * @param {{link:InviteLink, passphrase:Passphrase, memberId:MemberId}} o
 */
export async function submitJoinClaim(deps, { link, passphrase, memberId }) {
  const { worker, remote } = deps;
  const storage = storageOf(deps);
  const { inviteId, s } = parseLink(link);

  // Resume: an existing context for this invite+account means we already provisioned + claimed — reuse it (a
  // fresh provision would mint different keys the owner can't have admitted).
  const persisted = loadJoinContext(storage, inviteId);
  if (persisted && persisted.memberId === memberId) return { ...persisted, passphrase };

  const response = await remote.getInviteMeta(inviteId);
  if (response !== null && !isRecord(response)) throw new Error('invite metadata is malformed');
  const meta = response;
  if (!meta) throw new InviteUnavailable('this invite no longer exists or has expired');
  if (typeof meta.uuid !== 'string' || !isMemberRole(meta.role) || !isKeyringEngine(meta.engine)
    || !(meta.pin instanceof Uint8Array) || !(meta.metaMac instanceof Uint8Array)) {
    throw new Error('invite metadata is malformed');
  }
  const metaUuid = /** @type {TreeUuid} */ (meta.uuid);
  const metaPin = /** @type {InvitePinBytes} */ (meta.pin);
  const metaMac = /** @type {InviteMacBytes} */ (meta.metaMac);
  // UNCONDITIONAL, fail-closed: any tamper/missing field throws (there is no un-authenticated fallback).
  const verified = await verifyMeta({
    s, inviteId, uuid: metaUuid, role: meta.role, engine: meta.engine, pin: metaPin, metaMac,
  });
  const treeId = uuidToTreeId(verified.uuid);
  const prov = await worker.provisionMember(passphrase);
  seedTreeIdentity(memberId, { bytes: treeId, uuid: verified.uuid }, storage ? { storage } : undefined);
  // SELF-CERT identity (OPE-543): the on-tree member id is `prov.memberId` — derived from the durable account's
  // author key, NOT the caller's account label. The claim carries it (the owner admits under it) and the join
  // context persists it (`selfMemberId`) for `joinAsMember`; `memberId` stays the LOCAL label (resume matching
  // + the seeded tree identity).
  const claimMsg = await buildClaim({
    s, inviteId, uuid: verified.uuid, role: verified.role,
    memberId: prov.memberId, hpkePublicKey: prov.hpkePublicKey, authorPublicKey: prov.authorPublicKey,
  });

  const ctx = /** @type {StoredJoinContext} */ ({
    inviteId, s, docId: /** @type {DocId} */ (/** @type {unknown} */ (verified.uuid)), treeId, uuid: verified.uuid,
    role: verified.role, engine: verified.engine, pin: verified.pin, memberId, selfMemberId: prov.memberId,
  });
  // Persist BEFORE the claim: a crash right after the claim must resume with the SAME account identity, never re-provision.
  saveJoinContext(storage, ctx);
  try {
    await remote.claimInvite(claimMsg);
  } catch (e) {
    // Lost the one-live-claim race (someone else holds it) → terminal; drop the context so a retry starts clean.
    if (isRecord(e) && (e.code === 'version_conflict' || e.httpStatus === 409)) {
      clearJoinContext(storage, inviteId);
      throw new InviteUnavailable('this invite was already claimed by someone else');
    }
    clearJoinContext(storage, inviteId);
    throw e;
  }
  return { ...ctx, passphrase };
}

/**
 * INVITEE step 2: attach the transport and join — the worker verifies the keyring against the VERIFIED engine/pin
 * and unlocks. Throws `WaitingForApproval` (retry) while unadmitted, or `InviteUnavailable` if the invite is gone
 * (a terminal re-`/meta` check distinguishes them). On success the member core is open + the context is cleared.
 */
/** @param {MembershipDeps} deps @param {JoinContext} ctx */
export async function completeJoin(deps, ctx) {
  const { worker, attachTransport, remote } = deps;
  const storage = storageOf(deps);
  if (!attachTransport) throw new Error('completeJoin requires a transport attachment function');
  await attachTransport(ctx.docId);
  try {
    const res = await worker.joinAsMember({
      treeId: ctx.treeId, treeUuid: ctx.uuid, docId: ctx.docId, passphrase: ctx.passphrase,
      memberId: ctx.selfMemberId, engine: ctx.engine, pin: ctx.pin,
    });
    clearJoinContext(storage, ctx.inviteId); // joined — the resumable context is done
    return { docId: ctx.docId, treeId: ctx.treeId, didKey: res.didKey };
  } catch (e) {
    if (!isNotYetAdmitted(e)) throw e;
    // Pre-admit: distinguish a normal wait from a terminal state — re-check the invite still exists.
    const meta = await remote.getInviteMeta(ctx.inviteId).catch(() => null);
    if (!meta) {
      clearJoinContext(storage, ctx.inviteId);
      throw new InviteUnavailable('this invite was canceled or expired before approval');
    }
    throw new WaitingForApproval(ctx);
  }
}

/**
 * INVITEE convenience: the whole join in one call (claim + complete). If the owner hasn't admitted yet it throws
 * `WaitingForApproval`; the UI then polls `completeJoin(deps, err.context)` rather than re-calling this (which
 * would resume from the persisted context, not re-claim).
 */
/** @param {MembershipDeps} deps @param {{ link: InviteLink, passphrase: Passphrase, memberId: MemberId }} options */
export async function joinTree(deps, { link, passphrase, memberId }) {
  const ctx = await submitJoinClaim(deps, { link, passphrase, memberId });
  return completeJoin(deps, ctx);
}

export const _internal = { isNotYetAdmitted, JOIN_KEY, saveJoinContext, loadJoinContext };
