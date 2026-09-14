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

/**
 * A normal, expected pre-admit condition (NOT an error): the invitee has claimed but the owner hasn't admitted
 * yet, so the keyring isn't readable. The UI shows "waiting for approval" and polls `completeJoin(deps,
 * err.context)`. `context` carries everything a retry needs — no re-provision, no re-claim.
 */
export class WaitingForApproval extends Error {
  constructor(context) {
    super('waiting for the owner to approve this join');
    this.name = 'WaitingForApproval';
    this.context = context;
  }
}

/** A TERMINAL condition: the invite is gone (canceled/expired) or unusable — the UI must ask for a NEW invite,
 *  not keep waiting. */
export class InviteUnavailable extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'InviteUnavailable';
  }
}

// The keyring isn't readable yet because our ACL entry hasn't landed: the server 403s a non-member's keyring GET
// (→ access_denied), or serves an empty history (→ JoinError 'no keyring history'). Either is the pre-admit state.
function isNotYetAdmitted(e) {
  if (e?.code === 'access_denied' || e?.httpStatus === 403) return true;
  return e?.name === 'JoinError' && /no keyring history/i.test(e.message ?? '');
}

// --- durable invitee join context (survives a restart; keyed by invite_id) -------------------------------------
const storageOf = (deps) => deps.storage ?? (typeof localStorage !== 'undefined' ? localStorage : null);
const JOIN_KEY = (inviteId) => `openom:join-ctx:${inviteId}`;
const u8ify = (o, keys) => { const w = { ...o }; for (const k of keys) if (w[k]) w[k] = Array.from(w[k]); return w; };
const BYTE_FIELDS = ['s', 'memberKdfParams', 'pin'];

function saveJoinContext(storage, ctx) {
  if (!storage) return;
  // The passphrase is NEVER persisted — the UI re-supplies it on resume (it must match the provisioning one).
  const { passphrase, ...persist } = ctx;
  try { storage.setItem(JOIN_KEY(ctx.inviteId), JSON.stringify(u8ify(persist, BYTE_FIELDS))); } catch { /* no storage */ }
}
function loadJoinContext(storage, inviteId) {
  if (!storage) return null;
  let raw;
  try { raw = storage.getItem(JOIN_KEY(inviteId)); } catch { return null; }
  if (!raw) return null;
  const w = JSON.parse(raw);
  for (const k of BYTE_FIELDS) if (w[k]) w[k] = Uint8Array.from(w[k]);
  return w;
}
function clearJoinContext(storage, inviteId) {
  try { storage?.removeItem(JOIN_KEY(inviteId)); } catch { /* best-effort */ }
}

/**
 * OWNER: mint a share invite for the active tree and register it. Returns `{ inviteId, link }` — deliver `link`
 * (short: `#invite=<id>&s=<s>`) out of band. The `s_mac_claim` mint record is stored durably inside the worker.
 * @param {{worker:object, remote:object}} deps
 * @param {{docId:string, treeId:Uint8Array, role:string, recipientPin?:string|null, ttlMs?:number, base?:string}} o
 */
export async function inviteMember({ worker, remote }, { docId, treeId, role, recipientPin = null, ttlMs, base }) {
  const minted = await worker.inviteMember(docId, { treeId, role, recipientPin, ttlMs, base });
  await remote.createInvite(docId, minted.pending);
  return { inviteId: minted.inviteId, link: minted.link };
}

/** OWNER: list this tree's pending invites + any submitted claims (each ready-to-admit item has a `claim`). */
export async function pendingInvites({ remote }, { docId }) {
  return remote.listInvites(docId);
}

/**
 * OWNER: admit a claimed invite. The worker verifies the claim's MAC + the anti-substitution admit gate, then
 * `addMember`s at the record's role. On success the server invite is MARKED ADMITTED (not deleted — the joiner
 * still needs `/meta` to complete). `claim` is the object from `pendingInvites`.
 * @param {{worker:object, remote:object}} deps
 * @param {{docId:string, treeId:Uint8Array, ownerMemberId:string, passphrase:string, inviteId:string, claim:object}} o
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
 * @param {{worker:object, remote:object, storage?:object}} deps
 * @param {{link:string, passphrase:string, memberId:string}} o
 */
export async function submitJoinClaim(deps, { link, passphrase, memberId }) {
  const { worker, remote } = deps;
  const storage = storageOf(deps);
  const { inviteId, s } = parseLink(link);

  // Resume: an existing context for this invite+account means we already provisioned + claimed — reuse it (a
  // fresh provision would mint different keys the owner can't have admitted).
  const persisted = loadJoinContext(storage, inviteId);
  if (persisted && persisted.memberId === memberId) return { ...persisted, passphrase };

  const meta = await remote.getInviteMeta(inviteId);
  if (!meta) throw new InviteUnavailable('this invite no longer exists or has expired');
  // UNCONDITIONAL, fail-closed: any tamper/missing field throws (there is no un-authenticated fallback).
  const verified = await verifyMeta({
    s, inviteId, uuid: meta.uuid, role: meta.role, engine: meta.engine, pin: meta.pin, metaMac: meta.metaMac,
  });
  const treeId = uuidToTreeId(verified.uuid);
  const prov = await worker.provisionMember(passphrase);
  seedTreeIdentity(memberId, { bytes: treeId, uuid: verified.uuid }, storage ? { storage } : undefined);
  const claimMsg = await buildClaim({
    s, inviteId, uuid: verified.uuid, role: verified.role,
    memberId, hpkePublicKey: prov.hpkePublicKey, authorPublicKey: prov.authorPublicKey,
  });

  const ctx = {
    inviteId, s, docId: verified.uuid, treeId, uuid: verified.uuid, role: verified.role, engine: verified.engine,
    pin: verified.pin, memberId, memberKdfParams: prov.kdfParams,
  };
  // Persist BEFORE the claim: a crash right after the claim must resume with the SAME kdfParams, never re-provision.
  saveJoinContext(storage, ctx);
  try {
    await remote.claimInvite(claimMsg);
  } catch (e) {
    // Lost the one-live-claim race (someone else holds it) → terminal; drop the context so a retry starts clean.
    if (e?.code === 'version_conflict' || e?.httpStatus === 409) {
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
export async function completeJoin(deps, ctx) {
  const { worker, attachTransport, remote } = deps;
  const storage = storageOf(deps);
  await attachTransport(ctx.docId);
  try {
    const res = await worker.joinAsMember({
      treeId: ctx.treeId, treeUuid: ctx.uuid, docId: ctx.docId, passphrase: ctx.passphrase,
      memberId: ctx.memberId, memberKdfParams: ctx.memberKdfParams, engine: ctx.engine, pin: ctx.pin,
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
export async function joinTree(deps, { link, passphrase, memberId }) {
  const ctx = await submitJoinClaim(deps, { link, passphrase, memberId });
  return completeJoin(deps, ctx);
}

export const _internal = { isNotYetAdmitted, JOIN_KEY, saveJoinContext, loadJoinContext };
