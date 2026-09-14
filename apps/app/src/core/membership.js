// App-level Mode A membership orchestration (OPE-442) — the coherent invite / admit / join API the members-UI
// (OPE-10/416) binds to. It sits ABOVE the built crypto (worker `inviteMember`/`admitMember`/`provisionMember`/
// `joinAsMember` + the two-channel invite MAC in invite.js) and the built server routes (`/invites`,
// `/keyring`, `/access`), and wires them into the two-channel flow of plan/sharing/design.mode-a-client-flow.md.
//
// Split cleanly by role so a screen can drive either side without knowing the other:
//   * OWNER:  inviteMember → (deliver link OOB) → pendingInvites → admitMember.
//   * INVITEE: joinTree = submitJoinClaim (provision + claim) → completeJoin (genesis-walk verify + unlock).
//
// Every function takes explicit deps ({ worker, remote, attachTransport, storage }) so this orchestration is
// unit-testable with a server double + a stubbed worker, exactly like sharing.js. CHAIN engine today; the dag
// invite/join path is tracked as OPE-446 (both engines must ship). No DOM, no globals.

import { parseLink, claim as buildClaim } from './invite.js';
import { uuidToTreeId } from './keyringPublish.js';
import { seedTreeIdentity } from './treeId.js';

/**
 * A normal, expected pre-admit condition (NOT an error): the invitee has submitted its claim but the owner
 * has not admitted it yet, so the keyring channel isn't readable. The UI shows a "waiting for approval" state
 * and polls `completeJoin(deps, err.context)` until it resolves. `context` carries everything a retry needs —
 * no re-provision, no re-claim (which the server would reject as a duplicate live claim).
 */
export class WaitingForApproval extends Error {
  constructor(context) {
    super('waiting for the owner to approve this join');
    this.name = 'WaitingForApproval';
    this.context = context;
  }
}

// The keyring channel isn't readable yet because our ACL entry hasn't landed: the server 403s a non-member's
// keyring GET (→ an `access_denied` AppError), or it serves an empty history (→ JoinError 'no keyring history').
// Either way it's the pre-admit state, not a failure.
function isNotYetAdmitted(e) {
  if (e?.code === 'access_denied' || e?.httpStatus === 403) return true;
  return e?.name === 'JoinError' && /no keyring history/i.test(e.message ?? '');
}

/**
 * OWNER: mint a share invite for the active tree and register it on the server. Returns `{ inviteId, link, fp }` —
 * deliver `link` to the invitee out of band (email/WhatsApp); `fp` is the human-readable signer fingerprint for
 * an optional OOB cross-check. The `s_mac` mint record stays inside the worker for `admitMember`.
 *
 * @param {{worker:object, remote:object}} deps
 * @param {{docId:string, treeId:Uint8Array, role:string, recipientPin?:string|null, ttlMs?:number, base?:string}} o
 */
export async function inviteMember({ worker, remote }, { docId, treeId, role, recipientPin = null, ttlMs, base }) {
  const minted = await worker.inviteMember(docId, { treeId, role, recipientPin, ttlMs, base });
  // Register the pending invite (public metadata only — no secret) so the invitee's claim has somewhere to land.
  // If this fails the mint record is a harmless orphan in the worker; the owner just re-invites.
  await remote.createInvite(docId, minted.pending);
  return { inviteId: minted.inviteId, link: minted.link, fp: minted.fp };
}

/**
 * OWNER: list this tree's pending invites and any submitted claims. Each is `{ inviteId, role, recipientPin,
 * expiry, status, claim }`; a non-null `claim` (`{ memberId, hpkePublicKey, authorPublicKey, tag }`) is ready to
 * admit. The MAC is verified inside `admitMember` against the local mint record — never trusted from this list.
 */
export async function pendingInvites({ remote }, { docId }) {
  return remote.listInvites(docId);
}

/**
 * OWNER: admit a claimed invite. The worker verifies the claim's MAC against the local mint record + recomputes
 * the signer fingerprint (refusing a since-mint signer change), then `addMember`s at the role from the record.
 * On success the server invite is consumed. `claim` is the object from `pendingInvites`.
 *
 * @param {{worker:object, remote:object}} deps
 * @param {{docId:string, treeId:Uint8Array, ownerMemberId:string, passphrase:string, inviteId:string, claim:object}} o
 */
export async function admitMember({ worker, remote }, { docId, treeId, ownerMemberId, passphrase, inviteId, claim }) {
  await worker.admitMember(docId, { passphrase, treeId, ownerMemberId, inviteId, claim });
  // Consume the invite (idempotent server-side). Best-effort: a failure here leaves a CLAIMED row the owner can
  // delete later; the membership change itself already landed.
  await remote.deleteInvite(inviteId);
}

/**
 * INVITEE step 1: parse the link, mint this account's member identity, seed the tree identity from the link, and
 * submit the MAC'd public-key claim to the server. Returns the `joinContext` `completeJoin` needs — nothing here
 * is a secret beyond the passphrase the caller already holds. `memberId` is the account's id (its JWT sub).
 *
 * @param {{worker:object, remote:object, storage?:object}} deps
 * @param {{link:string, passphrase:string, memberId:string}} o
 */
export async function submitJoinClaim({ worker, remote, storage }, { link, passphrase, memberId }) {
  const parsed = parseLink(link); // { uuid, inviteId, s, fp, role, pinnedRevision, pinnedHash }
  const treeId = uuidToTreeId(parsed.uuid);
  // Mint the member's account identity (signing + HPKE keys stay in the worker; kdfParams come back to re-derive
  // them at join). Seed the tree identity from the link so this member syncs the OWNER's tree, not a fresh one.
  const prov = await worker.provisionMember(passphrase);
  seedTreeIdentity(memberId, { bytes: treeId, uuid: parsed.uuid }, storage ? { storage } : undefined);
  // Authenticate our keys to the owner with s_mac (derived from the link's `s`) and hand the claim to the server.
  const claimMsg = await buildClaim({
    s: parsed.s,
    inviteId: parsed.inviteId,
    uuid: parsed.uuid,
    role: parsed.role,
    memberId,
    hpkePublicKey: prov.hpkePublicKey,
    authorPublicKey: prov.authorPublicKey,
  });
  await remote.claimInvite(claimMsg);
  return {
    docId: parsed.uuid,
    treeId,
    treeUuid: parsed.uuid,
    passphrase,
    memberId,
    memberKdfParams: prov.kdfParams,
    pinnedRevision: parsed.pinnedRevision,
    pinnedHash: parsed.pinnedHash,
    fp: parsed.fp,
    engine: 'chain',
  };
}

/**
 * INVITEE step 2: attach the transport and join — genesis-walk verify the keyring from the invite pin, retain
 * every revision, and unlock as the member (opening the durable member core in the worker). Throws
 * `WaitingForApproval` (carrying `ctx` to retry) if the owner hasn't admitted yet — the UI polls this. Returns
 * `{ docId, treeId, didKey }`. `attachTransport(docId)` must wire the worker's transport for `docId`.
 */
export async function completeJoin({ worker, attachTransport }, ctx) {
  await attachTransport(ctx.docId);
  try {
    const res = await worker.joinAsMember({
      treeId: ctx.treeId,
      treeUuid: ctx.treeUuid,
      docId: ctx.docId,
      passphrase: ctx.passphrase,
      memberId: ctx.memberId,
      memberKdfParams: ctx.memberKdfParams,
      pinnedRevision: ctx.pinnedRevision,
      pinnedHash: ctx.pinnedHash,
      fp: ctx.fp,
      engine: ctx.engine ?? 'chain',
    });
    return { docId: ctx.docId, treeId: ctx.treeId, didKey: res.didKey };
  } catch (e) {
    if (isNotYetAdmitted(e)) throw new WaitingForApproval(ctx);
    throw e;
  }
}

/**
 * INVITEE convenience: the whole join in one call (claim + complete) — for the synchronous path and tests. If the
 * owner hasn't admitted yet it throws `WaitingForApproval`; the UI then polls `completeJoin(deps, err.context)`
 * rather than re-calling this (which would re-submit the claim and be rejected as a duplicate).
 */
export async function joinTree(deps, { link, passphrase, memberId }) {
  const ctx = await submitJoinClaim(deps, { link, passphrase, memberId });
  return completeJoin(deps, ctx);
}

export const _internal = { isNotYetAdmitted };
