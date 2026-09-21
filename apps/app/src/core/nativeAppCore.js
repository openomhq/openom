// The NATIVE-mode app-core client (OPE-427 Full-A / OPE-429): under Tauri, the DEK + claim engine + local
// store all run natively in the Rust host, and this object drives them over `invoke` — presenting the SAME
// method surface `appCore.worker.js` exposes over Comlink, so `main.js` doesn't know whether it's talking to
// the wasm worker (web) or the native host (Tauri). The web build keeps using the worker; `appCoreWorker()`
// picks between them on `__TAURI__`.
//
// Conventions (must match apps/src-tauri/src/lib.rs):
//  - invoke arg keys are camelCase; Tauri maps them to the snake_case Rust params.
//  - byte arguments (ids, keyrings, hops) cross as number arrays (`Array.from`), Vec<u8> the other way.
//  - result structs derive serde camelCase, so fields arrive as recoveryCode/didKey/… already.
//  - open/join do NOT hydrate on the host, so this client bootstraps after them (as the worker's
//    openTree does its import+bootstrap) — a no-op on a fresh provision.
//
// STATUS: the local-first lifecycle (provision/unlock/recover/change-passphrase + all claim edits + reads +
// membership) is complete and matches the command surface. The sync path (attachTransport/syncNow) is a
// best-effort port of the worker tick and is the runtime-iteration target — it is only reached when a managed
// backend is configured (startSync() early-returns local-only), so it never blocks the local flow.

import { makeError, normalizeUnknown } from './errorModel.js';
import { frameHops } from './sharing.js';
import { mint as mintInvite, verifyClaim as verifyInviteClaim, signerIds, signersRetained } from './invite.js';
import { pushMembershipSummary } from './membershipSummary.js';

const invoke = () => globalThis.__TAURI__?.core?.invoke;

/** Is this a Tauri (native-host) runtime? */
export function isNativeHost() {
  return typeof globalThis.__TAURI__?.core?.invoke === 'function';
}

// A Vec<u8> argument as the number array Tauri deserializes; passes strings/undefined through untouched.
const bytes = (x) => (x == null ? x : Array.from(x));
// A Vec<u8> result (number array) back to a Uint8Array, the shape the web code expects for keyring bytes.
const u8 = (x) => (x == null ? x : x instanceof Uint8Array ? x : new Uint8Array(x));
// The remote (per-tree) blob-key prefix: the 16 tree-id bytes as lowercase hex — the same mapping main.js uses
// for the tree UUID's byte seam (the worker's `treeKey`). The core's LOCAL keyspace is `{docId}/…`; the shared
// REMOTE is `{treeKey}/…`, so the sync tick re-keys between them (exactly as appCore.worker.js does).
const hexKey = (treeId) => Array.from(treeId, (b) => b.toString(16).padStart(2, '0')).join('');

// OPE-407 durable create-tree marker (native mirror of the web worker's IndexedDB marker): this device
// PROVISIONED a new tree whose server `trees` row may not exist yet. Set at provision, consumed on the first
// sync tick that reaches the server. Durable via the webview's localStorage so an offline provision that RESTARTS
// before it ever synced still mints the tree on a later tick rather than 404ing forever. A JOINing member never
// sets it (it adopts a tree the owner already created), so a member never calls createTree — no 403 to swallow.
const NEEDS_TREE_KEY = (docId) => `openom:${docId}:needs-create-tree`;
const lstore = () => { try { return globalThis.localStorage ?? null; } catch { return null; } };

export function createNativeAppCore() {
  const call = (cmd, args) => {
    const inv = invoke();
    if (!inv) return Promise.reject(makeError('internal', { cause: 'native host unavailable (no __TAURI__.core.invoke)' }));
    return inv(cmd, args).catch((raw) => {
      // Tauri rejects our Err(String) with a structured {code,message} JSON — map it to the SAME AppError the
      // wasm worker throws (via makeError), so the gate's rollback/tamper/wrong-passphrase distinctions and the
      // sync driver's retriable/auth classification survive on native (design-review C1). Anything else falls
      // through to the generic normalizer.
      let parsed = null;
      if (typeof raw === 'string') { try { parsed = JSON.parse(raw); } catch { parsed = null; } }
      else if (raw && typeof raw === 'object') parsed = raw;
      if (parsed && typeof parsed.code === 'string') throw makeError(parsed.code, { cause: parsed.message });
      throw normalizeUnknown(raw);
    });
  };

  // Per-doc network transport (set by attachTransport) + the doc→treeKey map (the remote keyspace prefix,
  // recorded whenever a doc is opened) + a single-flight sync guard + the once-per-session create-tree gate.
  const transports = new Map();
  const treeKeys = new Map();
  const treeIds = new Map(); // doc → the RAW 16 tree-id bytes (keyring-before-data needs them, not just the hex key)
  const syncing = new Map();
  const treeEnsured = new Set();
  const reportedFrontier = new Map(); // last pull-frontier reported per doc (change-guard for the GC telemetry)
  const remember = (docId, treeId) => {
    treeKeys.set(docId, hexKey(treeId));
    treeIds.set(docId, treeId);
  };

  // The create-tree marker, localStorage-backed with an in-memory fallback so create-tree is never silently
  // disabled when storage is unavailable (private mode) — the fallback still gives within-session retry.
  const needsTreeMem = new Set();
  const markNeedsCreateTree = (docId) => { needsTreeMem.add(docId); try { lstore()?.setItem(NEEDS_TREE_KEY(docId), '1'); } catch { /* no storage */ } };
  const needsCreateTree = (docId) => { if (needsTreeMem.has(docId)) return true; try { return lstore()?.getItem(NEEDS_TREE_KEY(docId)) === '1'; } catch { return false; } };
  const clearNeedsCreateTree = (docId) => { needsTreeMem.delete(docId); try { lstore()?.removeItem(NEEDS_TREE_KEY(docId)); } catch { /* best-effort */ } };

  // Owner-local DURABLE invite mint records (invite model v3), keyed by invite_id in the webview's localStorage —
  // a refresh must not orphan outstanding invites (admit hard-fails without the record; the flow spans
  // hours-days). Holds `s_mac_claim` + role/engine/expiry + the mint-time flat signer set (the chain admit gate).
  // The whole serialized record is DEK-SEALED at rest under the tree DEK (OPE-453, core_seal_app_secret) —
  // `s_mac_claim` is a secret (it forges that invite's claim MAC), so localStorage holds the ciphertext (as a
  // JSON byte array), never the plaintext. NEVER sent to the host over the wire in the clear or to the server.
  // Mirrors the web worker's IndexedDB mint record — different store (main thread), same purpose.
  const MINT_KEY = (inviteId) => `openom:invite-mint:${inviteId}`;
  const saveMintRecord = async (docId, rec) => {
    const plaintext = new TextEncoder().encode(JSON.stringify({ ...rec, sMacClaim: Array.from(rec.sMacClaim) }));
    const sealed = u8(await call('core_seal_app_secret', { doc: docId, bytes: bytes(plaintext) }));
    try { lstore()?.setItem(MINT_KEY(rec.inviteId), JSON.stringify(Array.from(sealed))); } catch { /* no storage */ }
  };
  const loadMintRecord = async (docId, inviteId) => {
    let raw;
    try { raw = lstore()?.getItem(MINT_KEY(inviteId)); } catch { return null; }
    if (!raw) return null;
    const plaintext = u8(await call('core_open_app_secret', { doc: docId, sealed: JSON.parse(raw) }));
    const o = JSON.parse(new TextDecoder().decode(plaintext));
    return { ...o, sMacClaim: Uint8Array.from(o.sMacClaim) };
  };
  const deleteMintRecord = (inviteId) => { try { lstore()?.removeItem(MINT_KEY(inviteId)); } catch { /* best-effort */ } };

  // Publish a membership change to the server (OPE-433/434, review C2): the KEYRING channel (the crypto
  // revocation — the server serves the rotated keyring, so a removed member can no longer decrypt new content)
  // and the advisory /access summary (the coarse ACL). Best-effort + ordered to UNDER-grant (add/promote:
  // keyring→advisory; remove/demote: advisory→keyring — a crash between leaves the ACL more restrictive than
  // the crypto, never less). Both read the NATIVE keyring (never a webview-supplied one). The advisory CAS/
  // generation retry and the PULL side (keyring-before-data adoption on sync) are runtime-verified follow-ups
  // tracked on OPE-433/434.
  // Byte-array equality (the server's served raw keyring bytes vs our retained body — both plain number arrays).
  const u8eq = (a, b) => !!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]);

  // Publish this device's produced CHAIN keyring TAIL: walk server-head+1 .. local-head and PUT each wrapped
  // revision in ascending single-hop order (the server admits only revision == head+1, so a single-head PUT
  // can't bridge a >1 gap, and a solo tree's genesis must land before any share can be verified). Idempotent: a
  // 409 whose served bytes equal ours is benign (already admitted), differing bytes are a fork (surfaced).
  async function publishKeyringTail(docId) {
    const transport = transports.get(docId);
    const localHead = await call('core_keyring_head', { doc: docId }); // chain-only; a dag call rejects → caught by caller
    if (localHead === 0) return;
    const serverHead = (await transport.readKeyring(docId, localHead)).head ?? 0;
    for (let rev = serverHead + 1; rev <= localHead; rev += 1) {
      const { update, body } = await call('core_keyring_publish_payload_at', { doc: docId, revision: rev });
      try {
        await transport.putKeyring(docId, new Uint8Array(update));
      } catch (e) {
        if (e?.name === 'ConflictError') {
          const served = (await transport.readKeyring(docId, rev)).revisions?.[0]?.bytes;
          if (served && u8eq(Array.from(served), body)) continue; // already admitted with our bytes — benign
          throw makeError('keyring_verify_failed', { cause: `keyring fork at revision ${rev}` });
        }
        throw e;
      }
    }
  }

  // Assert the advisory /access summary under the server's CAS on `generation` (getAccess → PUT → retry-on-409),
  // via the SAME shared helper the web worker uses (membershipSummary.js) — not the naive no-generation PUT that
  // 409s on every push after the first.
  async function pushAdvisory(docId) {
    const transport = transports.get(docId);
    const s = JSON.parse(await call('core_membership_summary', { doc: docId }));
    await pushMembershipSummary(transport, docId, { view: s.members, basis: s.basis });
  }

  async function publishAfterMembership(docId, advisoryFirst) {
    const transport = transports.get(docId);
    if (!transport) return; // local-only: nothing to publish
    try {
      if (advisoryFirst) { await pushAdvisory(docId); await publishKeyringTail(docId); }
      else { await publishKeyringTail(docId); await pushAdvisory(docId); }
    } catch (err) {
      // The local keyring change stands (native custody is authoritative); the sync tick re-derives it from
      // local-head > server-head and retries — no durable flag needed.
      console.warn('[openom] native membership publish (best-effort) failed', err);
    }
  }

  const api = {
    // --- session lifecycle (host owns the DEK; no engine arg — the host picks it) ---
    ping: () => Promise.resolve(true), // the native host is in-process; always alive
    warm: () => Promise.resolve(), // nothing to preload
    hasKeyring: (docId) => call('core_has_keyring', { doc: docId }),

    accountCreate: (passphrase) => call('account_create', { passphrase }),
    accountUnlock: (passphrase) => call('account_unlock', { passphrase }),
    accountStatus: () => call('account_status'),
    accountLock: () => call('account_lock'),
    accountRecover: ({ recoveryCode, newPassphrase }) =>
      call('account_recover', { recoveryCode, newPassphrase }),
    async accountChangePassphrase({ current, next }) {
      await api.accountUnlock(current);
      const changed = await call('account_change_passphrase', { newPassphrase: next });
      return { recoveryCode: '', ...changed };
    },
    accountPublicIdentity: () => call('account_public_identity'),
    accountRotateRoot: ({ passphrase }) => call('account_rotate_root', { passphrase }),
    accountRegisterProof: ({ issuer, subject, timestamp }) =>
      call('account_register_proof', { issuer, subject, timestamp }),

    async provisionTree({ treeId, docId }) {
      remember(docId, treeId);
      markNeedsCreateTree(docId); // owner-only: a new tree whose server row the first tick must mint
      return call('core_provision', { doc: docId, treeId: bytes(treeId) });
    },

    async provisionCore({ passphrase, treeId, docId }) {
      let account;
      try {
        const opened = await api.accountCreate(passphrase);
        account = { ...opened, ...(await api.accountPublicIdentity()) };
      } catch {
        account = await api.accountUnlock(passphrase);
      }
      return { ...account, ...(await api.provisionTree({ treeId, docId })) };
    },

    async openTree({ treeId, docId }) {
      remember(docId, treeId);
      const out = await call('core_unlock', { doc: docId, treeId: bytes(treeId) });
      await call('core_bootstrap', { doc: docId });
      return out;
    },

    async unlockCore({ passphrase, treeId, docId }) {
      await api.accountUnlock(passphrase);
      return api.openTree({ treeId, docId });
    },

    async recoverCore({ recoveryCode, newPassphrase, treeId, docId }) {
      const account = await api.accountRecover({ recoveryCode, newPassphrase });
      return { ...account, ...(await api.openTree({ treeId, docId })) };
    },

    changePassphraseCore: ({ current, next }) =>
      api.accountChangePassphrase({ current, next }),

    // The demo/dev core (reserved dev key) is web-only — the native host has no keyless dev path.
    openDev: () => Promise.reject(new Error('the demo (dev) core is not available on the native host')),

    resetCore: (docId) => call('core_reset', { doc: docId }),
    close: (docId) => {
      transports.delete(docId);
      treeKeys.delete(docId);
      treeIds.delete(docId);
      treeEnsured.delete(docId);
      reportedFrontier.delete(docId);
      return call('core_close', { doc: docId });
    },

    // --- claim edits (buffered; commit seals them) ---
    assertAnchor: (docId, id, typeUri) => call('core_assert_anchor', { doc: docId, id, typeUri }),
    assertClaim: (docId, target, predicate, valueJson) =>
      call('core_assert_claim', { doc: docId, target, predicate, valueJson }),
    supersedeClaim: (docId, prior, target, predicate, valueJson) =>
      call('core_supersede_claim', { doc: docId, prior, target, predicate, valueJson }),
    removeRecord: (docId, target) => call('core_remove_record', { doc: docId, target }),
    revoke: (docId, removalOpId) => call('core_revoke', { doc: docId, removalOpId }),
    commit: (docId) => call('core_commit', { doc: docId }),
    setModerators: (docId, dids) => call('core_set_moderators', { doc: docId, moderators: dids }),

    // --- collaborative writes: editor propose / maintainer approve (OPE-360) ---
    /** The write-side role pre-check (UX guard): whether this device may commit directly, or must propose. */
    canCommitDirectly: (docId) => call('core_can_commit_directly', { doc: docId }),

    /** Submit a pending edit, routing on role: a maintainer (or solo) commits directly; an editor's edit
     *  becomes a proposal. Returns { committed: true } or { proposed: true, proposal }. */
    async submitEdit(docId) {
      if (await call('core_can_commit_directly', { doc: docId })) {
        await this.commit(docId);
        return { committed: true };
      }
      const proposal = await this.proposeEdit(docId);
      return { proposed: true, proposal };
    },

    /** Editor: seal the pending intention as a proposal and POST it to the proposals channel for a maintainer
     *  to review. Returns the server-minted `{ id, expiresAt }`, or null if nothing was minted. The ops stay
     *  optimistically applied locally but are not committed until an approval lands. */
    async proposeEdit(docId) {
      const sealed = u8(await call('core_propose', { doc: docId }));
      if (!sealed || sealed.length === 0) return null;
      const transport = transports.get(docId);
      if (!transport) throw makeError('internal', { cause: `proposeEdit: no transport attached for ${docId}` });
      return transport.createProposal(treeKeys.get(docId), sealed);
    },
    /** Maintainer: the open proposals to review, as [{ id, proposer, sizeBytes, createdAt, expiresAt }]. */
    async pendingProposals(docId) {
      const transport = transports.get(docId);
      if (!transport) return [];
      const list = await transport.listProposals(treeKeys.get(docId));
      return list.map(({ id, proposer, sizeBytes, createdAt, expiresAt }) => ({
        id, proposer, sizeBytes, createdAt, expiresAt,
      }));
    },

    /** Maintainer: verify proposal `proposalId` and commit it as an attributed delta, then delete it from the
     *  channel. Returns the number of ops committed. Throws on a forged/misattributed proposal (not deleted). */
    async approveProposal(docId, proposalId) {
      const transport = transports.get(docId);
      if (!transport) throw makeError('internal', { cause: `approveProposal: no transport attached for ${docId}` });
      const treeKey = treeKeys.get(docId);
      const p = (await transport.listProposals(treeKey)).find((x) => x.id === proposalId);
      if (!p) throw makeError('internal', { cause: `approveProposal: proposal ${proposalId} not found` });
      const committed = await call('core_approve_proposal', { doc: docId, proposal: bytes(p.payload) });
      await transport.deleteProposal(treeKey, proposalId);
      return committed;
    },

    /** Reject a proposal (maintainer, or the proposer): delete it from the channel without committing. */
    async rejectProposal(docId, proposalId) {
      const transport = transports.get(docId);
      if (!transport) throw makeError('internal', { cause: `rejectProposal: no transport attached for ${docId}` });
      return transport.deleteProposal(treeKeys.get(docId), proposalId);
    },

    /** The change-history activity feed: per-change records `{ author, createdAt, replica, counter, size,
     *  viewable, ops }`. The host decrypts each retained delta; an unreachable-epoch delta is viewable: false. */
    async history(docId, opts = {}) {
      const transport = transports.get(docId);
      if (!transport) return { entries: [], nextCursor: null };
      const treeKey = treeKeys.get(docId);
      const feed = await transport.getHistory(treeKey, opts);
      const entries = [];
      for (const e of feed.entries) {
        let ops = null;
        let viewable = false;
        try {
          const sealed = u8(await transport.blobGet(`${treeKey}/log/${e.replica}/${e.counter}`));
          if (sealed && sealed.length) {
            ops = JSON.parse(await call('core_open_history_delta', { doc: docId, envelope: bytes(sealed) }));
            viewable = true;
          }
        } catch {
          /* reaped, or an epoch this member can't reach → an un-viewable change */
        }
        entries.push({
          author: e.memberId, createdAt: e.createdAt, replica: e.replica, counter: e.counter, size: e.size, viewable, ops,
        });
      }
      return { entries, nextCursor: feed.nextCursor };
    },

    // --- reads (JSON strings the web code JSON.parses, matching the wasm veneer) ---
    project: (docId) => call('core_project', { doc: docId }),
    oplog: (docId) => call('core_oplog', { doc: docId }),
    liveRecords: (docId) => call('core_live_records', { doc: docId }),
    liveClaimsOf: (docId, target, predicate) =>
      call('core_live_claims_of', { doc: docId, target, predicate }),
    liveClaimsOfAny: (docId, target) => call('core_live_claims_of_any', { doc: docId, target }),
    resolveId: (docId, anchor) => call('core_resolve_id', { doc: docId, anchor }),
    pendingCount: (docId) => call('core_pending_count', { doc: docId }),
    anomalies: (docId) => call('core_anomalies', { doc: docId }),

    // --- soft-removal review queue (OPE-426) ---
    pendingReviews: async (docId) => JSON.parse(await call('core_pending_reviews', { doc: docId })),
    approvePending: (docId, { replica, counter }) =>
      call('core_approve_pending', { doc: docId, replica, counter }),
    discardPending: (docId, { replica, counter }) =>
      call('core_discard_pending', { doc: docId, replica, counter }),

    // --- membership / sharing (owner + member) ---
    provisionMember: async (passphrase) => {
      let account;
      try {
        account = await api.accountUnlock(passphrase);
      } catch {
        account = await api.accountCreate(passphrase);
      }
      const m = await api.accountPublicIdentity();
      const authorPublicKey = u8(m.authorPublicKey);
      // SELF-CERT identity (OPE-543): the on-tree id derives from the author key IN RUST (core_derive_member_id)
      // — same single-source derivation as the worker's wasm `deriveMemberId`, never re-implemented in JS.
      return {
        memberId: await call('core_derive_member_id', { authorPublicKey }),
        kdfParams: null, authorPublicKey, hpkePublicKey: u8(m.hpkePublicKey),
        recoveryCode: account?.recoveryCode ?? '',
      };
    },
    // Owner: mint a v3 share invite. The host supplies the engine pin (core_invite_material); the mint-time signer
    // fingerprint (the admit-gate baseline) comes from the engine-agnostic keyring summary; `invite.mint` (pure JS)
    // builds the short link + authenticated metadata; the record is persisted durably.
    async inviteMember(docId, { role, recipientPin = null, ttlMs, base }) {
      const material = await call('core_invite_material', { doc: docId }); // { engine, pin }
      const summary = JSON.parse(await call('core_membership_summary', { doc: docId }));
      const mintSigners = signerIds(summary.members);
      const minted = await mintInvite({
        uuid: docId, role, engine: material.engine, pin: u8(material.pin), recipientPin,
        ...(ttlMs ? { ttlMs } : {}), ...(base ? { base } : {}),
      });
      await saveMintRecord(docId, { ...minted.record, signerIds: mintSigners });
      return { inviteId: minted.inviteId, link: minted.link, pending: minted.pending };
    },
    // Owner: admit a claimed invite — durable record + local expiry re-check + the anti-substitution admit gate
    // for BOTH engines (REMOVAL-ONLY: refuse if a mint-time signer is no longer a signer — e.g. a soon-to-be-
    // removed co-owner pre-minting an invite for themselves; tolerate signers ADDED since mint), then verify the
    // claim MAC + addMember at the record's role. The caller MARKS the server invite admitted.
    async admitMember(docId, { passphrase, treeId, ownerMemberId, inviteId, claim }) {
      const record = await loadMintRecord(docId, inviteId);
      if (!record) throw makeError('internal', { cause: 'no local mint record for this invite — admit on the minting device' });
      if (Date.now() > record.expiry) throw makeError('internal', { cause: 'invite expired' });
      const summary = JSON.parse(await call('core_membership_summary', { doc: docId }));
      if (!signersRetained(record.signerIds, summary.members)) {
        throw makeError('internal', { cause: 'a signer was removed since mint — cancel and re-invite' });
      }
      if (!(await verifyInviteClaim(record, claim))) throw makeError('internal', { cause: 'invite claim MAC mismatch — rejected' });
      // SELF-CERT admission (OPE-543): derive the joiner's on-tree id from their claimed author key IN RUST —
      // never trust the claim's id (the host re-derives it too; identical single source as the worker).
      await api.addMember(docId, {
        passphrase, treeId, ownerMemberId,
        newMemberId: await call('core_derive_member_id', { authorPublicKey: claim.authorPublicKey }), role: record.role,
        memberAuthorPublic: claim.authorPublicKey, memberHpkePublic: claim.hpkePublicKey,
      });
      deleteMintRecord(inviteId);
    },
    async addMember(docId, { treeId, ownerMemberId, newMemberId, role, memberAuthorPublic, memberHpkePublic }) {
      const out = await call('core_add_member', {
        doc: docId, treeId: bytes(treeId),
        member: { memberId: newMemberId, role, authorPublicKey: bytes(memberAuthorPublic), hpkePublicKey: bytes(memberHpkePublic) },
      });
      await publishAfterMembership(docId, false); // add: keyring-first, then advisory
      // First-share ordered base seal (OPE-360 §5): on the solo→shared transition, force a compacting data sync
      // so the owner's pre-share history is sealed into a member-signed base snapshot + pushed — else a joiner
      // rejects the raw unsigned pre-share deltas and sees an empty tree. Best-effort: a later tick re-seals.
      if (out.firstShare && transports.get(docId)) {
        try { await this.syncNow(docId, 1); } catch { /* best-effort; the next tick compacts + pushes the base */ }
      }
      return { keyring: u8(out.keyring) };
    },
    async removeMember(docId, { treeId, removeMemberId }) {
      const out = await call('core_remove_member', {
        doc: docId, treeId: bytes(treeId), removeMemberId,
      });
      await publishAfterMembership(docId, true); // remove: advisory-first, then the rotated keyring
      return { keyring: u8(out.keyring), historyPreserved: out.historyPreserved };
    },
    async changeRole(docId, { treeId, targetMemberId, newRole }) {
      const out = await call('core_change_role', {
        doc: docId, treeId: bytes(treeId), targetMemberId, newRole,
      });
      await publishAfterMembership(docId, out.demote); // demote: advisory-first; promote: keyring-first
      return { keyring: u8(out.keyring), demote: out.demote };
    },
    // Fetches the keyring genesis-walk itself (transport.readKeyring → frameHops), so this presents the SAME
    // contract as the web worker's joinAsMember — the caller no longer pre-fetches `hops`. The transport must be
    // attached for `docId` first (attachTransport). Closes the OPE-434 join hops-fetch parity gap.
    async joinAsMember({ docId, treeId, passphrase, engine, pin, pinnedRevision, pinnedHash }) {
      remember(docId, treeId);
      await api.accountUnlock(passphrase);
      const transport = transports.get(docId);
      if (!transport) {
        return Promise.reject(makeError('internal', { cause: `joinAsMember: no transport attached for ${docId}` }));
      }
      if (engine === 'dag') {
        // Dag: the highest served revision is the self-contained anchor; the host verifies it against the OOB pin
        // (the v3 dag pin) and unlocks. No genesis-walk framing.
        const { revisions } = await transport.readKeyring(docId, 1);
        if (!revisions || revisions.length === 0) {
          return Promise.reject(makeError('internal', { cause: 'no keyring anchor to verify' }));
        }
        const anchor = revisions[revisions.length - 1].bytes;
        const out = await call('core_join_dag_anchor', {
          doc: docId, treeId: bytes(treeId), anchor: bytes(anchor), pin: bytes(u8(pin)),
        });
        await call('core_bootstrap', { doc: docId });
        return out;
      }
      // v3 chain: unpack the opaque pin (rev(u32 BE)‖kh(32) = 36 bytes) into (revision, hash); a low-level caller
      // may instead pass them already unpacked.
      if (pin !== undefined) {
        const p = u8(pin);
        if (p.length !== 36) return Promise.reject(makeError('internal', { cause: 'chain invite pin must be 36 bytes' }));
        pinnedRevision = new DataView(p.buffer, p.byteOffset, 4).getUint32(0, false);
        pinnedHash = p.slice(4);
      }
      const { revisions } = await transport.readKeyring(docId, 1); // the full walk from genesis (rev 1)
      const hops = frameHops((revisions ?? []).map((r) => r.bytes));
      const out = await call('core_join_as_member', {
        doc: docId, treeId: bytes(treeId), hops: bytes(hops), pinnedRevision, pinnedHash: bytes(pinnedHash),
      });
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    syncKeyring: (docId, treeId, hops) =>
      call('core_sync_keyring', { doc: docId, treeId: bytes(treeId), hops: bytes(hops) }),

    // --- sync (only reached when a managed backend is configured — startSync() is local-only otherwise) ---
    attachTransport(docId, transport) {
      transports.set(docId, transport);
    },
    // The DATA-channel tick, ported faithfully from appCore.worker.js::syncData: fetch the shared remote (under
    // the per-tree `{treeKey}/` prefix), re-key it into the core's local `{docId}/` namespace, hand it to
    // core_sync (which mirrors in, folds, compacts, and returns the diff to push — each upload carrying the
    // CORE's pointer flag, never a key this side inspects — plus the covered frontier), then re-key each upload
    // back and PUT it (the snapshot carries the covered GC header). Single-flight; failures degrade to
    // {state:'error'} (the driver treats that as offline), never a crash.
    //
    // The tick keeps the keyring in sync BEFORE folding data (chain): if the server is ahead it adopts the
    // successors (so arrivals verify against the current membership); if this device is ahead it republishes the
    // missing tail + advisory — both derived from local-head vs server-head in one readKeyring, no marker. So a
    // shared tree's members adopt rotations AND an owner's first-share / retried publish converge on sync, like
    // the web. (Dag adoption on the tick is the anchor-merge path, not wired — a dag keyring call rejects, caught.)
    async syncNow(docId, compactK = 8) {
      const transport = transports.get(docId);
      const treeKey = treeKeys.get(docId);
      if (!transport || !treeKey) return { state: 'no-transport' };
      if (syncing.get(docId)) return { state: 'busy' };
      syncing.set(docId, true);
      try {
        // First push per session: mint this owner's server `trees` row (OPE-407). Gated on the durable marker
        // that ONLY the provisioning owner set — a joining member skips this entirely (no createTree, so no 403
        // to swallow). A real failure (offline / entitlement / auth / 5xx) is NOT swallowed: createTree throws,
        // which propagates to the tick's catch → {state:'error'} → the driver retries, and because treeEnsured
        // stays false and the marker stays set (cleared only on success), a later tick / restart retries too.
        // Idempotent for the owner (a returning device re-POSTs and gets a 2xx no-op).
        if (!treeEnsured.has(docId)) {
          if (needsCreateTree(docId)) {
            await transport.createTree(docId);
            clearNeedsCreateTree(docId);
          }
          treeEnsured.add(docId);
        }
        // KEYRING sync, derived from local-head vs server-head in ONE readKeyring (chain only — a dag call
        // rejects, caught below). If the server is AHEAD: adopt its successors BEFORE folding data, so a shared
        // tree's arrivals verify against the CURRENT membership (keyring-before-data). If WE are ahead (a produced
        // revision the server hasn't seen — a first share, or an earlier publish that failed): republish the tail
        // + advisory. Best-effort — a network error / dag never fails the data tick; a host VERIFICATION refusal
        // does surface (below). A solo, in-sync tree no-ops.
        try {
          const treeId = treeIds.get(docId);
          if (treeId) {
            const localHead = await call('core_keyring_head', { doc: docId });
            const walk = await transport.readKeyring(docId, localHead + 1);
            const serverHead = walk.head ?? 0;
            const successors = (walk.revisions ?? []).filter((r) => r.revision > localHead);
            if (successors.length) {
              await call('core_sync_keyring', {
                doc: docId, treeId: bytes(treeId), hops: bytes(frameHops(successors.map((s) => s.bytes))),
              });
            } else if (localHead > serverHead) {
              await publishAfterMembership(docId, false); // keyring-first; publishAfterMembership swallows its own errors
            }
          }
        } catch (err) {
          // A host VERIFICATION refusal (a forked / rolled-back / rogue-signer server run) must SURFACE — folding
          // data against a stale membership is exactly what keyring-before-data prevents — so re-throw and let the
          // tick report {state:'error'}. A network error, or the dag engine (keyring_head / core_sync_keyring
          // reject dag), is benign — swallow and proceed.
          if (err?.code === 'keyring_verify_failed' || err?.code === 'revision_rollback') throw err;
          console.warn('[openom] native keyring-before-data (best-effort)', err);
        }
        const localPrefix = `${docId}/`;
        const remotePrefix = `${treeKey}/`;
        // PULL: list the shared remote, re-keyed into the core's local namespace. The core decides which objects
        // we still need to FETCH (OPE-464): immutable log objects we already pulled are skipped so we don't
        // re-download the whole retained log each tick. `present` = the full LIST so the core's upload-diff never
        // re-pushes a log object the remote already holds but we chose not to re-download.
        const listed = await transport.blobList(remotePrefix);
        const present = listed.map(({ key }) => localPrefix + key.slice(remotePrefix.length));
        const toFetch = new Set(await call('core_plan_fetch', { doc: docId, keys: present }));
        const remote = [];
        for (const { key } of listed) {
          const localKey = localPrefix + key.slice(remotePrefix.length);
          if (!toFetch.has(localKey)) continue;
          const b = await transport.blobGet(key);
          if (b) remote.push([localKey, Array.from(b)]);
        }
        // The core owns the whole keyspace + head-monotonicity decision; this is a dumb ferry.
        const { uploads, covered } = await call('core_sync', { doc: docId, remote, present, compactK });
        // PUSH: re-key each upload back to the shared namespace; the CORE decided pointer; the snapshot carries
        // the covered header (a well-known object key — the one key the worker itself checks, for the header).
        for (const o of uploads) {
          const remoteKey = remotePrefix + o.key.slice(localPrefix.length);
          const coveredHeader = o.key.endsWith('/snapshot') ? covered : undefined;
          await transport.blobPut(remoteKey, new Uint8Array(o.bytes), o.pointer, coveredHeader);
        }
        // Report the pull frontier for GC gate-2 liveness (OPE-409): change-guarded + best-effort — a failure
        // NEVER fails the tick, the floor just stays conservatively low for this member without the report.
        try {
          const frontier = await call('core_pull_frontier', { doc: docId });
          const sig = JSON.stringify(frontier);
          if (sig !== '{}' && sig !== reportedFrontier.get(docId)) {
            await transport.putFrontier(treeKey, frontier);
            reportedFrontier.set(docId, sig);
          }
        } catch { /* advisory telemetry — swallow; gate 2 stays conservative without it */ }
        return { state: 'ok', anomalies: await api.anomalies(docId) };
      } catch (err) {
        return { state: 'error', error: err };
      } finally {
        syncing.set(docId, false);
      }
    },
  };
  return api;
}
