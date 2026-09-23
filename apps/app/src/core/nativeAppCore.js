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
// membership) is complete and matches the command surface. The sync path reconciles chain and DAG membership
// before data transfer, while the broader native transport remains a runtime-iteration target. It is only
// reached when a managed backend is configured (startSync() early-returns local-only), so it never blocks the
// local flow.

import { makeError, normalizeUnknown } from './errorModel.js';
import { frameHops } from './sharing.js';
import { mint as mintInvite, verifyClaim as verifyInviteClaim, signerIds, signersRetained } from './invite.js';
import { pushMembershipSummary } from './membershipSummary.js';
import { invokeNative, isNativeHost } from './nativeHost.js';

export { isNativeHost };

/** @typedef {import('./types/domain.js').DocId} DocId */
/** @typedef {import('./types/domain.js').AppSecretEnvelopeBytes} AppSecretEnvelopeBytes */
/** @typedef {import('./types/domain.js').AppSecretPlaintextBytes} AppSecretPlaintextBytes */
/** @typedef {import('./types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('./types/domain.js').InviteId} InviteId */
/** @typedef {import('./types/domain.js').InviteMacBytes} InviteMacBytes */
/** @typedef {import('./types/domain.js').HistoryDeltaEnvelopeBytes} HistoryDeltaEnvelopeBytes */
/** @typedef {import('./types/domain.js').KeyringEngine} KeyringEngine */
/** @typedef {import('./types/domain.js').KeyringHashBytes} KeyringHashBytes */
/** @typedef {import('./types/domain.js').KeyringRevision} KeyringRevision */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').MemberRole} MemberRole */
/** @typedef {import('./types/domain.js').RemoteTreeKey} RemoteTreeKey */
/** @typedef {import('./types/domain.js').RecoveryCode} RecoveryCode */
/** @typedef {import('./types/domain.js').TreeId} TreeId */
/** @typedef {import('./types/domain.js').TreeObjectBytes} TreeObjectBytes */
/** @typedef {import('./types/domain.js').TreeObjectKey} TreeObjectKey */
/** @typedef {import('./types/domain.js').TreeUuid} TreeUuid */
/** @typedef {import('./types/appCoreApi.js').AppCoreTransport} AppCoreTransport */
/** @typedef {import('./types/appCoreApi.js').SyncResult} SyncResult */
/** @typedef {Omit<import('./types/appCoreApi.js').AppCoreService, 'syncNow'> & {
 *   syncNow: (docId: DocId, compactK?: number) => import('./types/appCoreApi.js').Awaitable<SyncResult>,
 *   anomalies: (docId: DocId) => import('./types/appCoreApi.js').Awaitable<number>
 * }} NativeAppCoreService */
/** @typedef {import('./types/nativeCommands.js').NativeBytes<Uint8Array>} NativeBytes */
/** @typedef {{
 *   inviteId: InviteId,
 *   uuid: TreeUuid,
 *   role: MemberRole,
 *   engine: KeyringEngine,
 *   sMacClaim: Uint8Array,
 *   expiry: number,
 *   recipientPin: string|null,
 *   signerIds: MemberId[],
 * }} NativeMintRecord */
/** @typedef {{ memberId: MemberId, role: number }} SummaryMember */
/** @typedef {{ members: SummaryMember[], basis: string[] }} MembershipSummary */

// A Vec<u8> argument as the number array Tauri deserializes; passes strings/undefined through untouched.
/**
 * @template {Uint8Array} Value
 * @param {Value} value
 * @returns {import('./types/nativeCommands.js').NativeBytes<Value>}
 */
const bytes = (value) => /** @type {import('./types/nativeCommands.js').NativeBytes<Value>} */ (
  /** @type {unknown} */ (Array.from(value))
);
// A Vec<u8> result (number array) back to a Uint8Array, the shape the web code expects for keyring bytes.
/** @template {Uint8Array} Value @param {Value} value @returns {Value} */
const u8 = (value) => /** @type {Value} */ (new Uint8Array(value));
// The remote (per-tree) blob-key prefix: the 16 tree-id bytes as lowercase hex — the same mapping main.js uses
// for the tree UUID's byte seam (the worker's `treeKey`). The core's LOCAL keyspace is `{docId}/…`; the shared
// REMOTE is `{treeKey}/…`, so the sync tick re-keys between them (exactly as appCore.worker.js does).
/** @param {TreeId} treeId @returns {RemoteTreeKey} */
const hexKey = (treeId) => /** @type {RemoteTreeKey} */ (
  Array.from(treeId, (byte) => byte.toString(16).padStart(2, '0')).join('')
);

// Real account trees use their UUID as the local doc id and every tree-route id (main.js owns that invariant).
/** @param {DocId} docId @returns {TreeUuid} */
const treeUuid = (docId) => /** @type {TreeUuid} */ (/** @type {unknown} */ (docId));

/** @param {number} value @returns {KeyringRevision} */
const keyringRevision = (value) => /** @type {KeyringRevision} */ (value);

/** @param {string} value @returns {TreeObjectKey} */
const treeObjectKey = (value) => /** @type {TreeObjectKey} */ (value);

// OPE-407 durable create-tree marker (native mirror of the web worker's IndexedDB marker): this device
// PROVISIONED a new tree whose server `trees` row may not exist yet. Set at provision, consumed on the first
// sync tick that reaches the server. Durable via the webview's localStorage so an offline provision that RESTARTS
// before it ever synced still mints the tree on a later tick rather than 404ing forever. A JOINing member never
// sets it (it adopts a tree the owner already created), so a member never calls createTree — no 403 to swallow.
/** @param {DocId} docId */
const NEEDS_TREE_KEY = (docId) => `openom:${docId}:needs-create-tree`;
const lstore = () => { try { return globalThis.localStorage ?? null; } catch { return null; } };

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** @param {unknown} error */
function isConflictError(error) {
  return isRecord(error) && error.name === 'ConflictError';
}

/** @param {unknown} value @returns {Uint8Array} */
function decodedBytes(value) {
  if (!Array.isArray(value) || !value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
    throw new Error('stored native bytes are malformed');
  }
  return Uint8Array.from(value);
}

/** @param {string} raw @returns {NativeMintRecord} */
function parseMintRecord(raw) {
  const value = /** @type {unknown} */ (JSON.parse(raw));
  if (!isRecord(value)) throw new Error('stored invite mint record is malformed');
  const role = value.role;
  const engine = value.engine;
  if (
    typeof value.inviteId !== 'string'
    || typeof value.uuid !== 'string'
    || (role !== 'owner' && role !== 'co-owner' && role !== 'maintainer' && role !== 'editor' && role !== 'viewer')
    || (engine !== 'chain' && engine !== 'dag')
    || !Number.isSafeInteger(value.expiry)
    || (value.recipientPin !== null && typeof value.recipientPin !== 'string')
    || !Array.isArray(value.signerIds)
    || !value.signerIds.every((memberId) => typeof memberId === 'string')
  ) {
    throw new Error('stored invite mint record is malformed');
  }
  return {
    inviteId: /** @type {InviteId} */ (value.inviteId),
    uuid: /** @type {TreeUuid} */ (value.uuid),
    role,
    engine,
    sMacClaim: decodedBytes(value.sMacClaim),
    expiry: Number(value.expiry),
    recipientPin: value.recipientPin,
    signerIds: /** @type {MemberId[]} */ (value.signerIds),
  };
}

/** @param {string} raw @returns {MembershipSummary} */
function parseMembershipSummary(raw) {
  const value = /** @type {unknown} */ (JSON.parse(raw));
  if (!isRecord(value) || !Array.isArray(value.members) || !Array.isArray(value.basis)) {
    throw new Error('native membership summary is malformed');
  }
  const members = value.members.map((item) => {
    if (!isRecord(item) || typeof item.memberId !== 'string' || !Number.isSafeInteger(item.role)) {
      throw new Error('native membership summary is malformed');
    }
    return { memberId: /** @type {MemberId} */ (item.memberId), role: Number(item.role) };
  });
  if (!value.basis.every((item) => typeof item === 'string')) {
    throw new Error('native membership summary is malformed');
  }
  return { members, basis: /** @type {string[]} */ (value.basis) };
}

/** @returns {NativeAppCoreService} */
export function createNativeAppCore() {
  /**
   * @param {import('./types/nativeCommands.js').NativeCommand} cmd
   * @param {unknown} [args]
   * @returns {Promise<unknown>}
   */
  const callRaw = (cmd, args) => /** @type {(command: string, payload?: unknown) => Promise<unknown>} */ (
    /** @type {unknown} */ (invokeNative)
  )(cmd, args).catch((raw) => {
    // Tauri rejects our Err(String) with a structured {code,message} JSON — map it to the SAME AppError the
    // wasm worker throws (via makeError), so the gate's rollback/tamper/wrong-passphrase distinctions and the
    // sync driver's retriable/auth classification survive on native (design-review C1). Anything else falls
    // through to the generic normalizer.
    /** @type {unknown} */
    let parsed = null;
    if (typeof raw === 'string') { try { parsed = JSON.parse(raw); } catch { parsed = null; } }
    else if (raw && typeof raw === 'object') parsed = raw;
    if (isRecord(parsed) && typeof parsed.code === 'string') {
      throw makeError(parsed.code, { cause: parsed.message });
    }
    throw normalizeUnknown(raw);
  });
  const call = /** @type {import('./types/nativeCommands.js').NativeInvoke} */ (
    /** @type {unknown} */ (callRaw)
  );

  // Per-doc network transport (set by attachTransport) + the doc→treeKey map (the remote keyspace prefix,
  // recorded whenever a doc is opened) + a single-flight sync guard + the once-per-session create-tree gate.
  /** @type {Map<DocId, AppCoreTransport>} */
  const transports = new Map();
  /** @type {Map<DocId, RemoteTreeKey>} */
  const treeKeys = new Map();
  /** @type {Map<DocId, TreeId>} */
  const treeIds = new Map(); // doc → the RAW 16 tree-id bytes (keyring-before-data needs them, not just the hex key)
  /** @type {Map<DocId, KeyringEngine>} */
  const treeEngines = new Map();
  /** @type {Map<DocId, boolean>} */
  const syncing = new Map();
  /** @type {Set<DocId>} */
  const treeEnsured = new Set();
  /** @type {Map<DocId, string>} */
  const reportedFrontier = new Map(); // last pull-frontier reported per doc (change-guard for the GC telemetry)
  /** @param {DocId} docId @param {TreeId} treeId */
  const remember = (docId, treeId) => {
    treeKeys.set(docId, hexKey(treeId));
    treeIds.set(docId, treeId);
  };
  /** @param {DocId} docId @returns {Promise<KeyringEngine>} */
  const engineFor = async (docId) => {
    const known = treeEngines.get(docId);
    if (known) return known;
    const material = await call('core_invite_material', { doc: docId });
    treeEngines.set(docId, material.engine);
    return material.engine;
  };

  // The create-tree marker, localStorage-backed with an in-memory fallback so create-tree is never silently
  // disabled when storage is unavailable (private mode) — the fallback still gives within-session retry.
  /** @type {Set<DocId>} */
  const needsTreeMem = new Set();
  /** @param {DocId} docId */
  const markNeedsCreateTree = (docId) => { needsTreeMem.add(docId); try { lstore()?.setItem(NEEDS_TREE_KEY(docId), '1'); } catch { /* no storage */ } };
  /** @param {DocId} docId */
  const needsCreateTree = (docId) => { if (needsTreeMem.has(docId)) return true; try { return lstore()?.getItem(NEEDS_TREE_KEY(docId)) === '1'; } catch { return false; } };
  /** @param {DocId} docId */
  const clearNeedsCreateTree = (docId) => { needsTreeMem.delete(docId); try { lstore()?.removeItem(NEEDS_TREE_KEY(docId)); } catch { /* best-effort */ } };

  // Owner-local DURABLE invite mint records (invite model v3), keyed by invite_id in the webview's localStorage —
  // a refresh must not orphan outstanding invites (admit hard-fails without the record; the flow spans
  // hours-days). Holds `s_mac_claim` + role/engine/expiry + the mint-time flat signer set (the chain admit gate).
  // The whole serialized record is DEK-SEALED at rest under the tree DEK (OPE-453, core_seal_app_secret) —
  // `s_mac_claim` is a secret (it forges that invite's claim MAC), so localStorage holds the ciphertext (as a
  // JSON byte array), never the plaintext. NEVER sent to the host over the wire in the clear or to the server.
  // Mirrors the web worker's IndexedDB mint record — different store (main thread), same purpose.
  /** @param {InviteId} inviteId */
  const MINT_KEY = (inviteId) => `openom:invite-mint:${inviteId}`;
  /** @param {DocId} docId @param {NativeMintRecord} rec */
  const saveMintRecord = async (docId, rec) => {
    const plaintext = new TextEncoder().encode(JSON.stringify({ ...rec, sMacClaim: Array.from(rec.sMacClaim) }));
    const sealed = u8(await call('core_seal_app_secret', {
      doc: docId,
      bytes: bytes(/** @type {AppSecretPlaintextBytes} */ (plaintext)),
    }));
    try { lstore()?.setItem(MINT_KEY(rec.inviteId), JSON.stringify(Array.from(sealed))); } catch { /* no storage */ }
  };
  /** @param {DocId} docId @param {InviteId} inviteId @returns {Promise<NativeMintRecord|null>} */
  const loadMintRecord = async (docId, inviteId) => {
    let raw;
    try { raw = lstore()?.getItem(MINT_KEY(inviteId)); } catch { return null; }
    if (!raw) return null;
    const stored = /** @type {unknown} */ (JSON.parse(raw));
    const sealed = /** @type {AppSecretEnvelopeBytes} */ (decodedBytes(stored));
    const plaintext = u8(await call('core_open_app_secret', { doc: docId, sealed: bytes(sealed) }));
    return parseMintRecord(new TextDecoder().decode(plaintext));
  };
  /** @param {InviteId} inviteId */
  const deleteMintRecord = (inviteId) => { try { lstore()?.removeItem(MINT_KEY(inviteId)); } catch { /* best-effort */ } };

  // Publish a membership change to the server (OPE-433/434, review C2): the KEYRING channel (the crypto
  // revocation — the server serves the rotated keyring, so a removed member can no longer decrypt new content)
  // and the advisory /access summary (the coarse ACL). Best-effort + ordered to UNDER-grant (add/promote:
  // keyring→advisory; remove/demote: advisory→keyring — a crash between leaves the ACL more restrictive than
  // the crypto, never less). Both read the NATIVE keyring (never a webview-supplied one). The advisory CAS/
  // generation retry and the PULL side (keyring-before-data adoption on sync) are runtime-verified follow-ups
  // tracked on OPE-433/434.
  // Byte-array equality (the server's served raw keyring bytes vs our retained body — both plain number arrays).
  /** @param {Uint8Array|null|undefined} a @param {Uint8Array} b */
  const u8eq = (a, b) => !!a && a.length === b.length && a.every((value, index) => value === b[index]);

  // Publish this device's produced CHAIN keyring TAIL: walk server-head+1 .. local-head and PUT each wrapped
  // revision in ascending single-hop order (the server admits only revision == head+1, so a single-head PUT
  // can't bridge a >1 gap, and a solo tree's genesis must land before any share can be verified). Idempotent: a
  // 409 whose served bytes equal ours is benign (already admitted), differing bytes are a fork (surfaced).
  /** @param {DocId} docId */
  async function publishKeyringTail(docId) {
    const transport = transports.get(docId);
    if (!transport) return;
    const localHead = await call('core_keyring_head', { doc: docId }); // chain-only; a dag call rejects → caught by caller
    if (localHead === 0) return;
    const serverHead = (await transport.readKeyring(treeUuid(docId), keyringRevision(localHead))).head ?? 0;
    for (let rev = serverHead + 1; rev <= localHead; rev += 1) {
      const { update, body } = await call('core_keyring_publish_payload_at', { doc: docId, revision: rev });
      try {
        await transport.putKeyring(treeUuid(docId), update);
      } catch (e) {
        if (isConflictError(e)) {
          const served = (await transport.readKeyring(treeUuid(docId), keyringRevision(rev))).revisions?.[0]?.bytes;
          if (served && u8eq(served, body)) continue; // already admitted with our bytes — benign
          throw makeError('keyring_verify_failed', { cause: `keyring fork at revision ${rev}` });
        }
        throw e;
      }
    }
  }

  // Publish the current native DAG anchor. A competing writer can win the target server slot between our read
  // and PUT; on 409, re-read and let RUST classify/adopt that anchor before retrying. A matching/adopted latest
  // anchor means the server already covers our custody; only `localAhead` emits another revision.
  /** @param {DocId} docId @param {TreeId} treeId */
  async function publishDagAnchor(docId, treeId) {
    const transport = transports.get(docId);
    if (!transport) return;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const walk = await transport.readKeyring(treeUuid(docId), keyringRevision(1));
      const latest = walk.revisions?.at(-1);
      if (latest) {
        const outcome = await call('core_sync_dag_anchor', {
          doc: docId, treeId: bytes(treeId), anchor: bytes(latest.bytes),
        });
        if (outcome !== 'localAhead') return;
      }
      const revision = keyringRevision((walk.head ?? 0) + 1);
      const { update } = await call('core_dag_keyring_publish_payload', {
        doc: docId, treeId: bytes(treeId), revision,
      });
      try {
        await transport.putKeyring(treeUuid(docId), update);
        return;
      } catch (error) {
        if (!isConflictError(error)) throw error;
      }
    }
    throw makeError('keyring_verify_failed', { cause: 'DAG keyring publish did not converge after 3 conflicts' });
  }

  /** @param {DocId} docId @param {TreeId} treeId @returns {Promise<boolean>} */
  async function reconcileDagMembership(docId, treeId) {
    const transport = transports.get(docId);
    if (!transport) return false;
    const walk = await transport.readKeyring(treeUuid(docId), keyringRevision(1));
    const latest = walk.revisions?.at(-1);
    if (!latest) {
      await publishDagAnchor(docId, treeId);
      return true;
    }
    const outcome = await call('core_sync_dag_anchor', {
      doc: docId, treeId: bytes(treeId), anchor: bytes(latest.bytes),
    });
    if (outcome === 'localAhead') {
      await publishDagAnchor(docId, treeId);
      return true;
    }
    return false;
  }

  /** @param {DocId} docId @param {TreeId} treeId @returns {Promise<boolean>} */
  async function reconcileChainMembership(docId, treeId) {
    const transport = transports.get(docId);
    if (!transport) return false;
    const localHead = await call('core_keyring_head', { doc: docId });
    const walk = await transport.readKeyring(treeUuid(docId), keyringRevision(localHead + 1));
    const serverHead = walk.head ?? 0;
    const successors = (walk.revisions ?? []).filter((revision) => revision.revision > localHead);
    if (successors.length) {
      await call('core_sync_keyring', {
        doc: docId, treeId: bytes(treeId), hops: bytes(frameHops(successors.map((revision) => revision.bytes))),
      });
      return false;
    }
    if (localHead > serverHead) {
      await publishKeyringTail(docId);
      return true;
    }
    return false;
  }

  /** @param {DocId} docId @param {TreeId} treeId @returns {Promise<boolean>} */
  async function reconcileMembership(docId, treeId) {
    return await engineFor(docId) === 'dag'
      ? reconcileDagMembership(docId, treeId)
      : reconcileChainMembership(docId, treeId);
  }

  /** @param {DocId} docId */
  async function publishMembershipChannel(docId) {
    const treeId = treeIds.get(docId);
    if (!treeId) return;
    if (await engineFor(docId) === 'dag') await publishDagAnchor(docId, treeId);
    else await publishKeyringTail(docId);
  }

  // Assert the advisory /access summary under the server's CAS on `generation` (getAccess → PUT → retry-on-409),
  // via the SAME shared helper the web worker uses (membershipSummary.js) — not the naive no-generation PUT that
  // 409s on every push after the first.
  /** @param {DocId} docId */
  async function pushAdvisory(docId) {
    const transport = transports.get(docId);
    if (!transport) return;
    const summary = parseMembershipSummary(await call('core_membership_summary', { doc: docId }));
    await pushMembershipSummary(
      transport,
      treeUuid(docId),
      { view: summary.members, basis: summary.basis },
    );
  }

  /** @param {DocId} docId @param {boolean} advisoryFirst */
  async function publishAfterMembership(docId, advisoryFirst) {
    const transport = transports.get(docId);
    if (!transport) return; // local-only: nothing to publish
    try {
      if (advisoryFirst) { await pushAdvisory(docId); await publishMembershipChannel(docId); }
      else { await publishMembershipChannel(docId); await pushAdvisory(docId); }
    } catch (err) {
      // The local keyring change stands (native custody is authoritative); the sync tick re-derives it from
      // local-head > server-head and retries — no durable flag needed.
      console.warn('[openom] native membership publish (best-effort) failed', err);
    }
  }

  /** @type {NativeAppCoreService} */
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
    accountSnapshot: () => call('account_snapshot'),
    accountSyncState: () => call('account_sync_state'),
    accountConfirmBinding: (binding) => call('account_confirm_binding', { binding }),
    accountStageBackup: ({ kind, binding }) => call('account_stage_backup', { kind, binding }),
    accountAcknowledgeBackup: ({ expected, checkpoint }) =>
      call('account_acknowledge_backup', { expected, checkpoint }),
    accountAdoptCandidate: ({ expectedMemberId, keystore, credential, binding, checkpoint }) => {
      if ('passphrase' in credential) {
        return call('account_adopt_candidate', {
          expectedMemberId,
          candidate: bytes(keystore),
          passphrase: credential.passphrase,
          binding,
          checkpoint,
        });
      }
      if ('recoveryCode' in credential) {
        return call('account_adopt_recovery_candidate', {
          expectedMemberId,
          candidate: bytes(keystore),
          recoveryCode: credential.recoveryCode,
          newPassphrase: credential.newPassphrase,
          binding,
          checkpoint,
        });
      }
      return Promise.reject(makeError('invalid_request', { cause: 'invalid account candidate credential' }));
    },
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

    async openTree({ treeId, docId }) {
      remember(docId, treeId);
      const out = await call('core_unlock', { doc: docId, treeId: bytes(treeId) });
      await call('core_bootstrap', { doc: docId });
      return out;
    },

    // The demo/dev core (reserved dev key) is web-only — the native host has no keyless dev path.
    openDev: () => Promise.reject(new Error('the demo (dev) core is not available on the native host')),

    resetCore: (docId) => call('core_reset', { doc: docId }),
    close: (docId) => {
      transports.delete(docId);
      treeKeys.delete(docId);
      treeIds.delete(docId);
      treeEngines.delete(docId);
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
      return transport.createProposal(treeUuid(docId), sealed);
    },
    /** Maintainer: the open proposals to review, as [{ id, proposer, sizeBytes, createdAt, expiresAt }]. */
    async pendingProposals(docId) {
      const transport = transports.get(docId);
      if (!transport) return [];
      const list = await transport.listProposals(treeUuid(docId));
      return list.map(({ id, proposer, sizeBytes, createdAt, expiresAt }) => ({
        id, proposer, sizeBytes, createdAt, expiresAt,
      }));
    },

    /** Maintainer: verify proposal `proposalId` and commit it as an attributed delta, then delete it from the
     *  channel. Returns the number of ops committed. Throws on a forged/misattributed proposal (not deleted). */
    async approveProposal(docId, proposalId) {
      const transport = transports.get(docId);
      if (!transport) throw makeError('internal', { cause: `approveProposal: no transport attached for ${docId}` });
      const tree = treeUuid(docId);
      const p = (await transport.listProposals(tree)).find((x) => x.id === proposalId);
      if (!p) throw makeError('internal', { cause: `approveProposal: proposal ${proposalId} not found` });
      const committed = await call('core_approve_proposal', { doc: docId, proposal: bytes(p.payload) });
      await transport.deleteProposal(tree, proposalId);
      return committed;
    },

    /** Reject a proposal (maintainer, or the proposer): delete it from the channel without committing. */
    async rejectProposal(docId, proposalId) {
      const transport = transports.get(docId);
      if (!transport) throw makeError('internal', { cause: `rejectProposal: no transport attached for ${docId}` });
      await transport.deleteProposal(treeUuid(docId), proposalId);
    },

    /** The change-history activity feed: per-change records `{ author, createdAt, replica, counter, size,
     *  viewable, ops }`. The host decrypts each retained delta; an unreachable-epoch delta is viewable: false. */
    async history(docId, opts = {}) {
      const transport = transports.get(docId);
      if (!transport) return { entries: [], nextCursor: null };
      const treeKey = treeKeys.get(docId);
      if (!treeKey) throw makeError('internal', { cause: `history: no tree key for ${docId}` });
      const feed = await transport.getHistory(treeUuid(docId), opts);
      const entries = [];
      for (const e of feed.entries) {
        let ops = null;
        let viewable = false;
        try {
          const sealed = await transport.blobGet(
            treeObjectKey(`${treeKey}/log/${e.replica}/${e.counter}`),
          );
          if (sealed && sealed.length) {
            const envelope = /** @type {HistoryDeltaEnvelopeBytes} */ (/** @type {unknown} */ (sealed));
            ops = JSON.parse(await call('core_open_history_delta', {
              doc: docId,
              envelope: bytes(envelope),
            }));
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
    resolveId: (docId, anchor) => call('core_resolve_id', { doc: docId, anchor }).then((id) => id ?? undefined),
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
      let recoveryCode = /** @type {RecoveryCode} */ ('');
      try {
        await api.accountUnlock(passphrase);
      } catch {
        recoveryCode = (await api.accountCreate(passphrase)).recoveryCode;
      }
      const m = await api.accountPublicIdentity();
      const authorPublicKey = u8(m.authorPublicKey);
      // SELF-CERT identity (OPE-543): the on-tree id derives from the author key IN RUST (core_derive_member_id)
      // — same single-source derivation as the worker's wasm `deriveMemberId`, never re-implemented in JS.
      return {
        memberId: await call('core_derive_member_id', { authorPublicKey: bytes(authorPublicKey) }),
        kdfParams: null, authorPublicKey, hpkePublicKey: u8(m.hpkePublicKey),
        recoveryCode,
      };
    },
    // Owner: mint a v3 share invite. The host supplies the engine pin (core_invite_material); the mint-time signer
    // fingerprint (the admit-gate baseline) comes from the engine-agnostic keyring summary; `invite.mint` (pure JS)
    // builds the short link + authenticated metadata; the record is persisted durably.
    async inviteMember(docId, { role, recipientPin = null, ttlMs, base }) {
      const material = await call('core_invite_material', { doc: docId }); // { engine, pin }
      const summary = parseMembershipSummary(await call('core_membership_summary', { doc: docId }));
      const mintSigners = signerIds(summary.members);
      const minted = await mintInvite({
        uuid: treeUuid(docId), role, engine: material.engine, pin: u8(material.pin), recipientPin,
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
      const summary = parseMembershipSummary(await call('core_membership_summary', { doc: docId }));
      if (!signersRetained(record.signerIds, summary.members)) {
        throw makeError('internal', { cause: 'a signer was removed since mint — cancel and re-invite' });
      }
      if (!(await verifyInviteClaim(record, claim))) throw makeError('internal', { cause: 'invite claim MAC mismatch — rejected' });
      // SELF-CERT admission (OPE-543): derive the joiner's on-tree id from their claimed author key IN RUST —
      // never trust the claim's id (the host re-derives it too; identical single source as the worker).
      await api.addMember(docId, {
        passphrase, treeId, ownerMemberId,
        newMemberId: await call('core_derive_member_id', { authorPublicKey: bytes(claim.authorPublicKey) }),
        role: record.role,
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
        if (!pin) return Promise.reject(makeError('invalid_request', { cause: 'dag invite pin is required' }));
        // Dag: the highest served revision is the self-contained anchor; the host verifies it against the OOB pin
        // (the v3 dag pin) and unlocks. No genesis-walk framing.
        const { revisions } = await transport.readKeyring(treeUuid(docId), keyringRevision(1));
        if (!revisions || revisions.length === 0) {
          return Promise.reject(makeError('internal', { cause: 'no keyring anchor to verify' }));
        }
        const anchor = revisions.at(-1)?.bytes;
        if (!anchor) return Promise.reject(makeError('internal', { cause: 'no keyring anchor to verify' }));
        const out = await call('core_join_dag_anchor', {
          doc: docId, treeId: bytes(treeId), anchor: bytes(anchor),
          pin: bytes(/** @type {import('./types/domain.js').DagAnchorPinBytes} */ (
            /** @type {unknown} */ (pin)
          )),
        });
        treeEngines.set(docId, 'dag');
        await call('core_bootstrap', { doc: docId });
        return out;
      }
      // v3 chain: unpack the opaque pin (rev(u32 BE)‖kh(32) = 36 bytes) into (revision, hash); a low-level caller
      // may instead pass them already unpacked.
      if (pin !== undefined) {
        const p = u8(pin);
        if (p.length !== 36) return Promise.reject(makeError('internal', { cause: 'chain invite pin must be 36 bytes' }));
        pinnedRevision = keyringRevision(new DataView(p.buffer, p.byteOffset, 4).getUint32(0, false));
        pinnedHash = /** @type {KeyringHashBytes} */ (p.slice(4));
      }
      if (pinnedRevision === undefined || pinnedHash === undefined) {
        return Promise.reject(makeError('invalid_request', { cause: 'chain invite pin is required' }));
      }
      const { revisions } = await transport.readKeyring(
        treeUuid(docId),
        keyringRevision(1),
      ); // the full walk from genesis (rev 1)
      const hops = frameHops((revisions ?? []).map((r) => r.bytes));
      const out = await call('core_join_as_member', {
        doc: docId, treeId: bytes(treeId), hops: bytes(hops), pinnedRevision, pinnedHash: bytes(pinnedHash),
      });
      treeEngines.set(docId, 'chain');
      await call('core_bootstrap', { doc: docId });
      return out;
    },
    async syncKeyring(docId, treeId) {
      const transport = transports.get(docId);
      if (!transport) return { changed: false };
      if (await engineFor(docId) === 'dag') {
        const walk = await transport.readKeyring(treeUuid(docId), keyringRevision(1));
        const latest = walk.revisions?.at(-1);
        if (!latest) return { changed: false };
        const outcome = await call('core_sync_dag_anchor', {
          doc: docId, treeId: bytes(treeId), anchor: bytes(latest.bytes),
        });
        return { changed: outcome === 'adopted' };
      }
      const localHead = await call('core_keyring_head', { doc: docId });
      const walk = await transport.readKeyring(
        treeUuid(docId),
        keyringRevision(localHead + 1),
      );
      const successors = (walk.revisions ?? []).filter((revision) => revision.revision > localHead);
      if (successors.length === 0) return { changed: false };
      const hops = frameHops(successors.map((revision) => revision.bytes));
      await call('core_sync_keyring', { doc: docId, treeId: bytes(treeId), hops: bytes(hops) });
      return { changed: true };
    },

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
    // The tick reconciles membership BEFORE folding data on both engines: it adopts a verified newer remote or
    // republishes locally-newer custody. A required keyring publication is a hard gate for the data channel.
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
            await transport.createTree(treeUuid(docId));
            clearNeedsCreateTree(docId);
          }
          treeEnsured.add(docId);
        }
        const treeId = treeIds.get(docId);
        if (treeId) {
          const published = await reconcileMembership(docId, treeId);
          if (published) {
            try { await pushAdvisory(docId); } catch (error) {
              console.warn('[openom] native membership advisory (best-effort)', error);
            }
          }
        }
        const localPrefix = `${docId}/`;
        const remotePrefix = /** @type {RemoteTreeKey} */ (`${treeKey}/`);
        // PULL: list the shared remote, re-keyed into the core's local namespace. The core decides which objects
        // we still need to FETCH (OPE-464): immutable log objects we already pulled are skipped so we don't
        // re-download the whole retained log each tick. `present` = the full LIST so the core's upload-diff never
        // re-pushes a log object the remote already holds but we chose not to re-download.
        const listed = await transport.blobList(remotePrefix);
        const present = listed.map(({ key }) => treeObjectKey(localPrefix + key.slice(remotePrefix.length)));
        const toFetch = new Set(await call('core_plan_fetch', { doc: docId, keys: present }));
        /** @type {import('./types/nativeCommands.js').NativeStoredObject[]} */
        const remote = [];
        for (const { key } of listed) {
          const localKey = treeObjectKey(localPrefix + key.slice(remotePrefix.length));
          if (!toFetch.has(localKey)) continue;
          const b = await transport.blobGet(key);
          if (b) remote.push([localKey, bytes(b)]);
        }
        // The core owns the whole keyspace + head-monotonicity decision; this is a dumb ferry.
        const { uploads, covered } = await call('core_sync', { doc: docId, remote, present, compactK });
        // PUSH: re-key each upload back to the shared namespace; the CORE decided pointer; the snapshot carries
        // the covered header (a well-known object key — the one key the worker itself checks, for the header).
        for (const o of uploads) {
          const remoteKey = treeObjectKey(remotePrefix + o.key.slice(localPrefix.length));
          const coveredHeader = o.key.endsWith('/snapshot') ? covered : undefined;
          await transport.blobPut(remoteKey, o.bytes, o.pointer, coveredHeader);
        }
        // Report the pull frontier for GC gate-2 liveness (OPE-409): change-guarded + best-effort — a failure
        // NEVER fails the tick, the floor just stays conservatively low for this member without the report.
        try {
          const frontier = await call('core_pull_frontier', { doc: docId });
          const sig = JSON.stringify(frontier);
          if (sig !== '{}' && sig !== reportedFrontier.get(docId)) {
            await transport.putFrontier(treeUuid(docId), frontier);
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
