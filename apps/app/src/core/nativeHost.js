/** @typedef {import('./types/appCoreApi.js').AccountBackupAcknowledged} AccountBackupAcknowledged */
/** @typedef {import('./types/appCoreApi.js').AccountCreated} AccountCreated */
/** @typedef {import('./types/appCoreApi.js').AccountRecovered} AccountRecovered */
/** @typedef {import('./types/appCoreApi.js').AccountSnapshot} AccountSnapshot */
/** @typedef {import('./types/appCoreApi.js').AccountSyncState} AccountSyncState */
/** @typedef {import('./types/appCoreApi.js').AdoptedAccount} AdoptedAccount */
/** @typedef {import('./types/appCoreApi.js').TreeOpenResult} TreeOpenResult */
/** @typedef {import('./types/contracts.js').AccountBackupCheckpoint} AccountBackupCheckpoint */
/** @typedef {import('./types/contracts.js').AccountBinding} AccountBinding */
/** @typedef {import('./types/contracts.js').AccountPublicIdentity} AccountPublicIdentity */
/** @typedef {import('./types/contracts.js').AccountVersion} AccountVersion */
/** @typedef {import('./types/contracts.js').PendingAccountBackup} PendingAccountBackup */
/** @typedef {import('./types/domain.js').AccountBackupEtag} AccountBackupEtag */
/** @typedef {import('./types/domain.js').AccountBlobHashBytes} AccountBlobHashBytes */
/** @typedef {import('./types/domain.js').AccountGeneration} AccountGeneration */
/** @typedef {import('./types/domain.js').AccountKeystoreBytes} AccountKeystoreBytes */
/** @typedef {import('./types/domain.js').AccountRecordRevision} AccountRecordRevision */
/** @typedef {import('./types/domain.js').AppSecretEnvelopeBytes} AppSecretEnvelopeBytes */
/** @typedef {import('./types/domain.js').AppSecretPlaintextBytes} AppSecretPlaintextBytes */
/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('./types/domain.js').ClaimsJson} ClaimsJson */
/** @typedef {import('./types/domain.js').CoveredFrontierJson} CoveredFrontierJson */
/** @typedef {import('./types/domain.js').DidKey} DidKey */
/** @typedef {import('./types/domain.js').HistoryDeltaJson} HistoryDeltaJson */
/** @typedef {import('./types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('./types/domain.js').InvitePinBytes} InvitePinBytes */
/** @typedef {import('./types/domain.js').KeyringBytes} KeyringBytes */
/** @typedef {import('./types/domain.js').KeyringSummaryJson} KeyringSummaryJson */
/** @typedef {import('./types/domain.js').KeyringUpdateBytes} KeyringUpdateBytes */
/** @typedef {import('./types/domain.js').LiveRecordsJson} LiveRecordsJson */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').OplogJson} OplogJson */
/** @typedef {import('./types/domain.js').PendingReviewsJson} PendingReviewsJson */
/** @typedef {import('./types/domain.js').ProjectionJson} ProjectionJson */
/** @typedef {import('./types/domain.js').ProposalEnvelopeBytes} ProposalEnvelopeBytes */
/** @typedef {import('./types/domain.js').RecordId} RecordId */
/** @typedef {import('./types/domain.js').RecoveryCode} RecoveryCode */
/** @typedef {import('./types/domain.js').RegistrationProofBytes} RegistrationProofBytes */
/** @typedef {import('./types/domain.js').RemovalOperationId} RemovalOperationId */
/** @typedef {import('./types/domain.js').TreeObjectBytes} TreeObjectBytes */
/** @typedef {import('./types/domain.js').TreeObjectKey} TreeObjectKey */
/** @typedef {import('./types/nativeCommands.js').NativeAddedMember} NativeAddedMember */
/** @typedef {import('./types/nativeCommands.js').NativeCommand} NativeCommand */
/** @typedef {import('./types/nativeCommands.js').NativeCommandParameters<NativeCommand>} AnyNativeCommandParameters */
/** @typedef {import('./types/nativeCommands.js').NativeInviteMaterial} NativeInviteMaterial */
/** @typedef {import('./types/nativeCommands.js').NativeKeyringRevisionPayload} NativeKeyringRevisionPayload */
/** @typedef {import('./types/nativeCommands.js').NativeRemovedMember} NativeRemovedMember */
/** @typedef {import('./types/nativeCommands.js').NativeResultDecoders} NativeResultDecoders */
/** @typedef {import('./types/nativeCommands.js').NativeRoleChanged} NativeRoleChanged */
/** @typedef {import('./types/nativeCommands.js').NativeSyncResult} NativeSyncResult */

/** @param {string} label @returns {never} */
function malformed(label) {
  throw new TypeError(`native host returned malformed ${label}`);
}

/** @param {unknown} value @param {string} label @returns {Record<string, unknown>} */
function objectValue(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) malformed(label);
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {unknown} value @param {string} label */
function stringValue(value, label) {
  if (typeof value !== 'string') malformed(label);
  return value;
}

/** @param {unknown} value @param {string} label */
function booleanValue(value, label) {
  if (typeof value !== 'boolean') malformed(label);
  return value;
}

/** @param {unknown} value @param {string} label */
function integerValue(value, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) malformed(label);
  return value;
}

/** @param {unknown} value @param {string} label */
function bytesValue(value, label) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (!Array.isArray(value)) malformed(label);
  const numbers = /** @type {unknown[]} */ (value);
  if (!numbers.every((item) => Number.isInteger(item) && Number(item) >= 0 && Number(item) <= 255)) {
    malformed(label);
  }
  return Uint8Array.from(/** @type {number[]} */ (numbers));
}

/** @param {unknown} value @param {string} label */
function stringArray(value, label) {
  if (!Array.isArray(value)) malformed(label);
  const values = /** @type {unknown[]} */ (value);
  if (!values.every((item) => typeof item === 'string')) malformed(label);
  return /** @type {string[]} */ (values);
}

/** @param {unknown} value @param {string} label */
function numberRecord(value, label) {
  const record = objectValue(value, label);
  for (const [key, item] of Object.entries(record)) {
    integerValue(item, `${label}.${key}`);
  }
  return /** @type {Readonly<Record<string, number>>} */ (record);
}

/** @param {unknown} value @param {string} label */
function voidValue(value, label) {
  if (value !== null && value !== undefined) malformed(label);
}

/** @param {unknown} value @returns {AccountVersion} */
function accountVersion(value) {
  const record = objectValue(value, 'account version');
  return {
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
    blobHash: /** @type {AccountBlobHashBytes} */ (bytesValue(record.blobHash, 'account blob hash')),
  };
}

/** @param {unknown} value @returns {AccountBinding} */
function accountBinding(value) {
  const record = objectValue(value, 'account binding');
  return {
    issuer: /** @type {AuthIssuer} */ (stringValue(record.issuer, 'account issuer')),
    subject: /** @type {AuthSubject} */ (stringValue(record.subject, 'account subject')),
    memberId: /** @type {MemberId} */ (stringValue(record.memberId, 'binding member id')),
  };
}

/** @param {unknown} value @returns {AccountBackupCheckpoint} */
function accountCheckpoint(value) {
  const record = objectValue(value, 'account checkpoint');
  return {
    etag: /** @type {AccountBackupEtag} */ (stringValue(record.etag, 'account checkpoint etag')),
    version: record.version === null ? null : accountVersion(record.version),
  };
}

/** @param {unknown} value @returns {PendingAccountBackup} */
function pendingAccountBackup(value) {
  const record = objectValue(value, 'pending account backup');
  const kind = stringValue(record.kind, 'pending account backup kind');
  if (kind !== 'backup' && kind !== 'revoke') malformed('pending account backup kind');
  return { kind, version: accountVersion(record.version), binding: accountBinding(record.binding) };
}

/** @param {unknown} value */
function accountSyncIdentity(value) {
  const record = objectValue(value, 'account sync identity');
  return {
    memberId: /** @type {MemberId} */ (stringValue(record.memberId, 'account member id')),
    version: accountVersion(record.version),
    floor: /** @type {AccountGeneration} */ (integerValue(record.floor, 'account floor')),
    effectiveFloor: /** @type {AccountGeneration} */ (
      integerValue(record.effectiveFloor, 'effective account floor')
    ),
  };
}

/** @param {unknown} value */
function accountSyncRecord(value) {
  const record = objectValue(value, 'account sync record');
  if (!Array.isArray(record.retainedIdentities)) malformed('retained account identities');
  return {
    revision: /** @type {AccountRecordRevision} */ (integerValue(record.revision, 'account record revision')),
    identity: accountSyncIdentity(record.identity),
    retainedIdentities: /** @type {unknown[]} */ (record.retainedIdentities).map(accountSyncIdentity),
    binding: record.binding === null ? null : accountBinding(record.binding),
    acknowledgedBackup: record.acknowledgedBackup === null
      ? null
      : accountCheckpoint(record.acknowledgedBackup),
    pendingBackup: record.pendingBackup === null ? null : pendingAccountBackup(record.pendingBackup),
  };
}

/** @param {unknown} value */
function storagePersistence(value) {
  const persistence = stringValue(value, 'storage persistence');
  if (persistence !== 'granted' && persistence !== 'denied' && persistence !== 'unavailable') {
    malformed('storage persistence');
  }
  return persistence;
}

/** @param {unknown} value @returns {AccountSyncState} */
function decodeAccountSyncState(value) {
  const record = objectValue(value, 'account sync state');
  return {
    record: record.record === null ? null : accountSyncRecord(record.record),
    storagePersistence: storagePersistence(record.storagePersistence),
  };
}

/** @param {unknown} value @returns {AccountCreated} */
function decodeAccountCreated(value) {
  const record = objectValue(value, 'created account');
  return {
    recoveryCode: /** @type {RecoveryCode} */ (stringValue(record.recoveryCode, 'recovery code')),
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
  };
}

/** @param {unknown} value @returns {AccountRecovered} */
function decodeAccountRecovered(value) {
  return decodeAccountCreated(value);
}

/** @param {unknown} value @returns {AccountPublicIdentity} */
function decodeAccountIdentity(value) {
  const record = objectValue(value, 'account identity');
  return {
    memberId: /** @type {MemberId} */ (stringValue(record.memberId, 'account member id')),
    authorPublicKey: /** @type {AuthorPublicKeyBytes} */ (
      bytesValue(record.authorPublicKey, 'author public key')
    ),
    hpkePublicKey: /** @type {HpkePublicKeyBytes} */ (
      bytesValue(record.hpkePublicKey, 'HPKE public key')
    ),
  };
}

/** @param {unknown} value @returns {AccountSnapshot} */
function decodeAccountSnapshot(value) {
  const record = objectValue(value, 'account snapshot');
  return {
    keystore: /** @type {AccountKeystoreBytes} */ (bytesValue(record.keystore, 'account keystore')),
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
    blobHash: /** @type {AccountBlobHashBytes} */ (bytesValue(record.blobHash, 'account blob hash')),
  };
}

/** @param {unknown} value @returns {AccountBackupAcknowledged} */
function decodeAccountBackupAcknowledged(value) {
  const state = decodeAccountSyncState(value);
  const record = objectValue(value, 'account backup acknowledgement');
  return { ...state, cleared: booleanValue(record.cleared, 'account backup cleared') };
}

/** @param {unknown} value @returns {AdoptedAccount} */
function decodeAdoptedAccount(value) {
  const record = objectValue(value, 'adopted account');
  return {
    memberId: /** @type {MemberId} */ (stringValue(record.memberId, 'adopted member id')),
    recoveryCode: /** @type {RecoveryCode} */ (stringValue(record.recoveryCode, 'recovery code')),
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
    blobHash: /** @type {AccountBlobHashBytes} */ (bytesValue(record.blobHash, 'account blob hash')),
  };
}

/** @param {unknown} value */
function decodeAccountChanged(value) {
  const record = objectValue(value, 'account change');
  return {
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
  };
}

/** @param {unknown} value */
function decodeAccountRotated(value) {
  const record = objectValue(value, 'account rotation');
  return {
    recoveryCode: /** @type {RecoveryCode} */ (stringValue(record.recoveryCode, 'recovery code')),
    generation: /** @type {AccountGeneration} */ (integerValue(record.generation, 'account generation')),
  };
}

/** @param {unknown} value */
function decodeAccountStatus(value) {
  const status = stringValue(value, 'account status');
  if (status !== 'none' && status !== 'locked' && status !== 'unlocked') malformed('account status');
  return status;
}

/** @param {unknown} value @returns {TreeOpenResult} */
function decodeTreeOpen(value) {
  const record = objectValue(value, 'opened tree');
  return {
    didKey: /** @type {DidKey} */ (stringValue(record.didKey, 'tree did:key')),
    needsReseal: booleanValue(record.needsReseal, 'needs reseal'),
    needsBackfill: booleanValue(record.needsBackfill, 'needs backfill'),
    needsRrkBackfill: booleanValue(record.needsRrkBackfill, 'needs RRK backfill'),
    writeEpochUnreachable: booleanValue(record.writeEpochUnreachable, 'write epoch unreachable'),
  };
}

/** @param {unknown} value */
function decodeDidKey(value) {
  const record = objectValue(value, 'native identity result');
  return { didKey: /** @type {DidKey} */ (stringValue(record.didKey, 'did:key')) };
}

/** @param {unknown} value @returns {NativeAddedMember} */
function decodeAddedMember(value) {
  const record = objectValue(value, 'added member');
  return {
    keyring: /** @type {KeyringUpdateBytes} */ (bytesValue(record.keyring, 'keyring')),
    firstShare: booleanValue(record.firstShare, 'first share'),
  };
}

/** @param {unknown} value @returns {NativeRemovedMember} */
function decodeRemovedMember(value) {
  const record = objectValue(value, 'removed member');
  return {
    keyring: /** @type {KeyringUpdateBytes} */ (bytesValue(record.keyring, 'keyring')),
    historyPreserved: booleanValue(record.historyPreserved, 'history preserved'),
  };
}

/** @param {unknown} value @returns {NativeRoleChanged} */
function decodeRoleChanged(value) {
  const record = objectValue(value, 'role change');
  return {
    keyring: /** @type {KeyringUpdateBytes} */ (bytesValue(record.keyring, 'keyring')),
    demote: booleanValue(record.demote, 'role demotion'),
  };
}

/** @param {unknown} value @returns {NativeInviteMaterial} */
function decodeInviteMaterial(value) {
  const record = objectValue(value, 'invite material');
  const engine = stringValue(record.engine, 'keyring engine');
  if (engine !== 'chain' && engine !== 'dag') malformed('keyring engine');
  return {
    engine,
    pin: /** @type {InvitePinBytes} */ (bytesValue(record.pin, 'invite pin')),
  };
}

/** @param {unknown} value @returns {NativeKeyringRevisionPayload} */
function decodeKeyringRevisionPayload(value) {
  const record = objectValue(value, 'keyring revision payload');
  return {
    update: /** @type {KeyringUpdateBytes} */ (bytesValue(record.update, 'keyring update')),
    body: /** @type {KeyringBytes} */ (bytesValue(record.body, 'keyring body')),
  };
}

/** @param {unknown} value @returns {NativeSyncResult} */
function decodeSyncResult(value) {
  const record = objectValue(value, 'sync result');
  if (!Array.isArray(record.uploads)) malformed('sync uploads');
  const uploads = /** @type {unknown[]} */ (record.uploads).map((item) => {
    const upload = objectValue(item, 'sync upload');
    return {
      key: /** @type {TreeObjectKey} */ (stringValue(upload.key, 'sync upload key')),
      bytes: /** @type {TreeObjectBytes} */ (bytesValue(upload.bytes, 'sync upload bytes')),
      pointer: booleanValue(upload.pointer, 'sync upload pointer'),
    };
  });
  return {
    uploads,
    folded: integerValue(record.folded, 'sync folded count'),
    covered: /** @type {CoveredFrontierJson} */ (
      JSON.stringify(numberRecord(record.covered, 'sync covered frontier'))
    ),
  };
}

/** @type {NativeResultDecoders} */
const RESULT_DECODERS = {
  account_create: decodeAccountCreated,
  account_unlock: decodeAccountIdentity,
  account_status: decodeAccountStatus,
  account_lock: (value) => voidValue(value, 'account lock result'),
  account_recover: decodeAccountRecovered,
  account_public_identity: decodeAccountIdentity,
  account_snapshot: decodeAccountSnapshot,
  account_sync_state: decodeAccountSyncState,
  account_confirm_binding: decodeAccountSyncState,
  account_stage_backup: decodeAccountSyncState,
  account_acknowledge_backup: decodeAccountBackupAcknowledged,
  account_adopt_candidate: decodeAdoptedAccount,
  account_adopt_recovery_candidate: decodeAdoptedAccount,
  account_change_passphrase: decodeAccountChanged,
  account_rotate_root: decodeAccountRotated,
  account_register_proof: (value) => /** @type {RegistrationProofBytes} */ (
    bytesValue(value, 'registration proof')
  ),
  core_provision: decodeDidKey,
  core_unlock: decodeTreeOpen,
  core_derive_member_id: (value) => /** @type {MemberId} */ (
    stringValue(value, 'derived member id')
  ),
  core_add_member: decodeAddedMember,
  core_remove_member: decodeRemovedMember,
  core_change_role: decodeRoleChanged,
  core_join_as_member: decodeDidKey,
  core_join_dag_anchor: decodeDidKey,
  core_has_keyring: (value) => booleanValue(value, 'has-keyring result'),
  core_bootstrap: (value) => voidValue(value, 'bootstrap result'),
  core_assert_anchor: (value) => voidValue(value, 'assert-anchor result'),
  core_commit: (value) => voidValue(value, 'commit result'),
  core_can_commit_directly: (value) => booleanValue(value, 'direct-commit result'),
  core_open_history_delta: (value) => /** @type {HistoryDeltaJson} */ (
    stringValue(value, 'history delta JSON')
  ),
  core_propose: (value) => /** @type {ProposalEnvelopeBytes} */ (
    bytesValue(value, 'proposal envelope')
  ),
  core_approve_proposal: (value) => integerValue(value, 'approved proposal count'),
  core_project: (value) => /** @type {ProjectionJson} */ (stringValue(value, 'projection JSON')),
  core_membership_summary: (value) => /** @type {KeyringSummaryJson} */ (
    stringValue(value, 'membership summary JSON')
  ),
  core_invite_material: decodeInviteMaterial,
  core_assert_claim: (value) => voidValue(value, 'assert-claim result'),
  core_supersede_claim: (value) => voidValue(value, 'supersede-claim result'),
  core_remove_record: (value) => /** @type {RemovalOperationId} */ (
    stringValue(value, 'removal operation id')
  ),
  core_revoke: (value) => voidValue(value, 'revoke result'),
  core_reset: (value) => voidValue(value, 'reset result'),
  core_set_moderators: (value) => voidValue(value, 'set-moderators result'),
  core_close: (value) => voidValue(value, 'close result'),
  core_oplog: (value) => /** @type {OplogJson} */ (stringValue(value, 'operation log JSON')),
  core_live_records: (value) => /** @type {LiveRecordsJson} */ (
    stringValue(value, 'live records JSON')
  ),
  core_live_claims_of: (value) => /** @type {ClaimsJson} */ (
    stringValue(value, 'live claims JSON')
  ),
  core_live_claims_of_any: (value) => /** @type {ClaimsJson} */ (
    stringValue(value, 'live claims JSON')
  ),
  core_resolve_id: (value) => value === null
    ? null
    : /** @type {RecordId} */ (stringValue(value, 'resolved record id')),
  core_pending_count: (value) => integerValue(value, 'pending count'),
  core_anomalies: (value) => integerValue(value, 'anomaly count'),
  core_pull_frontier: (value) => numberRecord(value, 'pull frontier'),
  core_pending_reviews: (value) => /** @type {PendingReviewsJson} */ (
    stringValue(value, 'pending reviews JSON')
  ),
  core_approve_pending: (value) => booleanValue(value, 'approve-pending result'),
  core_discard_pending: (value) => booleanValue(value, 'discard-pending result'),
  core_sync_keyring: (value) => voidValue(value, 'sync-keyring result'),
  core_keyring_head: (value) => integerValue(value, 'keyring head'),
  core_keyring_publish_payload_at: decodeKeyringRevisionPayload,
  core_sync: decodeSyncResult,
  core_plan_fetch: (value) => /** @type {TreeObjectKey[]} */ (
    stringArray(value, 'fetch plan')
  ),
  core_seal_app_secret: (value) => /** @type {AppSecretEnvelopeBytes} */ (
    bytesValue(value, 'sealed app secret')
  ),
  core_open_app_secret: (value) => /** @type {AppSecretPlaintextBytes} */ (
    bytesValue(value, 'opened app secret')
  ),
};

function tauriInvoke() {
  const tauri = Reflect.get(globalThis, '__TAURI__');
  if (tauri === null || typeof tauri !== 'object') return null;
  const core = Reflect.get(tauri, 'core');
  if (core === null || typeof core !== 'object') return null;
  const invoke = Reflect.get(core, 'invoke');
  if (typeof invoke !== 'function') return null;
  return /** @type {(command: string, args?: unknown) => Promise<unknown>} */ (invoke.bind(core));
}

export function isNativeHost() {
  return tauriInvoke() !== null;
}

/**
 * @param {NativeCommand} command
 * @param {unknown} [args]
 * @returns {Promise<unknown>}
 */
async function invokeNativeRaw(command, args) {
  const invoke = tauriInvoke();
  if (!invoke) throw new Error('native host unavailable (no __TAURI__.core.invoke)');
  const raw = await invoke(command, args);
  const decoded = RESULT_DECODERS[command](raw);
  return decoded;
}

export const invokeNative = /** @type {import('./types/nativeCommands.js').NativeInvoke} */ (
  /** @type {unknown} */ (invokeNativeRaw)
);
