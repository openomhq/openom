import init, * as wasm from '../vendor/app-core/openom_app_core.js';

/** @typedef {import('./types/domain.js').AccountGeneration} AccountGeneration */
/** @typedef {import('./types/domain.js').AccountKeystoreBytes} AccountKeystoreBytes */
/** @typedef {import('./types/domain.js').AccountTreeRole} AccountTreeRole */
/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('./types/domain.js').DagAnchorPinBytes} DagAnchorPinBytes */
/** @typedef {import('./types/domain.js').DidKey} DidKey */
/** @typedef {import('./types/domain.js').DocId} DocId */
/** @typedef {import('./types/domain.js').FramedKeyringHopsBytes} FramedKeyringHopsBytes */
/** @typedef {import('./types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('./types/domain.js').KeyringBytes} KeyringBytes */
/** @typedef {import('./types/domain.js').KeyringEngine} KeyringEngine */
/** @typedef {import('./types/domain.js').KeyringHashBytes} KeyringHashBytes */
/** @typedef {import('./types/domain.js').KeyringRevision} KeyringRevision */
/** @typedef {import('./types/domain.js').KeyringSummaryJson} KeyringSummaryJson */
/** @typedef {import('./types/domain.js').KeyringUpdateBytes} KeyringUpdateBytes */
/** @typedef {import('./types/domain.js').KeyringWatermarkBytes} KeyringWatermarkBytes */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/domain.js').MemberRole} MemberRole */
/** @typedef {import('./types/domain.js').Passphrase} Passphrase */
/** @typedef {import('./types/domain.js').RecoveryCode} RecoveryCode */
/** @typedef {import('./types/domain.js').RegistrationProofBytes} RegistrationProofBytes */
/** @typedef {import('./types/domain.js').ReplicaId} ReplicaId */
/** @typedef {import('./types/domain.js').ResetAuthorityBytes} ResetAuthorityBytes */
/** @typedef {import('./types/domain.js').TreeId} TreeId */
/** @typedef {import('./types/domain.js').TrustedSignersBytes} TrustedSignersBytes */
/** @typedef {import('./types/wasm.js').AccountHandle} AccountHandle */
/** @typedef {import('./types/wasm.js').AccountOpenResult} AccountOpenResult */
/** @typedef {import('./types/wasm.js').AccountPublicIdentity} AccountPublicIdentity */
/** @typedef {import('./types/wasm.js').AccountSnapshot} AccountSnapshot */
/** @typedef {import('./types/wasm.js').AccountUpdateResult} AccountUpdateResult */
/** @typedef {import('./types/wasm.js').AppCoreHandle} AppCoreHandle */
/** @typedef {import('./types/wasm.js').DagBackfilled} DagBackfilled */
/** @typedef {import('./types/wasm.js').KeyringWalk} KeyringWalk */
/** @typedef {import('./types/wasm.js').MembershipChange} MembershipChange */
/** @typedef {import('./types/wasm.js').OpenResult} OpenResult */

export function initAppCore() {
  return init();
}

/**
 * @param {Passphrase} passphrase
 * @returns {AccountOpenResult}
 */
export function accountCreate(passphrase) {
  return /** @type {AccountOpenResult} */ (wasm.accountCreate(passphrase));
}

/**
 * @param {Passphrase} passphrase
 * @param {AccountKeystoreBytes} keystore
 * @param {AccountGeneration} generationFloor
 * @returns {AccountHandle}
 */
export function accountUnlock(passphrase, keystore, generationFloor) {
  return /** @type {AccountHandle} */ (wasm.accountUnlock(passphrase, keystore, generationFloor));
}

/**
 * @param {RecoveryCode} recoveryCode
 * @param {Passphrase} newPassphrase
 * @param {AccountKeystoreBytes} keystore
 * @param {AccountGeneration} generationFloor
 * @returns {AccountOpenResult}
 */
export function accountRecover(recoveryCode, newPassphrase, keystore, generationFloor) {
  return /** @type {AccountOpenResult} */ (
    wasm.accountRecover(recoveryCode, newPassphrase, keystore, generationFloor)
  );
}

/**
 * @param {Passphrase} passphrase
 * @param {AccountKeystoreBytes} candidate
 * @param {AccountGeneration} generationFloor
 * @returns {AccountOpenResult}
 */
export function accountOpenCandidate(passphrase, candidate, generationFloor) {
  return /** @type {AccountOpenResult} */ (
    wasm.accountOpenCandidate(passphrase, candidate, generationFloor)
  );
}

/**
 * @param {RecoveryCode} recoveryCode
 * @param {Passphrase} newPassphrase
 * @param {AccountKeystoreBytes} candidate
 * @param {AccountGeneration} generationFloor
 * @returns {AccountOpenResult}
 */
export function accountRecoverCandidate(recoveryCode, newPassphrase, candidate, generationFloor) {
  return /** @type {AccountOpenResult} */ (
    wasm.accountRecoverCandidate(recoveryCode, newPassphrase, candidate, generationFloor)
  );
}

/**
 * @param {AccountHandle} account
 * @param {Passphrase} passphrase
 * @returns {AccountUpdateResult}
 */
export function accountChangePassphrase(account, passphrase) {
  return /** @type {AccountUpdateResult} */ (wasm.accountChangePassphrase(account, passphrase));
}

/**
 * @param {AccountHandle} account
 * @param {Passphrase} passphrase
 * @returns {AccountUpdateResult}
 */
export function accountRotateRoot(account, passphrase) {
  return /** @type {AccountUpdateResult} */ (wasm.accountRotateRoot(account, passphrase));
}

/**
 * @param {AccountHandle} account
 * @returns {AccountSnapshot}
 */
export function accountSnapshot(account) {
  return /** @type {AccountSnapshot} */ (wasm.accountSnapshot(account));
}

/**
 * @param {AccountHandle} account
 * @returns {AccountPublicIdentity}
 */
export function accountPublicIdentity(account) {
  return /** @type {AccountPublicIdentity} */ (wasm.accountPublicIdentity(account));
}

/**
 * @param {AccountHandle} account
 * @param {AuthIssuer} issuer
 * @param {AuthSubject} subject
 * @param {number} timestamp
 * @returns {RegistrationProofBytes}
 */
export function accountRegisterProof(account, issuer, subject, timestamp) {
  return /** @type {RegistrationProofBytes} */ (
    wasm.accountRegisterProof(account, issuer, subject, timestamp)
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @returns {AccountTreeRole}
 */
export function accountTreeRole(account, engine, keyring) {
  return /** @type {AccountTreeRole} */ (wasm.accountTreeRole(account, engine, keyring));
}

/**
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {DidKey} createdBy
 * @param {DocId} docId
 * @returns {AppCoreHandle}
 */
export function devCore(treeId, replicaId, createdBy, docId) {
  return /** @type {AppCoreHandle} */ (
    /** @type {unknown} */ (wasm.AppCoreHandle.dev(treeId, replicaId, createdBy, docId))
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {DocId} docId
 * @returns {OpenResult}
 */
export function provisionTree(account, engine, treeId, replicaId, docId) {
  return /** @type {OpenResult} */ (wasm.provisionTree(account, engine, treeId, replicaId, docId));
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {KeyringBytes} keyring
 * @param {DocId} docId
 * @returns {OpenResult}
 */
export function unlockTree(account, engine, treeId, replicaId, keyring, docId) {
  return /** @type {OpenResult} */ (
    wasm.unlockTree(account, engine, treeId, replicaId, keyring, docId)
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {TrustedSignersBytes} trustedSigners
 * @param {ReplicaId} replicaId
 * @param {KeyringRevision} minRevision
 * @param {DocId} docId
 * @returns {OpenResult}
 */
export function unlockTreeAsMember(
  account,
  engine,
  keyring,
  treeId,
  trustedSigners,
  replicaId,
  minRevision,
  docId,
) {
  return /** @type {OpenResult} */ (
    wasm.unlockTreeAsMember(
      account,
      engine,
      keyring,
      treeId,
      trustedSigners,
      replicaId,
      minRevision,
      docId,
    )
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {KeyringRevision} minRevision
 * @param {MemberId} newMemberId
 * @param {MemberRole} role
 * @param {AuthorPublicKeyBytes} authorPublicKey
 * @param {HpkePublicKeyBytes} hpkePublicKey
 * @returns {MembershipChange}
 */
export function addMemberWithAccount(
  account,
  engine,
  keyring,
  treeId,
  replicaId,
  minRevision,
  newMemberId,
  role,
  authorPublicKey,
  hpkePublicKey,
) {
  return /** @type {MembershipChange} */ (
    wasm.addMemberWithAccount(
      account,
      engine,
      keyring,
      treeId,
      replicaId,
      minRevision,
      newMemberId,
      role,
      authorPublicKey,
      hpkePublicKey,
    )
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {KeyringRevision} minRevision
 * @param {MemberId} removeMemberId
 * @returns {MembershipChange}
 */
export function removeMemberWithAccount(
  account,
  engine,
  keyring,
  treeId,
  replicaId,
  minRevision,
  removeMemberId,
) {
  return /** @type {MembershipChange} */ (
    wasm.removeMemberWithAccount(
      account,
      engine,
      keyring,
      treeId,
      replicaId,
      minRevision,
      removeMemberId,
    )
  );
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {KeyringRevision} minRevision
 * @param {MemberId} targetMemberId
 * @param {MemberRole} role
 * @returns {MembershipChange}
 */
export function changeRoleWithAccount(
  account,
  engine,
  keyring,
  treeId,
  replicaId,
  minRevision,
  targetMemberId,
  role,
) {
  return /** @type {MembershipChange} */ (
    wasm.changeRoleWithAccount(
      account,
      engine,
      keyring,
      treeId,
      replicaId,
      minRevision,
      targetMemberId,
      role,
    )
  );
}

/**
 * @param {AuthorPublicKeyBytes} authorPublicKey
 * @returns {MemberId}
 */
export function deriveMemberId(authorPublicKey) {
  return /** @type {MemberId} */ (wasm.deriveMemberId(authorPublicKey));
}

/**
 * @param {TreeId} treeId
 * @param {FramedKeyringHopsBytes} hops
 * @param {KeyringRevision} pinnedRevision
 * @param {KeyringHashBytes} pinnedHash
 * @returns {KeyringWalk}
 */
export function verifyKeyringWalk(treeId, hops, pinnedRevision, pinnedHash) {
  return /** @type {KeyringWalk} */ (
    wasm.verifyKeyringWalk(treeId, hops, pinnedRevision, pinnedHash)
  );
}

/**
 * @param {KeyringBytes} keyring
 * @returns {KeyringUpdateBytes}
 */
export function wrapChainKeyringUpdate(keyring) {
  return /** @type {KeyringUpdateBytes} */ (wasm.wrapChainKeyringUpdate(keyring));
}

/**
 * @param {KeyringUpdateBytes} update
 * @returns {KeyringBytes}
 */
export function unwrapChainKeyring(update) {
  return /** @type {KeyringBytes} */ (wasm.unwrapChainKeyring(update));
}

/**
 * @param {KeyringBytes} keyring
 * @returns {KeyringHashBytes}
 */
export function keyringHash(keyring) {
  return /** @type {KeyringHashBytes} */ (wasm.keyringHash(keyring));
}

/**
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {FramedKeyringHopsBytes} hops
 * @returns {MembershipChange}
 */
export function syncKeyring(keyring, treeId, hops) {
  return /** @type {MembershipChange} */ (wasm.syncKeyring(keyring, treeId, hops));
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 */
export function keyringHasBeenShared(engine, keyring) {
  return wasm.keyringHasBeenShared(engine, keyring);
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @returns {DidKey[]}
 */
export function moderatorsFromKeyring(engine, keyring) {
  return /** @type {DidKey[]} */ (wasm.moderatorsFromKeyring(engine, keyring));
}

/**
 * @param {KeyringBytes} keyring
 * @returns {DagAnchorPinBytes}
 */
export function dagAnchorPin(keyring) {
  return /** @type {DagAnchorPinBytes} */ (wasm.dagAnchorPin(keyring));
}

/**
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {DagAnchorPinBytes} pin
 * @returns {MembershipChange}
 */
export function verifyDagAnchor(keyring, treeId, pin) {
  return /** @type {MembershipChange} */ (wasm.verifyDagAnchor(keyring, treeId, pin));
}

/**
 * @param {KeyringBytes} local
 * @param {KeyringBytes} remote
 * @param {TreeId} treeId
 * @param {DagAnchorPinBytes} pin
 * @param {KeyringWatermarkBytes} floor
 * @returns {MembershipChange}
 */
export function acceptRemoteDagAnchor(local, remote, treeId, pin, floor) {
  return /** @type {MembershipChange} */ (
    wasm.acceptRemoteDagAnchor(local, remote, treeId, pin, floor)
  );
}

/**
 * @param {KeyringBytes} keyring
 * @param {TreeId} treeId
 * @param {KeyringRevision} revision
 * @returns {KeyringUpdateBytes}
 */
export function wrapDagKeyringUpdate(keyring, treeId, revision) {
  return /** @type {KeyringUpdateBytes} */ (wasm.wrapDagKeyringUpdate(keyring, treeId, revision));
}

/**
 * @param {KeyringUpdateBytes} update
 * @returns {KeyringBytes}
 */
export function unwrapDagKeyring(update) {
  return /** @type {KeyringBytes} */ (wasm.unwrapDagKeyring(update));
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {ResetAuthorityBytes} resetAuthority
 */
export function rotationConfirmed(engine, keyring, resetAuthority) {
  return wasm.rotationConfirmed(engine, keyring, resetAuthority);
}

/**
 * @param {AccountHandle} account
 * @param {KeyringEngine} engine
 * @param {TreeId} treeId
 * @param {ReplicaId} replicaId
 * @param {KeyringBytes} keyring
 * @param {KeyringWatermarkBytes} floor
 * @returns {DagBackfilled}
 */
export function backfillRrkWithAccount(account, engine, treeId, replicaId, keyring, floor) {
  return /** @type {DagBackfilled} */ (
    wasm.backfillRrkWithAccount(account, engine, treeId, replicaId, keyring, floor)
  );
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @returns {AuthorPublicKeyBytes}
 */
export function resolvedOwnerKey(engine, keyring) {
  return /** @type {AuthorPublicKeyBytes} */ (wasm.resolvedOwnerKey(engine, keyring));
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {AuthorPublicKeyBytes} ownerKey
 */
export function recoveryConfirmed(engine, keyring, ownerKey) {
  return wasm.recoveryConfirmed(engine, keyring, ownerKey);
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @returns {KeyringSummaryJson}
 */
export function keyringSummary(engine, keyring) {
  return /** @type {KeyringSummaryJson} */ (wasm.keyringSummary(engine, keyring));
}

/**
 * @param {KeyringBytes} keyring
 * @returns {TrustedSignersBytes}
 */
export function chainHeadSigners(keyring) {
  return /** @type {TrustedSignersBytes} */ (wasm.chainHeadSigners(keyring));
}

/**
 * @param {KeyringEngine} engine
 * @param {KeyringBytes} keyring
 * @param {string[]} storedBasis
 */
export function keyringCovers(engine, keyring, storedBasis) {
  return wasm.keyringCovers(engine, keyring, storedBasis);
}
