/** @typedef {import('../app/src/core/types/domain.js').AccountGeneration} AccountGeneration */
/** @typedef {import('../app/src/core/types/domain.js').AccountKeystoreBytes} AccountKeystoreBytes */
/** @typedef {import('../app/src/core/types/domain.js').AccountRecordRevision} AccountRecordRevision */
/** @typedef {import('../app/src/core/types/domain.js').DocId} DocId */
/** @typedef {import('../app/src/core/types/domain.js').KeyringBytes} KeyringBytes */
/** @typedef {import('../app/src/core/types/domain.js').MemberId} MemberId */
/** @typedef {import('../app/src/core/types/domain.js').MemberRole} MemberRole */
/** @typedef {import('../app/src/core/types/domain.js').ReplicaId} ReplicaId */
/** @typedef {import('../app/src/core/types/domain.js').StorageCasToken} StorageCasToken */
/** @typedef {import('../app/src/core/types/domain.js').TreeId} TreeId */

const treeId = /** @type {TreeId} */ (new Uint8Array(16));
const replicaId = /** @type {ReplicaId} */ (new Uint8Array(16));
const keyring = /** @type {KeyringBytes} */ (new Uint8Array());
const keystore = /** @type {AccountKeystoreBytes} */ (new Uint8Array());
const memberId = /** @type {MemberId} */ ('member');
const docId = /** @type {DocId} */ ('document');
const generation = /** @type {AccountGeneration} */ (1);
const recordRevision = /** @type {AccountRecordRevision} */ (1);
const storageCasToken = /** @type {StorageCasToken} */ ('v1');
/** @type {MemberRole} */
const memberRole = 'co-owner';

/**
 * @param {TreeId} tree
 * @param {ReplicaId} replica
 * @param {DocId} document
 */
function openTree(tree, replica, document) {
  return { tree, replica, document };
}

/**
 * @param {KeyringBytes} keyringBytes
 * @param {AccountKeystoreBytes} keystoreBytes
 */
function persistOpaqueBytes(keyringBytes, keystoreBytes) {
  return keyringBytes.byteLength + keystoreBytes.byteLength;
}

/**
 * @param {MemberId} member
 * @param {DocId} document
 */
function bindDocument(member, document) {
  return `${member}:${document}`;
}

/**
 * @param {AccountGeneration} accountGeneration
 * @param {AccountRecordRevision} revision
 */
function persistCounters(accountGeneration, revision) {
  return accountGeneration + revision;
}

/** @param {MemberRole} role */
function acceptMemberRole(role) {
  return role;
}

openTree(treeId, replicaId, docId);
persistOpaqueBytes(keyring, keystore);
bindDocument(memberId, docId);
persistCounters(generation, recordRevision);
void storageCasToken;
void memberRole;
acceptMemberRole(memberRole);

/** @type {Uint8Array} */
const rawTreeId = treeId;
void rawTreeId;

// @ts-expect-error TreeId and ReplicaId have the same runtime representation but distinct domains.
openTree(replicaId, treeId, docId);

// @ts-expect-error Required boundary arguments cannot be omitted.
openTree(treeId, replicaId);

// @ts-expect-error Keyring bytes cannot be used as an account keystore.
persistOpaqueBytes(keystore, keyring);

// @ts-expect-error Authentication/document labels cannot stand in for a durable member identity.
bindDocument(docId, memberId);

// @ts-expect-error Credential generations and local record revisions are independent counters.
persistCounters(recordRevision, generation);

// @ts-expect-error A storage CAS token is not a portable account-record revision.
persistCounters(generation, storageCasToken);

// @ts-expect-error Unvalidated raw bytes are not a TreeId.
openTree(new Uint8Array(16), replicaId, docId);

// @ts-expect-error Membership roles use the lowercase wire vocabulary.
acceptMemberRole('CoOwner');
