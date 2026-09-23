import {
  accountRegisterProof,
  accountUnlock,
  addMemberWithAccount,
  provisionTree,
  unlockTree,
} from '../app/src/core/wasmAppCore.js';

/** @typedef {import('../app/src/core/types/domain.js').AccountGeneration} AccountGeneration */
/** @typedef {import('../app/src/core/types/domain.js').AccountKeystoreBytes} AccountKeystoreBytes */
/** @typedef {import('../app/src/core/types/domain.js').AppSecretEnvelopeBytes} AppSecretEnvelopeBytes */
/** @typedef {import('../app/src/core/types/domain.js').AppSecretPlaintextBytes} AppSecretPlaintextBytes */
/** @typedef {import('../app/src/core/types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('../app/src/core/types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('../app/src/core/types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('../app/src/core/types/domain.js').DocId} DocId */
/** @typedef {import('../app/src/core/types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('../app/src/core/types/domain.js').KeyringBytes} KeyringBytes */
/** @typedef {import('../app/src/core/types/domain.js').KeyringRevision} KeyringRevision */
/** @typedef {import('../app/src/core/types/domain.js').MemberId} MemberId */
/** @typedef {import('../app/src/core/types/domain.js').Passphrase} Passphrase */
/** @typedef {import('../app/src/core/types/domain.js').PredicateUri} PredicateUri */
/** @typedef {import('../app/src/core/types/domain.js').ProposalEnvelopeBytes} ProposalEnvelopeBytes */
/** @typedef {import('../app/src/core/types/domain.js').RecordId} RecordId */
/** @typedef {import('../app/src/core/types/domain.js').ReplicaId} ReplicaId */
/** @typedef {import('../app/src/core/types/domain.js').TreeId} TreeId */
/** @typedef {import('../app/src/core/types/wasm.js').AccountHandle} AccountHandle */
/** @typedef {import('../app/src/core/types/wasm.js').AppCoreHandle} AppCoreHandle */

const account = /** @type {AccountHandle} */ (/** @type {unknown} */ ({}));
const core = /** @type {AppCoreHandle} */ (/** @type {unknown} */ ({}));
const generation = /** @type {AccountGeneration} */ (1);
const keystore = /** @type {AccountKeystoreBytes} */ (new Uint8Array());
const passphrase = /** @type {Passphrase} */ ('correct horse battery staple');
const appSecret = /** @type {AppSecretPlaintextBytes} */ (new Uint8Array());
const sealedAppSecret = /** @type {AppSecretEnvelopeBytes} */ (new Uint8Array());
const proposal = /** @type {ProposalEnvelopeBytes} */ (new Uint8Array());
const treeId = /** @type {TreeId} */ (new Uint8Array(16));
const replicaId = /** @type {ReplicaId} */ (new Uint8Array(16));
const docId = /** @type {DocId} */ ('document');
const keyring = /** @type {KeyringBytes} */ (new Uint8Array());
const revision = /** @type {KeyringRevision} */ (1);
const memberId = /** @type {MemberId} */ ('member');
const authorPublicKey = /** @type {AuthorPublicKeyBytes} */ (new Uint8Array());
const hpkePublicKey = /** @type {HpkePublicKeyBytes} */ (new Uint8Array());
const issuer = /** @type {AuthIssuer} */ ('https://issuer.example');
const subject = /** @type {AuthSubject} */ ('provider-subject');
const recordId = /** @type {RecordId} */ ('record');
const predicate = /** @type {PredicateUri} */ ('https://openom.org/predicate');

accountUnlock(passphrase, keystore, generation);
provisionTree(account, 'chain', treeId, replicaId, docId);
unlockTree(account, 'chain', treeId, replicaId, keyring, docId);
addMemberWithAccount(
  account,
  'chain',
  keyring,
  treeId,
  replicaId,
  revision,
  memberId,
  'editor',
  authorPublicKey,
  hpkePublicKey,
);
accountRegisterProof(account, issuer, subject, 1);
core.sealAppSecret(appSecret);
core.openAppSecret(sealedAppSecret);
core.approveProposal(proposal);

// @ts-expect-error The typed wasm adapter rejects tree/replica swaps before flattening to Uint8Array.
provisionTree(account, 'chain', replicaId, treeId, docId);

// @ts-expect-error The keyring cannot occupy the tree-id position.
unlockTree(account, 'chain', keyring, replicaId, treeId, docId);

addMemberWithAccount(
  account,
  'chain',
  keyring,
  treeId,
  replicaId,
  revision,
  memberId,
  'editor',
  // @ts-expect-error Author-signing and HPKE public keys are distinct admission inputs.
  hpkePublicKey,
  authorPublicKey,
);

// @ts-expect-error Issuer and provider subject are distinct registration-proof fields.
accountRegisterProof(account, subject, issuer, 1);

// @ts-expect-error Raw strings must be admitted as credentials at an explicit boundary.
accountUnlock('not-branded', keystore, generation);

// @ts-expect-error Required document context cannot be omitted.
provisionTree(account, 'chain', treeId, replicaId);

// @ts-expect-error An app-secret envelope cannot be opened as a proposal.
core.approveProposal(sealedAppSecret);

// @ts-expect-error Plaintext and sealed app-secret bytes are distinct handle inputs.
core.openAppSecret(appSecret);

// @ts-expect-error Record identifiers and predicates cannot exchange positions.
core.liveClaimsOf(predicate, recordId);
