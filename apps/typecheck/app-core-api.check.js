/** @typedef {import('../app/src/core/types/appCoreApi.js').AppCoreClient} AppCoreClient */
/** @typedef {import('../app/src/core/types/appCoreApi.js').AppCoreService} AppCoreService */
/** @typedef {import('../app/src/core/types/appCoreApi.js').WebAppCoreClient} WebAppCoreClient */
/** @typedef {import('../app/src/core/types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('../app/src/core/types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('../app/src/core/types/domain.js').AuthorPublicKeyBytes} AuthorPublicKeyBytes */
/** @typedef {import('../app/src/core/types/domain.js').DocId} DocId */
/** @typedef {import('../app/src/core/types/domain.js').HpkePublicKeyBytes} HpkePublicKeyBytes */
/** @typedef {import('../app/src/core/types/domain.js').MemberId} MemberId */
/** @typedef {import('../app/src/core/types/domain.js').Passphrase} Passphrase */
/** @typedef {import('../app/src/core/types/domain.js').ReplicaId} ReplicaId */
/** @typedef {import('../app/src/core/types/domain.js').TreeId} TreeId */

const client = /** @type {AppCoreClient} */ (/** @type {unknown} */ ({}));
const webClient = /** @type {WebAppCoreClient} */ (/** @type {unknown} */ ({}));
const service = /** @type {AppCoreService} */ (/** @type {unknown} */ ({}));
const passphrase = /** @type {Passphrase} */ ('correct horse battery staple');
const treeId = /** @type {TreeId} */ (new Uint8Array(16));
const replicaId = /** @type {ReplicaId} */ (new Uint8Array(16));
const docId = /** @type {DocId} */ ('document');
const memberId = /** @type {MemberId} */ ('member');
const issuer = /** @type {AuthIssuer} */ ('https://issuer.example');
const subject = /** @type {AuthSubject} */ ('provider-subject');
const authorPublicKey = /** @type {AuthorPublicKeyBytes} */ (new Uint8Array());
const hpkePublicKey = /** @type {HpkePublicKeyBytes} */ (new Uint8Array());

const opened = client.provisionTree({ treeId, docId, engine: 'chain' });
/** @type {Promise<import('../app/src/core/types/appCoreApi.js').TreeOpenResult>} */
const remoteResult = opened;
void remoteResult;

service.openDev(treeId, replicaId, /** @type {import('../app/src/core/types/domain.js').DidKey} */ ('did:key:z'), docId);
client.accountRegisterProof({ issuer, subject, timestamp: 1 });
client.addMember(docId, {
  passphrase,
  treeId,
  ownerMemberId: memberId,
  newMemberId: memberId,
  role: 'editor',
  memberAuthorPublic: authorPublicKey,
  memberHpkePublic: hpkePublicKey,
});
webClient.setCompactK(8);

// @ts-expect-error Tree and replica ids remain distinct across the worker RPC contract.
service.openDev(replicaId, treeId, /** @type {import('../app/src/core/types/domain.js').DidKey} */ ('did:key:z'), docId);

// @ts-expect-error Provider issuer and subject cannot swap at the registration-proof call site.
client.accountRegisterProof({ issuer: subject, subject: issuer, timestamp: 1 });

client.addMember(docId, {
  passphrase,
  treeId,
  ownerMemberId: memberId,
  newMemberId: memberId,
  role: 'editor',
  // @ts-expect-error Signing and HPKE keys are distinct admission fields across RPC.
  memberAuthorPublic: hpkePublicKey,
  // @ts-expect-error The reciprocal public-key swap is rejected too.
  memberHpkePublic: authorPublicKey,
});

// @ts-expect-error Worker-only diagnostics are not part of the production cross-host client surface.
client.setCompactK(8);
