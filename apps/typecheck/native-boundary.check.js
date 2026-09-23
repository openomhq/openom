import { invokeNative } from '../app/src/core/nativeHost.js';

/** @typedef {import('../app/src/core/types/contracts.js').AccountBinding} AccountBinding */
/** @typedef {import('../app/src/core/types/domain.js').MemberId} MemberId */
/** @typedef {import('../app/src/core/types/domain.js').Passphrase} Passphrase */
/** @typedef {import('../app/src/core/types/domain.js').RecoveryCode} RecoveryCode */
/** @typedef {import('../app/src/core/types/domain.js').DocId} DocId */
/** @typedef {import('../app/src/core/types/domain.js').FramedKeyringHopsBytes} FramedKeyringHopsBytes */
/** @typedef {import('../app/src/core/types/domain.js').TreeId} TreeId */
/** @typedef {import('../app/src/core/types/nativeCommands.js').NativeBytes<TreeId>} NativeTreeId */
/** @typedef {import('../app/src/core/types/nativeCommands.js').NativeBytes<FramedKeyringHopsBytes>} NativeHops */

const passphrase = /** @type {Passphrase} */ ('correct horse battery staple');
const recoveryCode = /** @type {RecoveryCode} */ ('recovery-code');
const memberId = /** @type {MemberId} */ ('member');
const docId = /** @type {DocId} */ ('doc');
const treeId = /** @type {NativeTreeId} */ (/** @type {unknown} */ ([]));
const hops = /** @type {NativeHops} */ (/** @type {unknown} */ ([]));
const binding = /** @type {AccountBinding} */ ({
  issuer: /** @type {import('../app/src/core/types/domain.js').AuthIssuer} */ ('https://issuer.example'),
  subject: /** @type {import('../app/src/core/types/domain.js').AuthSubject} */ ('subject'),
  memberId,
});

const created = invokeNative('account_create', { passphrase });
/** @type {Promise<import('../app/src/core/types/appCoreApi.js').AccountCreated>} */
const typedCreated = created;
void typedCreated;

invokeNative('account_recover', { recoveryCode, newPassphrase: passphrase });
invokeNative('account_confirm_binding', { binding });
invokeNative('account_status');
invokeNative('core_sync_keyring', { doc: docId, treeId, hops });

// @ts-expect-error Native command names are a closed vocabulary generated from the Rust host surface.
invokeNative('account_creat', { passphrase });

// @ts-expect-error No-argument commands reject accidental payloads.
invokeNative('account_status', {});

// @ts-expect-error Recovery and replacement passphrases are distinct credential domains.
invokeNative('account_recover', { recoveryCode: passphrase, newPassphrase: recoveryCode });

// @ts-expect-error Command payload field names must match Tauri's camelCase contract.
invokeNative('account_confirm_binding', { accountBinding: binding });

// @ts-expect-error Commands with payloads cannot silently omit their required arguments.
invokeNative('account_create');

// @ts-expect-error Serialized tree identifiers and keyring hops remain distinct domains.
invokeNative('core_sync_keyring', { doc: docId, treeId: hops, hops: treeId });
