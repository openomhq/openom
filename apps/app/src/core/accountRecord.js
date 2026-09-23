/** @typedef {import('./types/domain.js').AccountBlobHashBytes} AccountBlobHashBytes */
/** @typedef {import('./types/domain.js').AccountBackupEtag} AccountBackupEtag */
/** @typedef {import('./types/domain.js').AccountGeneration} AccountGeneration */
/** @typedef {import('./types/domain.js').AccountKeystoreBytes} AccountKeystoreBytes */
/** @typedef {import('./types/domain.js').AccountRecordRevision} AccountRecordRevision */
/** @typedef {import('./types/domain.js').AuthIssuer} AuthIssuer */
/** @typedef {import('./types/domain.js').AuthSubject} AuthSubject */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/appCoreApi.js').AccountSnapshot} AccountSnapshot */
/** @typedef {import('./types/contracts.js').AccountBackupCheckpoint} AccountBackupCheckpoint */
/** @typedef {import('./types/contracts.js').AccountBackupKind} AccountBackupKind */
/** @typedef {import('./types/contracts.js').AccountBinding} AccountBinding */
/** @typedef {import('./types/contracts.js').AccountIdentitySnapshot} AccountIdentitySnapshot */
/** @typedef {import('./types/contracts.js').AccountRecord} AccountRecord */
/** @typedef {import('./types/contracts.js').AccountVersion} AccountVersion */
/** @typedef {import('./types/contracts.js').PendingAccountBackup} PendingAccountBackup */

const HASH_BYTES = 32;

/** @param {string} message @returns {never} */
function fail(message) {
  throw new TypeError(`invalid account record: ${message}`);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);
}

/** @template {Uint8Array} Bytes @param {Bytes} value @param {string} name @returns {Bytes} */
function cloneBytes(value, name) {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return /** @type {Bytes} */ (new Uint8Array(value));
}

/** @param {unknown} value @param {string} name @returns {Uint8Array} */
function bytesFromJson(value, name) {
  if (!Array.isArray(value)) fail(`${name} must be a JSON byte array`);
  if (!value.every((byte) => typeof byte === 'number'
    && Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    fail(`${name} contains an invalid byte`);
  }
  return Uint8Array.from(value);
}

/** @param {unknown} value @param {string} name @returns {asserts value is number} */
function safeNonnegative(value, name) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${name} must be a safe nonnegative integer`);
  }
}

/** @param {unknown} value @param {string} name @returns {asserts value is number} */
function safePositive(value, name) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    fail(`${name} must be a safe positive integer`);
  }
}

/** @param {unknown} value @param {string} name @returns {asserts value is string} */
function nonemptyString(value, name) {
  if (typeof value !== 'string' || value.length === 0) fail(`${name} must be a nonempty string`);
}

/** @param {Record<string, unknown>} object @param {string} name @returns {unknown} */
function nullableProperty(object, name) {
  if (!Object.hasOwn(object, name) || object[name] === undefined) fail(`${name} must be present`);
  return object[name];
}

/** @param {Uint8Array} left @param {Uint8Array} right @returns {boolean} */
function bytesEqual(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** @param {AccountVersion} version @returns {AccountVersion} */
function cloneVersion(version) {
  return { generation: version.generation, blobHash: cloneBytes(version.blobHash, 'version.blobHash') };
}

/** @param {AccountBinding | null} binding @returns {AccountBinding | null} */
function cloneBinding(binding) {
  return binding === null ? null : {
    issuer: binding.issuer,
    subject: binding.subject,
    memberId: binding.memberId,
  };
}

/** @param {AccountBackupCheckpoint | null} checkpoint @returns {AccountBackupCheckpoint | null} */
function cloneCheckpoint(checkpoint) {
  return checkpoint === null ? null : {
    etag: checkpoint.etag,
    version: checkpoint.version === null ? null : cloneVersion(checkpoint.version),
  };
}

/** @param {PendingAccountBackup | null} pending @returns {PendingAccountBackup | null} */
function clonePending(pending) {
  return pending === null ? null : {
    kind: pending.kind,
    version: cloneVersion(pending.version),
    binding: { ...pending.binding },
  };
}

/** @param {AccountIdentitySnapshot} identity @param {string} [name] @returns {AccountIdentitySnapshot} */
function cloneIdentity(identity, name = 'identity') {
  return {
    memberId: identity.memberId,
    keystore: cloneBytes(identity.keystore, `${name}.keystore`),
    version: cloneVersion(identity.version),
    floor: identity.floor,
  };
}

/** @param {AccountBinding | null} left @param {AccountBinding | null} right @returns {boolean} */
function bindingEqual(left, right) {
  return left !== null
    && right !== null
    && left.issuer === right.issuer
    && left.subject === right.subject
    && left.memberId === right.memberId;
}

/** @param {PendingAccountBackup | null} left @param {PendingAccountBackup | null} right @returns {boolean} */
function pendingEqual(left, right) {
  return left !== null
    && right !== null
    && left.kind === right.kind
    && sameAccountVersion(left.version, right.version)
    && bindingEqual(left.binding, right.binding);
}

/** @param {AccountRecord} record @returns {AccountRecord} */
function immutableRecord(record) {
  /** @param {AccountIdentitySnapshot} value @param {string} name */
  const freezeIdentity = (value, name) => {
    const identity = cloneIdentity(value, name);
    Object.freeze(identity.version);
    return Object.freeze(identity);
  };
  const identity = freezeIdentity(record.identity, 'identity');
  const retainedIdentities = Object.freeze(record.retainedIdentities.map(
    (retained, index) => freezeIdentity(retained, `retainedIdentities[${index}]`),
  ));
  const binding = cloneBinding(record.binding);
  const checkpoint = cloneCheckpoint(record.acknowledgedBackup);
  const pending = clonePending(record.pendingBackup);
  if (binding !== null) Object.freeze(binding);
  if (checkpoint !== null && checkpoint.version !== null) Object.freeze(checkpoint.version);
  if (checkpoint !== null) Object.freeze(checkpoint);
  if (pending !== null) {
    Object.freeze(pending.version);
    Object.freeze(pending.binding);
    Object.freeze(pending);
  }
  return Object.freeze({
    revision: record.revision,
    identity,
    retainedIdentities,
    binding,
    acknowledgedBackup: checkpoint,
    pendingBackup: pending,
  });
}

/** @param {unknown} value @returns {unknown} */
function recordFromJson(value) {
  if (!isObject(value) || !isObject(value.identity)) fail('must be an object with identity');
  const binding = nullableProperty(value, 'binding');
  const acknowledgedBackup = nullableProperty(value, 'acknowledgedBackup');
  const pendingBackup = nullableProperty(value, 'pendingBackup');
  const retainedIdentities = nullableProperty(value, 'retainedIdentities');
  if (!Array.isArray(retainedIdentities)) fail('retainedIdentities must be an array');
  /** @param {unknown} identity @param {string} name @returns {unknown} */
  const identityFromJson = (identity, name) => {
    if (!isObject(identity) || !isObject(identity.blob)) fail(`${name} must contain a blob`);
    return {
      memberId: identity.memberId,
      keystore: bytesFromJson(identity.blob.keystore, `${name}.blob.keystore`),
      version: {
        generation: identity.blob.generation,
        blobHash: bytesFromJson(identity.blob.blobHash, `${name}.blob.blobHash`),
      },
      floor: identity.floor,
    };
  };
  return {
    revision: value.revision,
    identity: identityFromJson(value.identity, 'identity'),
    retainedIdentities: retainedIdentities.map(
      (identity, index) => identityFromJson(identity, `retainedIdentities[${index}]`),
    ),
    binding,
    acknowledgedBackup: acknowledgedBackup === null ? null : recordVersionFromJson(acknowledgedBackup, true),
    pendingBackup: pendingBackup === null ? null : recordVersionFromJson(pendingBackup, false),
  };
}

/** @param {unknown} value @param {boolean} checkpoint @returns {unknown} */
function recordVersionFromJson(value, checkpoint) {
  if (!isObject(value)) fail('backup checkpoint or pending backup must be an object');
  const version = value.version;
  if (checkpoint && version === null) return { etag: value.etag, version: null };
  if (!isObject(version)) fail('backup version must be an object');
  const parsedVersion = {
    generation: version.generation,
    blobHash: bytesFromJson(version.blobHash, 'backup.version.blobHash'),
  };
  return checkpoint
    ? { etag: value.etag, version: parsedVersion }
    : { kind: value.kind, version: parsedVersion, binding: value.binding };
}

/** @param {AccountRecord} record @returns {unknown} */
function recordToJson(record) {
  /** @param {AccountVersion} value */
  const version = (value) => ({ generation: value.generation, blobHash: Array.from(value.blobHash) });
  /** @param {AccountIdentitySnapshot} value */
  const identity = (value) => ({
    memberId: value.memberId,
    blob: {
      keystore: Array.from(value.keystore),
      generation: value.version.generation,
      blobHash: Array.from(value.version.blobHash),
    },
    floor: value.floor,
  });
  return {
    revision: record.revision,
    identity: identity(record.identity),
    retainedIdentities: record.retainedIdentities.map(identity),
    binding: record.binding === null ? null : { ...record.binding },
    acknowledgedBackup: record.acknowledgedBackup === null ? null : {
      etag: record.acknowledgedBackup.etag,
      version: record.acknowledgedBackup.version === null ? null : version(record.acknowledgedBackup.version),
    },
    pendingBackup: record.pendingBackup === null ? null : {
      kind: record.pendingBackup.kind,
      version: version(record.pendingBackup.version),
      binding: { ...record.pendingBackup.binding },
    },
  };
}

/** @param {unknown} version @param {string} name @returns {AccountVersion} */
function validateVersion(version, name) {
  if (!isObject(version)) fail(`${name} must be an object`);
  safeNonnegative(version.generation, `${name}.generation`);
  if (!(version.blobHash instanceof Uint8Array) || version.blobHash.length !== HASH_BYTES) {
    fail(`${name}.blobHash must contain ${HASH_BYTES} bytes`);
  }
  return {
    generation: /** @type {AccountGeneration} */ (version.generation),
    blobHash: /** @type {AccountBlobHashBytes} */ (version.blobHash),
  };
}

/** @param {unknown} binding @param {MemberId} memberId @param {string} name @returns {AccountBinding} */
function validateBinding(binding, memberId, name) {
  if (!isObject(binding)) fail(`${name} must be an object`);
  if (typeof binding.issuer !== 'string') fail(`${name}.issuer must be a string`);
  nonemptyString(binding.subject, `${name}.subject`);
  if (binding.memberId !== memberId) fail(`${name} belongs to another identity`);
  return {
    issuer: /** @type {AuthIssuer} */ (binding.issuer),
    subject: /** @type {AuthSubject} */ (binding.subject),
    memberId,
  };
}

/** @param {Uint8Array} bytes @returns {Promise<Uint8Array>} */
async function sha256(bytes) {
  const copy = new Uint8Array(bytes);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy));
}

/** @param {unknown} identity @param {string} name @returns {Promise<AccountIdentitySnapshot>} */
async function validateIdentity(identity, name) {
  if (!isObject(identity)) fail(`${name} must be an object`);
  nonemptyString(identity.memberId, `${name}.memberId`);
  if (!(identity.keystore instanceof Uint8Array)) fail(`${name}.keystore must be a Uint8Array`);
  const version = validateVersion(identity.version, `${name}.version`);
  safeNonnegative(identity.floor, `${name}.floor`);
  const actualHash = await sha256(identity.keystore);
  if (!bytesEqual(actualHash, version.blobHash)) {
    fail(`${name}.version.blobHash does not match ${name}.keystore`);
  }
  return {
    memberId: /** @type {MemberId} */ (identity.memberId),
    keystore: /** @type {AccountKeystoreBytes} */ (identity.keystore),
    version,
    floor: /** @type {AccountGeneration} */ (identity.floor),
  };
}

/** @param {unknown} left @param {unknown} right @returns {boolean} Returns true only when a generation and exact wrapped-blob digest match. */
export function sameAccountVersion(left, right) {
  return isObject(left)
    && isObject(right)
    && left.generation === right.generation
    && left.blobHash instanceof Uint8Array
    && right.blobHash instanceof Uint8Array
    && bytesEqual(left.blobHash, right.blobHash);
}

/** @param {AccountRecord} record @returns {AccountGeneration} Returns the anti-rollback floor, self-healed from the resident blob generation. */
export function effectiveAccountFloor(record) {
  return /** @type {AccountGeneration} */ (Math.max(record.identity.floor, record.identity.version.generation));
}

/** @param {AccountRecord | null} record @param {MemberId} memberId @returns {AccountGeneration} Returns the known floor, or zero for a new identity. */
export function accountFloorForMember(record, memberId) {
  if (!record) return /** @type {AccountGeneration} */ (0);
  const identity = record.identity.memberId === memberId
    ? record.identity
    : record.retainedIdentities.find((candidate) => candidate.memberId === memberId);
  return identity
    ? /** @type {AccountGeneration} */ (Math.max(identity.floor, identity.version.generation))
    : /** @type {AccountGeneration} */ (0);
}

/** @param {AccountRecord} record @returns {AccountIdentitySnapshot[]} */
function allIdentities(record) {
  return [record.identity, ...record.retainedIdentities];
}

/** @param {AccountRecord | null} previous @param {AccountRecord} next Refuses transitions that drop custody or lower a known identity's authenticated floor. */
export function assertAccountCustodyPreserved(previous, next) {
  if (!previous) return;
  for (const identity of allIdentities(previous)) {
    const becomesActive = next.identity.memberId === identity.memberId;
    const replacement = becomesActive
      ? next.identity
      : next.retainedIdentities.find((candidate) => candidate.memberId === identity.memberId);
    if (!replacement) fail(`transition drops custody for ${identity.memberId}`);
    const previousFloor = Math.max(identity.floor, identity.version.generation);
    const nextFloor = Math.max(replacement.floor, replacement.version.generation);
    if (nextFloor < previousFloor) fail(`transition lowers generation floor for ${identity.memberId}`);
    if (!becomesActive && (replacement.floor !== identity.floor
      || !sameAccountVersion(replacement.version, identity.version)
      || !bytesEqual(replacement.keystore, identity.keystore))) {
      fail(`transition mutates retained custody for ${identity.memberId}`);
    }
  }
}

/** @param {unknown} record @returns {Promise<AccountRecord>} Validates an in-memory record and returns an immutable, detached clone. */
export async function validateAccountRecord(record) {
  if (!isObject(record) || !isObject(record.identity)) fail('must be an object with identity');
  safePositive(record.revision, 'revision');
  const identity = await validateIdentity(record.identity, 'identity');
  if (!Array.isArray(record.retainedIdentities)) fail('retainedIdentities must be an array');
  const memberIds = new Set([identity.memberId]);
  /** @type {AccountIdentitySnapshot[]} */
  const retainedIdentities = [];
  for (const [index, retained] of record.retainedIdentities.entries()) {
    const validated = await validateIdentity(retained, `retainedIdentities[${index}]`);
    if (memberIds.has(validated.memberId)) fail('identity member ids must be unique');
    memberIds.add(validated.memberId);
    retainedIdentities.push(validated);
  }

  const binding = record.binding === null ? null : validateBinding(record.binding, identity.memberId, 'binding');
  /** @type {AccountBackupCheckpoint | null} */
  let acknowledgedBackup = null;
  if (record.acknowledgedBackup !== null) {
    if (binding === null) fail('acknowledgedBackup requires binding');
    if (!isObject(record.acknowledgedBackup)) fail('acknowledgedBackup must be an object');
    nonemptyString(record.acknowledgedBackup.etag, 'acknowledgedBackup.etag');
    const version = record.acknowledgedBackup.version === null
      ? null
      : validateVersion(record.acknowledgedBackup.version, 'acknowledgedBackup.version');
    acknowledgedBackup = {
      etag: /** @type {AccountBackupEtag} */ (record.acknowledgedBackup.etag),
      version,
    };
  }
  /** @type {PendingAccountBackup | null} */
  let pendingBackup = null;
  if (record.pendingBackup !== null) {
    if (!isObject(record.pendingBackup)) fail('pendingBackup must be an object');
    if (record.pendingBackup.kind !== 'backup' && record.pendingBackup.kind !== 'revoke') {
      fail('pendingBackup.kind must be backup or revoke');
    }
    const version = validateVersion(record.pendingBackup.version, 'pendingBackup.version');
    if (binding === null) fail('pendingBackup requires binding');
    const pendingBinding = validateBinding(record.pendingBackup.binding, identity.memberId, 'pendingBackup.binding');
    if (pendingBinding.issuer !== binding.issuer || pendingBinding.subject !== binding.subject) {
      fail('pendingBackup.binding is not the confirmed binding');
    }
    pendingBackup = {
      kind: /** @type {AccountBackupKind} */ (record.pendingBackup.kind),
      version,
      binding: pendingBinding,
    };
  }
  return immutableRecord({
    revision: /** @type {AccountRecordRevision} */ (record.revision),
    identity,
    retainedIdentities,
    binding,
    acknowledgedBackup,
    pendingBackup,
  });
}

/** @param {AccountSnapshot} snapshot @param {AccountGeneration} [floor] @returns {AccountIdentitySnapshot} */
function identityFromSnapshot(snapshot, floor = snapshot.generation) {
  if (!isObject(snapshot)) fail('snapshot must be an object');
  nonemptyString(snapshot.memberId, 'snapshot.memberId');
  return {
    memberId: /** @type {MemberId} */ (snapshot.memberId),
    keystore: cloneBytes(snapshot.keystore, 'snapshot.keystore'),
    version: {
      generation: snapshot.generation,
      blobHash: cloneBytes(snapshot.blobHash, 'snapshot.blobHash'),
    },
    floor,
  };
}

/** Creates revision one from a credential-authenticated account snapshot. */
/** @param {AccountSnapshot} snapshot @returns {Promise<AccountRecord>} */
export async function createAccountRecord(snapshot) {
  return validateAccountRecord({
    revision: 1,
    identity: identityFromSnapshot(snapshot),
    retainedIdentities: [],
    binding: null,
    acknowledgedBackup: null,
    pendingBackup: null,
  });
}

/** Replaces active custody while retaining every displaced wrapped identity and its scoped floor. */
/** @param {AccountRecord} record @param {AccountSnapshot} snapshot @param {{ pendingKind?: AccountBackupKind | null }} [options] @returns {Promise<AccountRecord>} */
export async function replaceAccountIdentity(record, snapshot, { pendingKind = null } = {}) {
  const current = await validateAccountRecord(record);
  if (current.revision === Number.MAX_SAFE_INTEGER) fail('revision is exhausted');
  if (pendingKind !== null && pendingKind !== 'backup' && pendingKind !== 'revoke') {
    fail('identity replacement pending kind must be backup, revoke, or null');
  }
  nonemptyString(snapshot.memberId, 'snapshot.memberId');
  const memberId = /** @type {MemberId} */ (snapshot.memberId);
  const sameIdentity = current.identity.memberId === memberId;
  const knownFloor = accountFloorForMember(current, memberId);
  if (snapshot.generation < knownFloor) fail('identity generation rolls back');
  const identity = identityFromSnapshot(
    snapshot,
    /** @type {AccountGeneration} */ (Math.max(knownFloor, snapshot.generation)),
  );
  const retainedIdentities = sameIdentity
    ? current.retainedIdentities
    : [
      ...current.retainedIdentities.filter((retained) => retained.memberId !== identity.memberId),
      current.identity,
    ];
  let pendingBackup = null;
  const changedVersion = !sameAccountVersion(current.identity.version, identity.version);
  if (sameIdentity && current.pendingBackup?.kind === 'revoke') {
    pendingBackup = { ...current.pendingBackup, version: identity.version };
  } else if (sameIdentity && current.binding !== null && changedVersion && pendingKind !== null) {
    pendingBackup = { kind: pendingKind, version: identity.version, binding: current.binding };
  } else if (sameIdentity && current.pendingBackup !== null
    && sameAccountVersion(current.pendingBackup.version, identity.version)) {
    pendingBackup = current.pendingBackup;
  }
  return validateAccountRecord({
    revision: current.revision + 1,
    identity,
    retainedIdentities,
    binding: sameIdentity ? current.binding : null,
    acknowledgedBackup: sameIdentity ? current.acknowledgedBackup : null,
    pendingBackup,
  });
}

/** Atomically activates verified remote custody with its binding/checkpoint and optional rotation intent. */
/** @param {AccountRecord | null} record @param {AccountSnapshot} snapshot @param {{ binding: AccountBinding; checkpoint: AccountBackupCheckpoint; pendingKind?: 'revoke' | null }} options @returns {Promise<AccountRecord>} */
export async function adoptRemoteAccountIdentity(record, snapshot, {
  binding,
  checkpoint,
  pendingKind = null,
}) {
  const replaced = record
    ? await replaceAccountIdentity(record, snapshot)
    : await createAccountRecord(snapshot);
  validateBinding(binding, replaced.identity.memberId, 'binding');
  if (!isObject(checkpoint)) fail('adoption checkpoint must be an object');
  nonemptyString(checkpoint.etag, 'adoption checkpoint.etag');
  if (checkpoint.version !== null) validateVersion(checkpoint.version, 'adoption checkpoint.version');
  if (pendingKind !== null && pendingKind !== 'revoke') {
    fail('recovery adoption pending kind must be revoke');
  }
  return validateAccountRecord({
    ...replaced,
    binding,
    acknowledgedBackup: checkpoint,
    pendingBackup: pendingKind === null ? null : {
      kind: pendingKind,
      version: replaced.identity.version,
      binding,
    },
  });
}

/** Commits a server-confirmed auth binding and clears checkpoints from any prior subject. */
/** @param {AccountRecord} record @param {AccountBinding} binding @returns {Promise<AccountRecord>} */
export async function confirmAccountBinding(record, binding) {
  const current = await validateAccountRecord(record);
  validateBinding(binding, current.identity.memberId, 'binding');
  if (bindingEqual(current.binding, binding)) return current;
  if (current.revision === Number.MAX_SAFE_INTEGER) fail('revision is exhausted');
  return validateAccountRecord({
    ...current,
    revision: current.revision + 1,
    binding,
    acknowledgedBackup: null,
    pendingBackup: null,
  });
}

/** Persists an upload/revocation intent for the exact current blob before any network request. */
/** @param {AccountRecord} record @param {{ kind: AccountBackupKind; binding: AccountBinding }} options @returns {Promise<AccountRecord>} */
export async function stageAccountBackup(record, { kind, binding }) {
  const current = await validateAccountRecord(record);
  if (!bindingEqual(current.binding, binding)) fail('pendingBackup.binding is not the confirmed binding');
  const pendingBackup = {
    kind,
    version: current.identity.version,
    binding,
  };
  if (pendingEqual(current.pendingBackup, pendingBackup)) return current;
  if (current.pendingBackup?.kind === 'revoke' && kind === 'backup'
    && current.pendingBackup.version.generation >= current.identity.version.generation) {
    return current;
  }
  if (current.revision === Number.MAX_SAFE_INTEGER) fail('revision is exhausted');
  return validateAccountRecord({
    ...current,
    revision: current.revision + 1,
    pendingBackup,
  });
}

/** Clears only the exact pending operation acknowledged by the server and records its remote checkpoint. */
/** @param {AccountRecord} record @param {PendingAccountBackup} expected @param {AccountBackupCheckpoint | null} checkpoint @returns {Promise<AccountRecord | null>} */
export async function acknowledgeAccountBackup(record, expected, checkpoint) {
  const current = await validateAccountRecord(record);
  if (!pendingEqual(current.pendingBackup, expected)) return null;
  const acknowledgedBackup = checkpoint === null ? null : cloneCheckpoint(checkpoint);
  if (acknowledgedBackup?.version === null
    || !sameAccountVersion(acknowledgedBackup?.version, expected.version)) {
    fail('backup acknowledgement version does not match pending backup');
  }
  if (current.revision === Number.MAX_SAFE_INTEGER) fail('revision is exhausted');
  return validateAccountRecord({
    ...current,
    revision: current.revision + 1,
    acknowledgedBackup,
    pendingBackup: null,
  });
}

/** Serializes a validated record with binary fields represented as JSON byte arrays. */
/** @param {AccountRecord} record @returns {Promise<Uint8Array>} */
export async function encodeAccountRecord(record) {
  const valid = await validateAccountRecord(record);
  return new TextEncoder().encode(JSON.stringify(recordToJson(valid)));
}

/** Decodes, validates, and detaches a persisted JSON account record. */
/** @param {Uint8Array} bytes @returns {Promise<AccountRecord>} */
export async function decodeAccountRecord(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('encoded record must be a Uint8Array');
  /** @type {unknown} */
  let parsed;
  try {
    parsed = /** @type {unknown} */ (JSON.parse(new TextDecoder().decode(bytes)));
  } catch {
    fail('encoded record is not valid JSON');
  }
  return validateAccountRecord(recordFromJson(parsed));
}
