const HASH_BYTES = 32;

function fail(message) {
  throw new TypeError(`invalid account record: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function cloneBytes(value, name) {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return new Uint8Array(value);
}

function bytesFromJson(value, name) {
  if (!Array.isArray(value)) fail(`${name} must be a JSON byte array`);
  if (!value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    fail(`${name} contains an invalid byte`);
  }
  return Uint8Array.from(value);
}

function safeNonnegative(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be a safe nonnegative integer`);
}

function safePositive(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${name} must be a safe positive integer`);
}

function nonemptyString(value, name) {
  if (typeof value !== 'string' || value.length === 0) fail(`${name} must be a nonempty string`);
}

function nullableProperty(object, name) {
  if (!Object.hasOwn(object, name) || object[name] === undefined) fail(`${name} must be present`);
  return object[name];
}

function bytesEqual(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function cloneVersion(version) {
  return { generation: version.generation, blobHash: cloneBytes(version.blobHash, 'version.blobHash') };
}

function cloneBinding(binding) {
  return binding === null ? null : {
    issuer: binding.issuer,
    subject: binding.subject,
    memberId: binding.memberId,
  };
}

function cloneCheckpoint(checkpoint) {
  return checkpoint === null ? null : {
    etag: checkpoint.etag,
    version: checkpoint.version === null ? null : cloneVersion(checkpoint.version),
  };
}

function clonePending(pending) {
  return pending === null ? null : {
    kind: pending.kind,
    version: cloneVersion(pending.version),
    binding: cloneBinding(pending.binding),
  };
}

function cloneIdentity(identity, name = 'identity') {
  return {
    memberId: identity.memberId,
    keystore: cloneBytes(identity.keystore, `${name}.keystore`),
    version: cloneVersion(identity.version),
    floor: identity.floor,
  };
}

function bindingEqual(left, right) {
  return left !== null
    && right !== null
    && left.issuer === right.issuer
    && left.subject === right.subject
    && left.memberId === right.memberId;
}

function pendingEqual(left, right) {
  return left !== null
    && right !== null
    && left.kind === right.kind
    && sameAccountVersion(left.version, right.version)
    && bindingEqual(left.binding, right.binding);
}

function immutableRecord(record) {
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

function recordFromJson(value) {
  if (!isObject(value) || !isObject(value.identity)) fail('must be an object with identity');
  const binding = nullableProperty(value, 'binding');
  const acknowledgedBackup = nullableProperty(value, 'acknowledgedBackup');
  const pendingBackup = nullableProperty(value, 'pendingBackup');
  const retainedIdentities = nullableProperty(value, 'retainedIdentities');
  if (!Array.isArray(retainedIdentities)) fail('retainedIdentities must be an array');
  const identityFromJson = (identity, name) => ({
    memberId: identity?.memberId,
    keystore: bytesFromJson(identity?.blob?.keystore, `${name}.blob.keystore`),
    version: {
      generation: identity?.blob?.generation,
      blobHash: bytesFromJson(identity?.blob?.blobHash, `${name}.blob.blobHash`),
    },
    floor: identity?.floor,
  });
  return {
    revision: value.revision,
    identity: identityFromJson(value.identity, 'identity'),
    retainedIdentities: retainedIdentities.map(
      (identity, index) => identityFromJson(identity, `retainedIdentities[${index}]`),
    ),
    binding,
    acknowledgedBackup: acknowledgedBackup === null ? null : {
      ...acknowledgedBackup,
      version: acknowledgedBackup.version === null ? null : {
        ...acknowledgedBackup.version,
        blobHash: bytesFromJson(acknowledgedBackup.version.blobHash, 'acknowledgedBackup.version.blobHash'),
      },
    },
    pendingBackup: pendingBackup === null ? null : {
      ...pendingBackup,
      version: {
        ...pendingBackup.version,
        blobHash: bytesFromJson(pendingBackup.version?.blobHash, 'pendingBackup.version.blobHash'),
      },
    },
  };
}

function recordToJson(record) {
  const version = (value) => ({ generation: value.generation, blobHash: Array.from(value.blobHash) });
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

function validateVersion(version, name) {
  if (!isObject(version)) fail(`${name} must be an object`);
  safeNonnegative(version.generation, `${name}.generation`);
  if (!(version.blobHash instanceof Uint8Array) || version.blobHash.length !== HASH_BYTES) {
    fail(`${name}.blobHash must contain ${HASH_BYTES} bytes`);
  }
}

function validateBinding(binding, memberId, name) {
  if (!isObject(binding)) fail(`${name} must be an object`);
  if (typeof binding.issuer !== 'string') fail(`${name}.issuer must be a string`);
  nonemptyString(binding.subject, `${name}.subject`);
  if (binding.memberId !== memberId) fail(`${name} belongs to another identity`);
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function validateIdentity(identity, name) {
  if (!isObject(identity)) fail(`${name} must be an object`);
  nonemptyString(identity.memberId, `${name}.memberId`);
  if (!(identity.keystore instanceof Uint8Array)) fail(`${name}.keystore must be a Uint8Array`);
  validateVersion(identity.version, `${name}.version`);
  safeNonnegative(identity.floor, `${name}.floor`);
  const actualHash = await sha256(identity.keystore);
  if (!bytesEqual(actualHash, identity.version.blobHash)) {
    fail(`${name}.version.blobHash does not match ${name}.keystore`);
  }
}

/** Returns true only when a generation and exact wrapped-blob digest match. */
export function sameAccountVersion(left, right) {
  return isObject(left)
    && isObject(right)
    && left.generation === right.generation
    && left.blobHash instanceof Uint8Array
    && right.blobHash instanceof Uint8Array
    && bytesEqual(left.blobHash, right.blobHash);
}

/** Returns the anti-rollback floor, self-healed from the resident blob generation. */
export function effectiveAccountFloor(record) {
  return Math.max(record.identity.floor, record.identity.version.generation);
}

/** Returns the authenticated floor already held for a member, or zero for a genuinely new identity. */
export function accountFloorForMember(record, memberId) {
  if (!record) return 0;
  const identity = record.identity.memberId === memberId
    ? record.identity
    : record.retainedIdentities.find((candidate) => candidate.memberId === memberId);
  return identity ? Math.max(identity.floor, identity.version.generation) : 0;
}

function allIdentities(record) {
  return [record.identity, ...record.retainedIdentities];
}

/** Refuses any record transition that drops custody or lowers a known identity's authenticated floor. */
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

/** Validates an in-memory typed record and returns an immutable, detached clone. */
export async function validateAccountRecord(record) {
  if (!isObject(record) || !isObject(record.identity)) fail('must be an object with identity');
  safePositive(record.revision, 'revision');
  const { identity } = record;
  await validateIdentity(identity, 'identity');
  if (!Array.isArray(record.retainedIdentities)) fail('retainedIdentities must be an array');
  const memberIds = new Set([identity.memberId]);
  for (const [index, retained] of record.retainedIdentities.entries()) {
    await validateIdentity(retained, `retainedIdentities[${index}]`);
    if (memberIds.has(retained.memberId)) fail('identity member ids must be unique');
    memberIds.add(retained.memberId);
  }

  if (record.binding !== null) validateBinding(record.binding, identity.memberId, 'binding');
  if (record.acknowledgedBackup !== null) {
    if (record.binding === null) fail('acknowledgedBackup requires binding');
    if (!isObject(record.acknowledgedBackup)) fail('acknowledgedBackup must be an object');
    nonemptyString(record.acknowledgedBackup.etag, 'acknowledgedBackup.etag');
    if (record.acknowledgedBackup.version !== null) validateVersion(record.acknowledgedBackup.version, 'acknowledgedBackup.version');
  }
  if (record.pendingBackup !== null) {
    if (!isObject(record.pendingBackup)) fail('pendingBackup must be an object');
    if (record.pendingBackup.kind !== 'backup' && record.pendingBackup.kind !== 'revoke') {
      fail('pendingBackup.kind must be backup or revoke');
    }
    validateVersion(record.pendingBackup.version, 'pendingBackup.version');
    if (record.binding === null) fail('pendingBackup requires binding');
    validateBinding(record.pendingBackup.binding, identity.memberId, 'pendingBackup.binding');
    if (record.pendingBackup.binding.issuer !== record.binding.issuer
      || record.pendingBackup.binding.subject !== record.binding.subject) {
      fail('pendingBackup.binding is not the confirmed binding');
    }
  }
  return immutableRecord(record);
}

function identityFromSnapshot(snapshot, floor = snapshot.generation) {
  if (!isObject(snapshot)) fail('snapshot must be an object');
  return {
    memberId: snapshot.memberId,
    keystore: cloneBytes(snapshot.keystore, 'snapshot.keystore'),
    version: {
      generation: snapshot.generation,
      blobHash: cloneBytes(snapshot.blobHash, 'snapshot.blobHash'),
    },
    floor,
  };
}

/** Creates revision one from a credential-authenticated account snapshot. */
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
export async function replaceAccountIdentity(record, snapshot) {
  const current = await validateAccountRecord(record);
  if (current.revision === Number.MAX_SAFE_INTEGER) fail('revision is exhausted');
  const sameIdentity = current.identity.memberId === snapshot?.memberId;
  const knownFloor = accountFloorForMember(current, snapshot?.memberId);
  if (snapshot.generation < knownFloor) fail('identity generation rolls back');
  const identity = identityFromSnapshot(
    snapshot,
    Math.max(knownFloor, snapshot.generation),
  );
  const retainedIdentities = sameIdentity
    ? current.retainedIdentities
    : [
      ...current.retainedIdentities.filter((retained) => retained.memberId !== identity.memberId),
      current.identity,
    ];
  let pendingBackup = null;
  if (sameIdentity && current.binding !== null
    && !sameAccountVersion(current.identity.version, identity.version)) {
    pendingBackup = { kind: 'revoke', version: identity.version, binding: current.binding };
  } else if (sameIdentity && current.pendingBackup?.kind === 'revoke') {
    pendingBackup = { ...current.pendingBackup, version: identity.version };
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
export async function encodeAccountRecord(record) {
  const valid = await validateAccountRecord(record);
  return new TextEncoder().encode(JSON.stringify(recordToJson(valid)));
}

/** Decodes, validates, and detaches a persisted JSON account record. */
export async function decodeAccountRecord(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('encoded record must be a Uint8Array');
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    fail('encoded record is not valid JSON');
  }
  return validateAccountRecord(recordFromJson(parsed));
}
