import { describe, expect, it } from 'vitest';
import {
  acknowledgeAccountBackup,
  accountFloorForMember,
  assertAccountCustodyPreserved,
  confirmAccountBinding,
  createAccountRecord,
  decodeAccountRecord,
  effectiveAccountFloor,
  encodeAccountRecord,
  replaceAccountIdentity,
  sameAccountVersion,
  stageAccountBackup,
  validateAccountRecord,
} from '../app/src/core/accountRecord.js';

async function snapshot(memberId = 'member-a', generation = 1, keystore = new Uint8Array([1, 2, 3])) {
  const blobHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keystore));
  return { memberId, keystore, generation, blobHash };
}

function withConfirmedBackup(record) {
  const binding = { issuer: 'https://issuer.example', subject: 'provider-subject', memberId: record.identity.memberId };
  return {
    ...record,
    binding,
    acknowledgedBackup: { etag: '"remote-v1"', version: record.identity.version },
    pendingBackup: { kind: 'backup', version: record.identity.version, binding },
  };
}

describe('account record codec', () => {
  it('round-trips the portable JSON shape without sharing mutable input bytes', async () => {
    const source = await snapshot();
    const record = await createAccountRecord(source);
    source.keystore[0] = 99;
    const bytes = await encodeAccountRecord(record);
    const json = JSON.parse(new TextDecoder().decode(bytes));
    expect(json).toMatchObject({ revision: 1, identity: { memberId: 'member-a', floor: 1 } });
    expect(json.identity.blob.keystore).toEqual([1, 2, 3]);
    expect(json.identity.blob.blobHash).toHaveLength(32);
    const decoded = await decodeAccountRecord(bytes);
    expect(decoded).toEqual(record);
    expect(Object.isFrozen(decoded)).toBe(true);
    expect(Object.isFrozen(decoded.identity)).toBe(true);
  });

  it('rejects a hash that does not authenticate the exact keystore bytes', async () => {
    const record = await createAccountRecord(await snapshot());
    const corrupt = { ...record, identity: { ...record.identity, keystore: new Uint8Array([9, 2, 3]) } };
    await expect(validateAccountRecord(corrupt)).rejects.toThrow('does not match');
    const json = JSON.parse(new TextDecoder().decode(await encodeAccountRecord(record)));
    json.identity.blob.blobHash[0] ^= 1;
    await expect(decodeAccountRecord(new TextEncoder().encode(JSON.stringify(json)))).rejects.toThrow('does not match');
  });

  it('self-heals the effective floor from the resident blob generation', async () => {
    const original = await createAccountRecord(await snapshot('member-a', 8));
    const staleFloor = await validateAccountRecord({ ...original, identity: { ...original.identity, floor: 2 } });
    expect(effectiveAccountFloor(staleFloor)).toBe(8);
    await expect(replaceAccountIdentity(staleFloor, await snapshot('member-a', 7))).rejects.toThrow('rolls back');
    const next = await replaceAccountIdentity(staleFloor, await snapshot('member-a', 9, new Uint8Array([7])));
    expect(next.identity.floor).toBe(9);
    expect(next.identity.version.generation).toBe(9);
  });

  it('preserves same-identity remote metadata but clears it for a different identity', async () => {
    const base = withConfirmedBackup(await createAccountRecord(await snapshot()));
    const confirmed = await validateAccountRecord(base);
    const sameVersion = await replaceAccountIdentity(confirmed, await snapshot('member-a', 1));
    expect(sameVersion.binding).toEqual(confirmed.binding);
    expect(sameVersion.acknowledgedBackup).toEqual(confirmed.acknowledgedBackup);
    expect(sameVersion.pendingBackup).toEqual(confirmed.pendingBackup);

    const changedVersion = await replaceAccountIdentity(
      confirmed,
      await snapshot('member-a', 2, new Uint8Array([8])),
      { pendingKind: 'backup' },
    );
    expect(changedVersion.acknowledgedBackup).toEqual(confirmed.acknowledgedBackup);
    expect(changedVersion.pendingBackup).toMatchObject({
      kind: 'backup', version: changedVersion.identity.version,
    });

    const different = await replaceAccountIdentity(confirmed, await snapshot('member-b', 0, new Uint8Array([4])));
    expect(different.identity.floor).toBe(0);
    expect(different.binding).toBeNull();
    expect(different.acknowledgedBackup).toBeNull();
    expect(different.pendingBackup).toBeNull();
    expect(different.retainedIdentities.map((identity) => identity.memberId)).toEqual(['member-a']);
  });

  it('keeps record revision, credential generation, and version equality distinct', async () => {
    const initial = await createAccountRecord(await snapshot('member-a', 4));
    const rewrapped = await replaceAccountIdentity(initial, await snapshot('member-a', 4, new Uint8Array([4, 5])));
    const rotated = await replaceAccountIdentity(rewrapped, await snapshot('member-a', 5, new Uint8Array([6])));
    expect([initial.revision, rewrapped.revision, rotated.revision]).toEqual([1, 2, 3]);
    expect([initial.identity.version.generation, rewrapped.identity.version.generation, rotated.identity.version.generation]).toEqual([4, 4, 5]);
    expect(sameAccountVersion(initial.identity.version, rewrapped.identity.version)).toBe(false);
    expect(sameAccountVersion(rewrapped.identity.version, rewrapped.identity.version)).toBe(true);
  });

  it('keeps displaced custody and its floor when identities become active again', async () => {
    const first = await createAccountRecord(await snapshot('member-a', 8));
    const second = await replaceAccountIdentity(first, await snapshot('member-b', 1, new Uint8Array([4])));
    expect(accountFloorForMember(second, 'member-a')).toBe(8);
    await expect(replaceAccountIdentity(second, await snapshot('member-a', 7, new Uint8Array([5]))))
      .rejects.toThrow('rolls back');

    const restored = await replaceAccountIdentity(second, await snapshot('member-a', 9, new Uint8Array([6])));
    expect(restored.identity.memberId).toBe('member-a');
    expect(restored.retainedIdentities.map((identity) => identity.memberId)).toEqual(['member-b']);
    expect(() => assertAccountCustodyPreserved(second, {
      ...restored, retainedIdentities: [],
    })).toThrow('drops custody for member-b');

    const substituted = await snapshot('member-a', 8, new Uint8Array([9]));
    expect(() => assertAccountCustodyPreserved(second, {
      ...second,
      revision: second.revision + 1,
      retainedIdentities: [{
        memberId: substituted.memberId,
        keystore: substituted.keystore,
        version: { generation: substituted.generation, blobHash: substituted.blobHash },
        floor: substituted.generation,
      }],
    })).toThrow('mutates retained custody for member-a');
  });

  it('rejects malformed remote metadata and JSON byte arrays', async () => {
    const record = await createAccountRecord(await snapshot());
    await expect(validateAccountRecord({ ...record, revision: 0 })).rejects.toThrow('revision');
    await expect(validateAccountRecord({ ...record, binding: { issuer: 1, subject: 's', memberId: 'member-a' } })).rejects.toThrow('issuer');
    await expect(validateAccountRecord({
      ...record, binding: { issuer: '', subject: 'dev-subject', memberId: 'member-a' },
    })).resolves.toMatchObject({ binding: { issuer: '', subject: 'dev-subject' } });
    await expect(validateAccountRecord({ ...record, acknowledgedBackup: { etag: '"v1"', version: null } })).rejects.toThrow('requires binding');
    await expect(validateAccountRecord({
      ...record,
      binding: { issuer: 'i', subject: 's', memberId: 'member-a' },
      pendingBackup: {
        kind: 'backup', version: record.identity.version,
        binding: { issuer: 'i', subject: 'other', memberId: 'member-a' },
      },
    })).rejects.toThrow('not the confirmed binding');
    const json = JSON.parse(new TextDecoder().decode(await encodeAccountRecord(record)));
    json.identity.blob.keystore[0] = 256;
    await expect(decodeAccountRecord(new TextEncoder().encode(JSON.stringify(json)))).rejects.toThrow('invalid byte');
    json.identity.blob.keystore[0] = 1;
    delete json.binding;
    await expect(decodeAccountRecord(new TextEncoder().encode(JSON.stringify(json)))).rejects.toThrow('binding must be present');
  });

  it('stages and compare-clears only the exact acknowledged backup', async () => {
    const initial = await createAccountRecord(await snapshot('member-a', 4));
    const binding = { issuer: 'https://issuer.example', subject: 'subject-a', memberId: 'member-a' };
    const bound = await confirmAccountBinding(initial, binding);
    const staged = await stageAccountBackup(bound, { kind: 'backup', binding });
    expect(staged.pendingBackup.version).toEqual(staged.identity.version);

    const staleExpected = {
      ...staged.pendingBackup,
      version: { ...staged.pendingBackup.version, generation: 3 },
    };
    await expect(acknowledgeAccountBackup(staged, staleExpected, {
      etag: '"v4"', version: staged.identity.version,
    })).resolves.toBeNull();

    const acknowledged = await acknowledgeAccountBackup(staged, staged.pendingBackup, {
      etag: '"v4"', version: staged.identity.version,
    });
    expect(acknowledged.pendingBackup).toBeNull();
    expect(acknowledged.acknowledgedBackup).toEqual({
      etag: '"v4"', version: staged.identity.version,
    });
  });

  it('never downgrades a pending revoke to an ordinary backup', async () => {
    const initial = await createAccountRecord(await snapshot());
    const binding = { issuer: 'https://issuer.example', subject: 'subject-a', memberId: 'member-a' };
    const bound = await confirmAccountBinding(initial, binding);
    const revoke = await stageAccountBackup(bound, { kind: 'revoke', binding });
    const attemptedBackup = await stageAccountBackup(revoke, { kind: 'backup', binding });
    expect(attemptedBackup).toEqual(revoke);

    const rewrapped = await replaceAccountIdentity(
      revoke,
      await snapshot('member-a', 1, new Uint8Array([9, 9])),
      { pendingKind: 'backup' },
    );
    expect(rewrapped.pendingBackup.kind).toBe('revoke');
    expect(rewrapped.pendingBackup.version).toEqual(rewrapped.identity.version);
    await expect(acknowledgeAccountBackup(rewrapped, revoke.pendingBackup, {
      etag: '"empty"', version: null,
    })).resolves.toBeNull();

    const acknowledged = await acknowledgeAccountBackup(revoke, revoke.pendingBackup, {
      etag: '"stored"', version: revoke.identity.version,
    });
    expect(acknowledged.acknowledgedBackup).toEqual({
      etag: '"stored"', version: revoke.identity.version,
    });
  });
});
