import { describe, it, expect } from 'vitest';
import { mint, parseLink, verifyMeta, claim, verifyClaim, fingerprintSigners } from '../app/src/core/invite.js';

// Two signers; distinct 32-byte author keys.
const OWNER = { memberId: '00000000-0000-0000-0000-0000000000aa', authorPublicKey: new Uint8Array(32).fill(0xa1) };
const COOWNER = { memberId: '00000000-0000-0000-0000-0000000000bb', authorPublicKey: new Uint8Array(32).fill(0xb2) };

// A would-be member's provisionMember output (simulated — the wasm crypto is tested elsewhere).
const M = {
  memberId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  hpkePublicKey: new Uint8Array(32).fill(0x11),
  authorPublicKey: new Uint8Array(32).fill(0x22),
};

const UUID = 'bc4e834a-7856-865c-98f7-7a91502b86bf';
// An opaque chain pin (rev(4)‖kh(32) = 36 bytes) — invite.js never interprets it.
const PIN = Uint8Array.from({ length: 36 }, (_, i) => i + 1);

async function ownerMints(role = 'editor', engine = 'chain', pin = PIN) {
  return mint({ uuid: UUID, role, engine, pin, now: 1_000_000, ttlMs: 3600_000 });
}

// The invitee's view of the server metadata (what GET /meta would return + the inviteId from the link).
const metaOf = (inviteId, s, pending) => ({
  s, inviteId, uuid: pending.uuid, role: pending.role, engine: pending.engine, pin: pending.pin, metaMac: pending.metaMac,
});

describe('invite crypto (two-channel, v3)', () => {
  it('fingerprintSigners is deterministic and order-independent', async () => {
    const a = await fingerprintSigners([OWNER, COOWNER]);
    const b = await fingerprintSigners([COOWNER, OWNER]); // reversed
    expect(a).toBe(b);
    expect(await fingerprintSigners([OWNER])).not.toBe(a); // a different signer set → a different fp
  });

  it('mint → short link → parseLink; the server payload carries metadata but no secret', async () => {
    const { link, record, pending, inviteId } = await ownerMints('maintainer');
    expect(link).toMatch(/\/join#invite=/);
    const parsed = parseLink(link);
    expect(parsed.inviteId).toBe(inviteId);
    expect(parsed.s).toBeInstanceOf(Uint8Array);
    expect(parsed.s.length).toBe(32);
    // the SHORT link carries ONLY invite + s — no uuid/role/engine/pin
    expect(link).not.toMatch(/tree=|role=|engine=|pin=/);
    // the server pending payload has NO s / no subkey — the secret is owner↔invitee only
    expect('s' in pending || 'sMac' in pending || 'sMacClaim' in pending).toBe(false);
    expect(pending).toMatchObject({ uuid: UUID, role: 'maintainer', engine: 'chain', expiry: 1_000_000 + 3600_000 });
    expect(pending.pin).toEqual(PIN);
    expect(pending.metaMac).toBeInstanceOf(Uint8Array);
    // the LOCAL record holds s_mac_claim (for admit), never the raw s
    expect(record.sMacClaim).toBeInstanceOf(Uint8Array);
    expect('s' in record).toBe(false);
  });

  it('mint rejects a bad engine or an empty pin', async () => {
    await expect(mint({ uuid: UUID, role: 'editor', engine: 'nope', pin: PIN })).rejects.toThrow(/engine/);
    await expect(mint({ uuid: UUID, role: 'editor', engine: 'chain', pin: new Uint8Array(0) })).rejects.toThrow(/pin/);
  });

  it('verifyMeta returns the trusted metadata for a genuine server response', async () => {
    const { link, pending } = await ownerMints('editor', 'dag', Uint8Array.from([9, 9, 9]));
    const { inviteId, s } = parseLink(link);
    const trusted = await verifyMeta(metaOf(inviteId, s, pending));
    expect(trusted).toEqual({ uuid: UUID, role: 'editor', engine: 'dag', pin: Uint8Array.from([9, 9, 9]) });
  });

  it('verifyMeta rejects tampered metadata (server substitutes role / engine / pin / uuid)', async () => {
    const { link, pending } = await ownerMints('viewer');
    const { inviteId, s } = parseLink(link);
    const base = metaOf(inviteId, s, pending);
    await expect(verifyMeta({ ...base, role: 'co-owner' })).rejects.toThrow(/MAC mismatch/); // role escalation
    await expect(verifyMeta({ ...base, engine: 'dag' })).rejects.toThrow(/MAC mismatch/); // engine swap
    await expect(verifyMeta({ ...base, pin: new Uint8Array(36).fill(0xff) })).rejects.toThrow(/MAC mismatch/);
    await expect(verifyMeta({ ...base, uuid: '00000000-0000-0000-0000-000000000000' })).rejects.toThrow(/MAC mismatch/);
  });

  it('verifyMeta is fail-closed on a missing field (no "if present" fallback)', async () => {
    const { link, pending } = await ownerMints('editor');
    const { inviteId, s } = parseLink(link);
    const base = metaOf(inviteId, s, pending);
    for (const drop of ['metaMac', 'pin', 'engine', 'uuid', 'role']) {
      await expect(verifyMeta({ ...base, [drop]: undefined })).rejects.toThrow(/missing|malformed|MAC/);
    }
  });

  it('verifyMeta rejects a wrong link secret', async () => {
    const { link, pending } = await ownerMints('editor');
    const { inviteId } = parseLink(link);
    await expect(verifyMeta(metaOf(inviteId, new Uint8Array(32).fill(1), pending))).rejects.toThrow(/MAC mismatch/);
  });

  it('domain separation: a claim tag cannot pass as a meta MAC (distinct subkeys)', async () => {
    const { link, pending } = await ownerMints('editor');
    const { inviteId, s } = parseLink(link);
    // A claim MAC is computed under s_mac_claim over a claim tuple; feeding it as meta_mac must fail.
    const c = await claim({ s, inviteId, uuid: UUID, role: 'editor', ...M });
    await expect(verifyMeta({ ...metaOf(inviteId, s, pending), metaMac: c.tag })).rejects.toThrow(/MAC mismatch/);
  });

  it('a genuine claim verifies against the owner record (uuid/role from the verified meta)', async () => {
    const { link, pending, record } = await ownerMints('editor');
    const { inviteId, s } = parseLink(link);
    const meta = await verifyMeta(metaOf(inviteId, s, pending));
    const c = await claim({ s, inviteId, uuid: meta.uuid, role: meta.role, ...M });
    expect(await verifyClaim(record, c)).toBe(true);
  });

  it('rejects a claim with substituted keys (the server-MITM the protocol exists to stop)', async () => {
    const { link, record } = await ownerMints('editor');
    const { inviteId, s } = parseLink(link);
    const c = await claim({ s, inviteId, uuid: UUID, role: 'editor', ...M });
    const tampered = { ...c, hpkePublicKey: new Uint8Array(32).fill(0x99) };
    expect(await verifyClaim(record, tampered)).toBe(false);
  });

  it('binds role + account + invite (each mismatch fails against the record)', async () => {
    const { link, record } = await ownerMints('editor');
    const { inviteId, s } = parseLink(link);
    const wrongRole = await claim({ s, inviteId, uuid: UUID, role: 'maintainer', ...M });
    expect(await verifyClaim(record, wrongRole)).toBe(false); // record's role governs
    const impostor = { ...(await claim({ s, inviteId, uuid: UUID, role: 'editor', ...M })), memberId: '00000000-0000-0000-0000-0000000000ff' };
    expect(await verifyClaim(record, impostor)).toBe(false);
    const other = await ownerMints('editor'); // a different invite (different s + id)
    const op = parseLink(other.link);
    const otherClaim = await claim({ s: op.s, inviteId: op.inviteId, uuid: UUID, role: 'editor', ...M });
    expect(await verifyClaim(record, otherClaim)).toBe(false); // replayed across invites → fails
  });

  it('parseLink rejects a malformed link', () => {
    expect(() => parseLink('https://openom.app/join#invite=x')).toThrow(/invalid invite link/); // missing s
    expect(() => parseLink('https://openom.app/join#s=AAAA')).toThrow(/invalid invite link/); // missing invite
  });
});
