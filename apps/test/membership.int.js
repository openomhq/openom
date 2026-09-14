// The two-account Mode A membership loop through the App API (invite model v3), on BOTH engines. Exercises the
// NET-NEW wiring for REAL — the short-link flow over a real RemoteStore against a faithful in-memory server, the
// authenticated-metadata round-trip (mint → GET /meta → verifyMeta), and the two-channel MACs through real
// invite.js. The wasm TRUST decisions (genesis-walk / anchor verify / unlock / addMember crypto) are stubbed —
// proven in Rust and unloadable in a Node .int, exactly as sharing.int.js documents. Also covers the Fable-found
// lifecycle: admit MARKS (never deletes), the join context RESUMES a restart, and a gone invite is TERMINAL.
import { describe, it, expect, beforeEach } from 'vitest';
import {
  inviteMember, pendingInvites, admitMember, submitJoinClaim, completeJoin, joinTree,
  WaitingForApproval, InviteUnavailable,
} from '../app/src/core/membership.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { mint, verifyClaim, signerIds, signersRetained } from '../app/src/core/invite.js';

const DOC = '00112233-4455-6677-8899-aabbccddeeff'; // tree uuid == docId
const TREE_ID = Uint8Array.from(DOC.replace(/-/g, '').match(/../g).map((h) => parseInt(h, 16)));
const OWNER_ID = 'acct-owner';
const JOINER_ID = 'acct-joiner';
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const chainPin = () => new Uint8Array(36).fill(7); // opaque to the JS layer (real shape: rev‖kh)

// ---- in-memory server double: the real /invites + /meta + keyring surface RemoteStore talks to -----------------
function makeServer() {
  const invites = new Map(); // inviteId -> row
  const keyrings = new Map(); // docId -> [revBytes]
  const resp = (status, text = '', headers = {}) => ({
    status, ok: status >= 200 && status < 300,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    async json() { return JSON.parse(text || 'null'); },
    async text() { return text; },
    async arrayBuffer() { return new TextEncoder().encode(text).buffer; },
  });
  const json = (o, status = 200) => resp(status, JSON.stringify(o), { 'content-type': 'application/json' });

  async function fetchImpl(url, { method = 'GET', body } = {}) {
    const p = new URL(url).pathname.split('/').filter(Boolean); // v1/trees/{id}/invites | v1/invites/{id}[/sub]
    if (p[1] === 'trees' && p[3] === 'invites') {
      const tree = p[2];
      if (method === 'POST') {
        const b = JSON.parse(body);
        invites.set(b.invite_id, { inviteId: b.invite_id, tree, role: b.role, engine: b.engine, pin: b.pin, meta_mac: b.meta_mac, recipient_pin: b.recipient_pin, expiry: b.expiry, status: 'open', claim: null });
        return json({ invite_id: b.invite_id });
      }
      const rows = [...invites.values()].filter((i) => i.tree === tree)
        .map((i) => ({ invite_id: i.inviteId, role: i.role, recipient_pin: i.recipient_pin, expiry: i.expiry, status: i.status, claim: i.claim }));
      return json(rows);
    }
    if (p[1] === 'invites') {
      const id = p[2];
      const inv = invites.get(id);
      if (p[3] === 'meta' && method === 'GET') {
        if (!inv || Date.now() > inv.expiry) return resp(404);
        return json({ uuid: inv.tree, role: inv.role, engine: inv.engine, pin: inv.pin, meta_mac: inv.meta_mac, expiry: inv.expiry, status: inv.status });
      }
      if (p[3] === 'claim' && method === 'PUT') {
        if (!inv) return resp(404);
        if (inv.status !== 'open') return resp(409);
        const b = JSON.parse(body);
        inv.claim = { member_id: b.member_id, hpke_public: b.hpke_public, author_public: b.author_public, tag: b.tag };
        inv.status = 'claimed';
        return resp(204);
      }
      if (p[3] === 'admit' && method === 'POST') { if (inv && inv.status === 'claimed') inv.status = 'admitted'; return resp(204); }
      if (p[3] === 'reopen' && method === 'POST') { if (inv && inv.status === 'claimed') { inv.status = 'open'; inv.claim = null; } return resp(204); }
      if (method === 'DELETE') { invites.delete(id); return resp(204); }
    }
    return resp(404);
  }

  return {
    fetch: (url, opts) => fetchImpl(url, opts),
    publishKeyring: (docId) => keyrings.set(docId, [...(keyrings.get(docId) ?? []), 1]),
    keyringOf: (docId) => keyrings.get(docId) ?? [],
    invite: (id) => invites.get(id),
    cancel: (id) => invites.delete(id),
  };
}

// ---- worker doubles: real invite.js crypto, stubbed wasm --------------------------------------------------------
function makeOwnerWorker(server, engine = 'chain') {
  const records = new Map();      // DURABLE mint records (simulated)
  const members = new Map([[OWNER_ID, 'co-owner']]);
  // The current SIGNER set (owner/co-owner), engine-agnostic (both engines derive the admit-gate fp from this);
  // the test flips it to simulate a signer add/remove since mint.
  let signerSet = [{ memberId: OWNER_ID, role: 1 }];
  const provisions = { count: 0 };
  return {
    engine, members, provisions, setSigners: (s) => { signerSet = s; },
    async inviteMember(docId, { role, ttlMs }) {
      const pin = engine === 'chain' ? chainPin() : new Uint8Array([9, 9, 9]);
      const m = await mint({ uuid: docId, role, engine, pin, ...(ttlMs ? { ttlMs } : {}) });
      records.set(m.inviteId, { ...m.record, signerIds: signerIds(signerSet) });
      return { inviteId: m.inviteId, link: m.link, pending: m.pending };
    },
    async admitMember(docId, { inviteId, claim }) {
      const record = records.get(inviteId);
      if (!record) throw new Error('no local mint record for this invite');
      if (Date.now() > record.expiry) throw new Error('invite expired');
      if (!signersRetained(record.signerIds, signerSet)) throw new Error('a signer was removed since mint');
      if (!(await verifyClaim(record, claim))) throw new Error('invite claim MAC mismatch — rejected');
      members.set(claim.memberId, record.role);
      server.publishKeyring(docId);
      records.delete(inviteId);
    },
  };
}

function makeJoinerWorker(server, ownerWorker) {
  return {
    async provisionMember() {
      ownerWorker.provisions.count += 1;
      return { kdfParams: new Uint8Array(8).fill(7), authorPublicKey: new Uint8Array(32).fill(0x22), hpkePublicKey: new Uint8Array(32).fill(0x33) };
    },
    async joinAsMember({ docId }) {
      if (server.keyringOf(docId).length === 0) throw Object.assign(new Error('no keyring history to verify'), { name: 'JoinError' });
      return { didKey: 'did:key:zJoiner', watermark: new Uint8Array(52) };
    },
  };
}

function memStorage() {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
}

describe('membership two-account loop v3 (App API)', () => {
  let server; let remote; let attachTransport; let attached;
  beforeEach(() => {
    server = makeServer();
    remote = new RemoteStore({ baseUrl: 'http://test', fetch: server.fetch });
    attached = [];
    attachTransport = async (docId) => { attached.push(docId); };
  });

  for (const engine of ['chain', 'dag']) {
    it(`shares → claims → waits → admits (no delete) → joins [${engine}]`, async () => {
      const ownerWorker = makeOwnerWorker(server, engine);
      const joinerWorker = makeJoinerWorker(server, ownerWorker);
      const ownerDeps = { worker: ownerWorker, remote };
      const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage: memStorage() };

      const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
      expect(invite.link).toMatch(/\/join#invite=/);

      // Whole flow, but unadmitted → WaitingForApproval.
      await expect(joinTree(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID }))
        .rejects.toBeInstanceOf(WaitingForApproval);
      expect(attached).toContain(DOC);

      // Owner admits: MAC verified against the durable mint record (real crypto).
      const pend = await pendingInvites(ownerDeps, { docId: DOC });
      expect(pend[0].claim.memberId).toBe(JOINER_ID);
      await admitMember(ownerDeps, { docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'pw-o', inviteId: pend[0].inviteId, claim: pend[0].claim });
      expect(ownerWorker.members.get(JOINER_ID)).toBe('viewer');
      // Fable Finding 1: the invite row SURVIVES admit (marked, not deleted) — the joiner still needs /meta.
      expect(server.invite(invite.inviteId).status).toBe('admitted');

      // Joiner resumes (poll) → now the keyring is served → joins.
      const ctx = await submitJoinClaim(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
      const joined = await completeJoin(joinerDeps, ctx);
      expect(joined.didKey).toBe('did:key:zJoiner');
    });
  }

  it('verifyMeta rejects a server that tampers with the metadata (role escalation)', async () => {
    const ownerWorker = makeOwnerWorker(server, 'chain');
    const joinerWorker = makeJoinerWorker(server, ownerWorker);
    const invite = await inviteMember({ worker: ownerWorker, remote }, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    server.invite(invite.inviteId).role = 'co-owner'; // a lying server escalates the role
    await expect(
      submitJoinClaim({ worker: joinerWorker, remote, attachTransport, storage: memStorage() }, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID }),
    ).rejects.toThrow(/MAC mismatch/);
  });

  it('resumes a restart from the persisted join context (no re-provision, no re-claim)', async () => {
    const ownerWorker = makeOwnerWorker(server, 'chain');
    const joinerWorker = makeJoinerWorker(server, ownerWorker);
    const storage = memStorage();
    const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage };
    const invite = await inviteMember({ worker: ownerWorker, remote }, { docId: DOC, treeId: TREE_ID, role: 'editor' });
    await submitJoinClaim(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    expect(ownerWorker.provisions.count).toBe(1);
    // "Restart": a fresh submit for the same invite+account reuses the persisted context.
    const ctx = await submitJoinClaim({ ...joinerDeps }, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    expect(ownerWorker.provisions.count).toBe(1); // did NOT re-provision
    expect(ctx.memberId).toBe(JOINER_ID);
  });

  it('a canceled invite is TERMINAL (InviteUnavailable), not an infinite wait', async () => {
    const ownerWorker = makeOwnerWorker(server, 'chain');
    const joinerWorker = makeJoinerWorker(server, ownerWorker);
    const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage: memStorage() };
    const invite = await inviteMember({ worker: ownerWorker, remote }, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    const ctx = await submitJoinClaim(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    server.cancel(invite.inviteId); // owner cancels before approving
    await expect(completeJoin(joinerDeps, ctx)).rejects.toBeInstanceOf(InviteUnavailable);
  });

  it('a second claimant on one invite is refused (one-live-claim → terminal)', async () => {
    const ownerWorker = makeOwnerWorker(server, 'chain');
    const joinerWorker = makeJoinerWorker(server, ownerWorker);
    const invite = await inviteMember({ worker: ownerWorker, remote }, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    await submitJoinClaim({ worker: joinerWorker, remote, attachTransport, storage: memStorage() }, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    await expect(
      submitJoinClaim({ worker: joinerWorker, remote, attachTransport, storage: memStorage() }, { link: invite.link, passphrase: 'pw2', memberId: 'acct-eve' }),
    ).rejects.toBeInstanceOf(InviteUnavailable);
  });

  // The anti-substitution admit gate is engine-agnostic (both engines derive the signer set from the keyring
  // summary) — run it on BOTH to prove parity. REMOVAL-ONLY: closes the "a co-owner about to be removed pre-mints
  // an invite for themselves, then it's admitted after their removal" hole, while TOLERATING benign additions.
  for (const engine of ['chain', 'dag']) {
    it(`admit gate: rejects a tampered claim + a since-mint signer REMOVAL, tolerates an ADD [${engine}]`, async () => {
      const ownerWorker = makeOwnerWorker(server, engine);
      const joinerWorker = makeJoinerWorker(server, ownerWorker);
      const ownerDeps = { worker: ownerWorker, remote };
      const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
      await submitJoinClaim({ worker: joinerWorker, remote, attachTransport, storage: memStorage() }, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
      const [p] = await pendingInvites(ownerDeps, { docId: DOC });
      const tampered = { ...p.claim, tag: new Uint8Array(p.claim.tag.length).fill(0) };
      await expect(admitMember(ownerDeps, { docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'x', inviteId: p.inviteId, claim: tampered }))
        .rejects.toThrow(/MAC mismatch/);
      // ADD a co-owner since mint → the mint-time signer is still present → admit is NOT blocked by the gate.
      ownerWorker.setSigners([{ memberId: OWNER_ID, role: 1 }, { memberId: 'carol', role: 2 }]);
      await admitMember(ownerDeps, { docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'x', inviteId: p.inviteId, claim: p.claim });
      expect(ownerWorker.members.get(JOINER_ID)).toBe('viewer'); // admitted despite the add
    });

    it(`admit gate: a mint-time signer REMOVED since mint fails admit [${engine}]`, async () => {
      const ownerWorker = makeOwnerWorker(server, engine);
      const joinerWorker = makeJoinerWorker(server, ownerWorker);
      const ownerDeps = { worker: ownerWorker, remote };
      const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
      await submitJoinClaim({ worker: joinerWorker, remote, attachTransport, storage: memStorage() }, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
      const [p] = await pendingInvites(ownerDeps, { docId: DOC });
      // The mint-time signer (OWNER_ID) is no longer a signer → the stale invite is refused.
      ownerWorker.setSigners([{ memberId: 'a-new-owner', role: 1 }]);
      await expect(admitMember(ownerDeps, { docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'x', inviteId: p.inviteId, claim: p.claim }))
        .rejects.toThrow(/signer was removed/);
    });
  }
});
