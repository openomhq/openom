// The two-account Mode A membership loop through the App API (OPE-442): share → claim → admit → join, plus a
// light edit/remove to complete the lifecycle. Exercises the NET-NEW wiring for REAL — the `/invites` transport
// over a real `RemoteStore` against a faithful in-memory server, and the two-channel MAC round-trip through real
// `invite.js` (owner mints s_mac → joiner claims with the link's `s` → owner verifies). The wasm TRUST decisions
// (genesis-walk verify / unlock / addMember crypto) are stubbed — proven in Rust (openom_vault::sharing e2es) and
// unloadable in a Node `.int`, exactly as sharing.int.js documents. The real-wasm edit/remove e2e is a browser
// @integration test (separate slice-1 deliverable); here "edit" = the member core opened, "remove" = the keyring
// rotated.
import { describe, it, expect, beforeEach } from 'vitest';
import {
  inviteMember, pendingInvites, admitMember, submitJoinClaim, completeJoin, joinTree, WaitingForApproval,
} from '../app/src/core/membership.js';
import { RemoteStore } from '../app/src/core/remoteStore.js';
import { mint, verifyClaim, fingerprintSigners } from '../app/src/core/invite.js';

// ---- fixtures -------------------------------------------------------------------------------------------------
const DOC = '00112233-4455-6677-8899-aabbccddeeff'; // the tree uuid (== docId == the seam bytes' UUID form)
const TREE_ID = Uint8Array.from(DOC.replace(/-/g, '').match(/../g).map((h) => parseInt(h, 16)));
const OWNER_ID = 'acct-owner';
const JOINER_ID = 'acct-joiner';
const SIGNERS = [{ memberId: OWNER_ID, authorPublicKey: new Uint8Array(32).fill(0x11) }];
const PIN_HASH = new Uint8Array(32).fill(0xab);

// ---- an in-memory server double: the real `/invites` + keyring surface `RemoteStore` talks to ------------------
function makeServer() {
  const invites = new Map(); // inviteId -> { inviteId, tree, role, recipient_pin, expiry, status, claim }
  const keyrings = new Map(); // docId -> [revBytes,...]

  const resp = (status, text = '', headers = {}) => ({
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    async json() { return JSON.parse(text || 'null'); },
    async text() { return text; },
    async arrayBuffer() { return new TextEncoder().encode(text).buffer; },
  });
  const json = (obj, status = 200) => resp(status, JSON.stringify(obj), { 'content-type': 'application/json' });

  async function fetchImpl(url, { method = 'GET', body } = {}) {
    const parts = new URL(url).pathname.split('/').filter(Boolean); // v1/trees/{id}/invites | v1/invites/{id}[/claim]
    // POST/GET /v1/trees/{id}/invites
    if (parts[1] === 'trees' && parts[3] === 'invites') {
      const tree = parts[2];
      if (method === 'POST') {
        const b = JSON.parse(body);
        invites.set(b.invite_id, { inviteId: b.invite_id, tree, role: b.role, recipient_pin: b.recipient_pin, expiry: b.expiry, status: 'open', claim: null });
        return json({ invite_id: b.invite_id });
      }
      const rows = [...invites.values()].filter((i) => i.tree === tree).map((i) => ({
        invite_id: i.inviteId, role: i.role, recipient_pin: i.recipient_pin, expiry: i.expiry, status: i.status, claim: i.claim,
      }));
      return json(rows);
    }
    // PUT /v1/invites/{id}/claim | DELETE /v1/invites/{id}
    if (parts[1] === 'invites') {
      const id = parts[2];
      const inv = invites.get(id);
      if (parts[3] === 'claim' && method === 'PUT') {
        if (!inv) return resp(404);
        if (inv.status !== 'open') return resp(409); // one live claim
        const b = JSON.parse(body);
        inv.claim = { member_id: b.member_id, hpke_public: b.hpke_public, author_public: b.author_public, tag: b.tag };
        inv.status = 'claimed';
        return resp(204);
      }
      if (method === 'DELETE') { invites.delete(id); return resp(204); }
    }
    return resp(404);
  }

  return {
    fetch: (url, opts) => fetchImpl(url, opts),
    publishKeyring: (docId, revBytes) => keyrings.set(docId, [...(keyrings.get(docId) ?? []), revBytes]),
    keyringOf: (docId) => keyrings.get(docId) ?? [],
    inviteCount: () => invites.size,
  };
}

// ---- worker doubles: real invite.js crypto, stubbed wasm trust decisions --------------------------------------
function makeOwnerWorker(server) {
  const records = new Map(); // inviteId -> the invite.mint() record (holds s_mac) — the real worker's in-memory store
  const members = new Map([[OWNER_ID, 'co-owner']]);
  return {
    async inviteMember(docId, { role }) {
      const m = await mint({ uuid: docId, role, signers: SIGNERS, pinnedRevision: 1, pinnedHash: PIN_HASH });
      records.set(m.inviteId, m.record);
      return { inviteId: m.inviteId, link: m.link, fp: m.fp, pending: m.pending };
    },
    async admitMember(docId, { inviteId, claim }) {
      const record = records.get(inviteId);
      if (!record) throw new Error('no local mint record for this invite');
      if ((await fingerprintSigners(SIGNERS)) !== record.fp) throw new Error('signer set changed since mint');
      if (!(await verifyClaim(record, claim))) throw new Error('invite claim MAC mismatch — rejected');
      members.set(claim.memberId, record.role);          // addMember effect
      server.publishKeyring(docId, new Uint8Array([members.size])); // a new keyring revision peers can pull
      records.delete(inviteId);
    },
    async removeMember(docId, { removeMemberId }) {
      members.delete(removeMemberId);
      server.publishKeyring(docId, new Uint8Array([0xff])); // forward-secret re-key: a rotated revision
    },
    members,
  };
}

function makeJoinerWorker(server) {
  return {
    async provisionMember() {
      return { kdfParams: new Uint8Array(8).fill(7), authorPublicKey: new Uint8Array(32).fill(0x22), hpkePublicKey: new Uint8Array(32).fill(0x33) };
    },
    async joinAsMember({ docId }) {
      // The genesis-walk verify is stubbed (Rust-proven). Model only the ADMIT gate: no revision yet ⇒ the ACL
      // hasn't admitted us ⇒ the same JoinError sharing.js throws for an empty keyring history.
      if (server.keyringOf(docId).length === 0) {
        throw Object.assign(new Error('no keyring history to verify'), { name: 'JoinError' });
      }
      return { didKey: 'did:key:zJoiner', watermark: new Uint8Array(52) };
    },
  };
}

function memStorage() {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
}

// ---- the loop -------------------------------------------------------------------------------------------------
describe('membership two-account loop (App API)', () => {
  let server; let remote; let ownerWorker; let joinerWorker; let attachTransport; let attached;

  beforeEach(() => {
    server = makeServer();
    remote = new RemoteStore({ baseUrl: 'http://test', fetch: server.fetch });
    ownerWorker = makeOwnerWorker(server);
    joinerWorker = makeJoinerWorker(server);
    attached = [];
    attachTransport = async (docId) => { attached.push(docId); };
  });

  it('shares → claims → (waits) → admits → joins, then removes', async () => {
    const ownerDeps = { worker: ownerWorker, remote };
    const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage: memStorage() };

    // 1. OWNER invites → a link + a pending server invite.
    const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    expect(invite.link).toMatch(/\/join#/);
    expect(invite.inviteId).toBeTruthy();
    expect(server.inviteCount()).toBe(1);

    // 2. JOINER runs the whole flow but the owner hasn't admitted → a normal pre-admit WaitingForApproval.
    let ctx;
    await expect(
      joinTree(joinerDeps, { link: invite.link, passphrase: 'pw-joiner', memberId: JOINER_ID }),
    ).rejects.toBeInstanceOf(WaitingForApproval);
    expect(attached).toContain(DOC); // the transport was attached before the join attempt

    // 3. OWNER sees the claim and admits it. The MAC verifies against the LOCAL mint record (real crypto).
    const pend = await pendingInvites(ownerDeps, { docId: DOC });
    expect(pend).toHaveLength(1);
    expect(pend[0].claim).not.toBeNull();
    expect(pend[0].claim.memberId).toBe(JOINER_ID);
    await admitMember(ownerDeps, {
      docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'pw-owner',
      inviteId: pend[0].inviteId, claim: pend[0].claim,
    });
    expect(ownerWorker.members.get(JOINER_ID)).toBe('viewer'); // admitted at the role from the RECORD
    expect(server.inviteCount()).toBe(0); // invite consumed

    // 4. JOINER polls completeJoin — now the keyring is served → the member core opens (edit-ready).
    ctx = await submitOnlyContext(joinerDeps, invite.link); // rebuild ctx without re-claiming (server rejects dup)
    const joined = await completeJoin(joinerDeps, ctx);
    expect(joined.didKey).toBe('did:key:zJoiner');
    expect(joined.docId).toBe(DOC);

    // 5. OWNER removes the member → a rotated (forward-secret) keyring revision.
    const before = server.keyringOf(DOC).length;
    await ownerWorker.removeMember(DOC, { removeMemberId: JOINER_ID });
    expect(ownerWorker.members.has(JOINER_ID)).toBe(false);
    expect(server.keyringOf(DOC).length).toBe(before + 1);
  });

  it('rejects a tampered claim at admit (MAC mismatch) — nothing admitted', async () => {
    const ownerDeps = { worker: ownerWorker, remote };
    const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage: memStorage() };
    const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    await submitJoinClaim(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    const pend = await pendingInvites(ownerDeps, { docId: DOC });
    const tampered = { ...pend[0].claim, tag: new Uint8Array(pend[0].claim.tag.length).fill(0) };
    await expect(
      admitMember(ownerDeps, { docId: DOC, treeId: TREE_ID, ownerMemberId: OWNER_ID, passphrase: 'pw', inviteId: pend[0].inviteId, claim: tampered }),
    ).rejects.toThrow(/MAC mismatch/);
    expect(ownerWorker.members.has(JOINER_ID)).toBe(false);
  });

  it('a second claim on the same invite is refused (one live claim)', async () => {
    const ownerDeps = { worker: ownerWorker, remote };
    const joinerDeps = { worker: joinerWorker, remote, attachTransport, storage: memStorage() };
    const invite = await inviteMember(ownerDeps, { docId: DOC, treeId: TREE_ID, role: 'viewer' });
    await submitJoinClaim(joinerDeps, { link: invite.link, passphrase: 'pw', memberId: JOINER_ID });
    await expect(
      submitJoinClaim({ ...joinerDeps, storage: memStorage() }, { link: invite.link, passphrase: 'pw2', memberId: 'acct-eve' }),
    ).rejects.toBeTruthy();
  });

  // Rebuild a joinContext WITHOUT re-submitting the claim (the server allows only one live claim), by re-parsing
  // the link + re-provisioning deterministically — mirrors a UI resuming a pending join to poll completeJoin.
  async function submitOnlyContext(deps, link) {
    const { parseLink } = await import('../app/src/core/invite.js');
    const parsed = parseLink(link);
    const prov = await deps.worker.provisionMember();
    return {
      docId: parsed.uuid, treeId: TREE_ID, treeUuid: parsed.uuid, passphrase: 'pw-joiner', memberId: JOINER_ID,
      memberKdfParams: prov.kdfParams, pinnedRevision: parsed.pinnedRevision, pinnedHash: parsed.pinnedHash,
      fp: parsed.fp, engine: 'chain',
    };
  }
});
