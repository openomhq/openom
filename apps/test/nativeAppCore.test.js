import { afterEach, describe, expect, it, vi } from 'vitest';
import { createNativeAppCore } from '../app/src/core/nativeAppCore.js';

const previousTauri = Reflect.get(globalThis, '__TAURI__');

afterEach(() => {
  vi.restoreAllMocks();
  if (previousTauri === undefined) Reflect.deleteProperty(globalThis, '__TAURI__');
  else Reflect.set(globalThis, '__TAURI__', previousTauri);
});

function installHost(handler) {
  const invoke = vi.fn(handler);
  Reflect.set(globalThis, '__TAURI__', { core: { invoke } });
  return invoke;
}

describe('native app-core parity', () => {
  it('fetches and adopts keyring successors through the shared syncKeyring contract', async () => {
    const invoke = installHost(async (command) => {
      if (command === 'core_invite_material') return { engine: 'chain', pin: [1] };
      if (command === 'core_keyring_head') return 1;
      if (command === 'core_sync_keyring') return null;
      throw new Error(`unexpected command: ${command}`);
    });
    const transport = {
      readKeyring: vi.fn(async () => ({
        head: 2,
        revisions: [{ revision: 2, bytes: new Uint8Array([1, 2, 3]) }],
      })),
    };
    const core = createNativeAppCore();
    core.attachTransport('doc', transport);

    await expect(core.syncKeyring('doc', new Uint8Array(16))).resolves.toEqual({ changed: true });
    expect(transport.readKeyring).toHaveBeenCalledWith('doc', 2);
    expect(invoke).toHaveBeenLastCalledWith('core_sync_keyring', expect.objectContaining({
      doc: 'doc',
      treeId: expect.any(Array),
      hops: expect.any(Array),
    }));
  });

  it('adopts a newer DAG anchor through the native host', async () => {
    const invoke = installHost(async (command) => {
      if (command === 'core_invite_material') return { engine: 'dag', pin: [1] };
      if (command === 'core_sync_dag_anchor') return 'adopted';
      throw new Error(`unexpected command: ${command}`);
    });
    const core = createNativeAppCore();
    core.attachTransport('doc', {
      readKeyring: vi.fn(async () => ({
        head: 2,
        revisions: [{ revision: 2, bytes: new Uint8Array([4, 5, 6]) }],
      })),
    });

    await expect(core.syncKeyring('doc', new Uint8Array(16))).resolves.toEqual({ changed: true });
    expect(invoke).toHaveBeenLastCalledWith('core_sync_dag_anchor', expect.objectContaining({
      doc: 'doc', treeId: expect.any(Array), anchor: [4, 5, 6],
    }));
  });

  it('retries a failed DAG publication before allowing blob transfer', async () => {
    let failKeyringPut = true;
    let serverAnchor = new Uint8Array([1]);
    let serverHead = 1;
    const events = [];
    installHost(async (command) => {
      if (command === 'core_provision') return { didKey: 'did:key:z6Mkowner' };
      if (command === 'core_invite_material') return { engine: 'dag', pin: [1] };
      if (command === 'core_sync_dag_anchor') {
        return serverAnchor[0] === 1 ? 'localAhead' : 'unchanged';
      }
      if (command === 'core_dag_keyring_publish_payload') return { update: [9], body: [2] };
      if (command === 'core_membership_summary') return JSON.stringify({ members: [], basis: ['op:2'] });
      if (command === 'core_plan_fetch') return [];
      if (command === 'core_sync') {
        events.push('data-sync');
        return {
          uploads: [{ key: 'doc/log/replica/1', bytes: [7], pointer: false }],
          folded: 1,
          covered: {},
        };
      }
      if (command === 'core_pull_frontier') return {};
      if (command === 'core_anomalies') return 0;
      throw new Error(`unexpected command: ${command}`);
    });
    const transport = {
      createTree: vi.fn(async () => {}),
      readKeyring: vi.fn(async () => ({
        head: serverHead,
        revisions: [{ revision: serverHead, bytes: serverAnchor }],
      })),
      putKeyring: vi.fn(async () => {
        events.push('keyring-put');
        if (failKeyringPut) throw new Error('offline keyring channel');
        serverAnchor = new Uint8Array([2]);
        serverHead += 1;
      }),
      getAccess: vi.fn(async () => null),
      putAccess: vi.fn(async () => ({ generation: 1, unchanged: false })),
      blobList: vi.fn(async () => []),
      blobGet: vi.fn(),
      blobPut: vi.fn(async () => { events.push('blob-put'); }),
      putFrontier: vi.fn(),
    };
    const core = createNativeAppCore();
    const docId = '11111111-1111-4111-8111-111111111111';
    await core.provisionTree({ treeId: new Uint8Array(16).fill(1), docId, engine: 'dag' });
    core.attachTransport(docId, transport);

    const blocked = await core.syncNow(docId);
    expect(blocked.state).toBe('error');
    expect(events).toEqual(['keyring-put']);
    expect(transport.blobPut).not.toHaveBeenCalled();

    failKeyringPut = false;
    events.length = 0;
    const recovered = await core.syncNow(docId);
    expect(recovered.state).toBe('ok');
    expect(events).toEqual(['keyring-put', 'data-sync', 'blob-put']);
    expect(transport.putKeyring).toHaveBeenCalledTimes(2);
    expect(transport.blobPut).toHaveBeenCalledTimes(1);
  });

  it('bounds DAG publication conflicts and retries them before data transfer', async () => {
    let conflictsRemaining = 3;
    const events = [];
    installHost(async (command) => {
      if (command === 'core_provision') return { didKey: 'did:key:z6Mkowner' };
      if (command === 'core_invite_material') return { engine: 'dag', pin: [1] };
      if (command === 'core_sync_dag_anchor') return 'localAhead';
      if (command === 'core_dag_keyring_publish_payload') return { update: [9], body: [2] };
      if (command === 'core_membership_summary') return JSON.stringify({ members: [], basis: ['op:2'] });
      if (command === 'core_plan_fetch') return [];
      if (command === 'core_sync') {
        events.push('data-sync');
        return {
          uploads: [{ key: 'doc/log/replica/1', bytes: [7], pointer: false }],
          folded: 1,
          covered: {},
        };
      }
      if (command === 'core_pull_frontier') return {};
      if (command === 'core_anomalies') return 0;
      throw new Error(`unexpected command: ${command}`);
    });
    const transport = {
      createTree: vi.fn(async () => {}),
      readKeyring: vi.fn(async () => ({
        head: 1,
        revisions: [{ revision: 1, bytes: new Uint8Array([1]) }],
      })),
      putKeyring: vi.fn(async () => {
        events.push('keyring-put');
        if (conflictsRemaining > 0) {
          conflictsRemaining -= 1;
          const conflict = new Error('competing DAG anchor');
          conflict.name = 'ConflictError';
          throw conflict;
        }
      }),
      getAccess: vi.fn(async () => null),
      putAccess: vi.fn(async () => ({ generation: 1, unchanged: false })),
      blobList: vi.fn(async () => []),
      blobGet: vi.fn(),
      blobPut: vi.fn(async () => { events.push('blob-put'); }),
      putFrontier: vi.fn(),
    };
    const core = createNativeAppCore();
    const docId = '22222222-2222-4222-8222-222222222222';
    await core.provisionTree({ treeId: new Uint8Array(16).fill(2), docId, engine: 'dag' });
    core.attachTransport(docId, transport);

    const blocked = await core.syncNow(docId);
    expect(blocked.state).toBe('error');
    expect(events).toEqual(['keyring-put', 'keyring-put', 'keyring-put']);
    expect(transport.blobPut).not.toHaveBeenCalled();

    events.length = 0;
    const recovered = await core.syncNow(docId);
    expect(recovered.state).toBe('ok');
    expect(events).toEqual(['keyring-put', 'data-sync', 'blob-put']);
    expect(transport.putKeyring).toHaveBeenCalledTimes(4);
  });

  it('normalizes the native nullable resolver result to the shared undefined result', async () => {
    installHost(async (command) => {
      if (command === 'core_resolve_id') return null;
      throw new Error(`unexpected command: ${command}`);
    });

    await expect(createNativeAppCore().resolveId('doc', 'anchor')).resolves.toBeUndefined();
  });

  it('uses the tree UUID for proposal routes rather than the blob-key prefix', async () => {
    const treeUuid = '9cc89391-8935-4bb7-b543-8a00a9d031f6';
    const treeId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    installHost(async (command) => {
      if (command === 'core_provision') return { didKey: 'did:key:z6Mkowner' };
      if (command === 'core_propose') return [7, 8, 9];
      throw new Error(`unexpected command: ${command}`);
    });
    const transport = {
      createProposal: vi.fn(async () => ({ id: 'proposal-1', expiresAt: 1_800_000_000 })),
    };
    const core = createNativeAppCore();
    core.attachTransport(treeUuid, transport);
    await core.provisionTree({ treeId, docId: treeUuid });

    await core.proposeEdit(treeUuid);

    expect(transport.createProposal).toHaveBeenCalledWith(treeUuid, new Uint8Array([7, 8, 9]));
    expect(transport.createProposal).not.toHaveBeenCalledWith(
      '0102030405060708090a0b0c0d0e0f10',
      expect.anything(),
    );
  });
});
