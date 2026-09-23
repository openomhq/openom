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

  it('treats the chain-only keyring command as a dag no-op', async () => {
    installHost(async () => Promise.reject(JSON.stringify({
      code: 'internal',
      message: 'keyring store: keyring_head is chain-only; a dag head is an anchor',
    })));
    const core = createNativeAppCore();
    core.attachTransport('doc', { readKeyring: vi.fn() });

    await expect(core.syncKeyring('doc', new Uint8Array(16))).resolves.toEqual({ changed: false });
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
