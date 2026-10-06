import { expect, test, type Browser, type BrowserContext, type Page, type Response } from '@playwright/test';
import { enterStagingGate } from './support/stagingGate.js';

const stagingAcceptance = process.env.OPENOM_STAGING_AUTH_ACCEPTANCE === '1';
const deployedAcceptance = process.env.OPENOM_DEPLOYED_AUTH_ACCEPTANCE === '1';
const enabled = stagingAcceptance || deployedAcceptance;
const deployedUrl = process.env.OPENOM_DEPLOYED_APP_URL
  ?? process.env.OPENOM_STAGING_APP_URL
  ?? 'https://app.staging.openom.org/';
const credentials = {
  email: process.env.SUPABASE_TEST_EMAIL ?? '',
  password: process.env.SUPABASE_TEST_PASSWORD ?? '',
};
const accountPassphrase = process.env.OPENOM_TEST_ACCOUNT_PASSPHRASE ?? '';
const gatePassword = process.env.STAGING_APP_GATE_PASSWORD ?? '';
const expectedCommit = (process.env.OPENOM_STAGING_COMMIT_SHA ?? '').slice(0, 7);

interface DeployedAccountResult {
  memberId: string;
  authSubject: string;
  path: 'created' | 'restored';
  state: { auth: string; account: string; binding: string; pending: string[] };
}

interface DeployedTreeMarker {
  docId: string;
  marker: string;
}

async function openDeployedApp(page: Page, readinessTimeoutMs: number): Promise<Response> {
  await page.route('**/src/main.js', (route) => route.fulfill({
    status: 200,
    contentType: 'application/javascript',
    body: 'export {};',
  }));

  let response: Response;
  if (stagingAcceptance) {
    response = await enterStagingGate(page, {
      stagingUrl: deployedUrl,
      password: gatePassword,
      expectedCommit,
      readinessTimeoutMs,
    });
  } else {
    const deadline = Date.now() + readinessTimeoutMs;
    let attempted: Response | null = null;
    while (Date.now() < deadline) {
      attempted = await page.goto(deployedUrl, { waitUntil: 'domcontentloaded' });
      if (attempted?.ok()) break;
      await page.waitForTimeout(2_000);
    }
    if (!attempted?.ok()) throw new Error('deployed app did not become reachable');
    response = attempted;
  }
  await expect(page.locator('meta[name="openom:auth-provider"]')).toHaveAttribute('content', 'supabase');
  return response;
}

async function composeAccount(page: Page) {
  await page.evaluate(async () => {
    const [{ composeAccountSession }, { createAuthProvider }, { appCoreWorker }, { RemoteStore }] = await Promise.all([
      import('/src/core/accountComposition.js'),
      import('/src/core/authProvider.js'),
      import('/src/core/appCoreClient.js'),
      import('/src/core/remoteStore.js'),
    ]);
    const serverUrl = document.querySelector('meta[name="openom:server"]')?.getAttribute('content')?.trim() ?? '';
    if (!serverUrl || serverUrl.startsWith('%')) throw new Error('staging server configuration is unresolved');
    const worker = appCoreWorker();
    await worker.warm();
    const composition = await composeAccountSession(worker, {
      createAuth: (account) => createAuthProvider(account),
      createRemote: (auth) => new RemoteStore({ baseUrl: serverUrl, auth }),
    });
    window.stagingAuthAcceptance = { ...composition, remote, worker };
  });
}

async function accountRoundTrip(page: Page, allowCreate: boolean): Promise<DeployedAccountResult> {
  return page.evaluate(async ({ signIn, passphrase, mayCreate }) => {
    const composition = window.stagingAuthAcceptance;
    await composition.auth.signIn(signIn);
    await composition.auth.getAccessToken({ forceRefresh: true });
    const probe = await composition.account.probe();

    let memberId;
    let path: 'created' | 'restored';
    if (probe.status === 'unregistered') {
      if (!mayCreate) throw new Error('the second staging context unexpectedly found an unregistered subject');
      const created = await composition.account.createAccount(passphrase);
      await composition.account.enableSync();
      memberId = created.memberId;
      path = 'created';
    } else {
      if (probe.remote.keystore === null) {
        throw new Error('the staging test subject is bound without a recoverable account backup');
      }
      const restored = await composition.account.restore({ passphrase });
      memberId = restored.memberId;
      path = 'restored';
    }

    const state = composition.account.state();
    return {
      memberId,
      authSubject: composition.auth.subject(),
      path,
      state: {
        auth: state.auth,
        account: state.account,
        binding: state.binding,
        pending: [...state.pending],
      },
    };
  }, { signIn: credentials, passphrase: accountPassphrase, mayCreate: allowCreate });
}

async function writeTreeMarker(page: Page, memberId: string): Promise<DeployedTreeMarker> {
  return page.evaluate(async ({ durableMemberId }) => {
    const composition = window.stagingAuthAcceptance;
    const [{ TreeLibrary }, { treeIdToUuid }, { remoteTransport }, Comlink] = await Promise.all([
      import('/src/core/library.js'),
      import('/src/core/keyringPublish.js'),
      import('/src/core/appCoreClient.js'),
      import('/src/vendor/comlink.js'),
    ]);
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(`openom deployed acceptance tree v1\0${durableMemberId}`),
    );
    const treeId = new Uint8Array(digest).slice(0, 16);
    const identity = { bytes: treeId, uuid: treeIdToUuid(treeId) };
    await composition.worker.attachTransport(identity.uuid, Comlink.proxy(remoteTransport(composition.remote)));
    const ownedTrees = await composition.remote.listOwnedTrees();
    let didKey: string;
    if (ownedTrees.length === 0) {
      ({ didKey } = await composition.worker.provisionTree({
        treeId: identity.bytes,
        docId: identity.uuid,
        engine: 'chain',
      }));
    } else {
      if (ownedTrees.length !== 1 || ownedTrees[0]?.id !== identity.uuid || ownedTrees[0]?.engine !== 'chain') {
        throw new Error('the deployed fixture account has an unexpected owner-tree selection');
      }
      ({ didKey } = await composition.worker.restoreTree({
        treeId: identity.bytes,
        docId: identity.uuid,
        engine: 'chain',
      }));
    }
    const tree = await new TreeLibrary(composition.worker).open(identity.uuid, didKey);
    const marker = `deployed-sync-${Date.now()}-${crypto.randomUUID()}`;
    await tree.createPerson({ given: marker, surname: 'acceptance' });
    const synced = await composition.worker.syncNow(identity.uuid);
    if (synced?.state !== 'ok') throw new Error(`tree write did not sync: ${JSON.stringify(synced)}`);
    return { docId: identity.uuid, marker };
  }, { durableMemberId: memberId });
}

async function readTreeMarker(page: Page, expected: DeployedTreeMarker): Promise<string[]> {
  return page.evaluate(async ({ source }) => {
    const composition = window.stagingAuthAcceptance;
    const [{ TreeLibrary }, { uuidToTreeId }, { remoteTransport }, Comlink] = await Promise.all([
      import('/src/core/library.js'),
      import('/src/core/keyringPublish.js'),
      import('/src/core/appCoreClient.js'),
      import('/src/vendor/comlink.js'),
    ]);
    const ownedTrees = await composition.remote.listOwnedTrees();
    if (ownedTrees.length !== 1 || ownedTrees[0]?.id !== source.docId) {
      throw new Error('the fresh context did not discover the expected owner tree');
    }
    const selected = ownedTrees[0];
    const treeId = uuidToTreeId(selected.id);
    await composition.worker.attachTransport(selected.id, Comlink.proxy(remoteTransport(composition.remote)));
    await composition.worker.restoreTree({
      treeId,
      docId: selected.id,
      engine: selected.engine,
    });
    const synced = await composition.worker.syncNow(selected.id);
    if (synced?.state !== 'ok') throw new Error(`tree read did not sync: ${JSON.stringify(synced)}`);
    const tree = await new TreeLibrary(composition.worker).open(selected.id);
    return tree.allPeople().map((person) => `${person.given} ${person.surname}`.trim());
  }, { source: expected });
}

async function acceptanceContext(browser: Browser, readinessTimeoutMs: number) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  const response = await openDeployedApp(page, readinessTimeoutMs);
  const csp = response.headers()['content-security-policy'] ?? '';
  const authOrigin = await page.locator('meta[name="openom:supabase-url"]').getAttribute('content') ?? '';
  expect(authOrigin).toMatch(/^https:\/\/[^%]+$/);
  expect(csp).toContain(authOrigin);
  await composeAccount(page);
  return { context, page, errors };
}

test('deployed app persists account custody and tree writes into a fresh context @staging', async ({ browser }) => {
  test.setTimeout(180_000);
  test.skip(!enabled, 'run from a deployed-app acceptance workflow with environment credentials');
  expect(credentials.email).not.toBe('');
  expect(credentials.password).not.toBe('');
  expect(accountPassphrase).not.toBe('');
  if (stagingAcceptance) expect(gatePassword).not.toBe('');
  if (expectedCommit) expect(expectedCommit).toMatch(/^[0-9a-f]{7}$/);

  const first = await acceptanceContext(browser, 120_000);
  let second: { context: BrowserContext; page: Page; errors: string[] } | null = null;
  try {
    const source = await accountRoundTrip(first.page, true);
    expect(source.authSubject).not.toBe(source.memberId);
    expect(source.state).toEqual({ auth: 'signedIn', account: 'unlocked', binding: 'backedUp', pending: [] });
    const treeMarker = await writeTreeMarker(first.page, source.memberId);

    second = await acceptanceContext(browser, 15_000);
    const restored = await accountRoundTrip(second.page, false);
    expect(restored.path).toBe('restored');
    expect(restored.memberId).toBe(source.memberId);
    expect(restored.authSubject).toBe(source.authSubject);
    expect(restored.state).toEqual({ auth: 'signedIn', account: 'unlocked', binding: 'backedUp', pending: [] });
    expect(await readTreeMarker(second.page, treeMarker)).toContain(`${treeMarker.marker} acceptance`);
    expect(first.errors).toEqual([]);
    expect(second.errors).toEqual([]);
  } finally {
    await first.context.close();
    await second?.context.close();
  }
});

declare global {
  interface Window {
    stagingAuthAcceptance: {
      account: {
        createAccount(passphrase: string): Promise<{ memberId: string }>;
        enableSync(): Promise<unknown>;
        probe(): Promise<
          { status: 'unregistered' }
          | { status: 'registered'; remote: { keystore: unknown | null } }
        >;
        restore(credential: { passphrase: string }): Promise<{ memberId: string }>;
        state(): { auth: string; account: string; binding: string; pending: readonly string[] };
      };
      auth: {
        signIn(credentials: { email: string; password: string }): Promise<void>;
        getAccessToken(options?: { forceRefresh?: boolean }): Promise<string>;
        subject(): string | null;
      };
      remote: {
        listOwnedTrees(): Promise<ReadonlyArray<{ id: string; engine: 'chain' | 'dag' }>>;
      };
      worker: {
        attachTransport(docId: string, transport: unknown): Promise<void>;
        provisionTree(input: {
          treeId: Uint8Array;
          docId: string;
          engine: 'chain';
        }): Promise<{ didKey: string }>;
        restoreTree(input: {
          treeId: Uint8Array;
          docId: string;
          engine: 'chain';
        }): Promise<{ didKey: string }>;
        syncNow(docId: string): Promise<{ state: string }>;
      };
      dispose(): void;
    };
  }
}
