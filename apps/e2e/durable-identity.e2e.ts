import { createHmac, randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';

const enabled = process.env.OPENOM_DURABLE_IDENTITY_ACCEPTANCE === '1';
const serverUrl = process.env.OPENOM_DURABLE_IDENTITY_SERVER_URL ?? 'http://localhost:6061';
const jwtSecret = process.env.OPENOM_DURABLE_IDENTITY_JWT_SECRET ?? 'openom-ope547-local-hs256-secret';
const jwtIssuer = process.env.OPENOM_DURABLE_IDENTITY_JWT_ISSUER ?? 'https://ope547.local.openom.test';
const harnessUrl = `http://localhost:5173/e2e/durable-identity-harness.html?server=${encodeURIComponent(serverUrl)}`;

interface TestAuth {
  accessToken: string;
  issuer: string;
  subject: string;
}

interface AcceptanceState {
  auth: string;
  binding: string;
  pending: string[];
}

interface SignUpFirstResult {
  memberId: string;
  ownerMemberId: string;
  authSubject: string;
  hadTreeBeforeRegister: boolean;
  hadTreeAfterRegister: boolean;
  registeredState: AcceptanceState;
  syncedState: AcceptanceState;
  people: string[];
}

interface LocalFirstResult {
  memberIds: string[];
  didKeys: string[];
  pins: number[][];
  authSubject: string;
  oldPassphraseRejected: boolean;
  finalState: AcceptanceState;
  people: string[];
}

function jwt(subject: string): TestAuth {
  const now = Math.floor(Date.now() / 1000);
  const encodedHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify({
    sub: subject,
    iss: jwtIssuer,
    aud: 'authenticated',
    iat: now - 30,
    exp: now + 3_600,
  })).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', jwtSecret).update(signingInput).digest('base64url');
  return { accessToken: `${signingInput}.${signature}`, issuer: jwtIssuer, subject };
}

async function ready(page: import('@playwright/test').Page) {
  await page.goto(harnessUrl);
  await expect(page.locator('#status')).toHaveText('ready', { timeout: 20_000 });
}

test('durable identity registers before creating its first DAG tree @integration', async ({ page }) => {
  test.skip(!enabled, 'run through scripts/durable-identity-acceptance.mjs');
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await ready(page);
  const auth = jwt(`ope547-signup-first-${randomUUID()}`);

  const result = await page.evaluate(async (input) => window.durableIdentityAcceptance.signUpFirst(input), {
    auth,
    passphrase: 'OPE-547 signup-first passphrase',
    given: 'Signup',
  });

  expect(result.authSubject).not.toBe(result.memberId);
  expect(result.ownerMemberId).toBe(result.memberId);
  expect(result.hadTreeBeforeRegister).toBe(false);
  expect(result.hadTreeAfterRegister).toBe(false);
  expect(result.registeredState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });
  expect(result.syncedState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });
  expect(result.people).toContain('Signup signup-first');
  expect(errors).toEqual([]);
});

test('local DAG signup and credential changes preserve identity and keyring @integration', async ({ page }) => {
  test.skip(!enabled, 'run through scripts/durable-identity-acceptance.mjs');
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await ready(page);
  const auth = jwt(`ope547-local-first-${randomUUID()}`);

  const result = await page.evaluate(
    async (input) => window.durableIdentityAcceptance.localFirstThenSignUpAndRotate(input),
    {
      auth,
      passphrase: 'OPE-547 local-first passphrase',
      changedPassphrase: 'OPE-547 changed passphrase',
      recoveredPassphrase: 'OPE-547 recovered passphrase',
      given: 'Local',
    },
  );

  expect(result.authSubject).not.toBe(result.memberIds[0]);
  expect(new Set(result.memberIds).size).toBe(1);
  expect(new Set(result.didKeys).size).toBe(1);
  expect(result.pins.every((pin) => JSON.stringify(pin) === JSON.stringify(result.pins[0]))).toBe(true);
  expect(result.oldPassphraseRejected).toBe(true);
  expect(result.finalState).toEqual({ auth: 'signedIn', binding: 'backedUp', pending: [] });
  expect(result.people).toContain('Local local-first');
  expect(errors).toEqual([]);
});

declare global {
  interface Window {
    durableIdentityAcceptance: {
      signUpFirst(input: {
        auth: TestAuth;
        passphrase: string;
        given: string;
      }): Promise<SignUpFirstResult>;
      localFirstThenSignUpAndRotate(input: {
        auth: TestAuth;
        passphrase: string;
        changedPassphrase: string;
        recoveredPassphrase: string;
        given: string;
      }): Promise<LocalFirstResult>;
    };
  }
}
