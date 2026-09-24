import { expect, type Page, type Response } from '@playwright/test';

const GATE_COOKIE = 'openom_staging_gate';

export interface StagingGateOptions {
  readonly stagingUrl: string;
  readonly password: string;
  readonly expectedCommit: string;
  readonly readinessTimeoutMs?: number;
}

async function gateObservation(page: Page, response: Response | null) {
  const form = page.locator('form[action="/__gate"]');
  const visible = await form.isVisible().catch(() => false);
  const commit = visible
    ? (await page.locator('footer .meta code').first().textContent().catch(() => null))?.trim() ?? ''
    : '';
  return { status: response?.status() ?? null, visible, commit };
}

async function waitForExpectedGate(page: Page, options: StagingGateOptions): Promise<Response> {
  const deadline = Date.now() + (options.readinessTimeoutMs ?? 120_000);
  let last = 'no response';
  do {
    try {
      const response = await page.goto(options.stagingUrl, { waitUntil: 'domcontentloaded' });
      const observed = await gateObservation(page, response);
      last = `status=${observed.status ?? 'none'}, gate=${observed.visible}, commit=${observed.commit || 'none'}`;
      if (response?.status() === 401 && observed.visible && observed.commit === options.expectedCommit) {
        return response;
      }
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() < deadline) await page.waitForTimeout(2_000);
  } while (Date.now() < deadline);
  throw new Error(`expected staging gate for commit ${options.expectedCommit}; last observation: ${last}`);
}

export async function enterStagingGate(page: Page, options: StagingGateOptions): Promise<Response> {
  await waitForExpectedGate(page, options);
  await page.locator('input[name="password"]').fill(options.password);
  const navigation = page.waitForNavigation({ waitUntil: 'domcontentloaded' });
  await page.locator('button[type="submit"]').click();
  const response = await navigation;
  if (!response?.ok()) {
    throw new Error(`staging gate rejected the configured password (status ${response?.status() ?? 'none'})`);
  }

  const cookies = await page.context().cookies(options.stagingUrl);
  const cookie = cookies.find(({ name }) => name === GATE_COOKIE);
  expect(cookie, 'staging gate sets its admission cookie').toMatchObject({
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
  });
  expect(cookie?.value).toMatch(/^[0-9a-f]{64}$/);
  return response;
}
